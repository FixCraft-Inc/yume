/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "modules/files/file_receiver.hpp"
#include "modules/relay/identity.hpp"
#include "test_support/allocation_failure.hpp"

#include <array>
#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cerrno>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <typeinfo>
#include <utility>
#include <vector>

#if defined(YUME_TEST_RECEIVE_IO_WRAP)
#include <openssl/evp.h>
#include <dirent.h>
#endif

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

constexpr std::string_view kRelayStagePrefix = ".yume-relay-part.";

#if defined(YUME_TEST_RECEIVE_IO_WRAP)
enum class ReceiveFaultKind { Write, Hash, Validation };

struct ReceiveFault {
    ReceiveFaultKind kind{ReceiveFaultKind::Write};
    yume::files::RelayFileReceiver* receiver{nullptr};
    const char* stage{nullptr};
    dev_t device{};
    ino_t inode{};
    int file_fd{-1};
    bool armed{false};
    bool fired{false};
    bool allocation_failed{false};
    bool cleaned_before_diagnostic{false};
    bool hash_throw_seen{false};
};

thread_local ReceiveFault receive_fault;

void FailDiagnosticAllocation(std::size_t) {
    struct stat info{};
    const bool stage_removed =
        ::lstat(receive_fault.stage, &info) != 0 && errno == ENOENT;
    const bool file_closed =
        receive_fault.file_fd < 0 ||
        (::fcntl(receive_fault.file_fd, F_GETFD) < 0 && errno == EBADF);
    receive_fault.cleaned_before_diagnostic =
        !receive_fault.receiver->active() && stage_removed && file_closed;
    receive_fault.allocation_failed = true;
    yume::test::fail_allocations.store(true, std::memory_order_relaxed);
    throw std::bad_alloc();
}

std::size_t OpenDescriptorCount() {
    DIR* directory = ::opendir("/proc/self/fd");
    assert(directory != nullptr);
    std::size_t count = 0;
    while (const auto* entry = ::readdir(directory)) {
        if (entry->d_name[0] != '.') ++count;
    }
    assert(::closedir(directory) == 0);
    return count;
}
#endif

class TempDirectory {
public:
    TempDirectory() {
        std::array<char, 64> pattern{};
        const std::string prefix = "/tmp/yume-relay-receive-test-XXXXXX";
        std::copy(prefix.begin(), prefix.end(), pattern.begin());
        char* made = ::mkdtemp(pattern.data());
        assert(made != nullptr);
        path_ = made;
        assert(::chmod(path_.c_str(), S_IRWXU) == 0);
    }
    ~TempDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }
    const std::filesystem::path& path() const { return path_; }
private:
    std::filesystem::path path_;
};

std::vector<std::filesystem::path> RelayStageEntries(
        const std::filesystem::path& directory) {
    std::vector<std::filesystem::path> entries;
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        const std::string name = entry.path().filename().string();
        if (name.starts_with(kRelayStagePrefix)) {
            entries.push_back(entry.path());
        }
    }
    std::sort(entries.begin(), entries.end());
    return entries;
}

void MakeStale(const std::filesystem::path& path) {
    struct timespec times[2] {};
    assert(::clock_gettime(CLOCK_REALTIME, &times[0]) == 0);
    times[0].tv_sec -= 48 * 60 * 60;
    times[1] = times[0];
    assert(::utimensat(AT_FDCWD, path.c_str(), times,
                       AT_SYMLINK_NOFOLLOW) == 0);
}

void CreatePrivateFile(const std::filesystem::path& path,
                       std::string_view content = {}) {
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        assert(output.good());
        if (!content.empty()) {
            output.write(content.data(),
                         static_cast<std::streamsize>(content.size()));
        }
        assert(output.good());
    }
    assert(::chmod(path.c_str(), S_IRUSR | S_IWUSR) == 0);
}

void test_basename_validation_without_allocations() {
    using yume::files::RelayFileReceiver;
    const std::string maximum_name(128U, 'a');
    const std::string long_stem = std::string(120U, 'a') + ".bin";

    // Validation is noexcept and must keep working when allocations fail.
    yume::test::arm_allocation_failure(1U);
    bool accepted = RelayFileReceiver::IsSafeBasename(maximum_name) &&
                    RelayFileReceiver::IsSafeBasename(long_stem);
    for (const std::string_view name :
         {"COM0.txt", "COM10.txt", "conx.txt", "auxiliary.txt", "LPT9x"}) {
        accepted = RelayFileReceiver::IsSafeBasename(name) && accepted;
    }
    bool rejected = true;
    for (const std::string_view name :
         {"con", "PrN.txt", "aUx.tar", "nul", "cOm1.dat", "LpT9.txt"}) {
        rejected = !RelayFileReceiver::IsSafeBasename(name) && rejected;
    }
    const bool allocated = yume::test::disarm_allocation_failure();

    assert(accepted && rejected);
    assert(!allocated);
}

void test_receive_deadline_bounds() {
    using namespace std::chrono;
    using yume::files::RelayFileReceiver;
    using yume::files::RelayReceiveLimits;
    using Clock = steady_clock;
    TempDirectory temp;
    const auto destination = temp.path() / "must-not-be-created";
    const std::string digest =
        yume::relay::identity::sha256_hex(std::span<const std::uint8_t>{});
    const auto horizon =
        duration_cast<milliseconds>(Clock::time_point::max() - Clock::now());
    const auto largest_duration =
        duration_cast<milliseconds>(Clock::duration::max());
    for (const auto duration :
         {milliseconds::zero(), milliseconds{-1}, milliseconds::max(),
          largest_duration + milliseconds{1}, horizon + milliseconds{1}}) {
        RelayReceiveLimits limits;
        limits.max_duration = duration;
        RelayFileReceiver receiver;
        std::string error;
        assert(!receiver.Begin(destination, "rejected.bin", 0, digest, limits,
                               &error));
        assert(!receiver.active() && !receiver.complete());
        assert(error == "relay receive limits are invalid");
        assert(!std::filesystem::exists(destination));
    }
    for (const auto duration : {milliseconds{1000}, horizon - hours{1}}) {
        RelayReceiveLimits limits;
        limits.max_duration = duration;
        RelayFileReceiver receiver;
        std::string error;
        assert(receiver.Begin(temp.path(), "accepted.bin", 0, digest, limits,
                              &error));
        assert(receiver.active() && !receiver.expired());
        receiver.Abort();
        assert(RelayStageEntries(temp.path()).empty());
    }
}

#if defined(YUME_TEST_RECEIVE_IO_WRAP)
void test_failure_cleanup_before_diagnostic() {
    using yume::files::RelayFileReceiver;
    using yume::files::RelayReceiveLimits;
    for (const auto kind : {ReceiveFaultKind::Write, ReceiveFaultKind::Hash,
                            ReceiveFaultKind::Validation}) {
        TempDirectory temp;
        const auto descriptors = OpenDescriptorCount();
        RelayFileReceiver receiver;
        const std::array<std::uint8_t, 1> bytes{42};
        std::string error;
        const auto digest = yume::relay::identity::sha256_hex(bytes);
        assert(receiver.Begin(temp.path(), "failed.bin", 1, digest,
                              RelayReceiveLimits{}, &error));
        const auto stages = RelayStageEntries(temp.path());
        assert(stages.size() == 1U);
        struct stat info{};
        assert(::stat(stages.front().c_str(), &info) == 0);
        receive_fault = {};
        receive_fault.kind = kind;
        receive_fault.receiver = &receiver;
        receive_fault.stage = stages.front().c_str();
        receive_fault.device = info.st_dev;
        receive_fault.inode = info.st_ino;
        receive_fault.armed = true;
        if (kind == ReceiveFaultKind::Validation) {
            receive_fault.fired = true;
            yume::test::before_allocate = FailDiagnosticAllocation;
        }
        struct Disarm {
            ~Disarm() {
                receive_fault.armed = false;
                yume::test::before_allocate = nullptr;
                yume::test::fail_allocations.store(false,
                                                   std::memory_order_relaxed);
            }
        };
        bool result = true;
        bool escaped = false;
        {
            Disarm disarm;
            try {
                result = receiver.Append(kind == ReceiveFaultKind::Validation
                                             ? std::span<const std::uint8_t>{}
                                             : bytes,
                                         &error);
            } catch (const std::bad_alloc&) {
                escaped = true;
            }
        }
        assert(receive_fault.fired && receive_fault.allocation_failed);
        assert(kind != ReceiveFaultKind::Hash || receive_fault.hash_throw_seen);
        assert(receive_fault.cleaned_before_diagnostic);
        assert(!escaped && !result);
        assert(error.empty());
        assert(!receiver.active() && !receiver.complete());
        assert(RelayStageEntries(temp.path()).empty());
        assert(!std::filesystem::exists(temp.path() / "failed.bin"));
        assert(OpenDescriptorCount() == descriptors);
    }
}
#endif

}  // namespace

#if defined(YUME_TEST_RECEIVE_IO_WRAP)
extern "C" ssize_t __real_write(int fd, const void* bytes, std::size_t size);
extern "C" ssize_t __wrap_write(int fd, const void* bytes, std::size_t size) {
    if (receive_fault.armed && !receive_fault.fired) {
        struct stat info{};
        if (::fstat(fd, &info) == 0 && info.st_dev == receive_fault.device &&
            info.st_ino == receive_fault.inode) {
            receive_fault.file_fd = fd;
            if (receive_fault.kind == ReceiveFaultKind::Write) {
                receive_fault.fired = true;
                yume::test::before_allocate = FailDiagnosticAllocation;
                errno = EIO;
                return -1;
            }
        }
    }
    return __real_write(fd, bytes, size);
}

extern "C" int __real_EVP_DigestUpdate(EVP_MD_CTX* context, const void* data,
                                       std::size_t size);
extern "C" int __wrap_EVP_DigestUpdate(EVP_MD_CTX* context, const void* data,
                                       std::size_t size) {
    if (receive_fault.armed && !receive_fault.fired &&
        receive_fault.kind == ReceiveFaultKind::Hash) {
        receive_fault.fired = true;
        return 0;
    }
    return __real_EVP_DigestUpdate(context, data, size);
}

extern "C" [[noreturn]] void __real___cxa_throw(void*, std::type_info*,
                                                void (*)(void*));
extern "C" [[noreturn]] void __wrap___cxa_throw(void* exception,
                                                std::type_info* type,
                                                void (*destroy)(void*)) {
    if (receive_fault.armed && receive_fault.fired &&
        receive_fault.kind == ReceiveFaultKind::Hash &&
        *type == typeid(std::runtime_error)) {
        // Arm after the initiating error owns its message, independent of
        // how the selected C++ runtime allocates exception storage.
        receive_fault.hash_throw_seen = true;
        yume::test::before_allocate = FailDiagnosticAllocation;
    }
    __real___cxa_throw(exception, type, destroy);
}
#endif

int main() {
    using yume::files::RelayFileReceiver;
    using yume::files::RelayReceiveLimits;

#if defined(YUME_TEST_RECEIVE_IO_WRAP)
    test_failure_cleanup_before_diagnostic();
#endif
    test_receive_deadline_bounds();
    test_basename_validation_without_allocations();
    assert(RelayFileReceiver::IsSafeBasename("archive.bin"));
    assert(RelayFileReceiver::IsSafeBasename("report-2026.dat"));
    assert(!RelayFileReceiver::IsSafeBasename(""));
    assert(!RelayFileReceiver::IsSafeBasename("."));
    assert(!RelayFileReceiver::IsSafeBasename(".."));
    assert(!RelayFileReceiver::IsSafeBasename("../escape"));
    assert(!RelayFileReceiver::IsSafeBasename("sub/file"));
    assert(!RelayFileReceiver::IsSafeBasename("sub\\file"));
    assert(!RelayFileReceiver::IsSafeBasename("/absolute"));
    assert(!RelayFileReceiver::IsSafeBasename("report 2026.dat"));
    assert(!RelayFileReceiver::IsSafeBasename("NUL.txt"));
    assert(!RelayFileReceiver::IsSafeBasename(std::string(129, 'a')));
    const std::string empty_sha256 = yume::relay::identity::sha256_hex(
        std::span<const std::uint8_t>{});
    assert(RelayFileReceiver::IsCanonicalSha256Digest(empty_sha256));
    assert(!RelayFileReceiver::IsCanonicalSha256Digest(
        std::string(64, 'A')));
    assert(!RelayFileReceiver::IsCanonicalSha256Digest(
        std::string(63, 'a')));

    const std::array<std::uint8_t, 3> hash_input{'a', 'b', 'c'};
    constexpr std::string_view kAbcSha256 =
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad";
    assert(yume::relay::identity::sha256_hex(hash_input) == kAbcSha256);
    yume::relay::identity::Sha256Stream stream;
    stream.Update(std::span(hash_input).first(2));
    yume::relay::identity::Sha256Stream moved_stream(std::move(stream));
    bool moved_from_update_rejected = false;
    try {
        stream.Update(hash_input);
    } catch (const std::logic_error&) {
        moved_from_update_rejected = true;
    }
    assert(moved_from_update_rejected);
    moved_stream.Update(std::span(hash_input).subspan(2));
    assert(moved_stream.FinishHex() == kAbcSha256);
    bool finalized_update_rejected = false;
    try {
        moved_stream.Update(hash_input);
    } catch (const std::logic_error&) {
        finalized_update_rejected = true;
    }
    assert(finalized_update_rejected);
    bool finalized_finish_rejected = false;
    try {
        (void)moved_stream.Finish();
    } catch (const std::logic_error&) {
        finalized_finish_rejected = true;
    }
    assert(finalized_finish_rejected);

    TempDirectory temp;
    std::string error;
    assert(yume::files::PrepareRelayReceiveDirectory(temp.path(), &error));
    const RelayReceiveLimits limits{64, 8, std::chrono::seconds(2)};

    const auto created_directory = temp.path() / "created" / "nested";
    assert(yume::files::PrepareRelayReceiveDirectory(
        created_directory, &error));
    struct stat created_parent_info {};
    struct stat created_directory_info {};
    assert(::stat((temp.path() / "created").c_str(),
                  &created_parent_info) == 0);
    assert(::stat(created_directory.c_str(), &created_directory_info) == 0);
    assert((created_parent_info.st_mode & 07777) == S_IRWXU);
    assert((created_directory_info.st_mode & 07777) == S_IRWXU);

    const auto real_component = temp.path() / "real-component";
    assert(std::filesystem::create_directory(real_component));
    assert(::chmod(real_component.c_str(), S_IRWXU) == 0);
    const auto linked_component = temp.path() / "linked-component";
    assert(::symlink("real-component", linked_component.c_str()) == 0);
    assert(!yume::files::PrepareRelayReceiveDirectory(
        linked_component, &error));
    RelayFileReceiver linked_directory;
    assert(!linked_directory.Begin(linked_component, "linked.bin", 0,
                                   empty_sha256, limits, &error));
    assert(!std::filesystem::exists(real_component / "linked.bin"));

    const auto unsafe_directory = temp.path() / "unsafe-directory";
    assert(std::filesystem::create_directory(unsafe_directory));
    assert(::chmod(unsafe_directory.c_str(),
                   S_IRWXU | S_IRGRP | S_IXGRP) == 0);
    assert(!yume::files::PrepareRelayReceiveDirectory(
        unsafe_directory, &error));
    RelayFileReceiver unsafe_destination;
    assert(!unsafe_destination.Begin(unsafe_directory, "unsafe.bin", 0,
                                     empty_sha256, limits, &error));

    std::vector<std::uint8_t> decoded;
    assert(yume::files::DecodeRelayChunkBase64("AQI=", 2, &decoded, &error));
    assert((decoded == std::vector<std::uint8_t>{1, 2}));
    assert(!yume::files::DecodeRelayChunkBase64("AQI=ignored", 8, &decoded, &error));
    assert(!yume::files::DecodeRelayChunkBase64("AQ I=", 8, &decoded, &error));
    assert(!yume::files::DecodeRelayChunkBase64("AQI", 8, &decoded, &error));

    RelayFileReceiver complete;
    const std::array<std::uint8_t, 2> first{1, 2};
    const std::array<std::uint8_t, 2> second{3, 4};
    const std::array<std::uint8_t, 4> complete_bytes{1, 2, 3, 4};
    const std::string complete_sha256 =
        yume::relay::identity::sha256_hex(complete_bytes);
    assert(complete.Begin(temp.path(), "complete.bin", 4,
                          complete_sha256, limits, &error));
    assert(!std::filesystem::exists(temp.path() / "complete.bin"));
    assert(RelayStageEntries(temp.path()).size() == 1);
    assert(complete.Append(first, &error));
    RelayFileReceiver moved_complete(std::move(complete));
    assert(moved_complete.Append(second, &error));
    assert(moved_complete.Finish(&error));
    assert(moved_complete.complete());
    assert(std::filesystem::file_size(temp.path() / "complete.bin") == 4);
    assert(RelayStageEntries(temp.path()).empty());
    struct stat completed_info {};
    assert(::stat((temp.path() / "complete.bin").c_str(), &completed_info) == 0);
    assert((completed_info.st_mode & 0777) == (S_IRUSR | S_IWUSR));

    RelayFileReceiver zero_bytes;
    assert(zero_bytes.Begin(temp.path(), "zero.bin", 0,
                            empty_sha256, limits, &error));
    assert(!std::filesystem::exists(temp.path() / "zero.bin"));
    assert(zero_bytes.Finish(&error));
    assert(zero_bytes.complete());
    assert(std::filesystem::file_size(temp.path() / "zero.bin") == 0);

    RelayFileReceiver tampered;
    const std::array<std::uint8_t, 4> tampered_bytes{1, 2, 3, 5};
    assert(tampered.Begin(temp.path(), "tampered.bin", 4,
                          complete_sha256, limits, &error));
    assert(tampered.Append(tampered_bytes, &error));
    assert(!tampered.Finish(&error));
    assert(error.find("digest mismatch") != std::string::npos);
    assert(!std::filesystem::exists(temp.path() / "tampered.bin"));
    assert(RelayStageEntries(temp.path()).empty());

    RelayFileReceiver invalid_digest;
    assert(!invalid_digest.Begin(temp.path(), "uppercase-digest.bin", 0,
                                 std::string(64, 'A'), limits, &error));
    assert(!std::filesystem::exists(
        temp.path() / "uppercase-digest.bin"));
    assert(RelayStageEntries(temp.path()).empty());

    {
        std::ofstream existing(temp.path() / "existing.bin");
        existing << "keep";
    }
    RelayFileReceiver overwrite;
    assert(!overwrite.Begin(temp.path(), "existing.bin", 1,
                            empty_sha256, limits, &error));
    std::ifstream existing(temp.path() / "existing.bin");
    std::string existing_text;
    existing >> existing_text;
    assert(existing_text == "keep");

    assert(::symlink("existing.bin", (temp.path() / "link.bin").c_str()) == 0);
    RelayFileReceiver symlink;
    assert(!symlink.Begin(temp.path(), "link.bin", 1,
                          empty_sha256, limits, &error));

    RelayFileReceiver too_large;
    assert(!too_large.Begin(temp.path(), "too-large.bin", 65,
                            empty_sha256, limits, &error));
    assert(!std::filesystem::exists(temp.path() / "too-large.bin"));

    RelayFileReceiver chunk_overflow;
    assert(chunk_overflow.Begin(temp.path(), "chunk-overflow.bin", 16,
                                empty_sha256, limits, &error));
    const std::array<std::uint8_t, 9> oversized_chunk{};
    assert(!chunk_overflow.Append(oversized_chunk, &error));
    assert(!std::filesystem::exists(temp.path() / "chunk-overflow.bin"));

    RelayFileReceiver cumulative_overflow;
    assert(cumulative_overflow.Begin(temp.path(), "cumulative.bin", 3,
                                     empty_sha256, limits, &error));
    assert(cumulative_overflow.Append(first, &error));
    assert(!cumulative_overflow.Append(second, &error));
    assert(!std::filesystem::exists(temp.path() / "cumulative.bin"));

    RelayFileReceiver early_done;
    assert(early_done.Begin(temp.path(), "early.bin", 4,
                            complete_sha256, limits, &error));
    assert(early_done.Append(first, &error));
    assert(!early_done.Finish(&error));
    assert(!std::filesystem::exists(temp.path() / "early.bin"));

    RelayFileReceiver destination_collision;
    assert(destination_collision.Begin(temp.path(), "race.bin", 4,
                                       complete_sha256, limits, &error));
    assert(destination_collision.Append(complete_bytes, &error));
    CreatePrivateFile(temp.path() / "race.bin", "replacement");
    assert(!destination_collision.Finish(&error));
    assert(error.find("without replacing") != std::string::npos);
    assert(std::filesystem::exists(temp.path() / "race.bin"));
    std::ifstream replacement(temp.path() / "race.bin");
    std::string replacement_text;
    replacement >> replacement_text;
    assert(replacement_text == "replacement");
    assert(RelayStageEntries(temp.path()).empty());

    RelayFileReceiver late_symlink;
    assert(late_symlink.Begin(temp.path(), "late-link.bin", 4,
                              complete_sha256, limits, &error));
    assert(late_symlink.Append(complete_bytes, &error));
    assert(::symlink("existing.bin",
                     (temp.path() / "late-link.bin").c_str()) == 0);
    assert(!late_symlink.Finish(&error));
    assert(std::filesystem::is_symlink(temp.path() / "late-link.bin"));
    assert(RelayStageEntries(temp.path()).empty());

    {
        RelayFileReceiver abandoned;
        assert(abandoned.Begin(temp.path(), "abandoned.bin", 4,
                               complete_sha256, limits, &error));
        assert(abandoned.Append(first, &error));
    }
    assert(!std::filesystem::exists(temp.path() / "abandoned.bin"));
    assert(RelayStageEntries(temp.path()).empty());

    const pid_t crash_child = ::fork();
    assert(crash_child >= 0);
    if (crash_child == 0) {
        RelayFileReceiver crash_residue;
        std::string child_error;
        if (!crash_residue.Begin(temp.path(), "crash.bin", 2,
                                 yume::relay::identity::sha256_hex(first),
                                 limits, &child_error)) {
            ::_exit(10);
        }
        if (!crash_residue.Append(first, &child_error)) {
            ::_exit(11);
        }
        // Model abrupt process loss: no receiver destructor or Abort call.
        ::_exit(0);
    }
    int crash_status = 0;
    assert(::waitpid(crash_child, &crash_status, 0) == crash_child);
    assert(WIFEXITED(crash_status) && WEXITSTATUS(crash_status) == 0);
    assert(!std::filesystem::exists(temp.path() / "crash.bin"));
    auto crash_stages = RelayStageEntries(temp.path());
    assert(crash_stages.size() == 1);
    MakeStale(crash_stages.front());
    RelayFileReceiver stale_cleanup;
    assert(stale_cleanup.Begin(temp.path(), "stale-cleanup.bin", 0,
                               empty_sha256, limits, &error));
    stale_cleanup.Abort();
    assert(RelayStageEntries(temp.path()).empty());

    const auto recent_stage = temp.path() /
        ".yume-relay-part.4294967295.1";
    CreatePrivateFile(recent_stage);
    RelayFileReceiver recent_cleanup;
    assert(recent_cleanup.Begin(temp.path(), "recent-cleanup.bin", 0,
                                empty_sha256, limits, &error));
    recent_cleanup.Abort();
    auto recent_entries = RelayStageEntries(temp.path());
    assert(recent_entries.size() == 1 && recent_entries.front() == recent_stage);
    assert(std::filesystem::remove(recent_stage));

    const auto unsafe_stage_symlink = temp.path() /
        ".yume-relay-part.4294967295.2";
    assert(::symlink("existing.bin", unsafe_stage_symlink.c_str()) == 0);
    RelayFileReceiver unsafe_stage_link_receiver;
    assert(!unsafe_stage_link_receiver.Begin(
        temp.path(), "unsafe-stage-link.bin", 0,
        empty_sha256, limits, &error));
    assert(std::filesystem::is_symlink(unsafe_stage_symlink));
    assert(std::filesystem::remove(unsafe_stage_symlink));

    const auto hardlink_source = temp.path() / "stage-hardlink-source";
    const auto hardlinked_stage = temp.path() /
        ".yume-relay-part.4294967295.3";
    CreatePrivateFile(hardlink_source);
    assert(::link(hardlink_source.c_str(), hardlinked_stage.c_str()) == 0);
    MakeStale(hardlinked_stage);
    RelayFileReceiver hardlinked_stage_receiver;
    assert(!hardlinked_stage_receiver.Begin(
        temp.path(), "hardlinked-stage.bin", 0,
        empty_sha256, limits, &error));
    assert(std::filesystem::exists(hardlinked_stage));
    assert(std::filesystem::remove(hardlinked_stage));
    assert(std::filesystem::remove(hardlink_source));

    const auto public_stage = temp.path() /
        ".yume-relay-part.4294967295.4";
    CreatePrivateFile(public_stage);
    assert(::chmod(public_stage.c_str(), S_IRUSR | S_IWUSR | S_IRGRP) == 0);
    MakeStale(public_stage);
    RelayFileReceiver public_stage_receiver;
    assert(!public_stage_receiver.Begin(
        temp.path(), "public-stage.bin", 0,
        empty_sha256, limits, &error));
    assert(std::filesystem::exists(public_stage));
    assert(std::filesystem::remove(public_stage));

    for (unsigned index = 0; index < 20; ++index) {
        const auto stale_stage = temp.path() /
            (".yume-relay-part.4294967294." + std::to_string(index));
        CreatePrivateFile(stale_stage);
        MakeStale(stale_stage);
    }
    RelayFileReceiver bounded_cleanup;
    assert(bounded_cleanup.Begin(temp.path(), "bounded-cleanup.bin", 0,
                                 empty_sha256, limits, &error));
    bounded_cleanup.Abort();
    assert(RelayStageEntries(temp.path()).size() == 4);
    RelayFileReceiver remaining_cleanup;
    assert(remaining_cleanup.Begin(temp.path(), "remaining-cleanup.bin", 0,
                                   empty_sha256, limits, &error));
    remaining_cleanup.Abort();
    assert(RelayStageEntries(temp.path()).empty());

    RelayReceiveLimits short_limits = limits;
    short_limits.max_duration = std::chrono::milliseconds(1);
    RelayFileReceiver timed_out;
    assert(timed_out.Begin(temp.path(), "timeout.bin", 2,
                           yume::relay::identity::sha256_hex(first),
                           short_limits, &error));
    std::this_thread::sleep_for(std::chrono::milliseconds(3));
    assert(!timed_out.Append(first, &error));
    assert(!std::filesystem::exists(temp.path() / "timeout.bin"));
    return 0;
}
