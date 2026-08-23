/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/relay/file_receiver.hpp"
#include "core/security/crypto.hpp"

#include <array>
#include <algorithm>
#include <cassert>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

#if !defined(_WIN32)
constexpr std::string_view kRelayStagePrefix = ".yume-relay-part.";

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
#endif

}  // namespace

int main() {
    using yume::client::RelayFileReceiver;
    using yume::client::RelayReceiveLimits;

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
    const std::string empty_sha256 = yume::crypto::sha256_hex(
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
    assert(yume::crypto::sha256_hex(hash_input) == kAbcSha256);
    yume::crypto::Sha256Stream stream;
    stream.Update(std::span(hash_input).first(2));
    yume::crypto::Sha256Stream moved_stream(std::move(stream));
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

#if defined(_WIN32)
    RelayFileReceiver unsupported;
    std::string error;
    assert(!unsupported.Begin(
        "C:\\temp", "data.bin", 1, empty_sha256, {}, &error));
    assert(!error.empty());
#else
    TempDirectory temp;
    std::string error;
    assert(yume::client::PrepareRelayReceiveDirectory(temp.path(), &error));
    const RelayReceiveLimits limits{64, 8, std::chrono::seconds(2)};

    const auto created_directory = temp.path() / "created" / "nested";
    assert(yume::client::PrepareRelayReceiveDirectory(
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
    assert(!yume::client::PrepareRelayReceiveDirectory(
        linked_component, &error));
    RelayFileReceiver linked_directory;
    assert(!linked_directory.Begin(linked_component, "linked.bin", 0,
                                   empty_sha256, limits, &error));
    assert(!std::filesystem::exists(real_component / "linked.bin"));

    const auto unsafe_directory = temp.path() / "unsafe-directory";
    assert(std::filesystem::create_directory(unsafe_directory));
    assert(::chmod(unsafe_directory.c_str(),
                   S_IRWXU | S_IRGRP | S_IXGRP) == 0);
    assert(!yume::client::PrepareRelayReceiveDirectory(
        unsafe_directory, &error));
    RelayFileReceiver unsafe_destination;
    assert(!unsafe_destination.Begin(unsafe_directory, "unsafe.bin", 0,
                                     empty_sha256, limits, &error));

    std::vector<std::uint8_t> decoded;
    assert(yume::client::DecodeRelayChunkBase64("AQI=", 2, &decoded, &error));
    assert((decoded == std::vector<std::uint8_t>{1, 2}));
    assert(!yume::client::DecodeRelayChunkBase64("AQI=ignored", 8, &decoded, &error));
    assert(!yume::client::DecodeRelayChunkBase64("AQ I=", 8, &decoded, &error));
    assert(!yume::client::DecodeRelayChunkBase64("AQI", 8, &decoded, &error));

    RelayFileReceiver complete;
    const std::array<std::uint8_t, 2> first{1, 2};
    const std::array<std::uint8_t, 2> second{3, 4};
    const std::array<std::uint8_t, 4> complete_bytes{1, 2, 3, 4};
    const std::string complete_sha256 =
        yume::crypto::sha256_hex(complete_bytes);
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
                                 yume::crypto::sha256_hex(first),
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
                           yume::crypto::sha256_hex(first),
                           short_limits, &error));
    std::this_thread::sleep_for(std::chrono::milliseconds(3));
    assert(!timed_out.Append(first, &error));
    assert(!std::filesystem::exists(temp.path() / "timeout.bin"));
#endif
    return 0;
}
