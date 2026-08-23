/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/relay/file_receiver.hpp"

#include <basefwx/crypto.hpp>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <ctime>
#include <exception>
#include <limits>
#include <memory>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "core/security/crypto.hpp"
#include "util.hpp"

#if !defined(_WIN32)
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(__linux__)
#include <linux/fs.h>
#include <sys/syscall.h>
#endif
#endif

#if !defined(_WIN32) && defined(O_NOFOLLOW) && defined(O_DIRECTORY) && \
    defined(O_CLOEXEC) && defined(AT_SYMLINK_NOFOLLOW) && \
    defined(SYS_renameat2) && defined(RENAME_NOREPLACE)
#define YUME_RELAY_HAS_SECURE_FILE_RECEIVE 1
#else
#define YUME_RELAY_HAS_SECURE_FILE_RECEIVE 0
#endif

namespace yume::client {
namespace {

void SetError(std::string* error, std::string message) noexcept {
    if (!error) return;
    try {
        *error = std::move(message);
    } catch (...) {
    }
}

#if YUME_RELAY_HAS_SECURE_FILE_RECEIVE
std::string ErrorMessage(const char* action, int error_number) {
    return std::string(action) + ": " +
        std::error_code(error_number, std::generic_category()).message();
}
#endif

#if YUME_RELAY_HAS_SECURE_FILE_RECEIVE

constexpr mode_t kPrivateDirectoryMode = S_IRWXU;
constexpr mode_t kPrivateFileMode = S_IRUSR | S_IWUSR;
constexpr std::string_view kStagingPrefix = ".yume-relay-part.";
constexpr unsigned kStagingCreateAttempts = 128U;
constexpr std::size_t kMaxStagingScanEntries = 512U;
constexpr std::size_t kMaxStaleStageRemovals = 16U;
constexpr std::time_t kStaleStageAgeSeconds = 24 * 60 * 60;
std::atomic<std::uint64_t> g_staging_sequence{0};

class ScopedFd {
public:
    explicit ScopedFd(int fd = -1) noexcept : fd_(fd) {}
    ~ScopedFd() {
        if (fd_ >= 0) (void)::close(fd_);
    }

    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;

    ScopedFd(ScopedFd&& other) noexcept
        : fd_(std::exchange(other.fd_, -1)) {}
    ScopedFd& operator=(ScopedFd&& other) noexcept {
        if (this != &other) {
            if (fd_ >= 0) (void)::close(fd_);
            fd_ = std::exchange(other.fd_, -1);
        }
        return *this;
    }

    int get() const noexcept { return fd_; }
    int release() noexcept { return std::exchange(fd_, -1); }

private:
    int fd_;
};

bool IsPrivateDirectory(const struct stat& info) noexcept {
    return S_ISDIR(info.st_mode) && info.st_uid == ::geteuid() &&
        (info.st_mode & 07777) == kPrivateDirectoryMode;
}

bool IsPrivateRegularFile(const struct stat& info) noexcept {
    return S_ISREG(info.st_mode) && info.st_uid == ::geteuid() &&
        info.st_nlink == 1 &&
        (info.st_mode & 07777) == kPrivateFileMode;
}

bool SameObject(const struct stat& lhs, const struct stat& rhs) noexcept {
    return lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino;
}

bool ValidPathComponent(std::string_view component) noexcept {
    return !component.empty() && component != "." && component != ".." &&
        component.find('\0') == std::string_view::npos;
}

bool PathComponents(const std::filesystem::path& path,
                    std::vector<std::string>* components,
                    bool* absolute,
                    std::string* error) {
    if (!components || !absolute || path.empty() ||
        !path.root_name().empty()) {
        SetError(error, "relay receive directory path is invalid");
        return false;
    }
    *absolute = path.is_absolute();
    components->clear();
    for (const auto& part : path.relative_path()) {
        const std::string component = part.string();
        if (component == ".") continue;
        if (!ValidPathComponent(component)) {
            SetError(error,
                     "relay receive directory contains an unsafe path component");
            return false;
        }
        components->push_back(component);
    }
    if (components->empty() && !*absolute && path != ".") {
        SetError(error, "relay receive directory path is invalid");
        return false;
    }
    return true;
}

ScopedFd OpenDirectoryPath(const std::filesystem::path& path,
                           bool create,
                           std::string* error) {
    std::vector<std::string> components;
    bool absolute = false;
    if (!PathComponents(path, &components, &absolute, error)) {
        return ScopedFd();
    }

    ScopedFd current(::open(absolute ? "/" : ".",
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (current.get() < 0) {
        SetError(error, ErrorMessage("open relay receive path anchor", errno));
        return ScopedFd();
    }

    for (const std::string& component : components) {
        bool created = false;
        int next_fd = ::openat(current.get(), component.c_str(),
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next_fd < 0 && errno == ENOENT && create) {
            if (::mkdirat(current.get(), component.c_str(),
                          kPrivateDirectoryMode) != 0) {
                SetError(error,
                         ErrorMessage("create relay receive directory component",
                                      errno));
                return ScopedFd();
            }
            created = true;
            next_fd = ::openat(current.get(), component.c_str(),
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        if (next_fd < 0) {
            SetError(error,
                     ErrorMessage(
                         "open relay receive directory component without following links",
                         errno));
            return ScopedFd();
        }
        ScopedFd next(next_fd);
        struct stat info {};
        if (::fstat(next.get(), &info) != 0 || !S_ISDIR(info.st_mode)) {
            SetError(error,
                     "relay receive path component is not a directory");
            return ScopedFd();
        }
        if (created) {
            if (::fchmod(next.get(), kPrivateDirectoryMode) != 0 ||
                ::fstat(next.get(), &info) != 0 ||
                !IsPrivateDirectory(info)) {
                SetError(error,
                         "new relay receive directory component is not private");
                return ScopedFd();
            }
            if (::fsync(next.get()) != 0 || ::fsync(current.get()) != 0) {
                SetError(error,
                         ErrorMessage("sync new relay receive directory",
                                      errno));
                return ScopedFd();
            }
        }
        current = std::move(next);
    }

    struct stat final_info {};
    if (::fstat(current.get(), &final_info) != 0 ||
        !IsPrivateDirectory(final_info)) {
        SetError(error,
                 "relay receive directory must be owner-only mode 0700");
        return ScopedFd();
    }
    return current;
}

bool IsStagingBasename(std::string_view name) noexcept {
    if (!name.starts_with(kStagingPrefix)) return false;
    name.remove_prefix(kStagingPrefix.size());
    const std::size_t separator = name.find('.');
    if (separator == std::string_view::npos || separator == 0 ||
        separator + 1 >= name.size()) {
        return false;
    }
    const auto digits_only = [](std::string_view value) noexcept {
        return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
            return ch >= '0' && ch <= '9';
        });
    };
    return digits_only(name.substr(0, separator)) &&
        digits_only(name.substr(separator + 1));
}

bool NamedEntryMatches(int directory_fd,
                       const std::string& name,
                       std::uint64_t device,
                       std::uint64_t inode,
                       struct stat* result = nullptr) noexcept {
    struct stat info {};
    if (::fstatat(directory_fd, name.c_str(), &info,
                  AT_SYMLINK_NOFOLLOW) != 0) {
        return false;
    }
    if (result) *result = info;
    return static_cast<std::uint64_t>(info.st_dev) == device &&
        static_cast<std::uint64_t>(info.st_ino) == inode;
}

bool CleanupStaleStages(int directory_fd, std::string* error) {
    ScopedFd enumeration_fd(::openat(
        directory_fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (enumeration_fd.get() < 0) {
        SetError(error,
                 ErrorMessage("open relay staging cleanup directory", errno));
        return false;
    }
    const int raw_fd = enumeration_fd.release();
    DIR* raw_directory = ::fdopendir(raw_fd);
    if (!raw_directory) {
        const int saved_errno = errno;
        (void)::close(raw_fd);
        SetError(error,
                 ErrorMessage("enumerate relay staging directory", saved_errno));
        return false;
    }
    struct DirectoryCloser {
        DIR* value;
        ~DirectoryCloser() {
            if (value) (void)::closedir(value);
        }
    } directory_closer{raw_directory};

    const std::time_t now = std::time(nullptr);
    if (now == static_cast<std::time_t>(-1)) {
        SetError(error, "read clock for relay staging cleanup failed");
        return false;
    }
    std::size_t scanned = 0;
    std::size_t removed = 0;
    errno = 0;
    while (scanned < kMaxStagingScanEntries &&
           removed < kMaxStaleStageRemovals) {
        dirent* entry = ::readdir(raw_directory);
        if (!entry) break;
        const std::string name(entry->d_name);
        if (name == "." || name == "..") {
            errno = 0;
            continue;
        }
        ++scanned;
        if (!IsStagingBasename(name)) {
            errno = 0;
            continue;
        }

        struct stat named_info {};
        if (::fstatat(directory_fd, name.c_str(), &named_info,
                      AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) {
                errno = 0;
                continue;
            }
            SetError(error, ErrorMessage("inspect relay staging entry", errno));
            return false;
        }
        if (!IsPrivateRegularFile(named_info)) {
            SetError(error,
                     "relay staging namespace contains an unsafe entry");
            return false;
        }
        if (named_info.st_mtime > now - kStaleStageAgeSeconds) {
            errno = 0;
            continue;
        }

        ScopedFd staged_file(::openat(
            directory_fd, name.c_str(),
            O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
        struct stat opened_info {};
        struct stat rechecked_info {};
        if (staged_file.get() < 0 ||
            ::fstat(staged_file.get(), &opened_info) != 0 ||
            !IsPrivateRegularFile(opened_info) ||
            ::fstatat(directory_fd, name.c_str(), &rechecked_info,
                      AT_SYMLINK_NOFOLLOW) != 0 ||
            !IsPrivateRegularFile(rechecked_info) ||
            !SameObject(named_info, opened_info) ||
            !SameObject(opened_info, rechecked_info)) {
            SetError(error,
                     "relay staging entry changed during safe cleanup");
            return false;
        }
        if (::unlinkat(directory_fd, name.c_str(), 0) != 0) {
            SetError(error, ErrorMessage("remove stale relay staging file", errno));
            return false;
        }
        ++removed;
        errno = 0;
    }
    if (errno != 0) {
        SetError(error,
                 ErrorMessage("enumerate relay staging directory", errno));
        return false;
    }
    if (removed > 0 && ::fsync(directory_fd) != 0) {
        SetError(error, ErrorMessage("sync relay staging cleanup", errno));
        return false;
    }
    return true;
}

bool RenameNoReplace(int directory_fd,
                     const std::string& source,
                     const std::string& destination,
                     int* failure_errno) noexcept {
    int result = -1;
    do {
        result = static_cast<int>(::syscall(
            SYS_renameat2, directory_fd, source.c_str(),
            directory_fd, destination.c_str(),
            RENAME_NOREPLACE));
    } while (result != 0 && errno == EINTR);
    if (result == 0) return true;
    if (failure_errno) *failure_errno = errno;
    return false;
}

#endif  // YUME_RELAY_HAS_SECURE_FILE_RECEIVE

}  // namespace

bool PrepareRelayReceiveDirectory(const std::filesystem::path& directory,
                                  std::string* error) {
    if (directory.empty()) {
        SetError(error, "relay receive directory is empty");
        return false;
    }
#if !YUME_RELAY_HAS_SECURE_FILE_RECEIVE
    SetError(error,
             "atomic confined relay file receive is unsupported on this platform");
    return false;
#else
    ScopedFd receive_directory = OpenDirectoryPath(directory, true, error);
    if (receive_directory.get() < 0) return false;
    if (error) error->clear();
    return true;
#endif
}

bool DecodeRelayChunkBase64(std::string_view encoded,
                            std::size_t max_decoded_bytes,
                            std::vector<std::uint8_t>* decoded,
                            std::string* error) {
    if (!decoded || max_decoded_bytes == 0 || encoded.empty()) {
        SetError(error, "relay chunk Base64 input is empty or invalid");
        return false;
    }
    constexpr std::size_t kMaxSize =
        std::numeric_limits<std::size_t>::max();
    if (max_decoded_bytes > kMaxSize - 2U ||
        (max_decoded_bytes + 2U) / 3U > kMaxSize / 4U) {
        SetError(error, "relay chunk Base64 limit is invalid");
        return false;
    }
    const std::size_t max_encoded =
        4U * ((max_decoded_bytes + 2U) / 3U);
    if (encoded.size() > max_encoded || encoded.size() % 4U != 0U) {
        SetError(error, "relay chunk Base64 length exceeds the allowed bounds");
        return false;
    }
    std::size_t padding = 0;
    if (!encoded.empty() && encoded.back() == '=') {
        padding = 1;
        if (encoded.size() > 1 && encoded[encoded.size() - 2] == '=') {
            padding = 2;
        }
    }
    for (std::size_t i = 0; i < encoded.size(); ++i) {
        const unsigned char ch = static_cast<unsigned char>(encoded[i]);
        const bool alphabet = (ch >= 'A' && ch <= 'Z') ||
            (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
            ch == '+' || ch == '/';
        const bool allowed_padding = ch == '=' && i >= encoded.size() - padding;
        if (!alphabet && !allowed_padding) {
            SetError(error, "relay chunk contains invalid Base64");
            return false;
        }
    }
    const std::string encoded_string(encoded);
    const std::string raw = util::base64_decode(encoded_string);
    if (raw.empty() || raw.size() > max_decoded_bytes ||
        util::base64_encode(raw) != encoded_string) {
        SetError(error, "relay chunk is not canonical Base64");
        return false;
    }
    decoded->assign(raw.begin(), raw.end());
    if (error) error->clear();
    return true;
}

RelayFileReceiver::RelayFileReceiver(RelayFileReceiver&& other) noexcept {
    MoveFrom(std::move(other));
}

RelayFileReceiver& RelayFileReceiver::operator=(
    RelayFileReceiver&& other) noexcept {
    if (this != &other) {
        Abort();
        MoveFrom(std::move(other));
    }
    return *this;
}

RelayFileReceiver::~RelayFileReceiver() {
    Abort();
}

void RelayFileReceiver::MoveFrom(RelayFileReceiver&& other) noexcept {
    directory_fd_ = std::exchange(other.directory_fd_, -1);
    file_fd_ = std::exchange(other.file_fd_, -1);
    basename_ = std::move(other.basename_);
    staging_basename_ = std::move(other.staging_basename_);
    path_ = std::move(other.path_);
    declared_size_ = std::exchange(other.declared_size_, 0);
    received_size_ = std::exchange(other.received_size_, 0);
    expected_sha256_ = std::move(other.expected_sha256_);
    basefwx::crypto::SecureClear(other.expected_sha256_);
    sha256_ = std::move(other.sha256_);
    limits_ = other.limits_;
    deadline_ = other.deadline_;
    file_device_ = std::exchange(other.file_device_, 0);
    file_inode_ = std::exchange(other.file_inode_, 0);
    committed_ = std::exchange(other.committed_, false);
}

bool RelayFileReceiver::IsSafeBasename(std::string_view name) noexcept {
    if (name.empty() || name.size() > 128) {
        return false;
    }
    const auto is_ascii_alnum = [](unsigned char ch) noexcept {
        return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
            (ch >= '0' && ch <= '9');
    };
    if (!is_ascii_alnum(static_cast<unsigned char>(name.front())) ||
        !is_ascii_alnum(static_cast<unsigned char>(name.back()))) {
        return false;
    }
    for (const unsigned char ch : name) {
        if (!is_ascii_alnum(ch) && ch != '.' && ch != '_' && ch != '-') {
            return false;
        }
    }
    // Windows device names remain special even with extensions. Rejecting
    // them on every platform keeps received names portable.
    std::string stem;
    for (const unsigned char ch : name.substr(0, name.find('.'))) {
        stem.push_back(static_cast<char>(
            ch >= 'a' && ch <= 'z' ? ch - ('a' - 'A') : ch));
    }
    if (stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" ||
        (stem.size() == 4 &&
         (stem.rfind("COM", 0) == 0 || stem.rfind("LPT", 0) == 0) &&
         stem[3] >= '1' && stem[3] <= '9')) {
        return false;
    }
    return true;
}

bool RelayFileReceiver::IsCanonicalSha256Digest(
        std::string_view digest) noexcept {
    return digest.size() == 64U &&
        std::all_of(digest.begin(), digest.end(), [](unsigned char ch) {
            return (ch >= '0' && ch <= '9') ||
                (ch >= 'a' && ch <= 'f');
        });
}

bool RelayFileReceiver::Begin(
    const std::filesystem::path& receive_directory,
    std::string_view basename,
    std::uint64_t declared_size,
    std::string_view expected_sha256,
    RelayReceiveLimits limits,
    std::string* error) {
    if (active() || committed_) {
        SetError(error, "relay receive destination is already in use");
        return false;
    }
    if (receive_directory.empty()) {
        SetError(error, "relay receive directory is empty");
        return false;
    }
    if (!IsSafeBasename(basename)) {
        SetError(error, "relay transfer name must be one safe basename");
        return false;
    }
    if (!IsCanonicalSha256Digest(expected_sha256)) {
        SetError(error,
                 "relay transfer SHA-256 must be 64 lowercase hex characters");
        return false;
    }
    if (limits.max_transfer_bytes == 0 || limits.max_chunk_bytes == 0 ||
        limits.max_duration <= std::chrono::milliseconds::zero()) {
        SetError(error, "relay receive limits are invalid");
        return false;
    }
    if (declared_size > limits.max_transfer_bytes) {
        SetError(error, "relay transfer exceeds the receive size limit");
        return false;
    }

#if !YUME_RELAY_HAS_SECURE_FILE_RECEIVE
    (void)declared_size;
    (void)expected_sha256;
    (void)limits;
    SetError(error,
             "atomic confined relay file receive is unsupported on this platform");
    return false;
#else
    std::string name;
    std::string staging_name;
    std::string expected_digest;
    basefwx::crypto::SecretGuard expected_digest_wiper;
    expected_digest_wiper.Add(expected_digest);
    std::unique_ptr<crypto::Sha256Stream> hasher;
    try {
        name.assign(basename);
        expected_digest.assign(expected_sha256);
        hasher = std::make_unique<crypto::Sha256Stream>();
    } catch (const std::exception& ex) {
        basefwx::crypto::SecureClear(expected_digest);
        SetError(error,
                 std::string("initialize relay receive digest: ") + ex.what());
        return false;
    }

    ScopedFd directory = OpenDirectoryPath(receive_directory, false, error);
    if (directory.get() < 0) return false;
    if (!CleanupStaleStages(directory.get(), error)) return false;

    struct stat destination_info {};
    if (::fstatat(directory.get(), name.c_str(), &destination_info,
                  AT_SYMLINK_NOFOLLOW) == 0) {
        SetError(error,
                 "relay receive destination already exists and will not be replaced");
        return false;
    }
    if (errno != ENOENT) {
        SetError(error,
                 ErrorMessage("inspect relay receive destination", errno));
        return false;
    }

    int file_fd = -1;
    for (unsigned attempt = 0; attempt < kStagingCreateAttempts; ++attempt) {
        try {
            const auto sequence = g_staging_sequence.fetch_add(
                1, std::memory_order_relaxed);
            staging_name = std::string(kStagingPrefix) +
                std::to_string(static_cast<std::uint64_t>(::getpid())) + "." +
                std::to_string(sequence);
        } catch (const std::exception& ex) {
            SetError(error,
                     std::string("create relay staging name: ") + ex.what());
            return false;
        }
        file_fd = ::openat(directory.get(), staging_name.c_str(),
                           O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                           kPrivateFileMode);
        if (file_fd >= 0) break;
        if (errno != EEXIST) {
            SetError(error,
                     ErrorMessage("exclusively create relay staging file",
                                  errno));
            return false;
        }
        staging_name.clear();
    }
    if (file_fd < 0) {
        SetError(error,
                 "create relay staging file: name attempts exhausted");
        return false;
    }
    ScopedFd file(file_fd);
    struct stat file_info {};
    if (::fstat(file.get(), &file_info) != 0 ||
        !S_ISREG(file_info.st_mode) || file_info.st_uid != ::geteuid() ||
        file_info.st_nlink != 1 ||
        ::fchmod(file.get(), kPrivateFileMode) != 0 ||
        ::fstat(file.get(), &file_info) != 0 ||
        !IsPrivateRegularFile(file_info)) {
        if (file_info.st_ino != 0 &&
            NamedEntryMatches(
                directory.get(), staging_name,
                static_cast<std::uint64_t>(file_info.st_dev),
                static_cast<std::uint64_t>(file_info.st_ino))) {
            (void)::unlinkat(directory.get(), staging_name.c_str(), 0);
            (void)::fsync(directory.get());
        }
        SetError(error, "relay receive file failed security validation");
        return false;
    }
    const auto remove_staging = [&]() noexcept {
        if (NamedEntryMatches(
                directory.get(), staging_name,
                static_cast<std::uint64_t>(file_info.st_dev),
                static_cast<std::uint64_t>(file_info.st_ino))) {
            (void)::unlinkat(directory.get(), staging_name.c_str(), 0);
            (void)::fsync(directory.get());
        }
    };
    if (::fsync(directory.get()) != 0) {
        const int saved_errno = errno;
        remove_staging();
        SetError(error,
                 ErrorMessage("sync new relay staging entry", saved_errno));
        return false;
    }

    try {
        basename_ = name;
        staging_basename_ = staging_name;
        path_ = receive_directory / name;
        expected_sha256_ = std::move(expected_digest);
        sha256_ = std::move(hasher);
    } catch (const std::exception& ex) {
        basefwx::crypto::SecureClear(expected_digest);
        basefwx::crypto::SecureClear(expected_sha256_);
        sha256_.reset();
        basename_.clear();
        staging_basename_.clear();
        path_.clear();
        remove_staging();
        SetError(error,
                 std::string("initialize relay receive state: ") + ex.what());
        return false;
    }
    directory_fd_ = directory.release();
    file_fd_ = file.release();
    declared_size_ = declared_size;
    received_size_ = 0;
    limits_ = limits;
    deadline_ = std::chrono::steady_clock::now() + limits.max_duration;
    file_device_ = static_cast<std::uint64_t>(file_info.st_dev);
    file_inode_ = static_cast<std::uint64_t>(file_info.st_ino);
    committed_ = false;
    if (error) error->clear();
    return true;
#endif
}

bool RelayFileReceiver::Append(std::span<const std::uint8_t> chunk,
                               std::string* error) {
    if (!active() || committed_) {
        return Fail("relay receive file is not active", error);
    }
    if (expired()) {
        return Fail("relay transfer exceeded its receive deadline", error);
    }
    if (chunk.empty() || chunk.size() > limits_.max_chunk_bytes) {
        return Fail("relay transfer chunk exceeds the allowed bounds", error);
    }
    if (received_size_ > declared_size_ ||
        chunk.size() > declared_size_ - received_size_) {
        return Fail("relay transfer exceeds its declared size", error);
    }

#if !YUME_RELAY_HAS_SECURE_FILE_RECEIVE
    return Fail("confined relay file receive is unavailable", error);
#else
    std::size_t offset = 0;
    while (offset < chunk.size()) {
        const ssize_t count = ::write(file_fd_,
                                      chunk.data() + offset,
                                      chunk.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            const int saved_errno = count < 0 ? errno : EIO;
            return Fail(ErrorMessage("write relay receive file", saved_errno),
                        error);
        }
        offset += static_cast<std::size_t>(count);
    }
    if (!sha256_) {
        return Fail("relay receive digest state is missing", error);
    }
    try {
        sha256_->Update(chunk);
    } catch (const std::exception& ex) {
        return Fail(std::string("hash relay receive data: ") + ex.what(),
                    error);
    }
    received_size_ += static_cast<std::uint64_t>(chunk.size());
    if (error) error->clear();
    return true;
#endif
}

bool RelayFileReceiver::Finish(std::string* error) {
    if (!active() || committed_) {
        return Fail("relay receive file is not active", error);
    }
    if (expired()) {
        return Fail("relay transfer exceeded its receive deadline", error);
    }
    if (received_size_ != declared_size_) {
        return Fail("relay transfer ended before its declared size", error);
    }

#if !YUME_RELAY_HAS_SECURE_FILE_RECEIVE
    return Fail("confined relay file receive is unavailable", error);
#else
    if (!sha256_ || expected_sha256_.empty()) {
        return Fail("relay receive digest state is missing", error);
    }
    std::string actual_sha256;
    try {
        actual_sha256 = sha256_->FinishHex();
    } catch (const std::exception& ex) {
        return Fail(std::string("finalize relay receive digest: ") + ex.what(),
                    error);
    }
    const bool digest_matches = actual_sha256 == expected_sha256_;
    basefwx::crypto::SecureClear(actual_sha256);
    if (!digest_matches) {
        return Fail("relay transfer SHA-256 digest mismatch", error);
    }
    sha256_.reset();
    basefwx::crypto::SecureClear(expected_sha256_);

    if (::fsync(file_fd_) != 0) {
        return Fail(ErrorMessage("sync relay receive file", errno), error);
    }
    struct stat descriptor_info {};
    struct stat staging_info {};
    if (::fstat(file_fd_, &descriptor_info) != 0 ||
        !IsPrivateRegularFile(descriptor_info) ||
        !NamedEntryMatches(directory_fd_, staging_basename_,
                           file_device_, file_inode_, &staging_info) ||
        !SameObject(descriptor_info, staging_info) ||
        !IsPrivateRegularFile(staging_info)) {
        return Fail("relay staging file changed before publication", error);
    }

    int publish_error = 0;
    if (!RenameNoReplace(directory_fd_, staging_basename_, basename_,
                         &publish_error)) {
        if (publish_error == ENOSYS || publish_error == EINVAL ||
            publish_error == EOPNOTSUPP || publish_error == ENOTSUP) {
            return Fail(
                "atomic no-clobber relay publication is unsupported by this "
                "kernel/filesystem",
                error);
        }
        return Fail(ErrorMessage("publish relay receive file without replacing",
                                 publish_error),
                    error);
    }

    const auto rollback_publication = [&]() noexcept {
        if (!NamedEntryMatches(directory_fd_, basename_,
                               file_device_, file_inode_)) {
            return false;
        }
        int rollback_error = 0;
        return RenameNoReplace(directory_fd_, basename_, staging_basename_,
                               &rollback_error);
    };
    const auto preserve_published_failure = [&](std::string message) {
        if (file_fd_ >= 0) {
            (void)::close(file_fd_);
            file_fd_ = -1;
        }
        if (directory_fd_ >= 0) {
            (void)::close(directory_fd_);
            directory_fd_ = -1;
        }
        staging_basename_.clear();
        committed_ = true;
        SetError(error, std::move(message));
        return false;
    };

    struct stat published_info {};
    if (!NamedEntryMatches(directory_fd_, basename_,
                           file_device_, file_inode_, &published_info) ||
        !IsPrivateRegularFile(published_info)) {
        if (rollback_publication()) {
            (void)::fsync(directory_fd_);
            return Fail("published relay file changed during verification",
                        error);
        }
        return preserve_published_failure(
            "relay file publication completed but its identity changed; the "
            "destination was retained to avoid deleting unrelated data");
    }
    if (::fsync(directory_fd_) != 0) {
        const int sync_error = errno;
        if (rollback_publication()) {
            (void)::fsync(directory_fd_);
            return Fail(ErrorMessage(
                            "sync atomically published relay receive file",
                            sync_error),
                        error);
        }
        return preserve_published_failure(
            ErrorMessage(
                "relay file was published but directory durability could not "
                "be confirmed; destination retained",
                sync_error));
    }

    const int completed_fd = file_fd_;
    file_fd_ = -1;
    if (::close(completed_fd) != 0) {
        const int close_error = errno;
        return preserve_published_failure(
            ErrorMessage(
                "relay file was durably published but closing its descriptor "
                "failed; destination retained",
                close_error));
    }
    (void)::close(directory_fd_);
    directory_fd_ = -1;
    staging_basename_.clear();
    committed_ = true;
    if (error) error->clear();
    return true;
#endif
}

bool RelayFileReceiver::expired() const noexcept {
    return active() && std::chrono::steady_clock::now() > deadline_;
}

bool RelayFileReceiver::Fail(std::string message,
                             std::string* error) noexcept {
    SetError(error, std::move(message));
    Abort();
    return false;
}

void RelayFileReceiver::Abort() noexcept {
    sha256_.reset();
    basefwx::crypto::SecureClear(expected_sha256_);
#if YUME_RELAY_HAS_SECURE_FILE_RECEIVE
    bool entry_is_original = false;
    if (!committed_ && directory_fd_ >= 0 && !staging_basename_.empty()) {
        struct stat entry_info {};
        entry_is_original = NamedEntryMatches(
            directory_fd_, staging_basename_, file_device_, file_inode_,
            &entry_info) && IsPrivateRegularFile(entry_info);
    }
    if (file_fd_ >= 0) {
        (void)::close(file_fd_);
        file_fd_ = -1;
    }
    if (entry_is_original) {
        if (::unlinkat(directory_fd_, staging_basename_.c_str(), 0) == 0) {
            (void)::fsync(directory_fd_);
        }
    }
    if (directory_fd_ >= 0) {
        (void)::close(directory_fd_);
        directory_fd_ = -1;
    }
#endif
    basename_.clear();
    staging_basename_.clear();
    if (!committed_) path_.clear();
    declared_size_ = 0;
    received_size_ = 0;
    file_device_ = 0;
    file_inode_ = 0;
}

}  // namespace yume::client
