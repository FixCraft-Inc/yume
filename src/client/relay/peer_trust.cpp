/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/relay/peer_trust.hpp"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "core/security/crypto.hpp"

#if !defined(_WIN32)
#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace yume::client::relay_v2 {

namespace {

constexpr std::size_t kMaxEndpointIdBytes = 255;
constexpr std::size_t kFingerprintBytes = 32;
constexpr std::size_t kFingerprintHexBytes = kFingerprintBytes * 2U;

#if !defined(_WIN32)

constexpr std::size_t kMaxCanonicalIdentityBytes = 16U * 1024U;
constexpr std::size_t kMaxTrustRecordBytes = 1024;
constexpr std::size_t kMaxScannedTrustDirectoryEntries =
    (2U * kMaxListedPeerTrustEntries) + 32U;
constexpr std::string_view kPinFormat = "yume-relay-peer-pin-v1";
constexpr std::string_view kExplicitFormat =
    "yume-relay-peer-explicit-v1";

enum class RecordKind {
    Pin,
    Explicit,
};

struct ParsedTrustPath {
    bool absolute{false};
    std::vector<std::string> components;
};

struct DiskState {
    std::optional<std::string> pin;
    std::optional<std::string> explicit_marker;
};

struct PinRecord {
    std::string endpoint_id;
    std::string fingerprint;
};

[[noreturn]] void ThrowErrno(std::string_view action, int error) {
    throw PeerTrustError(std::string(action) + ": " +
                         std::generic_category().message(error));
}

[[noreturn]] void ThrowPolicy(std::string_view message,
                              std::string_view endpoint_id) {
    throw PeerTrustError(std::string(message) + " for relay peer " +
                         std::string(endpoint_id));
}

ParsedTrustPath ParseTrustPath(const std::filesystem::path& path) {
    if (path.empty()) {
        throw PeerTrustError("relay peer trust directory is empty");
    }
    if (!path.root_name().empty()) {
        throw PeerTrustError(
            "relay peer trust directory has an unsupported root name");
    }
    if (!path.is_absolute()) {
        throw PeerTrustError(
            "relay peer trust directory must be an absolute path");
    }

    ParsedTrustPath parsed;
    parsed.absolute = path.is_absolute();
    for (const auto& component_path : path.relative_path()) {
        const std::string component = component_path.string();
        if (component.empty()) continue;
        if (component == "." || component == "..") {
            throw PeerTrustError(
                "relay peer trust directory must not contain '.' or '..'");
        }
        if (component.find('\0') != std::string::npos) {
            throw PeerTrustError(
                "relay peer trust directory contains a NUL byte");
        }
        parsed.components.push_back(component);
    }
    if (parsed.components.empty()) {
        throw PeerTrustError(
            "relay peer trust directory must name a private subdirectory");
    }
    return parsed;
}

void ValidateRequirement(PeerTrustRequirement requirement) {
    switch (requirement) {
        case PeerTrustRequirement::Ordinary:
        case PeerTrustRequirement::Admin:
            return;
    }
    throw PeerTrustError("invalid relay peer trust requirement");
}

std::string CanonicalIdentityFingerprint(
        std::span<const std::uint8_t> canonical_identity) {
    if (canonical_identity.empty() ||
        canonical_identity.size() > kMaxCanonicalIdentityBytes) {
        throw PeerTrustError(
            "relay peer canonical composite identity size is invalid");
    }

    crypto::Bytes encoded(canonical_identity.begin(),
                          canonical_identity.end());
    crypto::CompositePublicKey parsed =
        crypto::parse_composite_identity(encoded);
    if (!parsed.valid()) {
        throw PeerTrustError(
            "relay peer composite identity is invalid");
    }
    const crypto::Bytes reencoded = crypto::encode_composite_identity(
        parsed.classical.get(), parsed.pq.get());
    if (reencoded != encoded) {
        throw PeerTrustError(
            "relay peer composite identity is not canonical");
    }
    const std::string fingerprint = crypto::composite_fingerprint(parsed);
    if (!IsCanonicalCompositeFingerprint(fingerprint)) {
        throw PeerTrustError(
            "relay peer composite fingerprint generation failed");
    }
    return fingerprint;
}

std::string RecordFormat(RecordKind kind) {
    return std::string(kind == RecordKind::Pin ? kPinFormat
                                                : kExplicitFormat);
}

std::string RecordName(std::string_view endpoint_id, RecordKind kind) {
    return crypto::sha256_hex(endpoint_id) +
           (kind == RecordKind::Pin ? ".pin" : ".explicit");
}

std::string EncodeRecord(RecordKind kind,
                         std::string_view endpoint_id,
                         std::string_view fingerprint) {
    return "format=" + RecordFormat(kind) + "\nendpoint=" +
           std::string(endpoint_id) + "\nfingerprint=" +
           std::string(fingerprint) + "\n";
}

std::string DecodeRecord(RecordKind kind,
                         std::string_view endpoint_id,
                         const std::string& content) {
    const std::string prefix =
        "format=" + RecordFormat(kind) + "\nendpoint=" +
        std::string(endpoint_id) + "\nfingerprint=";
    if (!content.starts_with(prefix) ||
        content.size() != prefix.size() + kFingerprintHexBytes + 1U ||
        content.back() != '\n') {
        ThrowPolicy("malformed protected trust record", endpoint_id);
    }
    const std::string fingerprint = content.substr(
        prefix.size(), kFingerprintHexBytes);
    if (!IsCanonicalCompositeFingerprint(fingerprint) ||
        content != EncodeRecord(kind, endpoint_id, fingerprint)) {
        ThrowPolicy("noncanonical protected trust record", endpoint_id);
    }
    return fingerprint;
}

class FileDescriptor {
public:
    explicit FileDescriptor(int fd = -1) noexcept : fd_(fd) {}
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&& other) noexcept : fd_(other.fd_) {
        other.fd_ = -1;
    }
    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        if (this != &other) {
            if (fd_ >= 0) (void)::close(fd_);
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }
    ~FileDescriptor() {
        if (fd_ >= 0) (void)::close(fd_);
    }

    int get() const noexcept { return fd_; }
    explicit operator bool() const noexcept { return fd_ >= 0; }

    // Hands the descriptor to an owner that closes it itself, such as
    // fdopendir's DIR*. Double-closing a descriptor another thread may have
    // already reused is the bug this exists to prevent.
    int release() noexcept {
        const int released = fd_;
        fd_ = -1;
        return released;
    }

private:
    int fd_;
};

class DirectoryLock {
public:
    DirectoryLock(int fd, int operation) : fd_(fd) {
        while (::flock(fd_, operation) != 0) {
            if (errno == EINTR) continue;
            ThrowErrno("lock relay peer trust directory", errno);
        }
    }
    DirectoryLock(const DirectoryLock&) = delete;
    DirectoryLock& operator=(const DirectoryLock&) = delete;
    ~DirectoryLock() { (void)::flock(fd_, LOCK_UN); }

private:
    int fd_;
};

void ValidatePrivateDirectory(int fd) {
    struct stat info {};
    if (::fstat(fd, &info) != 0) {
        ThrowErrno("stat relay peer trust directory", errno);
    }
    if (!S_ISDIR(info.st_mode) || info.st_uid != ::geteuid()) {
        throw PeerTrustError(
            "relay peer trust directory must be owned by the current user");
    }
    if ((info.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        throw PeerTrustError(
            "relay peer trust directory must not be group/world accessible "
            "(chmod 700)");
    }
}

void ValidateTrustedAncestorDirectory(int fd) {
    struct stat info {};
    if (::fstat(fd, &info) != 0) {
        ThrowErrno("stat relay peer trust path ancestor", errno);
    }
    if (!S_ISDIR(info.st_mode)) {
        throw PeerTrustError(
            "relay peer trust path ancestor is not a directory");
    }

    const uid_t effective_uid = ::geteuid();
    if (info.st_uid != effective_uid && info.st_uid != 0) {
        throw PeerTrustError(
            "relay peer trust path ancestor must be owned by the current "
            "user or root");
    }

    const mode_t shared_write = info.st_mode & (S_IWGRP | S_IWOTH);
    const bool root_sticky_shared =
        info.st_uid == 0 && (info.st_mode & S_ISVTX) != 0 &&
        (info.st_mode & S_IWOTH) != 0;
    if (shared_write != 0 && !root_sticky_shared) {
        throw PeerTrustError(
            "relay peer trust path ancestor must not be group/world "
            "writable (except a root-owned sticky directory)");
    }
}

struct stat ValidatePrivateRegular(int fd, std::string_view label) {
    struct stat info {};
    if (::fstat(fd, &info) != 0) {
        ThrowErrno("stat protected relay peer trust file", errno);
    }
    if (!S_ISREG(info.st_mode) || info.st_uid != ::geteuid() ||
        info.st_nlink != 1) {
        throw PeerTrustError(
            std::string(label) +
            " must be a singly-linked regular file owned by the current user");
    }
    if ((info.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        throw PeerTrustError(
            std::string(label) +
            " must not be group/world accessible (chmod 600)");
    }
    return info;
}

std::optional<FileDescriptor> OpenTrustDirectory(
        const std::filesystem::path& path, bool create) {
#if !defined(O_NOFOLLOW) || !defined(O_DIRECTORY) || !defined(O_CLOEXEC)
    (void)path;
    (void)create;
    throw PeerTrustError(
        "secure relay peer trust storage requires O_NOFOLLOW, O_DIRECTORY, "
        "and O_CLOEXEC");
#else
    const ParsedTrustPath parsed = ParseTrustPath(path);
    const char* root = parsed.absolute ? "/" : ".";
    FileDescriptor current(::open(
        root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (!current) ThrowErrno("open relay peer trust path root", errno);
    ValidateTrustedAncestorDirectory(current.get());

    for (std::size_t index = 0; index < parsed.components.size(); ++index) {
        const std::string& component = parsed.components[index];
        const bool final = index + 1U == parsed.components.size();
        bool created = false;
        int raw = ::openat(current.get(), component.c_str(),
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                               O_CLOEXEC);
        if (raw < 0 && errno == ENOENT) {
            if (!create) return std::nullopt;
            if (::mkdirat(current.get(), component.c_str(), S_IRWXU) != 0) {
                if (errno != EEXIST) {
                    ThrowErrno("create relay peer trust directory", errno);
                }
            } else {
                created = true;
            }
            raw = ::openat(current.get(), component.c_str(),
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                               O_CLOEXEC);
        }
        if (raw < 0) {
            ThrowErrno("open relay peer trust directory component", errno);
        }

        FileDescriptor next(raw);
        if (created && ::fchmod(next.get(), S_IRWXU) != 0) {
            ThrowErrno("protect new relay peer trust directory", errno);
        }
        if (created && ::fsync(next.get()) != 0) {
            ThrowErrno("sync new relay peer trust directory", errno);
        }
        if (created && ::fsync(current.get()) != 0) {
            ThrowErrno("sync relay peer trust parent directory", errno);
        }
        if (final) {
            ValidatePrivateDirectory(next.get());
        } else {
            ValidateTrustedAncestorDirectory(next.get());
        }
        current = std::move(next);
    }
    return std::optional<FileDescriptor>{std::move(current)};
#endif
}

// Reads one record file by its on-disk name and returns its exact bytes.
// `subject` names the record in policy errors: a lookup knows the endpoint it
// asked for, while a directory listing only knows the file it found.
std::optional<std::string> ReadRecordContent(
        int directory_fd,
        RecordKind kind,
        const std::string& name,
        std::string_view subject) {
#if !defined(O_NOFOLLOW) || !defined(O_CLOEXEC) || !defined(O_NONBLOCK)
    (void)directory_fd;
    (void)kind;
    (void)name;
    (void)subject;
    throw PeerTrustError(
        "secure relay peer trust storage requires O_NOFOLLOW, O_CLOEXEC, "
        "and O_NONBLOCK");
#else
    FileDescriptor file(::openat(
        directory_fd, name.c_str(),
        O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
    if (!file) {
        const int open_error = errno;
        if (open_error == ENOENT) return std::nullopt;
        ThrowErrno("open protected relay peer trust file", open_error);
    }

    const struct stat info = ValidatePrivateRegular(
        file.get(), kind == RecordKind::Pin ? "relay peer pin" :
                                             "relay peer explicit marker");
    if (info.st_size <= 0 ||
        static_cast<std::uintmax_t>(info.st_size) >
            kMaxTrustRecordBytes) {
        ThrowPolicy("protected trust record size is invalid", subject);
    }

    std::string content(static_cast<std::size_t>(info.st_size), '\0');
    std::size_t offset = 0;
    while (offset < content.size()) {
        const ssize_t count = ::pread(file.get(), content.data() + offset,
                                      content.size() - offset,
                                      static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            ThrowErrno("read protected relay peer trust file", errno);
        }
        if (count == 0) {
            ThrowPolicy("protected trust record changed while read", subject);
        }
        offset += static_cast<std::size_t>(count);
    }
    char extra = 0;
    ssize_t extra_count;
    do {
        extra_count = ::pread(file.get(), &extra, 1,
                              static_cast<off_t>(content.size()));
    } while (extra_count < 0 && errno == EINTR);
    if (extra_count < 0) {
        ThrowErrno("verify protected relay peer trust file size", errno);
    }
    if (extra_count != 0) {
        ThrowPolicy("protected trust record grew while read", subject);
    }
    return content;
#endif
}

std::optional<std::string> ReadRecordIfPresent(
        int directory_fd,
        RecordKind kind,
        std::string_view endpoint_id) {
    auto content = ReadRecordContent(
        directory_fd, kind, RecordName(endpoint_id, kind), endpoint_id);
    if (!content) return std::nullopt;
    return DecodeRecord(kind, endpoint_id, *content);
}

void WriteAll(int fd, std::string_view content) {
    std::size_t offset = 0;
    while (offset < content.size()) {
        const ssize_t count = ::write(fd, content.data() + offset,
                                      content.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            ThrowErrno("write protected relay peer trust file",
                       count < 0 ? errno : EIO);
        }
        offset += static_cast<std::size_t>(count);
    }
}

void UnlinkIfSameFile(int directory_fd,
                      const std::string& name,
                      int file_fd) noexcept {
#if defined(AT_SYMLINK_NOFOLLOW)
    struct stat opened {};
    struct stat named {};
    if (::fstat(file_fd, &opened) != 0 ||
        ::fstatat(directory_fd, name.c_str(), &named,
                  AT_SYMLINK_NOFOLLOW) != 0) {
        return;
    }
    if (opened.st_dev == named.st_dev && opened.st_ino == named.st_ino) {
        (void)::unlinkat(directory_fd, name.c_str(), 0);
        (void)::fsync(directory_fd);
    }
#else
    (void)directory_fd;
    (void)name;
    (void)file_fd;
#endif
}

bool CreateRecordExclusive(int directory_fd,
                           RecordKind kind,
                           std::string_view endpoint_id,
                           std::string_view fingerprint) {
#if !defined(O_NOFOLLOW) || !defined(O_CLOEXEC)
    (void)directory_fd;
    (void)kind;
    (void)endpoint_id;
    (void)fingerprint;
    throw PeerTrustError(
        "secure relay peer trust storage requires O_NOFOLLOW and O_CLOEXEC");
#else
    const std::string name = RecordName(endpoint_id, kind);
    const std::string content = EncodeRecord(
        kind, endpoint_id, fingerprint);
    FileDescriptor file(::openat(
        directory_fd, name.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
        S_IRUSR | S_IWUSR));
    if (!file) {
        const int open_error = errno;
        if (open_error == EEXIST) return false;
        ThrowErrno("create protected relay peer trust file", open_error);
    }

    bool file_synced = false;
    try {
        if (::fchmod(file.get(), S_IRUSR | S_IWUSR) != 0) {
            ThrowErrno("protect new relay peer trust file", errno);
        }
        (void)ValidatePrivateRegular(
            file.get(), kind == RecordKind::Pin ? "relay peer pin" :
                                                 "relay peer explicit marker");
        WriteAll(file.get(), content);
        if (::fsync(file.get()) != 0) {
            ThrowErrno("sync protected relay peer trust file", errno);
        }
        file_synced = true;
        if (::fsync(directory_fd) != 0) {
            ThrowErrno("sync relay peer trust directory", errno);
        }
    } catch (...) {
        if (!file_synced) {
            UnlinkIfSameFile(directory_fd, name, file.get());
        }
        throw;
    }
    return true;
#endif
}

bool IsPinRecordName(std::string_view name) {
    constexpr std::string_view suffix = ".pin";
    if (name.size() != kFingerprintHexBytes + suffix.size() ||
        !name.ends_with(suffix)) {
        return false;
    }
    const std::string_view digest = name.substr(0, kFingerprintHexBytes);
    return std::all_of(digest.begin(), digest.end(), [](unsigned char value) {
        return (value >= '0' && value <= '9') ||
               (value >= 'a' && value <= 'f');
    });
}

// Names of every pin record in the trust directory. Enumeration is bounded:
// a corrupted or hostile directory must not be able to make a listing
// allocate without limit, and refusing loudly beats silently hiding peers.
std::vector<std::string> ListPinRecordNames(int directory_fd) {
    FileDescriptor duplicate(::dup(directory_fd));
    if (!duplicate) {
        ThrowErrno("duplicate relay peer trust directory", errno);
    }
    DIR* stream = ::fdopendir(duplicate.get());
    if (stream == nullptr) {
        ThrowErrno("enumerate relay peer trust directory", errno);
    }
    // fdopendir owns the descriptor once it succeeds; closedir closes it.
    (void)duplicate.release();
    struct StreamCloser {
        DIR* stream;
        ~StreamCloser() { (void)::closedir(stream); }
    } closer{stream};

    std::vector<std::string> names;
    ::rewinddir(stream);
    std::size_t scanned = 0;
    for (;;) {
        errno = 0;
        const dirent* entry = ::readdir(stream);
        if (entry == nullptr) {
            if (errno != 0) {
                ThrowErrno("enumerate relay peer trust directory", errno);
            }
            break;
        }
        const std::string_view name(entry->d_name);
        if (name == "." || name == "..") continue;
        if (++scanned > kMaxScannedTrustDirectoryEntries) {
            throw PeerTrustError(
                "relay peer trust directory holds more entries than the "
                "scan bound allows");
        }
        if (!IsPinRecordName(name)) continue;
        if (names.size() >= kMaxListedPeerTrustEntries) {
            throw PeerTrustError(
                "relay peer trust directory holds more pin records than the "
                "listing bound allows");
        }
        names.emplace_back(name);
    }
    return names;
}

// A pin record names the endpoint it belongs to, while its filename is that
// endpoint's digest. Reading both and requiring them to agree means a planted
// file cannot claim trust for an endpoint it is not named after.
std::optional<PinRecord> ReadPinRecordByName(int directory_fd,
                                             const std::string& name) {
    auto content = ReadRecordContent(
        directory_fd, RecordKind::Pin, name, name);
    if (!content) return std::nullopt;

    const std::string prefix =
        "format=" + RecordFormat(RecordKind::Pin) + "\nendpoint=";
    if (!content->starts_with(prefix)) {
        ThrowPolicy("malformed protected trust record", name);
    }
    const auto terminator = content->find('\n', prefix.size());
    if (terminator == std::string::npos) {
        ThrowPolicy("malformed protected trust record", name);
    }
    PinRecord record;
    record.endpoint_id = content->substr(prefix.size(),
                                         terminator - prefix.size());
    if (!IsValidPeerEndpointId(record.endpoint_id) ||
        RecordName(record.endpoint_id, RecordKind::Pin) != name) {
        ThrowPolicy("protected trust record does not match its file name",
                    name);
    }
    record.fingerprint = DecodeRecord(
        RecordKind::Pin, record.endpoint_id, *content);
    return record;
}

DiskState ReadDiskState(int directory_fd, std::string_view endpoint_id) {
    DiskState state;
    state.pin = ReadRecordIfPresent(
        directory_fd, RecordKind::Pin, endpoint_id);
    state.explicit_marker = ReadRecordIfPresent(
        directory_fd, RecordKind::Explicit, endpoint_id);
    if (state.explicit_marker && !state.pin) {
        ThrowPolicy("explicit trust marker exists without a peer pin",
                    endpoint_id);
    }
    if (state.pin && state.explicit_marker &&
        *state.pin != *state.explicit_marker) {
        ThrowPolicy("peer pin and explicit trust marker disagree",
                    endpoint_id);
    }
    return state;
}

void EnsureRecord(int directory_fd,
                  RecordKind kind,
                  std::string_view endpoint_id,
                  std::string_view fingerprint) {
    if (CreateRecordExclusive(directory_fd, kind, endpoint_id,
                              fingerprint)) {
        return;
    }
    const auto existing = ReadRecordIfPresent(
        directory_fd, kind, endpoint_id);
    if (!existing) {
        ThrowPolicy("concurrently created trust record disappeared",
                    endpoint_id);
    }
    if (*existing != fingerprint) {
        ThrowPolicy("relay peer trust mismatch", endpoint_id);
    }
}

const std::string* ConfiguredPin(const PeerTrustConfig& config,
                                 std::string_view endpoint_id) {
    const auto found = config.explicit_pins.find(endpoint_id);
    return found == config.explicit_pins.end() ? nullptr : &found->second;
}

PeerTrustDecision Evaluate(const PeerTrustConfig& config,
                           std::string_view endpoint_id,
                           const std::string& fingerprint,
                           const DiskState& state,
                           PeerTrustRequirement requirement) {
    ValidateRequirement(requirement);
    const std::string* configured = ConfiguredPin(config, endpoint_id);
    if (configured != nullptr && *configured != fingerprint) {
        ThrowPolicy("configured relay peer pin mismatch", endpoint_id);
    }
    if (state.pin && *state.pin != fingerprint) {
        ThrowPolicy("persisted relay peer pin mismatch", endpoint_id);
    }
    if (state.explicit_marker &&
        *state.explicit_marker != fingerprint) {
        ThrowPolicy("explicit relay peer trust mismatch", endpoint_id);
    }

    const bool configured_authorized = configured != nullptr;
    const bool explicit_authorized =
        configured_authorized || state.explicit_marker.has_value();
    if (!state.pin && config.mode == PeerTrustMode::Pinned &&
        !configured_authorized) {
        ThrowPolicy("pinned relay trust requires a pre-authorized identity",
                    endpoint_id);
    }
    if (requirement == PeerTrustRequirement::Admin &&
        !explicit_authorized) {
        ThrowPolicy("admin relay trust requires an explicit/OOB pin",
                    endpoint_id);
    }

    PeerTrustDecision decision;
    decision.fingerprint = fingerprint;
    decision.pin_persisted = state.pin.has_value();
    decision.explicit_authorized = explicit_authorized;
    decision.commit_required =
        !state.pin || (configured_authorized && !state.explicit_marker);
    return decision;
}

#endif  // !defined(_WIN32)

}  // namespace

bool IsValidPeerEndpointId(std::string_view endpoint_id) noexcept {
    if (endpoint_id.empty() || endpoint_id.size() > kMaxEndpointIdBytes ||
        endpoint_id == "." || endpoint_id == "..") {
        return false;
    }
    return std::all_of(
        endpoint_id.begin(), endpoint_id.end(), [](unsigned char value) {
            return (value >= 'a' && value <= 'z') ||
                   (value >= 'A' && value <= 'Z') ||
                   (value >= '0' && value <= '9') || value == '-' ||
                   value == '_' || value == '.' || value == ':';
        });
}

bool IsCanonicalCompositeFingerprint(
        std::string_view fingerprint) noexcept {
    return fingerprint.size() == kFingerprintHexBytes &&
           std::all_of(
               fingerprint.begin(), fingerprint.end(),
               [](unsigned char value) {
                   return (value >= '0' && value <= '9') ||
                          (value >= 'a' && value <= 'f');
               });
}

PeerTrustStore::PeerTrustStore(PeerTrustConfig config)
    : config_(std::move(config)) {
#if defined(_WIN32)
    throw PeerTrustError(
        "relay peer trust storage is unavailable on Windows until secure "
        "descriptor-relative no-follow persistence has platform parity");
#else
    (void)ParseTrustPath(config_.directory);
    switch (config_.mode) {
        case PeerTrustMode::Tofu:
        case PeerTrustMode::Pinned:
            break;
        default:
            throw PeerTrustError("invalid relay peer trust mode");
    }
    for (const auto& [endpoint_id, fingerprint] : config_.explicit_pins) {
        if (!IsValidPeerEndpointId(endpoint_id)) {
            throw PeerTrustError(
                "configured relay peer pin has an invalid endpoint ID");
        }
        if (!IsCanonicalCompositeFingerprint(fingerprint)) {
            throw PeerTrustError(
                "configured relay peer pin has a noncanonical fingerprint");
        }
    }
#endif
}

PeerTrustDecision PeerTrustStore::precheck(
        std::string_view endpoint_id,
        std::span<const std::uint8_t> canonical_identity,
        PeerTrustRequirement requirement) const {
#if defined(_WIN32)
    (void)endpoint_id;
    (void)canonical_identity;
    (void)requirement;
    throw PeerTrustError("secure relay peer trust storage is unavailable on Windows");
#else
    if (!IsValidPeerEndpointId(endpoint_id)) {
        throw PeerTrustError("invalid relay peer endpoint ID");
    }
    const std::string fingerprint =
        CanonicalIdentityFingerprint(canonical_identity);
    auto directory = OpenTrustDirectory(config_.directory, false);
    if (!directory) {
        return Evaluate(config_, endpoint_id, fingerprint, {}, requirement);
    }
    DirectoryLock lock(directory->get(), LOCK_SH);
    return Evaluate(config_, endpoint_id, fingerprint,
                    ReadDiskState(directory->get(), endpoint_id),
                    requirement);
#endif
}

PeerTrustDecision PeerTrustStore::commit_verified(
        std::string_view endpoint_id,
        std::span<const std::uint8_t> canonical_identity,
        PeerTrustRequirement requirement) const {
#if defined(_WIN32)
    (void)endpoint_id;
    (void)canonical_identity;
    (void)requirement;
    throw PeerTrustError("secure relay peer trust storage is unavailable on Windows");
#else
    if (!IsValidPeerEndpointId(endpoint_id)) {
        throw PeerTrustError("invalid relay peer endpoint ID");
    }
    const std::string fingerprint =
        CanonicalIdentityFingerprint(canonical_identity);
    auto directory = OpenTrustDirectory(config_.directory, true);
    if (!directory) {
        throw PeerTrustError("failed to create relay peer trust directory");
    }
    DirectoryLock lock(directory->get(), LOCK_EX);

    DiskState state = ReadDiskState(directory->get(), endpoint_id);
    (void)Evaluate(config_, endpoint_id, fingerprint, state, requirement);
    if (!state.pin) {
        EnsureRecord(directory->get(), RecordKind::Pin,
                     endpoint_id, fingerprint);
    }
    if (ConfiguredPin(config_, endpoint_id) != nullptr &&
        !state.explicit_marker) {
        EnsureRecord(directory->get(), RecordKind::Explicit,
                     endpoint_id, fingerprint);
    }

    PeerTrustDecision committed = Evaluate(
        config_, endpoint_id, fingerprint,
        ReadDiskState(directory->get(), endpoint_id), requirement);
    if (committed.commit_required) {
        throw PeerTrustError(
            "relay peer trust commit did not reach a durable state");
    }
    return committed;
#endif
}

std::vector<PeerTrustEntry> PeerTrustStore::list() const {
#if defined(_WIN32)
    throw PeerTrustError(
        "secure relay peer trust storage is unavailable on Windows");
#else
    // Keyed by endpoint ID so disk and configuration merge into one row per
    // peer and the result is ordered without a separate sort.
    std::map<std::string, PeerTrustEntry, std::less<>> merged;

    if (auto directory = OpenTrustDirectory(config_.directory, false)) {
        DirectoryLock lock(directory->get(), LOCK_SH);
        for (const auto& name : ListPinRecordNames(directory->get())) {
            auto record = ReadPinRecordByName(directory->get(), name);
            if (!record) continue;  // removed between listing and read
            // Re-read through the shared path so the pin/marker agreement
            // rules that guard a handshake also guard what is listed.
            const DiskState state = ReadDiskState(
                directory->get(), record->endpoint_id);
            if (!state.pin) continue;

            PeerTrustEntry entry;
            entry.endpoint_id = record->endpoint_id;
            entry.fingerprint = *state.pin;
            entry.explicit_marker = state.explicit_marker.has_value();
            entry.source = entry.explicit_marker ? PeerTrustSource::Explicit
                                                 : PeerTrustSource::Tofu;
            merged.insert_or_assign(entry.endpoint_id, std::move(entry));
        }
    }

    for (const auto& [endpoint_id, fingerprint] : config_.explicit_pins) {
        const auto found = merged.find(endpoint_id);
        if (found == merged.end()) {
            PeerTrustEntry entry;
            entry.endpoint_id = endpoint_id;
            entry.fingerprint = fingerprint;
            entry.source = PeerTrustSource::Configured;
            merged.emplace(endpoint_id, std::move(entry));
            continue;
        }
        found->second.source = PeerTrustSource::Configured;
        found->second.configured_mismatch =
            found->second.fingerprint != fingerprint;
    }

    std::vector<PeerTrustEntry> entries;
    entries.reserve(merged.size());
    for (auto& [endpoint_id, entry] : merged) {
        entries.push_back(std::move(entry));
    }
    return entries;
#endif
}

bool PeerTrustStore::forget(std::string_view endpoint_id) const {
#if defined(_WIN32)
    (void)endpoint_id;
    throw PeerTrustError(
        "secure relay peer trust storage is unavailable on Windows");
#else
    if (!IsValidPeerEndpointId(endpoint_id)) {
        throw PeerTrustError("invalid relay peer endpoint ID");
    }
    if (ConfiguredPin(config_, endpoint_id) != nullptr) {
        throw PeerTrustError(
            "a configured relay peer pin is operator authorization, not "
            "learned trust; remove it from the configuration instead");
    }

    auto directory = OpenTrustDirectory(config_.directory, false);
    if (!directory) return false;
    DirectoryLock lock(directory->get(), LOCK_EX);

    const DiskState state = ReadDiskState(directory->get(), endpoint_id);
    if (!state.pin) return false;
    if (state.explicit_marker) {
        throw PeerTrustError(
            "an explicitly authorized relay peer cannot be forgotten; its "
            "trust came from an out-of-band decision, not from first use");
    }

    const std::string name = RecordName(endpoint_id, RecordKind::Pin);
    if (::unlinkat(directory->get(), name.c_str(), 0) != 0) {
        const int unlink_error = errno;
        if (unlink_error == ENOENT) return false;
        ThrowErrno("remove relay peer pin", unlink_error);
    }
    if (::fsync(directory->get()) != 0) {
        ThrowErrno("sync relay peer trust directory", errno);
    }
    return true;
#endif
}

std::string_view to_string(PeerTrustSource source) noexcept {
    switch (source) {
        case PeerTrustSource::Tofu:       return "tofu";
        case PeerTrustSource::Explicit:   return "explicit";
        case PeerTrustSource::Configured: return "configured";
    }
    return "unknown";
}

}  // namespace yume::client::relay_v2
