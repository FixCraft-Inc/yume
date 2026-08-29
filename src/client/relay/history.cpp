/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/relay/history.hpp"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <limits>
#include <map>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>

#include <nlohmann/json.hpp>

#include "client/relay/secret.hpp"
#include "core/security/crypto.hpp"
#include "core/security/identity.hpp"
#include "core/security/secure_erase.hpp"
#include "util.hpp"

#if !defined(_WIN32)
#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace yume::client {

namespace {

constexpr char kHistoryKeyFile[] = "history.key";
constexpr std::size_t kHistoryKeyBytes = 32;
constexpr std::size_t kHistoryNonceBytes = 12;
constexpr std::uintmax_t kMaxHistoryFileBytes = 64U * 1024U * 1024U;
constexpr std::size_t kMaxHistoryRecordBytes = 1U * 1024U * 1024U;
constexpr std::uintmax_t kMaxHistoryBytesPerList =
    64U * 1024U * 1024U;
constexpr std::size_t kMaxHistoryResultPlaintextBytes = 512U * 1024U;
constexpr std::size_t kMaxHistoryListItems = 1000U;
constexpr std::size_t kMaxHistoryFilesPerOperation = 1024U;
constexpr std::size_t kMaxHistoryDirectoryEntriesPerOperation = 4096U;
constexpr std::size_t kHistoryRecordFieldCount = 5U;

bool is_valid_history_direction(std::string_view direction) noexcept {
    return direction == "in" || direction == "out";
}

bool is_valid_history_timestamp(const nlohmann::json& value) {
    if (!value.is_number_integer()) return false;
    // JSON text has no signed-integer tag, and nlohmann parses ordinary
    // non-negative values as unsigned. Accept those only within int64_t so the
    // subsequent conversion cannot narrow or wrap.
    return !value.is_number_unsigned() ||
        value.get<std::uint64_t>() <=
            static_cast<std::uint64_t>(
                std::numeric_limits<std::int64_t>::max());
}

std::string safe_component(std::string value) {
    const bool safe = !value.empty() && value.size() <= 128 &&
        value != "." && value != ".." &&
        std::all_of(value.begin(), value.end(), [](unsigned char ch) {
            return std::isalnum(ch) != 0 || ch == '-' || ch == '_';
        });
    if (safe) return value;
    return identity::derive_instance_key(value);
}

class StringWiper {
public:
    explicit StringWiper(std::string& value) noexcept : value_(value) {}
    ~StringWiper() { wipe_relay_secret(value_); }
    StringWiper(const StringWiper&) = delete;
    StringWiper& operator=(const StringWiper&) = delete;
private:
    std::string& value_;
};

class BytesWiper {
public:
    explicit BytesWiper(std::vector<std::uint8_t>& value) noexcept
        : value_(value) {}
    ~BytesWiper() { security::secure_erase(value_); }
    BytesWiper(const BytesWiper&) = delete;
    BytesWiper& operator=(const BytesWiper&) = delete;
private:
    std::vector<std::uint8_t>& value_;
};

class HistoryJsonWiper {
public:
    explicit HistoryJsonWiper(nlohmann::json& value) noexcept : value_(value) {}
    ~HistoryJsonWiper() {
        try {
            if (value_.is_object() && value_.contains("text") &&
                value_["text"].is_string()) {
                wipe_relay_secret(value_["text"].get_ref<std::string&>());
                value_.erase("text");
            }
        } catch (...) {
        }
    }
    HistoryJsonWiper(const HistoryJsonWiper&) = delete;
    HistoryJsonWiper& operator=(const HistoryJsonWiper&) = delete;
private:
    nlohmann::json& value_;
};

#if !defined(_WIN32)

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
            if (fd_ >= 0) ::close(fd_);
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }
    ~FileDescriptor() { if (fd_ >= 0) ::close(fd_); }
    int get() const noexcept { return fd_; }
private:
    int fd_;
};

class ExclusiveFileLock {
public:
    ExclusiveFileLock(int fd, const char* action) : fd_(fd) {
        while (::flock(fd_, LOCK_EX) != 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(),
                                    action);
        }
    }
    ExclusiveFileLock(const ExclusiveFileLock&) = delete;
    ExclusiveFileLock& operator=(const ExclusiveFileLock&) = delete;
    ~ExclusiveFileLock() { (void)::flock(fd_, LOCK_UN); }

private:
    int fd_;
};

class SharedFileLock {
public:
    SharedFileLock(int fd, const char* action) : fd_(fd) {
        while (::flock(fd_, LOCK_SH) != 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), action);
        }
    }
    SharedFileLock(const SharedFileLock&) = delete;
    SharedFileLock& operator=(const SharedFileLock&) = delete;
    ~SharedFileLock() { (void)::flock(fd_, LOCK_UN); }

private:
    int fd_;
};

int close_on_exec_flag() noexcept {
#if defined(O_CLOEXEC)
    return O_CLOEXEC;
#else
    return 0;
#endif
}

int no_follow_flag() noexcept {
#if defined(O_NOFOLLOW)
    return O_NOFOLLOW;
#else
    return 0;
#endif
}

void validate_owned_private_directory(int fd, const std::string& label) {
    struct stat info {};
    if (::fstat(fd, &info) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "stat " + label);
    }
    if (!S_ISDIR(info.st_mode) || info.st_uid != ::geteuid()) {
        throw std::runtime_error(label +
                                 " must be a directory owned by the current user");
    }
    if (::fchmod(fd, S_IRWXU) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "protect " + label);
    }
}

FileDescriptor open_private_instance_directory(
        const std::filesystem::path& root,
        const std::string& instance_key) {
    std::error_code directory_error;
    std::filesystem::create_directories(root, directory_error);
    if (directory_error) {
        throw std::runtime_error("create relay history root: " +
                                 directory_error.message());
    }
    FileDescriptor root_fd(::open(root.c_str(),
                                  O_RDONLY | O_DIRECTORY |
                                      close_on_exec_flag() | no_follow_flag()));
    if (root_fd.get() < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "open relay history root");
    }
    validate_owned_private_directory(root_fd.get(), "relay history root");

    if (::mkdirat(root_fd.get(), instance_key.c_str(), S_IRWXU) != 0 &&
        errno != EEXIST) {
        throw std::system_error(errno, std::generic_category(),
                                "create relay history instance directory");
    }
    FileDescriptor instance_fd(::openat(
        root_fd.get(), instance_key.c_str(),
        O_RDONLY | O_DIRECTORY | close_on_exec_flag() | no_follow_flag()));
    if (instance_fd.get() < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "open relay history instance directory");
    }
    validate_owned_private_directory(instance_fd.get(),
                                     "relay history instance directory");
    return instance_fd;
}

struct stat validate_owned_private_regular(int fd,
                                           const std::string& label) {
    struct stat info {};
    if (::fstat(fd, &info) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "stat " + label);
    }
    if (!S_ISREG(info.st_mode) || info.st_uid != ::geteuid()) {
        throw std::runtime_error(label +
                                 " must be a regular file owned by the current user");
    }
    if ((info.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        throw std::runtime_error(label +
                                 " must not be group/world accessible (chmod 600)");
    }
    return info;
}

std::vector<std::uint8_t> read_private_file_at(
        int directory_fd,
        const std::string& name,
        std::uintmax_t max_bytes) {
    FileDescriptor fd(::openat(directory_fd, name.c_str(),
                               O_RDONLY | O_NONBLOCK | close_on_exec_flag() |
                                   no_follow_flag()));
    if (fd.get() < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "open protected relay history file");
    }
    const std::string label = "relay history file " + name;
    // Reject FIFOs/devices before attempting an advisory lock, then lock and
    // revalidate so a cross-process append cannot expose a partial record or
    // a stale pre-append size.
    (void)validate_owned_private_regular(fd.get(), label);
    SharedFileLock read_lock(fd.get(), "lock relay history file for read");
    const auto info = validate_owned_private_regular(fd.get(), label);
    if (info.st_size < 0 ||
        static_cast<std::uintmax_t>(info.st_size) > max_bytes) {
        throw std::runtime_error("relay history file size is out of range");
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(info.st_size));
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const ssize_t count = ::read(fd.get(), bytes.data() + offset,
                                     bytes.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            security::secure_erase(bytes);
            throw std::system_error(errno, std::generic_category(),
                                    "read protected relay history file");
        }
        if (count == 0) {
            security::secure_erase(bytes);
            throw std::runtime_error(
                "protected relay history file shrank while being read");
        }
        offset += static_cast<std::size_t>(count);
    }
    return bytes;
}

bool write_new_private_file_at(int directory_fd,
                               const std::string& name,
                               const std::vector<std::uint8_t>& bytes) {
    FileDescriptor fd(::openat(directory_fd, name.c_str(),
                               O_WRONLY | O_CREAT | O_EXCL |
                                   close_on_exec_flag() | no_follow_flag(),
                               S_IRUSR | S_IWUSR));
    if (fd.get() < 0) return false;
    if (::fchmod(fd.get(), S_IRUSR | S_IWUSR) != 0) {
        const int mode_error = errno;
        ::unlinkat(directory_fd, name.c_str(), 0);
        throw std::system_error(mode_error, std::generic_category(),
                                "protect relay history key");
    }
    validate_owned_private_regular(fd.get(), "relay history key");
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const ssize_t count = ::write(fd.get(), bytes.data() + offset,
                                      bytes.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            const int write_error = count < 0 ? errno : EIO;
            ::unlinkat(directory_fd, name.c_str(), 0);
            throw std::system_error(write_error, std::generic_category(),
                                    "write relay history key");
        }
        offset += static_cast<std::size_t>(count);
    }
    return true;
}

void append_private_line_at(int directory_fd,
                            const std::string& name,
                            const std::string& line) {
    if (line.size() + 1 > kMaxHistoryRecordBytes) {
        throw std::runtime_error("relay history record is too large");
    }
    FileDescriptor fd(::openat(directory_fd, name.c_str(),
                               O_WRONLY | O_APPEND | O_CREAT | O_NONBLOCK |
                                   close_on_exec_flag() | no_follow_flag(),
                               S_IRUSR | S_IWUSR));
    if (fd.get() < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "open relay history log for append");
    }
    ExclusiveFileLock append_lock(fd.get(), "lock relay history log");
    const auto info = validate_owned_private_regular(
        fd.get(), "relay history log " + name);
    if (::fchmod(fd.get(), S_IRUSR | S_IWUSR) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "protect relay history log");
    }
    if (info.st_size < 0 ||
        static_cast<std::uintmax_t>(info.st_size) + line.size() + 1 >
            kMaxHistoryFileBytes) {
        throw std::runtime_error("relay history log reached its size limit");
    }
    std::string record = line;
    record.push_back('\n');
    std::size_t offset = 0;
    while (offset < record.size()) {
        const ssize_t count = ::write(fd.get(), record.data() + offset,
                                      record.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            const int write_error = count < 0 ? errno : EIO;
            throw std::system_error(write_error, std::generic_category(),
                                    "append relay history log");
        }
        offset += static_cast<std::size_t>(count);
    }
}

bool is_history_log_name(const std::string& name) {
    constexpr std::string_view prefix = "chat-";
    constexpr std::string_view suffix = ".log";
    return name.size() > prefix.size() + suffix.size() &&
        name.starts_with(prefix) && name.ends_with(suffix);
}

std::vector<std::string> history_log_names(int directory_fd) {
    const int duplicate = ::dup(directory_fd);
    if (duplicate < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "duplicate relay history directory");
    }
    DIR* raw_directory = ::fdopendir(duplicate);
    if (!raw_directory) {
        const int open_error = errno;
        ::close(duplicate);
        throw std::system_error(open_error, std::generic_category(),
                                "enumerate relay history directory");
    }
    struct DirectoryCloser {
        DIR* value;
        ~DirectoryCloser() { if (value) ::closedir(value); }
    } closer{raw_directory};

    std::vector<std::string> names;
    names.reserve(kMaxHistoryFilesPerOperation);
    std::size_t entries_scanned = 0;
    errno = 0;
    while (dirent* entry = ::readdir(raw_directory)) {
        if (++entries_scanned > kMaxHistoryDirectoryEntriesPerOperation) {
            throw std::runtime_error(
                "relay history directory exceeds the safe scan limit");
        }
        const std::string name(entry->d_name);
        if (is_history_log_name(name)) {
            if (names.size() >= kMaxHistoryFilesPerOperation) {
                throw std::runtime_error(
                    "relay history directory exceeds the safe scan limit");
            }
            names.push_back(name);
        }
        errno = 0;
    }
    if (errno != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "enumerate relay history directory");
    }
    // readdir(3) order is filesystem-dependent. Stable file order gives
    // deterministic tie-breaking when records share a millisecond timestamp.
    std::sort(names.begin(), names.end());
    return names;
}

bool validate_private_removal_target_at(int directory_fd,
                                        const std::string& name) {
    FileDescriptor fd(::openat(directory_fd, name.c_str(),
                               O_RDONLY | O_NONBLOCK |
                                   close_on_exec_flag() |
                                   no_follow_flag()));
    if (fd.get() < 0) {
        if (errno == ENOENT) return false;
        throw std::system_error(errno, std::generic_category(),
                                "open protected relay history file");
    }
    (void)validate_owned_private_regular(
        fd.get(), "relay history file " + name);
    return true;
}

#endif

}  // namespace

HistoryListResult::~HistoryListResult() noexcept {
    for (auto& item : items) {
        wipe_relay_secret(item.text);
    }
}

HistoryListResult& HistoryListResult::operator=(
        HistoryListResult&& other) noexcept {
    if (this == &other) return *this;
    for (auto& item : items) {
        wipe_relay_secret(item.text);
    }
    items.clear();
    available = other.available;
    truncated = other.truncated;
    error = std::move(other.error);
    items = std::move(other.items);
    return *this;
}

HistoryStore::HistoryStore(std::filesystem::path root_dir,
                           std::string instance_key)
    : root_dir_(std::move(root_dir))
    , instance_key_(safe_component(std::move(instance_key))) {}

bool HistoryStore::enabled() const {
#if defined(_WIN32)
    // Protected-DACL creation exists for new files, but strict owner/reparse
    // validation for mutable history logs does not. Keep history fail-closed.
    return false;
#else
    return !root_dir_.empty() && !instance_key_.empty();
#endif
}

void HistoryStore::append_chat(const ChatHistoryEntry& entry) {
    if (!enabled() || entry.peer_id.empty() ||
        !is_valid_history_direction(entry.direction)) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        nlohmann::json json{
            {"ts_ms", entry.ts_ms},
            {"peer_id", entry.peer_id},
            {"peer_name", entry.peer_name},
            {"direction", entry.direction},
            {"text", entry.text},
        };
        HistoryJsonWiper json_wiper{json};
        std::string plain = json.dump();
        StringWiper plain_wiper{plain};
        // Never persist a record that this implementation must reject when it
        // is read back. Check before encrypt_line() can create the history key
        // or any on-disk state.
        if (plain.size() > kMaxHistoryResultPlaintextBytes) {
            return;
        }
        const std::string encrypted = encrypt_line(plain);
#if !defined(_WIN32)
        auto directory = open_private_instance_directory(root_dir_, instance_key_);
        append_private_line_at(directory.get(),
                               chat_path_for_peer(entry.peer_id).filename().string(),
                               encrypted);
#endif
    } catch (...) {
        // History is optional; a protection or I/O failure must not weaken the
        // file contract or tear down the relay channel.
    }
}

HistoryListResult HistoryStore::list_chat(
        const std::optional<std::string>& peer_id,
        std::size_t limit) const {
    HistoryListResult result;
    if (!enabled()) {
        result.available = false;
        result.error = "protected relay history is unavailable";
        return result;
    }
    if (limit == 0U) {
        result.available = false;
        result.error = "relay history limit must be positive";
        return result;
    }
    if (limit > kMaxHistoryListItems) {
        result.available = false;
        result.error = "relay history limit exceeds the safe maximum";
        return result;
    }
    std::lock_guard<std::mutex> lock(mutex_);
#if !defined(_WIN32)
    using RecordKey = std::pair<std::int64_t, std::uint64_t>;
    struct RetainedRecord {
        ChatHistoryEntry item;
        std::size_t plaintext_bytes{0};
    };
    std::multimap<RecordKey, RetainedRecord> newest;
    std::uint64_t sequence = 0;
    std::uintmax_t bytes_scanned = 0;
    std::size_t plaintext_bytes_retained = 0;
    const auto wipe_retained = [&] {
        for (auto& [_, retained] : newest) {
            wipe_relay_secret(retained.item.text);
        }
        newest.clear();
        plaintext_bytes_retained = 0;
    };
    try {
        auto directory = open_private_instance_directory(root_dir_, instance_key_);
        auto consume_file = [&](const std::string& name) {
            std::vector<std::uint8_t> bytes;
            try {
                const std::uintmax_t remaining =
                    kMaxHistoryBytesPerList - bytes_scanned;
                bytes = read_private_file_at(
                    directory.get(), name,
                    std::min(kMaxHistoryFileBytes, remaining));
            } catch (const std::system_error& ex) {
                if (ex.code().value() == ENOENT) return;
                throw;
            }
            bytes_scanned += bytes.size();
            std::size_t line_start = 0;
            while (line_start < bytes.size()) {
                const auto line_end = std::find(
                    bytes.begin() + static_cast<std::ptrdiff_t>(line_start),
                    bytes.end(), static_cast<std::uint8_t>('\n'));
                const std::size_t line_size = static_cast<std::size_t>(
                    line_end - (bytes.begin() +
                                static_cast<std::ptrdiff_t>(line_start)));
                if (line_size == 0U || line_size > kMaxHistoryRecordBytes) {
                    throw std::runtime_error(
                        "relay history contains an invalid record");
                }
                try {
                    std::string line(
                        reinterpret_cast<const char*>(bytes.data() + line_start),
                        line_size);
                    std::string plain = decrypt_line(line);
                    StringWiper plain_wiper{plain};
                    if (plain.size() > kMaxHistoryResultPlaintextBytes) {
                        throw std::runtime_error(
                            "relay history record exceeds the safe result limit");
                    }
                    auto json = nlohmann::json::parse(plain);
                    HistoryJsonWiper json_wiper{json};
                    // This protected on-disk record is a closed schema. Any
                    // future field change needs an explicit version/migration,
                    // not a permissive decoder that silently changes meaning.
                    if (!json.is_object() ||
                        json.size() != kHistoryRecordFieldCount ||
                        !json.contains("ts_ms") ||
                        !is_valid_history_timestamp(json["ts_ms"]) ||
                        !json.contains("peer_id") ||
                        !json["peer_id"].is_string() ||
                        json["peer_id"].get_ref<const std::string&>().empty() ||
                        !json.contains("peer_name") ||
                        !json["peer_name"].is_string() ||
                        !json.contains("direction") ||
                        !json["direction"].is_string() ||
                        !is_valid_history_direction(
                            json["direction"]
                                .get_ref<const std::string&>()) ||
                        !json.contains("text") ||
                        !json["text"].is_string()) {
                        throw std::runtime_error(
                            "relay history record schema is invalid");
                    }
                    ChatHistoryEntry item;
                    item.ts_ms = json["ts_ms"].get<std::int64_t>();
                    item.peer_id = json["peer_id"].get<std::string>();
                    item.peer_name = json["peer_name"].get<std::string>();
                    item.direction = json["direction"].get<std::string>();
                    item.text = json["text"].get<std::string>();
                    StringWiper item_text_wiper{item.text};
                    if (chat_path_for_peer(item.peer_id).filename() != name) {
                        throw std::runtime_error(
                            "relay history record does not match its log");
                    }
                    const RecordKey key{item.ts_ms, sequence++};
                    plaintext_bytes_retained += plain.size();
                    newest.emplace(
                        key, RetainedRecord{std::move(item), plain.size()});
                    while (newest.size() > limit ||
                           plaintext_bytes_retained >
                               kMaxHistoryResultPlaintextBytes) {
                        result.truncated = true;
                        const auto oldest = newest.begin();
                        plaintext_bytes_retained -=
                            oldest->second.plaintext_bytes;
                        wipe_relay_secret(oldest->second.item.text);
                        newest.erase(oldest);
                    }
                } catch (...) {
                    throw std::runtime_error(
                        "relay history contains an invalid record");
                }
                if (line_end == bytes.end()) break;
                line_start = static_cast<std::size_t>(
                    line_end - bytes.begin()) + 1U;
            }
        };
        if (peer_id) {
            consume_file(chat_path_for_peer(*peer_id).filename().string());
        } else {
            for (const auto& name : history_log_names(directory.get())) {
                consume_file(name);
            }
        }
        result.items.reserve(newest.size());
        for (auto& [_, retained] : newest) {
            result.items.push_back(std::move(retained.item));
        }
        // Moved-from strings can retain ordinary-allocation capacity. Wipe
        // them too before releasing the temporary selection container.
        wipe_retained();
    } catch (const std::exception& ex) {
        wipe_retained();
        for (auto& item : result.items) wipe_relay_secret(item.text);
        result.items.clear();
        result.available = false;
        result.truncated = false;
        result.error = ex.what();
    } catch (...) {
        wipe_retained();
        for (auto& item : result.items) wipe_relay_secret(item.text);
        result.items.clear();
        result.available = false;
        result.truncated = false;
        result.error = "unknown relay history read failure";
    }
#else
    (void)peer_id;
    (void)limit;
#endif
    return result;
}

bool HistoryStore::delete_chat(const std::optional<std::string>& peer_id,
                               std::string* error) {
    if (error) error->clear();
    if (!enabled()) {
#if defined(_WIN32)
        if (error) {
            *error =
                "protected relay history deletion is unavailable on Windows";
        }
        return false;
#else
        return true;
#endif
    }
    std::lock_guard<std::mutex> lock(mutex_);
#if !defined(_WIN32)
    try {
        auto directory = open_private_instance_directory(root_dir_, instance_key_);
        std::vector<std::string> names;
        if (peer_id) {
            names.push_back(
                chat_path_for_peer(*peer_id).filename().string());
        } else {
            names = history_log_names(directory.get());
        }

        // Validate the complete bounded snapshot before unlinking anything.
        // A bad late entry or an exceeded scan bound must not turn a reported
        // failure into an undocumented partial delete.
        std::vector<std::string> validated_names;
        validated_names.reserve(names.size());
        for (const auto& name : names) {
            if (validate_private_removal_target_at(directory.get(), name)) {
                validated_names.push_back(name);
            }
        }

        bool removed = false;
        for (const auto& name : validated_names) {
            if (::unlinkat(directory.get(), name.c_str(), 0) != 0) {
                if (errno == ENOENT) continue;
                throw std::system_error(
                    errno, std::generic_category(),
                    "remove protected relay history file");
            }
            removed = true;
        }
        if (removed && ::fsync(directory.get()) != 0) {
            throw std::system_error(
                errno, std::generic_category(),
                "sync relay history directory after deletion");
        }
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    } catch (...) {
        if (error) *error = "unknown relay history deletion failure";
        return false;
    }
#else
    (void)peer_id;
    return false;
#endif
}

std::filesystem::path HistoryStore::key_path() const {
    return root_dir_ / instance_key_ / kHistoryKeyFile;
}

std::filesystem::path HistoryStore::chat_path_for_peer(
        const std::string& peer_id) const {
    return root_dir_ / instance_key_ /
        ("chat-" + safe_component(peer_id) + ".log");
}

std::vector<std::uint8_t> HistoryStore::load_or_create_key() const {
#if defined(_WIN32)
    throw std::runtime_error("protected relay history is unavailable on Windows");
#else
    auto directory = open_private_instance_directory(root_dir_, instance_key_);
    ExclusiveFileLock key_lock(
        directory.get(), "lock relay history key creation");
    auto decode_key = [&](std::vector<std::uint8_t> encoded_bytes) {
        BytesWiper encoded_bytes_wiper{encoded_bytes};
        std::string encoded(encoded_bytes.begin(), encoded_bytes.end());
        StringWiper encoded_wiper{encoded};
        while (!encoded.empty() &&
               std::isspace(static_cast<unsigned char>(encoded.back())) != 0) {
            encoded.pop_back();
        }
        std::string raw = util::base64_decode(encoded);
        StringWiper raw_wiper{raw};
        if (raw.size() != kHistoryKeyBytes) {
            throw std::runtime_error("relay history key has an invalid length");
        }
        return std::vector<std::uint8_t>(raw.begin(), raw.end());
    };

    try {
        return decode_key(read_private_file_at(
            directory.get(), kHistoryKeyFile, 256));
    } catch (const std::system_error& ex) {
        if (ex.code().value() != ENOENT) throw;
    }

    auto generated = crypto::random_bytes(kHistoryKeyBytes);
    BytesWiper generated_wiper{generated};
    std::string raw(generated.begin(), generated.end());
    StringWiper raw_wiper{raw};
    std::string encoded = util::base64_encode(raw);
    StringWiper encoded_wiper{encoded};
    std::vector<std::uint8_t> encoded_bytes(encoded.begin(), encoded.end());
    BytesWiper encoded_bytes_wiper{encoded_bytes};
    if (write_new_private_file_at(
            directory.get(), kHistoryKeyFile, encoded_bytes)) {
        return std::vector<std::uint8_t>(generated.begin(), generated.end());
    }
    return decode_key(read_private_file_at(
        directory.get(), kHistoryKeyFile, 256));
#endif
}

std::string HistoryStore::encrypt_line(const std::string& line) const {
    auto key = load_or_create_key();
    BytesWiper key_wiper{key};
    auto nonce = crypto::random_bytes(kHistoryNonceBytes);
    crypto::Bytes plain(line.begin(), line.end());
    BytesWiper plain_wiper{plain};
    auto blob = crypto::encrypt_chacha20(plain, key, nonce);
    std::string packed;
    packed.reserve(nonce.size() + blob.size());
    packed.append(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    packed.append(reinterpret_cast<const char*>(blob.data()), blob.size());
    return util::base64_encode(packed);
}

std::string HistoryStore::decrypt_line(const std::string& line) const {
    std::string raw = util::base64_decode(line);
    if (raw.size() < kHistoryNonceBytes) {
        throw std::runtime_error("history line too short");
    }
    auto key = load_or_create_key();
    BytesWiper key_wiper{key};
    crypto::Bytes nonce(raw.begin(), raw.begin() + kHistoryNonceBytes);
    crypto::Bytes blob(raw.begin() + kHistoryNonceBytes, raw.end());
    auto plain = crypto::decrypt_chacha20(blob, key, nonce);
    BytesWiper plain_wiper{plain};
    return std::string(plain.begin(), plain.end());
}

}  // namespace yume::client
