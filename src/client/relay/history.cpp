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
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <system_error>

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
                               O_RDONLY | close_on_exec_flag() |
                                   no_follow_flag()));
    if (fd.get() < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "open protected relay history file");
    }
    const auto info = validate_owned_private_regular(
        fd.get(), "relay history file " + name);
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
                               O_WRONLY | O_APPEND | O_CREAT |
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

template <typename Callback>
void for_each_history_log(int directory_fd, Callback&& callback) {
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

    errno = 0;
    while (dirent* entry = ::readdir(raw_directory)) {
        const std::string name(entry->d_name);
        if (is_history_log_name(name)) callback(name);
        errno = 0;
    }
    if (errno != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "enumerate relay history directory");
    }
}

#endif

}  // namespace

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
    if (!enabled() || entry.peer_id.empty()) return;
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

std::vector<ChatHistoryEntry> HistoryStore::list_chat(
        const std::optional<std::string>& peer_id) const {
    std::vector<ChatHistoryEntry> out;
    if (!enabled()) return out;
    std::lock_guard<std::mutex> lock(mutex_);
#if !defined(_WIN32)
    try {
        auto directory = open_private_instance_directory(root_dir_, instance_key_);
        auto consume_file = [&](const std::string& name) {
            std::vector<std::uint8_t> bytes;
            try {
                bytes = read_private_file_at(
                    directory.get(), name, kMaxHistoryFileBytes);
            } catch (...) {
                return;
            }
            std::string content(bytes.begin(), bytes.end());
            std::istringstream input(content);
            std::string line;
            while (std::getline(input, line)) {
                if (line.empty() || line.size() > kMaxHistoryRecordBytes) continue;
                try {
                    std::string plain = decrypt_line(line);
                    StringWiper plain_wiper{plain};
                    auto json = nlohmann::json::parse(plain);
                    HistoryJsonWiper json_wiper{json};
                    ChatHistoryEntry item;
                    item.ts_ms = json.value("ts_ms", 0LL);
                    item.peer_id = json.value("peer_id", "");
                    item.peer_name = json.value("peer_name", "");
                    item.direction = json.value("direction", "");
                    item.text = json.value("text", "");
                    out.push_back(std::move(item));
                } catch (...) {
                }
            }
        };
        if (peer_id) {
            consume_file(chat_path_for_peer(*peer_id).filename().string());
        } else {
            for_each_history_log(directory.get(), consume_file);
        }
        std::sort(out.begin(), out.end(), [](const auto& left, const auto& right) {
            return left.ts_ms < right.ts_ms;
        });
    } catch (...) {
    }
#else
    (void)peer_id;
#endif
    return out;
}

void HistoryStore::delete_chat(const std::optional<std::string>& peer_id) {
    if (!enabled()) return;
    std::lock_guard<std::mutex> lock(mutex_);
#if !defined(_WIN32)
    try {
        auto directory = open_private_instance_directory(root_dir_, instance_key_);
        auto remove_valid = [&](const std::string& name) {
            try {
                auto bytes = read_private_file_at(
                    directory.get(), name, kMaxHistoryFileBytes);
                security::secure_erase(bytes);
                (void)::unlinkat(directory.get(), name.c_str(), 0);
            } catch (...) {
            }
        };
        if (peer_id) {
            remove_valid(chat_path_for_peer(*peer_id).filename().string());
        } else {
            for_each_history_log(directory.get(), remove_valid);
        }
    } catch (...) {
    }
#else
    (void)peer_id;
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
