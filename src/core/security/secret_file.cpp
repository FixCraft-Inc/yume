/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/security/secret_file.hpp"

#include <algorithm>
#include <cerrno>
#include <limits>
#include <stdexcept>
#include <string>
#include <system_error>

#include "core/security/secure_erase.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace yume::security {
namespace {

[[maybe_unused]] std::uint8_t DecodeNibble(std::uint8_t ch) {
    if (ch >= '0' && ch <= '9') return static_cast<std::uint8_t>(ch - '0');
    if (ch >= 'a' && ch <= 'f') return static_cast<std::uint8_t>(ch - 'a' + 10);
    throw std::runtime_error("secret file must contain lowercase hexadecimal only");
}

#if !defined(_WIN32)
class FileDescriptor {
public:
    explicit FileDescriptor(int fd) : fd_(fd) {}
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    ~FileDescriptor() { if (fd_ >= 0) ::close(fd_); }
    int get() const noexcept { return fd_; }
private:
    int fd_;
};
#endif

void SetWriteError(std::string* error,
                   const char* action,
                   int error_number,
                   const std::error_category& category) noexcept {
    if (!error) {
        return;
    }
    try {
        *error = std::string(action) + ": " +
            std::error_code(error_number, category).message();
    } catch (...) {
        try {
            error->assign(action);
        } catch (...) {
        }
    }
}

void AppendCleanupError(std::string* error,
                        const char* action,
                        int error_number,
                        const std::error_category& category) noexcept {
    if (!error) {
        return;
    }
    try {
        if (!error->empty()) {
            error->append("; ");
        }
        error->append(action);
        error->append(": ");
        error->append(std::error_code(error_number, category).message());
    } catch (...) {
        // Preserve the primary operation error if extending its diagnostic
        // runs out of memory.
    }
}

#if defined(_WIN32)

bool RemovePartialFile(const std::filesystem::path& path,
                       std::string* error) noexcept {
    if (::DeleteFileW(path.c_str()) != 0) {
        return true;
    }
    AppendCleanupError(
        error, "remove partial private file",
        static_cast<int>(::GetLastError()), std::system_category());
    return false;
}

bool WriteNewPrivateFile(const std::filesystem::path& path,
                         std::span<const std::uint8_t> contents,
                         std::string* error) {
    // Protected DACL: full access for the file owner and LocalSystem only.
    // Applying it through SECURITY_ATTRIBUTES makes the file private at the
    // instant CREATE_NEW succeeds; there is no create-then-tighten window.
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;FA;;;SY)(A;;FA;;;OW)",
            SDDL_REVISION_1,
            &descriptor,
            nullptr) == 0) {
        SetWriteError(
            error, "create private file security descriptor",
            static_cast<int>(::GetLastError()), std::system_category());
        return false;
    }

    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;
    attributes.bInheritHandle = FALSE;
    const HANDLE handle = ::CreateFileW(
        path.c_str(),
        GENERIC_WRITE,
        0,
        &attributes,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    ::LocalFree(descriptor);
    if (handle == INVALID_HANDLE_VALUE) {
        SetWriteError(
            error, "create private file",
            static_cast<int>(::GetLastError()), std::system_category());
        return false;
    }

    auto close_and_remove = [&](const char* action,
                                DWORD error_number) noexcept {
        SetWriteError(
            error, action, static_cast<int>(error_number),
            std::system_category());
        if (::CloseHandle(handle) == 0) {
            AppendCleanupError(
                error, "close partial private file",
                static_cast<int>(::GetLastError()), std::system_category());
        }
        RemovePartialFile(path, error);
        return false;
    };

    std::size_t offset = 0;
    while (offset < contents.size()) {
        const std::size_t remaining = contents.size() - offset;
        const DWORD chunk = static_cast<DWORD>(
            std::min<std::size_t>(
                remaining,
                static_cast<std::size_t>(
                    std::numeric_limits<DWORD>::max())));
        DWORD written = 0;
        if (::WriteFile(
                handle, contents.data() + offset, chunk, &written, nullptr) == 0) {
            const DWORD write_error = ::GetLastError();
            return close_and_remove("write private file", write_error);
        }
        if (written == 0) {
            return close_and_remove("write private file", ERROR_WRITE_FAULT);
        }
        offset += static_cast<std::size_t>(written);
    }

    if (::CloseHandle(handle) == 0) {
        const DWORD close_error = ::GetLastError();
        SetWriteError(
            error, "close private file", static_cast<int>(close_error),
            std::system_category());
        RemovePartialFile(path, error);
        return false;
    }
    if (error) error->clear();
    return true;
}

#else

bool RemovePartialFile(const std::filesystem::path& path,
                       std::string* error) noexcept {
    if (::unlink(path.c_str()) == 0) {
        return true;
    }
    AppendCleanupError(
        error, "remove partial private file", errno,
        std::generic_category());
    return false;
}

bool WriteNewPrivateFile(const std::filesystem::path& path,
                         std::span<const std::uint8_t> contents,
                         std::string* error) {
    int open_flags = O_WRONLY | O_CREAT | O_EXCL;
#if defined(O_CLOEXEC)
    open_flags |= O_CLOEXEC;
#endif
#if defined(O_NOFOLLOW)
    open_flags |= O_NOFOLLOW;
#endif
    const int fd = ::open(path.c_str(), open_flags, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        SetWriteError(
            error, "create private file", errno, std::generic_category());
        return false;
    }

    auto close_and_remove = [&](const char* action,
                                int error_number) noexcept {
        SetWriteError(
            error, action, error_number, std::generic_category());
        if (::close(fd) != 0) {
            AppendCleanupError(
                error, "close partial private file", errno,
                std::generic_category());
        }
        RemovePartialFile(path, error);
        return false;
    };

#if !defined(O_CLOEXEC)
    if (::fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        return close_and_remove("mark private file close-on-exec", errno);
    }
#endif
    if (::fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        return close_and_remove("set private file permissions", errno);
    }

    std::size_t offset = 0;
    while (offset < contents.size()) {
        const std::size_t remaining = contents.size() - offset;
        const std::size_t chunk = std::min<std::size_t>(
            remaining,
            static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()));
        const ssize_t count = ::write(fd, contents.data() + offset, chunk);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            const int write_error = count < 0 ? errno : EIO;
            return close_and_remove("write private file", write_error);
        }
        offset += static_cast<std::size_t>(count);
    }

    if (::close(fd) != 0) {
        const int close_error = errno;
        SetWriteError(
            error, "close private file", close_error,
            std::generic_category());
        RemovePartialFile(path, error);
        return false;
    }
    if (error) error->clear();
    return true;
}

#endif

}  // namespace

Secret32::Secret32(std::array<std::uint8_t, 32>&& bytes) noexcept
    : bytes_(bytes) {
    volatile std::uint8_t* cursor = bytes.data();
    for (std::size_t i = 0; i < bytes.size(); ++i) cursor[i] = 0;
}

Secret32::Secret32(Secret32&& other) noexcept : bytes_(other.bytes_) {
    other.Wipe();
}

Secret32& Secret32::operator=(Secret32&& other) noexcept {
    if (this != &other) {
        Wipe();
        bytes_ = other.bytes_;
        other.Wipe();
    }
    return *this;
}

Secret32::~Secret32() { Wipe(); }

std::vector<std::uint8_t> Secret32::CopyBytes() const {
    return {bytes_.begin(), bytes_.end()};
}

void Secret32::Wipe() noexcept {
    volatile std::uint8_t* cursor = bytes_.data();
    for (std::size_t i = 0; i < bytes_.size(); ++i) cursor[i] = 0;
}

bool WriteFileExclusive0600(const std::filesystem::path& path,
                            std::span<const std::uint8_t> contents,
                            std::string* error) {
    if (path.empty()) {
        if (error) *error = "private file path is empty";
        return false;
    }

    std::error_code directory_error;
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path(), directory_error);
        if (directory_error) {
            if (error) {
                *error = "create private file directory: " +
                    directory_error.message();
            }
            return false;
        }
    }

    return WriteNewPrivateFile(path, contents, error);
}

Secret32 LoadSecretFile32(const std::filesystem::path& path) {
#if defined(_WIN32)
    (void)path;
    throw std::runtime_error("YUME 2.0 protected secret files are currently Linux/POSIX only");
#else
    const int raw_fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (raw_fd < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "open protected YUME secret file");
    }
    FileDescriptor fd(raw_fd);
    struct stat info {};
    if (::fstat(fd.get(), &info) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "stat protected YUME secret file");
    }
    if (!S_ISREG(info.st_mode)) {
        throw std::runtime_error("YUME secret path must be a regular file");
    }
    if ((info.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        throw std::runtime_error("YUME secret file must not be group/world accessible");
    }
    if (info.st_size != 64) {
        throw std::runtime_error("YUME secret file must contain exactly 64 lowercase hex characters");
    }

    std::vector<std::uint8_t> encoded(64);
    std::size_t offset = 0;
    while (offset < encoded.size()) {
        const ssize_t count = ::read(fd.get(), encoded.data() + offset,
                                     encoded.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            secure_erase(encoded);
            throw std::system_error(errno, std::generic_category(),
                                    "read protected YUME secret file");
        }
        if (count == 0) {
            secure_erase(encoded);
            throw std::runtime_error("YUME secret file ended before 64 characters");
        }
        offset += static_cast<std::size_t>(count);
    }
    std::uint8_t extra = 0;
    while (true) {
        const ssize_t count = ::read(fd.get(), &extra, 1);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            secure_erase(encoded);
            throw std::system_error(errno, std::generic_category(),
                                    "verify protected YUME secret file EOF");
        }
        if (count != 0) {
            secure_erase(encoded);
            throw std::runtime_error(
                "YUME secret file must contain exactly 64 lowercase hex characters");
        }
        break;
    }

    std::array<std::uint8_t, 32> decoded{};
    try {
        for (std::size_t i = 0; i < decoded.size(); ++i) {
            decoded[i] = static_cast<std::uint8_t>(
                (DecodeNibble(encoded[2 * i]) << 4) |
                DecodeNibble(encoded[2 * i + 1]));
        }
    } catch (...) {
        secure_erase(encoded);
        volatile std::uint8_t* cursor = decoded.data();
        for (std::size_t i = 0; i < decoded.size(); ++i) cursor[i] = 0;
        throw;
    }
    secure_erase(encoded);
    return Secret32(std::move(decoded));
#endif
}

std::vector<std::uint8_t> ReadPrivateKeyFileStrict(
    const std::filesystem::path& path) {
#if defined(_WIN32)
    (void)path;
    throw std::runtime_error(
        "YUME protected private key files are currently Linux/POSIX only");
#else
    if (path.empty()) {
        throw std::runtime_error("private key path is empty");
    }
    const int raw_fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (raw_fd < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "open YUME private key file");
    }
    FileDescriptor fd(raw_fd);
    struct stat info {};
    if (::fstat(fd.get(), &info) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "stat YUME private key file");
    }
    if (!S_ISREG(info.st_mode)) {
        throw std::runtime_error("YUME private key path must be a regular file");
    }
    // A key owned by another account is not this process's identity, even when
    // a privileged process happens to be able to read it.
    if (info.st_uid != ::geteuid()) {
        throw std::runtime_error(
            "YUME private key file " + path.string() +
            " must be owned by the current user");
    }
    if ((info.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        throw std::runtime_error(
            "YUME private key file " + path.string() +
            " must not be group/world accessible (chmod 600)");
    }
    if (info.st_size < 0 ||
        static_cast<std::uintmax_t>(info.st_size) > kMaxPrivateKeyFileBytes) {
        throw std::runtime_error("YUME private key file size is out of range");
    }

    std::vector<std::uint8_t> contents(static_cast<std::size_t>(info.st_size));
    std::size_t offset = 0;
    while (offset < contents.size()) {
        const ssize_t count = ::read(fd.get(), contents.data() + offset,
                                     contents.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            secure_erase(contents);
            throw std::system_error(errno, std::generic_category(),
                                    "read YUME private key file");
        }
        if (count == 0) {
            secure_erase(contents);
            throw std::runtime_error(
                "YUME private key file shrank while being read");
        }
        offset += static_cast<std::size_t>(count);
    }
    return contents;
#endif
}

}  // namespace yume::security
