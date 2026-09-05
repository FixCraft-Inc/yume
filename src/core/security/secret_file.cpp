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
    ~FileDescriptor() { if (fd_ >= 0) (void)::close(fd_); }
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

class LocalSecurityDescriptor {
public:
    LocalSecurityDescriptor() = default;
    ~LocalSecurityDescriptor() {
        if (value_) (void)::LocalFree(value_);
    }

    LocalSecurityDescriptor(const LocalSecurityDescriptor&) = delete;
    LocalSecurityDescriptor& operator=(const LocalSecurityDescriptor&) = delete;

    PSECURITY_DESCRIPTOR* out() noexcept { return &value_; }
    PSECURITY_DESCRIPTOR get() const noexcept { return value_; }

private:
    PSECURITY_DESCRIPTOR value_{nullptr};
};

bool ensure_private_directory_windows(const std::filesystem::path& path,
                                      std::string* error) {
    LocalSecurityDescriptor descriptor;
    if (::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;FA;;;SY)(A;;FA;;;OW)", SDDL_REVISION_1,
            descriptor.out(), nullptr) == 0) {
        SetWriteError(error, "create private directory security descriptor",
                      static_cast<int>(::GetLastError()),
                      std::system_category());
        return false;
    }

    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor.get();
    attributes.bInheritHandle = FALSE;

    std::filesystem::path current = path.root_path();
    std::vector<std::filesystem::path> components;
    for (const auto& part : path.relative_path()) {
        if (part.empty()) continue;
        if (part == "." || part == "..") {
            if (error) {
                *error = "private directory path contains an unsafe component";
            }
            return false;
        }
        components.push_back(part);
    }
    if (components.empty()) {
        if (error) *error = "private directory path has no components";
        return false;
    }

    for (std::size_t index = 0; index < components.size(); ++index) {
        current /= components[index];
        bool created = false;
        if (::CreateDirectoryW(current.c_str(), &attributes) != 0) {
            created = true;
        } else {
            const DWORD create_error = ::GetLastError();
            if (create_error != ERROR_ALREADY_EXISTS) {
                SetWriteError(error, "create private directory",
                              static_cast<int>(create_error),
                              std::system_category());
                return false;
            }
        }

        const DWORD attributes_value = ::GetFileAttributesW(current.c_str());
        if (attributes_value == INVALID_FILE_ATTRIBUTES ||
            (attributes_value & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (attributes_value & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            if (error) {
                *error = "private directory path must contain only "
                         "non-reparse directories";
            }
            return false;
        }

        const bool final_component = index + 1U == components.size();
        if ((created || final_component) &&
            ::SetFileSecurityW(current.c_str(), DACL_SECURITY_INFORMATION,
                               descriptor.get()) == 0) {
            SetWriteError(error, "protect private directory",
                          static_cast<int>(::GetLastError()),
                          std::system_category());
            return false;
        }
    }
    return true;
}

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

    if (::FlushFileBuffers(handle) == 0) {
        const DWORD flush_error = ::GetLastError();
        return close_and_remove("flush private file", flush_error);
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

bool flush_parent_directory(const std::filesystem::path& path,
                            std::string* error) {
    const std::filesystem::path parent =
        path.parent_path().empty() ? std::filesystem::path(".")
                                   : path.parent_path();
    int flags = O_RDONLY;
#if defined(O_CLOEXEC)
    flags |= O_CLOEXEC;
#endif
#if defined(O_DIRECTORY)
    flags |= O_DIRECTORY;
#endif
    const int descriptor = ::open(parent.c_str(), flags);
    if (descriptor < 0) {
        SetWriteError(error, "open private file directory", errno,
                      std::generic_category());
        return false;
    }
    if (::fsync(descriptor) != 0) {
        const int flush_error = errno;
        (void)::close(descriptor);
        SetWriteError(error, "flush private file directory", flush_error,
                      std::generic_category());
        return false;
    }
    if (::close(descriptor) != 0) {
        SetWriteError(error, "close private file directory", errno,
                      std::generic_category());
        return false;
    }
    return true;
}

bool ensure_private_directory_posix(const std::filesystem::path& path,
                                    std::string* error) {
#if !defined(O_NOFOLLOW) || !defined(O_DIRECTORY)
    if (error) {
        *error = "private directory creation requires O_NOFOLLOW and "
                 "O_DIRECTORY";
    }
    return false;
#else
    std::vector<std::string> components;
    const std::filesystem::path relative =
        path.is_absolute() ? path.relative_path() : path;
    for (const auto& part : relative) {
        const std::string component = part.string();
        if (component.empty()) continue;
        if (component == "." || component == ".." ||
            component.find('\0') != std::string::npos) {
            if (error) {
                *error = "private directory path contains an unsafe component";
            }
            return false;
        }
        components.push_back(component);
    }
    if (components.empty()) {
        if (error) *error = "private directory path has no components";
        return false;
    }

    int directory_flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW;
#if defined(O_CLOEXEC)
    directory_flags |= O_CLOEXEC;
#endif
    FileDescriptor current(::open(path.is_absolute() ? "/" : ".",
                                  directory_flags));
    if (current.get() < 0) {
        SetWriteError(error, "open private directory root", errno,
                      std::generic_category());
        return false;
    }
#if !defined(O_CLOEXEC)
    if (::fcntl(current.get(), F_SETFD, FD_CLOEXEC) != 0) {
        SetWriteError(error, "protect private directory root descriptor", errno,
                      std::generic_category());
        return false;
    }
#endif

    for (std::size_t index = 0; index < components.size(); ++index) {
        const std::string& component = components[index];
        bool created = false;
        if (::mkdirat(current.get(), component.c_str(), S_IRWXU) == 0) {
            created = true;
        } else if (errno != EEXIST) {
            SetWriteError(error, "create private directory component", errno,
                          std::generic_category());
            return false;
        }

        FileDescriptor next(::openat(current.get(), component.c_str(),
                                     directory_flags));
        if (next.get() < 0) {
            const int open_error = errno;
            if (created) {
                (void)::unlinkat(current.get(), component.c_str(),
                                 AT_REMOVEDIR);
            }
            SetWriteError(error,
                          "open private directory component without following links",
                          open_error, std::generic_category());
            return false;
        }
#if !defined(O_CLOEXEC)
        if (::fcntl(next.get(), F_SETFD, FD_CLOEXEC) != 0) {
            SetWriteError(error, "protect private directory descriptor", errno,
                          std::generic_category());
            return false;
        }
#endif

        struct stat status {};
        if (::fstat(next.get(), &status) != 0) {
            SetWriteError(error, "inspect private directory component", errno,
                          std::generic_category());
            return false;
        }
        const bool final_component = index + 1U == components.size();
        if (!S_ISDIR(status.st_mode)) {
            if (error) *error = "private directory path contains a non-directory";
            return false;
        }
        if (final_component && status.st_uid != ::geteuid()) {
            if (error) {
                *error = "private directory must be owned by the current user";
            }
            return false;
        }
        if ((created || final_component) &&
            ::fchmod(next.get(), S_IRWXU) != 0) {
            SetWriteError(error, "protect private directory", errno,
                          std::generic_category());
            return false;
        }
        if (created) {
            if (::fsync(next.get()) != 0 || ::fsync(current.get()) != 0) {
                SetWriteError(error, "flush private directory creation", errno,
                              std::generic_category());
                return false;
            }
        }
        current = std::move(next);
    }
    return true;
#endif
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

    if (::fsync(fd) != 0) {
        return close_and_remove("flush private file", errno);
    }

    if (::close(fd) != 0) {
        const int close_error = errno;
        SetWriteError(
            error, "close private file", close_error,
            std::generic_category());
        RemovePartialFile(path, error);
        return false;
    }
    if (!flush_parent_directory(path, error)) {
        RemovePartialFile(path, error);
        return false;
    }
    if (error) error->clear();
    return true;
}

#endif

}  // namespace

bool ensure_private_directory(const std::filesystem::path& path,
                              std::string* error) {
    if (error) error->clear();
    if (path.empty() || path.filename().empty()) {
        if (error) *error = "private directory path is invalid";
        return false;
    }

#if defined(_WIN32)
    return ensure_private_directory_windows(path, error);
#else
    return ensure_private_directory_posix(path, error);
#endif
}

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
                            std::string* error,
                            PrivateParentPolicy parent_policy) {
    if (error) error->clear();
    if (path.empty()) {
        if (error) *error = "private file path is empty";
        return false;
    }

    if (path.has_parent_path()) {
        std::error_code status_error;
        const auto parent_status = std::filesystem::symlink_status(
            path.parent_path(), status_error);
        const bool missing =
            parent_status.type() == std::filesystem::file_type::not_found ||
            status_error == std::errc::no_such_file_or_directory;
        if (missing && parent_policy == PrivateParentPolicy::CreateOwnerOnly) {
            if (!ensure_private_directory(path.parent_path(), error)) {
                return false;
            }
        } else if (missing) {
            if (error) *error = "private file parent directory does not exist";
            return false;
        } else if (status_error) {
            if (error) {
                *error = "inspect private file parent directory: " +
                    status_error.message();
            }
            return false;
        } else if (parent_status.type() !=
                   std::filesystem::file_type::directory) {
            if (error) {
                *error = "private file parent must be a real directory";
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
    if (path.empty() || path.native().find('\0') != std::string::npos) {
        throw std::runtime_error("protected secret file path is invalid");
    }
    // Validate the opened type before any potentially blocking read. O_RDONLY
    // alone waits for a writer on a FIFO before fstat can reject it.
    const int raw_fd = ::open(
        path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
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

std::vector<std::uint8_t> read_private_file_strict(
    const std::filesystem::path& path,
    std::size_t maximum_bytes,
    std::string_view description) {
    const std::string label = description.empty()
        ? std::string("private file")
        : std::string(description);
#if defined(_WIN32)
    (void)path;
    (void)maximum_bytes;
    throw std::runtime_error(
        "YUME protected " + label +
        " files are currently Linux/POSIX only");
#else
    if (path.empty() || path.native().find('\0') != std::string::npos) {
        throw std::runtime_error(label + " path is invalid");
    }
    // Opening a FIFO for reading blocks before fstat unless O_NONBLOCK is set.
    const int raw_fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (raw_fd < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "open YUME " + label + " file");
    }
    FileDescriptor fd(raw_fd);
    struct stat info {};
    if (::fstat(fd.get(), &info) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "stat YUME " + label + " file");
    }
    if (!S_ISREG(info.st_mode)) {
        throw std::runtime_error(
            "YUME " + label + " path must be a regular file");
    }
    // Private material owned by another account is not this process's secret,
    // even when a privileged process happens to be able to read it.
    if (info.st_uid != ::geteuid()) {
        throw std::runtime_error(
            "YUME " + label + " file " + path.string() +
            " must be owned by the current user");
    }
    if ((info.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        throw std::runtime_error(
            "YUME " + label + " file " + path.string() +
            " must not be group/world accessible (chmod 600)");
    }
    if (info.st_size < 0 ||
        static_cast<std::uintmax_t>(info.st_size) > maximum_bytes) {
        throw std::runtime_error(
            "YUME " + label + " file size is out of range");
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
                                    "read YUME " + label + " file");
        }
        if (count == 0) {
            secure_erase(contents);
            throw std::runtime_error(
                "YUME " + label + " file shrank while being read");
        }
        offset += static_cast<std::size_t>(count);
    }
    std::uint8_t extra = 0;
    while (true) {
        const ssize_t count = ::read(fd.get(), &extra, 1);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            secure_erase(contents);
            throw std::system_error(
                errno, std::generic_category(),
                "verify YUME " + label + " file length");
        }
        if (count != 0) {
            secure_erase(contents);
            throw std::runtime_error(
                "YUME " + label + " file grew while being read");
        }
        break;
    }
    return contents;
#endif
}

std::vector<std::uint8_t> ReadPrivateKeyFileStrict(
    const std::filesystem::path& path) {
    return read_private_file_strict(
        path, kMaxPrivateKeyFileBytes, "private key");
}

}  // namespace yume::security
