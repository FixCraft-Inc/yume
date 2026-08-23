/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/runtime/atomic_file.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <limits>
#include <system_error>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace yume::runtime {
namespace {

constexpr unsigned kCreateAttempts = 128;
std::atomic<std::uint64_t> g_temp_sequence{0};

void set_error(std::string* error,
               const std::filesystem::path& path,
               const std::string& operation,
               const std::string& detail) {
    if (!error) return;
    *error = operation + " '" + path.string() + "': " + detail;
}

std::filesystem::path parent_or_dot(const std::filesystem::path& path) {
    const auto parent = path.parent_path();
    return parent.empty() ? std::filesystem::path(".") : parent;
}

std::filesystem::path temp_candidate(const std::filesystem::path& path,
                                     std::uint64_t process_id) {
    const auto sequence = g_temp_sequence.fetch_add(1, std::memory_order_relaxed);
    return parent_or_dot(path) /
           (path.filename().string() + ".tmp." + std::to_string(process_id) +
            "." + std::to_string(sequence));
}

#ifdef _WIN32

std::string windows_error(DWORD code) {
    char* message = nullptr;
    const DWORD length = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<char*>(&message), 0, nullptr);
    std::string result = length && message
                             ? std::string(message, message + length)
                             : "Windows error " + std::to_string(code);
    if (message) LocalFree(message);
    while (!result.empty() &&
           (result.back() == '\r' || result.back() == '\n')) {
        result.pop_back();
    }
    return result;
}

#else

class ScopedFd {
public:
    explicit ScopedFd(int fd = -1) noexcept : fd_(fd) {}
    ~ScopedFd() {
        if (fd_ >= 0) (void)::close(fd_);
    }

    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;

    int get() const noexcept { return fd_; }
    int release() noexcept {
        const int fd = fd_;
        fd_ = -1;
        return fd;
    }

private:
    int fd_;
};

std::string errno_message(int value) {
    return std::strerror(value);
}

#endif

}  // namespace

bool AtomicWriteFile(const std::filesystem::path& path,
                     std::string_view content,
                     std::string* error,
                     ParentDirectoryPolicy parent_policy) {
    if (error) error->clear();
    if (path.empty() || path.filename().empty()) {
        set_error(error, path, "cannot atomically write", "invalid destination path");
        return false;
    }

    const auto parent = path.parent_path();
    if (!parent.empty() &&
        parent_policy == ParentDirectoryPolicy::Create) {
        std::error_code directory_error;
        std::filesystem::create_directories(parent, directory_error);
        if (directory_error) {
            set_error(error, parent, "cannot create config directory",
                      directory_error.message());
            return false;
        }
    }

#ifdef _WIN32
    HANDLE file = INVALID_HANDLE_VALUE;
    std::filesystem::path temporary;
    for (unsigned attempt = 0; attempt < kCreateAttempts; ++attempt) {
        temporary = temp_candidate(path, GetCurrentProcessId());
        file = CreateFileW(
            temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
            nullptr);
        if (file != INVALID_HANDLE_VALUE) break;
        const DWORD create_error = GetLastError();
        if (create_error != ERROR_FILE_EXISTS &&
            create_error != ERROR_ALREADY_EXISTS) {
            set_error(error, temporary, "cannot create temporary config",
                      windows_error(create_error));
            return false;
        }
    }
    if (file == INVALID_HANDLE_VALUE) {
        set_error(error, path, "cannot atomically write",
                  "temporary-name attempts exhausted");
        return false;
    }

    auto fail = [&](const char* operation, DWORD code) {
        (void)CloseHandle(file);
        file = INVALID_HANDLE_VALUE;
        (void)DeleteFileW(temporary.c_str());
        set_error(error, temporary, operation, windows_error(code));
        return false;
    };

    std::size_t written = 0;
    while (written < content.size()) {
        const auto chunk = static_cast<DWORD>(std::min<std::size_t>(
            content.size() - written, std::numeric_limits<DWORD>::max()));
        DWORD count = 0;
        if (!WriteFile(file, content.data() + written, chunk, &count, nullptr)) {
            return fail("cannot write temporary config", GetLastError());
        }
        if (count == 0) {
            return fail("cannot write temporary config", ERROR_WRITE_FAULT);
        }
        written += count;
    }
    if (!FlushFileBuffers(file)) {
        return fail("cannot flush temporary config", GetLastError());
    }
    if (!CloseHandle(file)) {
        const DWORD close_error = GetLastError();
        file = INVALID_HANDLE_VALUE;
        (void)DeleteFileW(temporary.c_str());
        set_error(error, temporary, "cannot close temporary config",
                  windows_error(close_error));
        return false;
    }
    file = INVALID_HANDLE_VALUE;
    if (!MoveFileExW(temporary.c_str(), path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const DWORD rename_error = GetLastError();
        (void)DeleteFileW(temporary.c_str());
        set_error(error, path, "cannot replace config",
                  windows_error(rename_error));
        return false;
    }
    return true;
#else
    int file_fd = -1;
    std::filesystem::path temporary;
    const auto process_id = static_cast<std::uint64_t>(::getpid());
    for (unsigned attempt = 0; attempt < kCreateAttempts; ++attempt) {
        temporary = temp_candidate(path, process_id);
        int flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC;
#ifdef O_NOFOLLOW
        flags |= O_NOFOLLOW;
#endif
        file_fd = ::open(temporary.c_str(), flags, S_IRUSR | S_IWUSR);
        if (file_fd >= 0) break;
        const int create_error = errno;
        if (create_error != EEXIST) {
            set_error(error, temporary, "cannot create temporary config",
                      errno_message(create_error));
            return false;
        }
    }
    if (file_fd < 0) {
        set_error(error, path, "cannot atomically write",
                  "temporary-name attempts exhausted");
        return false;
    }

    ScopedFd file(file_fd);
    auto fail = [&](const char* operation, int failure_errno) {
        (void)::unlink(temporary.c_str());
        set_error(error, temporary, operation, errno_message(failure_errno));
        return false;
    };

    std::size_t written = 0;
    while (written < content.size()) {
        const std::size_t chunk = std::min<std::size_t>(
            content.size() - written,
            static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()));
        const ssize_t count = ::write(file.get(), content.data() + written, chunk);
        if (count < 0) {
            if (errno == EINTR) continue;
            return fail("cannot write temporary config", errno);
        }
        if (count == 0) {
            return fail("cannot write temporary config", EIO);
        }
        written += static_cast<std::size_t>(count);
    }
    if (::fsync(file.get()) != 0) {
        return fail("cannot flush temporary config", errno);
    }
    const int released_fd = file.release();
    if (::close(released_fd) != 0) {
        return fail("cannot close temporary config", errno);
    }
    if (::rename(temporary.c_str(), path.c_str()) != 0) {
        return fail("cannot replace config", errno);
    }

    int directory_flags = O_RDONLY | O_CLOEXEC;
#ifdef O_DIRECTORY
    directory_flags |= O_DIRECTORY;
#endif
    ScopedFd directory(::open(parent_or_dot(path).c_str(), directory_flags));
    if (directory.get() < 0) {
        set_error(error, parent_or_dot(path), "cannot open config directory",
                  errno_message(errno));
        return false;
    }
    if (::fsync(directory.get()) != 0) {
        set_error(error, parent_or_dot(path), "cannot flush config directory",
                  errno_message(errno));
        return false;
    }
    return true;
#endif
}

bool DurableRemoveFile(const std::filesystem::path& path, std::string* error) {
    if (error) error->clear();
    if (path.empty() || path.filename().empty()) {
        set_error(error, path, "cannot durably remove", "invalid path");
        return false;
    }

#ifdef _WIN32
    if (!DeleteFileW(path.c_str())) {
        const DWORD remove_error = GetLastError();
        if (remove_error == ERROR_FILE_NOT_FOUND ||
            remove_error == ERROR_PATH_NOT_FOUND) {
            return true;
        }
        set_error(error, path, "cannot remove file",
                  windows_error(remove_error));
        return false;
    }
    return true;
#else
    if (::unlink(path.c_str()) != 0) {
        const int remove_error = errno;
        if (remove_error == ENOENT) return true;
        set_error(error, path, "cannot remove file",
                  errno_message(remove_error));
        return false;
    }

    int directory_flags = O_RDONLY | O_CLOEXEC;
#ifdef O_DIRECTORY
    directory_flags |= O_DIRECTORY;
#endif
    const auto parent = parent_or_dot(path);
    ScopedFd directory(::open(parent.c_str(), directory_flags));
    if (directory.get() < 0) {
        set_error(error, parent, "cannot open file directory",
                  errno_message(errno));
        return false;
    }
    if (::fsync(directory.get()) != 0) {
        set_error(error, parent, "cannot flush file directory",
                  errno_message(errno));
        return false;
    }
    return true;
#endif
}

}  // namespace yume::runtime
