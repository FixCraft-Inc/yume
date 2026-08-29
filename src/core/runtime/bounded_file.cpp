/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/runtime/bounded_file.hpp"

#include <algorithm>
#include <cerrno>
#include <limits>
#include <system_error>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace yume::runtime {
namespace {

void wipe_bytes(std::vector<std::uint8_t>* bytes) noexcept {
    if (!bytes) return;
    volatile std::uint8_t* cursor = bytes->data();
    for (std::size_t index = 0; index < bytes->size(); ++index) {
        cursor[index] = 0;
    }
    bytes->clear();
}

void wipe_text(std::string* text) noexcept {
    if (!text) return;
    volatile char* cursor = text->data();
    for (std::size_t index = 0; index < text->size(); ++index) {
        cursor[index] = 0;
    }
    text->clear();
}

class ByteVectorWiper {
public:
    explicit ByteVectorWiper(std::vector<std::uint8_t>& bytes) noexcept
        : bytes_(bytes) {}
    ~ByteVectorWiper() { wipe_bytes(&bytes_); }

    ByteVectorWiper(const ByteVectorWiper&) = delete;
    ByteVectorWiper& operator=(const ByteVectorWiper&) = delete;

private:
    std::vector<std::uint8_t>& bytes_;
};

void set_error(std::string* error,
               const std::filesystem::path& path,
               const char* action,
               const std::string& detail) {
    if (!error) return;
    *error = std::string(action) + " '" + path.string() + "': " + detail;
}

#if defined(_WIN32)

class FileHandle {
public:
    explicit FileHandle(HANDLE handle) noexcept : handle_(handle) {}
    ~FileHandle() {
        if (handle_ != INVALID_HANDLE_VALUE) (void)::CloseHandle(handle_);
    }

    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;

    HANDLE get() const noexcept { return handle_; }

private:
    HANDLE handle_{INVALID_HANDLE_VALUE};
};

std::string system_error_message(DWORD value) {
    return std::error_code(static_cast<int>(value), std::system_category())
        .message();
}

#else

class FileDescriptor {
public:
    explicit FileDescriptor(int descriptor) noexcept : descriptor_(descriptor) {}
    ~FileDescriptor() {
        if (descriptor_ >= 0) (void)::close(descriptor_);
    }

    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;

    int get() const noexcept { return descriptor_; }

private:
    int descriptor_{-1};
};

#endif

}  // namespace

bool read_file_bounded(const std::filesystem::path& path,
                       std::size_t maximum_bytes,
                       std::vector<std::uint8_t>* contents,
                       std::string* error) {
    if (error) error->clear();
    if (!contents) {
        if (error) *error = "bounded file destination is null";
        return false;
    }
    wipe_bytes(contents);
    if (path.empty() || path.filename().empty()) {
        if (error) *error = "bounded file path is invalid";
        return false;
    }

#if defined(_WIN32)
    const HANDLE raw_handle = ::CreateFileW(
        path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
            FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);
    if (raw_handle == INVALID_HANDLE_VALUE) {
        set_error(error, path, "cannot open file",
                  system_error_message(::GetLastError()));
        return false;
    }
    FileHandle handle(raw_handle);

    FILE_ATTRIBUTE_TAG_INFO tag_info{};
    if (::GetFileInformationByHandleEx(
            handle.get(), FileAttributeTagInfo, &tag_info,
            static_cast<DWORD>(sizeof(tag_info))) == 0) {
        set_error(error, path, "cannot inspect file",
                  system_error_message(::GetLastError()));
        return false;
    }
    if ((tag_info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (tag_info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
        (tag_info.FileAttributes & FILE_ATTRIBUTE_DEVICE) != 0 ||
        ::GetFileType(handle.get()) != FILE_TYPE_DISK) {
        set_error(error, path, "cannot read file",
                  "path must be a regular non-reparse file");
        return false;
    }

    LARGE_INTEGER file_size{};
    if (::GetFileSizeEx(handle.get(), &file_size) == 0) {
        set_error(error, path, "cannot determine file size",
                  system_error_message(::GetLastError()));
        return false;
    }
    if (file_size.QuadPart < 0 ||
        static_cast<unsigned long long>(file_size.QuadPart) > maximum_bytes) {
        set_error(error, path, "cannot read file", "file exceeds size limit");
        return false;
    }

    try {
        contents->resize(static_cast<std::size_t>(file_size.QuadPart));
    } catch (const std::exception& exception) {
        set_error(error, path, "cannot allocate file buffer", exception.what());
        return false;
    }
    std::size_t offset = 0;
    while (offset < contents->size()) {
        const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(
            contents->size() - offset,
            static_cast<std::size_t>(std::numeric_limits<DWORD>::max())));
        DWORD count = 0;
        if (::ReadFile(handle.get(), contents->data() + offset, chunk, &count,
                       nullptr) == 0) {
            set_error(error, path, "cannot read file",
                      system_error_message(::GetLastError()));
            wipe_bytes(contents);
            return false;
        }
        if (count == 0) {
            set_error(error, path, "cannot read file",
                      "file shrank while being read");
            wipe_bytes(contents);
            return false;
        }
        offset += static_cast<std::size_t>(count);
    }
    std::uint8_t extra = 0;
    DWORD extra_count = 0;
    if (::ReadFile(handle.get(), &extra, 1, &extra_count, nullptr) == 0) {
        set_error(error, path, "cannot verify file length",
                  system_error_message(::GetLastError()));
        wipe_bytes(contents);
        return false;
    }
    if (extra_count != 0) {
        set_error(error, path, "cannot read file",
                  "file grew while being read");
        wipe_bytes(contents);
        return false;
    }
#else
#if !defined(O_NOFOLLOW)
    set_error(error, path, "cannot open file",
              "platform does not provide no-follow file opens");
    return false;
#else
    int flags = O_RDONLY;
#if defined(O_CLOEXEC)
    flags |= O_CLOEXEC;
#endif
    flags |= O_NOFOLLOW;
    const int raw_descriptor = ::open(path.c_str(), flags);
    if (raw_descriptor < 0) {
        set_error(error, path, "cannot open file",
                  std::error_code(errno, std::generic_category()).message());
        return false;
    }
    FileDescriptor descriptor(raw_descriptor);
#if !defined(O_CLOEXEC)
    if (::fcntl(descriptor.get(), F_SETFD, FD_CLOEXEC) != 0) {
        set_error(error, path, "cannot mark file close-on-exec",
                  std::error_code(errno, std::generic_category()).message());
        return false;
    }
#endif

    struct stat status {};
    if (::fstat(descriptor.get(), &status) != 0) {
        set_error(error, path, "cannot inspect file",
                  std::error_code(errno, std::generic_category()).message());
        return false;
    }
    if (!S_ISREG(status.st_mode)) {
        set_error(error, path, "cannot read file", "path must be a regular file");
        return false;
    }
    if (status.st_size < 0 ||
        static_cast<std::uintmax_t>(status.st_size) > maximum_bytes) {
        set_error(error, path, "cannot read file", "file exceeds size limit");
        return false;
    }

    try {
        contents->resize(static_cast<std::size_t>(status.st_size));
    } catch (const std::exception& exception) {
        set_error(error, path, "cannot allocate file buffer", exception.what());
        return false;
    }
    std::size_t offset = 0;
    while (offset < contents->size()) {
        const ssize_t count = ::read(
            descriptor.get(), contents->data() + offset,
            contents->size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            set_error(error, path, "cannot read file",
                      std::error_code(errno, std::generic_category()).message());
            wipe_bytes(contents);
            return false;
        }
        if (count == 0) {
            set_error(error, path, "cannot read file",
                      "file shrank while being read");
            wipe_bytes(contents);
            return false;
        }
        offset += static_cast<std::size_t>(count);
    }
    std::uint8_t extra = 0;
    while (true) {
        const ssize_t count = ::read(descriptor.get(), &extra, 1);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            set_error(error, path, "cannot verify file length",
                      std::error_code(errno, std::generic_category()).message());
            wipe_bytes(contents);
            return false;
        }
        if (count != 0) {
            set_error(error, path, "cannot read file",
                      "file grew while being read");
            wipe_bytes(contents);
            return false;
        }
        break;
    }
#endif
#endif
    return true;
}

bool read_text_file_bounded(const std::filesystem::path& path,
                            std::size_t maximum_bytes,
                            std::string* contents,
                            std::string* error) {
    if (!contents) {
        if (error) *error = "bounded text destination is null";
        return false;
    }
    wipe_text(contents);
    std::vector<std::uint8_t> bytes;
    if (!read_file_bounded(path, maximum_bytes, &bytes, error)) {
        return false;
    }
    ByteVectorWiper bytes_wiper(bytes);
    if (bytes.empty()) {
        return true;
    }
    try {
        contents->assign(reinterpret_cast<const char*>(bytes.data()),
                         bytes.size());
    } catch (const std::exception& exception) {
        wipe_text(contents);
        set_error(error, path, "cannot allocate text file buffer",
                  exception.what());
        return false;
    }
    return true;
}

}  // namespace yume::runtime
