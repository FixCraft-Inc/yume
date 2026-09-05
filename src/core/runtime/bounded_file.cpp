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
#include <utility>

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
    int release() noexcept { return std::exchange(descriptor_, -1); }
    void reset(int descriptor) noexcept {
        if (descriptor_ >= 0) (void)::close(descriptor_);
        descriptor_ = descriptor;
    }

private:
    int descriptor_{-1};
};

bool read_descriptor_bounded(int descriptor,
                             const std::filesystem::path& path,
                             std::size_t maximum_bytes,
                             std::vector<std::uint8_t>* contents,
                             std::string* error) {
#if !defined(O_CLOEXEC)
    if (::fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0) {
        set_error(error, path, "cannot mark file close-on-exec",
                  std::error_code(errno, std::generic_category()).message());
        return false;
    }
#endif

    struct stat status {};
    if (::fstat(descriptor, &status) != 0) {
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
            descriptor, contents->data() + offset,
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
        const ssize_t count = ::read(descriptor, &extra, 1);
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
    return true;
}

#endif

bool assign_text(const std::filesystem::path& path,
                 std::vector<std::uint8_t>& bytes,
                 std::string* contents,
                 std::string* error) {
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
    if (path.empty() || path.filename().empty() ||
        path.native().find(std::filesystem::path::value_type{}) !=
            std::filesystem::path::string_type::npos) {
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
    // O_NONBLOCK lets fstat reject a FIFO before open waits for its writer.
    int flags = O_RDONLY | O_NONBLOCK;
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
    return read_descriptor_bounded(
        descriptor.get(), path, maximum_bytes, contents, error);
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
    return assign_text(path, bytes, contents, error);
}

bool read_optional_text_file_bounded(const std::filesystem::path& path,
                                     std::size_t maximum_bytes,
                                     bool allow_missing,
                                     std::string* contents,
                                     bool* existed,
                                     std::string* error) {
    if (error) error->clear();
    if (!contents) {
        if (error) *error = "bounded text destination is null";
        return false;
    }
    wipe_text(contents);
    if (existed) *existed = false;
    if (path.empty() || path.native().find(std::filesystem::path::value_type{}) !=
                            std::filesystem::path::string_type::npos) {
        if (error) *error = "bounded file path is invalid";
        return false;
    }

    std::error_code status_error;
    const auto status = std::filesystem::symlink_status(path, status_error);
    const bool missing =
        status.type() == std::filesystem::file_type::not_found ||
        status_error == std::errc::no_such_file_or_directory;
    if (missing) {
        if (allow_missing) return true;
        if (error) *error = "file does not exist: " + path.string();
        return false;
    }
    if (status_error) {
        if (error) {
            *error = "cannot inspect '" + path.string() + "': " +
                     status_error.message();
        }
        return false;
    }
    if (!read_text_file_bounded(path, maximum_bytes, contents, error)) {
        return false;
    }
    if (existed) *existed = true;
    return true;
}


FileRoot::~FileRoot() {
#if !defined(_WIN32)
    if (descriptor_ >= 0) (void)::close(descriptor_);
#endif
}

FileRoot::FileRoot(FileRoot&& other) noexcept
    : descriptor_(std::exchange(other.descriptor_, -1)) {}

FileRoot& FileRoot::operator=(FileRoot&& other) noexcept {
    if (this == &other) return *this;
#if !defined(_WIN32)
    if (descriptor_ >= 0) (void)::close(descriptor_);
#endif
    descriptor_ = std::exchange(other.descriptor_, -1);
    return *this;
}

std::optional<FileRoot> FileRoot::open(const std::filesystem::path& root,
                                      std::string* error) {
    if (error) error->clear();
#if defined(_WIN32) || !defined(O_NOFOLLOW) || !defined(O_DIRECTORY) || !defined(O_CLOEXEC)
    set_error(error, root, "cannot open confined root",
              "platform lacks descriptor-confined directory access");
    return std::nullopt;
#else
    constexpr std::size_t kMaxPathBytes = 4096;
    if (root.empty() || root.native().size() > kMaxPathBytes ||
        root.native().find('\0') != std::string::npos) {
        set_error(error, root, "cannot open confined root", "invalid path");
        return std::nullopt;
    }
    std::error_code path_error;
    const auto absolute = std::filesystem::absolute(root, path_error);
    if (path_error) {
        set_error(error, root, "cannot resolve root", path_error.message());
        return std::nullopt;
    }
    if (absolute.native().size() > kMaxPathBytes) {
        set_error(error, root, "cannot resolve root", "path exceeds size limit");
        return std::nullopt;
    }
    constexpr int kDirectoryFlags =
        O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY;
    FileDescriptor directory(::open("/", kDirectoryFlags));
    if (directory.get() < 0) {
        set_error(error, root, "cannot open root directory",
                  std::error_code(errno, std::generic_category()).message());
        return std::nullopt;
    }
    // Do not canonicalize paths: that would resolve symlinks before the
    // descriptor walk could reject them and introduce a validation/open race.
    for (const auto& component : absolute.relative_path()) {
        if (component.empty() || component == ".") continue;
        if (component == "..") {
            set_error(error, root, "cannot open confined root",
                      "parent components are not allowed");
            return std::nullopt;
        }
        const int next = ::openat(directory.get(), component.c_str(), kDirectoryFlags);
        if (next < 0) {
            set_error(error, root, "cannot open root component",
                      std::error_code(errno, std::generic_category()).message());
            return std::nullopt;
        }
        directory.reset(next);
    }
    return FileRoot(directory.release());
#endif
}

bool FileRoot::read_text(const std::filesystem::path& relative_path,
                         std::size_t maximum_bytes,
                         std::string* contents,
                         std::string* error,
                         std::time_t* modification_time) const {
    if (error) error->clear();
    if (!contents) {
        if (error) *error = "bounded text destination is null";
        return false;
    }
    wipe_text(contents);
#if defined(_WIN32) || !defined(O_NOFOLLOW) || !defined(O_DIRECTORY) || !defined(O_CLOEXEC)
    (void)maximum_bytes;
    (void)modification_time;
    set_error(error, relative_path, "cannot read confined file",
              "platform lacks descriptor-confined directory access");
    return false;
#else
    constexpr std::size_t kMaxPathBytes = 4096;
    if (descriptor_ < 0 || relative_path.empty() || relative_path.is_absolute() ||
        relative_path.filename().empty() || relative_path.native().size() > kMaxPathBytes ||
        relative_path.native().find('\0') != std::string::npos) {
        set_error(error, relative_path, "cannot read confined file", "invalid relative path");
        return false;
    }
    for (const auto& component : relative_path) {
        if (component.empty() || component == "." || component == "..") {
            set_error(error, relative_path, "cannot read confined file",
                      "empty, current and parent components are not allowed");
            return false;
        }
    }
    FileDescriptor directory(-1);
    int parent = descriptor_;
    const auto parent_path = relative_path.parent_path();
    constexpr int kReadFlags = O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW;
    for (const auto& component : parent_path) {
        const int next = ::openat(parent, component.c_str(), kReadFlags | O_DIRECTORY);
        if (next < 0) {
            set_error(error, relative_path, "cannot open child directory",
                      std::error_code(errno, std::generic_category()).message());
            return false;
        }
        directory.reset(next);
        parent = directory.get();
    }
    FileDescriptor file(::openat(parent, relative_path.filename().c_str(), kReadFlags));
    if (file.get() < 0) {
        set_error(error, relative_path, "cannot open confined file",
                  std::error_code(errno, std::generic_category()).message());
        return false;
    }
    std::vector<std::uint8_t> bytes;
    if (!read_descriptor_bounded(file.get(), relative_path, maximum_bytes, &bytes, error)) {
        return false;
    }
    if (modification_time) {
        struct stat status {};
        if (::fstat(file.get(), &status) != 0) {
            set_error(error, relative_path, "cannot inspect confined file",
                      std::error_code(errno, std::generic_category()).message());
            return false;
        }
        // HTTP validators need whole Unix seconds. Keeping that representation
        // avoids clock-offset rounding and nanosecond overflow on distant dates.
        *modification_time = status.st_mtime;
    }
    return assign_text(relative_path, bytes, contents, error);
#endif
}

}  // namespace yume::runtime
