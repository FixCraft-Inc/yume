/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/security/secret_file.hpp"

#include <algorithm>
#include <cerrno>
#include <stdexcept>
#include <string>
#include <system_error>

#include "core/security/secure_erase.hpp"

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace yume::security {
namespace {

std::uint8_t DecodeNibble(std::uint8_t ch) {
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

}  // namespace yume::security
