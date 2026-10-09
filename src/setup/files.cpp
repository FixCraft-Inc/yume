/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "setup/files.hpp"

#include <array>
#include <atomic>
#include <cstdlib>
#include <exception>
#include <memory>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <system_error>
#include <utility>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/rand.h>

#include "common/hex.hpp"
#include "common/secure_erase.hpp"

namespace yume::setup {
namespace {

namespace fs = std::filesystem;

std::string describe(int error) {
    return std::generic_category().message(error);
}

[[noreturn]] void fail_with(const std::string& action, const fs::path& path,
                            int error) {
    throw SetupError(action + " " + path.string() + ": " + describe(error));
}

// Closes a descriptor on every path. close() errors after a successful
// fsync cannot lose written data, so the destructor ignores them.
class Descriptor final {
public:
    explicit Descriptor(int fd) noexcept : fd_(fd) {}
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    ~Descriptor() {
        if (fd_ >= 0) static_cast<void>(::close(fd_));
    }
    int get() const noexcept { return fd_; }
    // Closes now and reports the result.
    int close() noexcept {
        const int fd = std::exchange(fd_, -1);
        return fd >= 0 ? ::close(fd) : 0;
    }

private:
    int fd_;
};

bool write_all(int fd, std::span<const std::uint8_t> contents) noexcept {
    std::size_t written = 0;
    while (written < contents.size()) {
        const auto count =
            ::write(fd, contents.data() + written, contents.size() - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        written += static_cast<std::size_t>(count);
    }
    return true;
}

}  // namespace

SecretBytes& SecretBytes::operator=(SecretBytes&& other) noexcept {
    if (this != &other) {
        security::secure_erase(bytes_);
        bytes_ = std::move(other.bytes_);
    }
    return *this;
}

SecretBytes::~SecretBytes() {
    security::secure_erase(bytes_);
}

Owner owner_of(const fs::path& path) {
    struct stat status{};
    if (::stat(path.c_str(), &status) != 0)
        fail_with("cannot inspect", path, errno);
    return {status.st_uid, status.st_gid};
}

void give_to(const fs::path& path, const Owner& owner) {
    if (::lchown(path.c_str(), owner.uid, owner.gid) != 0) {
        fail_with("cannot change the owner of", path, errno);
    }
}

bool running_as_root() noexcept {
    return ::geteuid() == 0;
}

void make_private_directory(const fs::path& path) {
    if (::mkdir(path.c_str(), 0700) != 0)
        fail_with("cannot create directory", path, errno);
    if (::chmod(path.c_str(), 0700) != 0)
        fail_with("cannot protect directory", path, errno);
}

void write_new_file(const fs::path& path,
                    std::span<const std::uint8_t> contents, mode_t mode) {
    Descriptor fd(::open(path.c_str(),
                         O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                         mode));
    if (fd.get() < 0) fail_with("cannot create", path, errno);
    int error = 0;
    errno = 0;
    if (::fchmod(fd.get(), mode) != 0 || !write_all(fd.get(), contents) ||
        ::fsync(fd.get()) != 0 || fd.close() != 0) {
        error = errno != 0 ? errno : EIO;
    }
    if (error == 0) return;
    static_cast<void>(fd.close());
    static_cast<void>(::unlink(path.c_str()));
    fail_with("cannot write", path, error);
}

std::vector<std::uint8_t> read_bounded(const fs::path& path,
                                       std::size_t maximum) {
    Descriptor fd(
        ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (fd.get() < 0) throw SetupError("cannot open " + path.string());
    struct stat status{};
    if (::fstat(fd.get(), &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_size < 0 ||
        static_cast<std::uint64_t>(status.st_size) > maximum) {
        throw SetupError(path.string() + " is not a bounded regular file");
    }
    // One allocation with a byte to spare, so the read that finds the end of
    // the file never grows the buffer: growth would free a copy of a secret
    // before anything wiped it.
    const auto size = static_cast<std::size_t>(status.st_size);
    std::vector<std::uint8_t> contents(size + 1U);
    try {
        std::size_t used = 0;
        while (used < contents.size()) {
            const auto count = ::read(fd.get(), contents.data() + used,
                                      contents.size() - used);
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) throw SetupError("cannot read " + path.string());
            if (count == 0) break;
            used += static_cast<std::size_t>(count);
        }
        if (used != size)
            throw SetupError(path.string() + " changed while it was read");
        contents.resize(used);
    } catch (...) {
        security::secure_erase(contents);
        throw;
    }
    return contents;
}

SecretBytes read_secret(const fs::path& path, std::size_t maximum) {
    return SecretBytes(read_bounded(path, maximum));
}

void copy_private_file(const fs::path& source, const fs::path& destination,
                       mode_t mode) {
    // Every file a kit copies is small: keys, certificates and signed lists.
    constexpr std::size_t kMaxCopyBytes = std::size_t{4} * 1024U * 1024U;
    const auto contents = read_secret(source, kMaxCopyBytes);
    write_new_file(destination, contents.bytes(), mode);
}

bool file_at(const fs::path& path) noexcept {
    struct stat status{};
    return ::stat(path.c_str(), &status) == 0 && S_ISREG(status.st_mode);
}

bool directory_at(const fs::path& path) noexcept {
    struct stat status{};
    return ::stat(path.c_str(), &status) == 0 && S_ISDIR(status.st_mode);
}

bool exists_no_follow(const fs::path& path) noexcept {
    struct stat status{};
    return ::lstat(path.c_str(), &status) == 0;
}

void fsync_directory(const fs::path& path) {
    Descriptor fd(::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (fd.get() < 0) fail_with("cannot open directory", path, errno);
    if (::fsync(fd.get()) != 0)
        fail_with("cannot flush directory", path, errno);
}

namespace {

// Flushes every regular file and directory below the directory open at fd,
// refusing anything else. A kit is a few levels deep.
void sync_contents(int fd, const fs::path& path, int depth) {
    constexpr int kMaxDepth = 16;
    if (depth > kMaxDepth) throw SetupError("generated kit is too deep");
    const int listing = ::dup(fd);
    if (listing < 0) fail_with("cannot walk", path, errno);
    DIR* directory = ::fdopendir(listing);
    if (directory == nullptr) {
        const int error = errno;
        static_cast<void>(::close(listing));
        fail_with("cannot walk", path, error);
    }
    struct CloseDirectory final {
        void operator()(DIR* open) const noexcept {
            static_cast<void>(::closedir(open));
        }
    };
    const std::unique_ptr<DIR, CloseDirectory> owned(directory);
    while (const dirent* entry = ::readdir(directory)) {
        const char* name = entry->d_name;
        if (std::strcmp(name, ".") == 0 || std::strcmp(name, "..") == 0)
            continue;
        Descriptor child(
            ::openat(fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
        struct stat status{};
        if (child.get() < 0 || ::fstat(child.get(), &status) != 0) {
            fail_with("cannot open", path / name, errno);
        }
        if (S_ISDIR(status.st_mode)) {
            sync_contents(child.get(), path / name, depth + 1);
        } else if (!S_ISREG(status.st_mode)) {
            throw SetupError("generated kit contains a non-regular file");
        }
        if (::fsync(child.get()) != 0)
            fail_with("cannot flush", path / name, errno);
    }
}

}  // namespace

void fsync_tree(const fs::path& root) {
    Descriptor fd(
        ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (fd.get() < 0) fail_with("cannot open directory", root, errno);
    sync_contents(fd.get(), root, 0);
    if (::fsync(fd.get()) != 0)
        fail_with("cannot flush directory", root, errno);
}

void rename_no_replace(const fs::path& from, const fs::path& to) {
    if (::renameat2(AT_FDCWD, from.c_str(), AT_FDCWD, to.c_str(),
                    RENAME_NOREPLACE) == 0) {
        return;
    }
    const int error = errno;
    if (error == EEXIST || error == ENOTEMPTY) {
        throw SetupError("refusing to overwrite existing path: " + to.string());
    }
    if (error == ENOSYS || error == EINVAL) {
        throw SetupError(
            "atomic no-overwrite directory publication is unavailable on this "
            "filesystem");
    }
    throw SetupError("unable to publish generated kit: " + describe(error));
}

void rename_replace(const fs::path& from, const fs::path& to) {
    if (::rename(from.c_str(), to.c_str()) != 0)
        fail_with("cannot replace", to, errno);
}

void remove_file(const fs::path& path) noexcept {
    static_cast<void>(::unlink(path.c_str()));
}

namespace {

// Empties the directory open at fd, never following a symlink. It needs no
// C++ allocation, so a cleanup path still runs when memory is exhausted.
void remove_contents(int fd, int depth) noexcept {
    // Kits are a few levels deep. A deeper tree is not one setup made.
    constexpr int kMaxDepth = 16;
    if (depth > kMaxDepth) return;
    DIR* directory = ::fdopendir(fd);
    if (directory == nullptr) {
        static_cast<void>(::close(fd));
        return;
    }
    while (const dirent* entry = ::readdir(directory)) {
        const char* name = entry->d_name;
        if (std::strcmp(name, ".") == 0 || std::strcmp(name, "..") == 0)
            continue;
        if (::unlinkat(fd, name, 0) == 0) continue;
        const int child =
            ::openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (child < 0) continue;
        remove_contents(child, depth + 1);
        static_cast<void>(::unlinkat(fd, name, AT_REMOVEDIR));
    }
    static_cast<void>(::closedir(directory));
}

void remove_tree_at(const char* path) noexcept {
    const int fd =
        ::open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        static_cast<void>(::unlink(path));
        return;
    }
    remove_contents(fd, 0);
    static_cast<void>(::rmdir(path));
}

}  // namespace

void remove_tree(const fs::path& path) noexcept {
    remove_tree_at(path.c_str());
}

std::string random_hex(std::size_t size) {
    std::array<std::uint8_t, 32> bytes{};
    if (size > bytes.size() ||
        RAND_bytes(bytes.data(), static_cast<int>(size)) != 1) {
        throw SetupError("OpenSSL random generation failed");
    }
    return encoding::hex_lower(
        std::span<const std::uint8_t>(bytes.data(), size));
}

fs::path replacement_path(const fs::path& path) {
    return path.parent_path() /
           ("." + path.filename().string() + "." + random_hex(8) + ".new");
}

namespace {

// The path of the staging directory that exists now, for the terminate
// handler. One command makes at most one at a time.
std::atomic<const char*> current_staging{nullptr};

[[noreturn]] void terminate_after_cleanup() noexcept {
    if (const char* staging = current_staging.exchange(nullptr)) {
        remove_tree_at(staging);
    }
    // A fixed text through write(2), since nothing here may allocate.
    constexpr std::string_view kMessage =
        "yume-setup: stopped by an internal failure\n";
    // A short or failed write changes nothing: the process aborts next.
    if (::write(STDERR_FILENO, kMessage.data(), kMessage.size()) < 0) {
        std::abort();
    }
    std::abort();
}

}  // namespace

void remove_staging_on_terminate() noexcept {
    std::set_terminate(terminate_after_cleanup);
}

Staging::Staging(const fs::path& parent) {
    std::string pattern =
        (parent / (std::string(kStagingPrefix) + "XXXXXX")).string();
    if (::mkdtemp(pattern.data()) == nullptr) {
        fail_with("cannot create a staging directory in", parent, errno);
    }
    try {
        path_ = pattern;
    } catch (...) {
        // The directory exists now, and no destructor will run for it.
        static_cast<void>(::rmdir(pattern.c_str()));
        throw;
    }
    current_staging.store(path_.c_str());
    if (::chmod(path_.c_str(), 0700) != 0) {
        const int error = errno;
        current_staging.store(nullptr);
        remove_tree(path_);
        fail_with("cannot protect directory", path_, error);
    }
}

Staging::~Staging() {
    current_staging.store(nullptr);
    if (published_) return;
    // Only an owner-only directory this object made, never a symlink.
    const std::string_view text(path_.c_str());
    const auto name = text.substr(text.rfind('/') + 1U);
    struct stat status{};
    if (::lstat(path_.c_str(), &status) == 0 && S_ISDIR(status.st_mode) &&
        name.starts_with(kStagingPrefix)) {
        remove_tree(path_);
    }
}

void Staging::publish(const fs::path& source, const fs::path& target) {
    rename_no_replace(source, target);
    if (source == path_) published_ = true;
}

fs::path require_output_path(const fs::path& raw) {
    std::string text = raw.string();
    for (const auto& part : raw) {
        if (part == "~") throw SetupError("output path is invalid");
    }
    if (text.empty()) throw SetupError("output path is invalid");
    while (text.size() > 1U && text.back() == '/') text.pop_back();
    std::error_code error;
    const fs::path absolute = fs::absolute(fs::path(text), error);
    if (error) throw SetupError("output path cannot be resolved");
    if (exists_no_follow(absolute)) {
        throw SetupError("refusing to overwrite existing path: " +
                         absolute.string());
    }
    const fs::path output = fs::weakly_canonical(absolute, error);
    if (error) throw SetupError("output path cannot be resolved");
    if (output == output.root_path() || output.filename().empty() ||
        output.filename() == "." || output.filename() == "..") {
        throw SetupError(
            "output must name a new directory below an existing parent");
    }
    const fs::path parent = fs::canonical(output.parent_path(), error);
    if (error)
        throw SetupError("output parent must already exist and be accessible");
    struct stat status{};
    if (::lstat(parent.c_str(), &status) != 0) {
        throw SetupError("output parent must already exist and be accessible");
    }
    if (!S_ISDIR(status.st_mode))
        throw SetupError("output parent must be a real directory");
    const fs::path result = parent / output.filename();
    if (exists_no_follow(result)) {
        throw SetupError("refusing to overwrite existing path: " +
                         result.string());
    }
    return result;
}

std::optional<fs::path> resolve_existing(const fs::path& path) {
    std::error_code error;
    auto resolved = fs::canonical(path, error);
    if (error) return std::nullopt;
    return resolved;
}

}  // namespace yume::setup
