/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <vector>

namespace yume::setup {

// A fail-closed provisioning error. Its text is for the operator and names
// paths and settings, never secret material.
class SetupError final : public std::runtime_error {
public:
    explicit SetupError(const std::string& message)
        : std::runtime_error(message) {}
};

// Bytes that are wiped when they are released. Moving transfers the
// obligation. Wiping is best effort, not locked memory.
class SecretBytes final {
public:
    SecretBytes() noexcept = default;
    explicit SecretBytes(std::size_t size) : bytes_(size) {}
    explicit SecretBytes(std::vector<std::uint8_t>&& bytes) noexcept
        : bytes_(std::move(bytes)) {}
    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
    SecretBytes(SecretBytes&& other) noexcept
        : bytes_(std::move(other.bytes_)) {}
    SecretBytes& operator=(SecretBytes&& other) noexcept;
    ~SecretBytes();

    std::uint8_t* data() noexcept { return bytes_.data(); }
    std::size_t size() const noexcept { return bytes_.size(); }
    std::span<const std::uint8_t> bytes() const noexcept { return bytes_; }
    std::string_view text() const noexcept {
        return {reinterpret_cast<const char*>(bytes_.data()), bytes_.size()};
    }

private:
    std::vector<std::uint8_t> bytes_;
};

inline std::span<const std::uint8_t> as_bytes(std::string_view text) noexcept {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

// The owner a file in an existing tree keeps, so that a root operator does
// not lock the daemon's account out of its own files.
struct Owner final {
    uid_t uid{0};
    gid_t gid{0};
};
Owner owner_of(const std::filesystem::path& path);
// Gives path to owner without following a final symlink. Only root may do
// that, so callers ask only when running as root.
void give_to(const std::filesystem::path& path, const Owner& owner);
bool running_as_root() noexcept;

// A new owner-only directory. Fails when anything exists at path.
void make_private_directory(const std::filesystem::path& path);
// A new file with the given mode, written in full and flushed. It never
// follows or replaces an existing path, and a failed write removes it.
void write_new_file(const std::filesystem::path& path,
                    std::span<const std::uint8_t> contents, mode_t mode = 0600);
// A regular, non-symlink file of at most maximum bytes, read through the
// handle whose type was checked. The caller wipes secrets.
std::vector<std::uint8_t> read_bounded(const std::filesystem::path& path,
                                       std::size_t maximum);
SecretBytes read_secret(const std::filesystem::path& path, std::size_t maximum);
// Copies a bounded file into a new file, wiping the bytes in between.
void copy_private_file(const std::filesystem::path& source,
                       const std::filesystem::path& destination,
                       mode_t mode = 0600);

// Whether path names a regular file or a directory, following a final
// symlink, as Python's is_file and is_dir did. A missing path is neither.
bool file_at(const std::filesystem::path& path) noexcept;
bool directory_at(const std::filesystem::path& path) noexcept;
// Whether anything, a dangling symlink included, exists at path.
bool exists_no_follow(const std::filesystem::path& path) noexcept;

void fsync_directory(const std::filesystem::path& path);
// Flushes every file and directory below root, refusing anything that is not
// a regular file or a directory.
void fsync_tree(const std::filesystem::path& root);
// Renames from to to only if nothing exists at to.
void rename_no_replace(const std::filesystem::path& from,
                       const std::filesystem::path& to);
// Replaces to with from atomically.
void rename_replace(const std::filesystem::path& from,
                    const std::filesystem::path& to);
// Removes a file, ignoring one that is already gone.
void remove_file(const std::filesystem::path& path) noexcept;
// Removes a tree without following symlinks and without C++ allocation,
// so cleanup still runs when memory is exhausted. Errors are ignored.
void remove_tree(const std::filesystem::path& path) noexcept;

// Lowercase hex of size random bytes from OpenSSL.
std::string random_hex(std::size_t size);
// Where a replacement of path is staged before it is renamed over path:
// ".name.<16 hex>.new" beside it.
std::filesystem::path replacement_path(const std::filesystem::path& path);

// The prefix of a staging directory. A failed command removes its staging
// directory, and only a directory with this prefix is ever removed that way.
inline constexpr std::string_view kStagingPrefix = ".yume-setup-staging-";

// An owner-only staging directory in parent, removed on destruction unless
// it was published by renaming it away. While it exists it is also the
// directory remove_staging_on_terminate removes.
class Staging final {
public:
    explicit Staging(const std::filesystem::path& parent);
    Staging(const Staging&) = delete;
    Staging& operator=(const Staging&) = delete;
    ~Staging();

    const std::filesystem::path& path() const noexcept { return path_; }
    // Renames the staging directory, or one directory in it, to target
    // without replacing anything. A published staging directory is not
    // removed.
    void publish(const std::filesystem::path& source,
                 const std::filesystem::path& target);

private:
    std::filesystem::path path_;
    bool published_{false};
};

// Installs a terminate handler that removes the current staging directory,
// without allocating, before the process aborts. A library destructor that
// fails to allocate ends the process through std::terminate, and a kit's
// fresh keys must not stay on disk then either.
void remove_staging_on_terminate() noexcept;

// A new directory a command may create, named by an operator: absolute, its
// parent an existing real directory and nothing at the path itself.
std::filesystem::path require_output_path(const std::filesystem::path& raw);

// An existing directory, resolved through symlinks, or nothing.
std::optional<std::filesystem::path> resolve_existing(
    const std::filesystem::path& path);

}  // namespace yume::setup
