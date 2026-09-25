/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace yume::runtime {

// Opens the final path component without following a symlink/reparse point,
// verifies that the opened object is a regular file, bounds the allocation,
// and reads from that same handle. POSIX opens are nonblocking so a FIFO cannot
// wait for a writer before the type check. A detected size change fails; this
// does not provide an immutable snapshot of concurrently modified contents.
bool read_file_bounded(const std::filesystem::path& path,
                       std::size_t maximum_bytes,
                       std::vector<std::uint8_t>* contents,
                       std::string* error = nullptr);

bool read_text_file_bounded(const std::filesystem::path& path,
                            std::size_t maximum_bytes,
                            std::string* contents,
                            std::string* error = nullptr);

// Presence-aware variant for stores that may be created by the current
// transaction. The opened object still goes through read_text_file_bounded;
// the preliminary status check is used only to distinguish an allowed absent
// path. A replaced final component is validated by the opened handle. Ancestor
// directories remain the caller's responsibility; use FileRoot for confinement.
bool read_optional_text_file_bounded(const std::filesystem::path& path,
                                     std::size_t maximum_bytes,
                                     bool allow_missing,
                                     std::string* contents,
                                     bool* existed,
                                     std::string* error = nullptr);

// A pinned POSIX directory. Resolves each child relative to an owned directory
// descriptor and refuses symlinks in both the root and child paths. Renaming a
// pathname after opening it cannot redirect a read to another directory tree.
// Unsupported platforms refuse open() rather than using pathname checks.
class FileRoot final {
public:
    static std::optional<FileRoot> open(const std::filesystem::path& root,
                                        std::string* error = nullptr);
    ~FileRoot();
    FileRoot(FileRoot&& other) noexcept;
    FileRoot& operator=(FileRoot&& other) noexcept;
    FileRoot(const FileRoot&) = delete;
    FileRoot& operator=(const FileRoot&) = delete;

    bool read_text(const std::filesystem::path& relative_path,
                   std::size_t maximum_bytes,
                   std::string* contents,
                   std::string* error = nullptr,
                   std::time_t* modification_time = nullptr) const;

private:
    explicit FileRoot(int descriptor) noexcept : descriptor_(descriptor) {}
    int descriptor_{-1};
};

}  // namespace yume::runtime
