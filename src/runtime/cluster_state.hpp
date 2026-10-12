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
#include <string>

#include "engine/status.hpp"

namespace yume::runtime::cluster {

// The newest cluster list a node has loaded, kept across restarts so that a
// list with a lower serial is refused even after the daemon starts again.
struct SavedState final {
    std::string cluster;
    std::uint64_t serial{0U};
};

inline constexpr std::size_t kMaxStateBytes = 4096U;

// Reads the state file, or nothing when no file exists at path. The file is
// the JSON object {"schema":1,"cluster":ID,"serial":N}, with ID the cluster's
// 64-character fingerprint and N at least 1, in a regular file owned by the
// daemon's user and closed to group and others. InvalidArgument for any
// other file or content.
engine::Result<std::optional<SavedState>> read_state(
    const std::filesystem::path& path) noexcept;

// Replaces the file atomically: writes path.new owner-only and flushes it,
// renames it over path, then flushes the directory, which must exist. A
// failure before the rename leaves any earlier file in place. If the rename
// succeeds but the directory flush fails, the newer file remains and the
// status reports that durability was not confirmed.
engine::Status write_state(const std::filesystem::path& path,
                           const SavedState& state) noexcept;

// Checks the directory operation that write_state needs after validation:
// create and remove a private replacement beside the state file, then flush
// the directory. This lets a service manager reject a read-only state path
// before starting a daemon that would fail on its first accepted list.
engine::Status check_state_directory_writable(
    const std::filesystem::path& path) noexcept;

}  // namespace yume::runtime::cluster
