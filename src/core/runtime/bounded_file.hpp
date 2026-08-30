/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace yume::runtime {

// Opens the final path component without following a symlink/reparse point,
// verifies that the opened object is a regular file, bounds the allocation,
// and reads from that same handle. A file that changes size while it is read
// fails instead of returning a truncated or attacker-extended value.
bool read_file_bounded(const std::filesystem::path& path,
                       std::size_t maximum_bytes,
                       std::vector<std::uint8_t>* contents,
                       std::string* error = nullptr);

bool read_text_file_bounded(const std::filesystem::path& path,
                            std::size_t maximum_bytes,
                            std::string* contents,
                            std::string* error = nullptr);

}  // namespace yume::runtime
