/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>

namespace yume::server::cover_response {

// Cover material is operator-controlled, but it is read by the long-running
// daemon and periodically refreshed. Keep one response, the directory walk,
// and the retained rotation set independently bounded.
inline constexpr std::size_t kMaxResponseBytes = 8U * 1024U * 1024U;
inline constexpr std::size_t kMaxResponseFiles = 256U;
inline constexpr std::size_t kMaxDirectoryEntries = 4096U;
inline constexpr std::size_t kMaxCacheBytes = 64U * 1024U * 1024U;

// Validate one complete HTTP/1.0 or HTTP/1.1 final response. Normalize LF only
// in its headers; preserve body bytes and chunk framing. Reject conflicting,
// truncated, or trailing framing and bound the normalized result.
bool normalize_http1_response(std::string_view raw,
                              std::size_t maximum_bytes,
                              std::string* normalized,
                              std::string* error = nullptr);

// Open one regular, non-symlink capture through the shared bounded reader and
// normalize it under kMaxResponseBytes.
bool load_file(const std::filesystem::path& path,
               std::string* normalized,
               std::string* error = nullptr);

}  // namespace yume::server::cover_response
