/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <string_view>

namespace yume::common {

inline constexpr std::size_t kMaxServiceNameBytes = 128U;

// Service names are already canonical bytes on the wire: lowercase ASCII
// namespace segments separated by '.', with '-' and '_' allowed only inside
// a segment. This avoids case folding and Unicode-normalization decisions in
// authorization maps implemented by different languages.
inline bool valid_service_name(std::string_view name) noexcept {
    if (name.empty() || name.size() > kMaxServiceNameBytes) {
        return false;
    }

    bool at_segment_start = true;
    bool previous_is_alphanumeric = false;
    for (const unsigned char byte : name) {
        const bool alphanumeric =
            (byte >= 'a' && byte <= 'z') ||
            (byte >= '0' && byte <= '9');
        if (alphanumeric) {
            at_segment_start = false;
            previous_is_alphanumeric = true;
            continue;
        }
        if (byte == '.') {
            if (at_segment_start || !previous_is_alphanumeric) {
                return false;
            }
            at_segment_start = true;
            previous_is_alphanumeric = false;
            continue;
        }
        if (byte == '-' || byte == '_') {
            if (at_segment_start) {
                return false;
            }
            previous_is_alphanumeric = false;
            continue;
        }
        return false;
    }
    return !at_segment_start && previous_is_alphanumeric;
}

}  // namespace yume::common
