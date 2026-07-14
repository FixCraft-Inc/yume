/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <charconv>
#include <cstdint>
#include <limits>
#include <string_view>

namespace yume::server_cli {

inline bool parse_int_strict(std::string_view raw, int* out) {
    if (!out || raw.empty()) {
        return false;
    }
    int value = 0;
    const auto [ptr, ec] =
        std::from_chars(raw.data(), raw.data() + raw.size(), value);
    if (ec != std::errc() || ptr != raw.data() + raw.size()) {
        return false;
    }
    *out = value;
    return true;
}

inline bool parse_u32_strict(std::string_view raw, std::uint32_t* out) {
    if (!out || raw.empty()) {
        return false;
    }
    unsigned long long value = 0;
    const auto [ptr, ec] =
        std::from_chars(raw.data(), raw.data() + raw.size(), value);
    if (ec != std::errc() || ptr != raw.data() + raw.size() ||
        value > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }
    *out = static_cast<std::uint32_t>(value);
    return true;
}

}  // namespace yume::server_cli
