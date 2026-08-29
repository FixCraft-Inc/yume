/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>

namespace yume::encoding {

inline std::string hex_lower(std::span<const std::uint8_t> bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    if (bytes.size() > std::numeric_limits<std::size_t>::max() / 2U) {
        throw std::length_error("hex input is too large");
    }
    std::string encoded(bytes.size() * 2U, '0');
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        encoded[2U * i] = kDigits[(bytes[i] >> 4U) & 0x0fU];
        encoded[2U * i + 1U] = kDigits[bytes[i] & 0x0fU];
    }
    return encoded;
}

}  // namespace yume::encoding
