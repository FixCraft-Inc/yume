/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

// Lowercase hexadecimal, the one text form YUME gives fingerprints, tokens
// and digests. Uppercase is refused, so each value has exactly one spelling.
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

inline std::string hex_lower(std::span<const std::byte> bytes) {
    return hex_lower(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()));
}

// Whether every character is a digit or a to f. Callers check the length.
constexpr bool is_lower_hex(std::string_view text) noexcept {
    return std::all_of(text.begin(), text.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

// Decodes text of exactly two characters per output byte. Any other length
// or character returns false before out is written.
inline bool decode_lower_hex(std::string_view text,
                             std::span<std::uint8_t> out) noexcept {
    if (text.size() != 2U * out.size() || !is_lower_hex(text)) return false;
    const auto value = [](char ch) noexcept {
        return static_cast<unsigned>(ch <= '9' ? ch - '0' : ch - 'a' + 10);
    };
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>((value(text[2U * i]) << 4U) |
                                           value(text[2U * i + 1U]));
    }
    return true;
}

inline bool decode_lower_hex(std::string_view text,
                             std::span<std::byte> out) noexcept {
    return decode_lower_hex(
        text, std::span<std::uint8_t>(
                  reinterpret_cast<std::uint8_t*>(out.data()), out.size()));
}

}  // namespace yume::encoding
