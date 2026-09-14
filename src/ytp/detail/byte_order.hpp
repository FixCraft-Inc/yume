/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace yume::ytp1::detail {

// Internal codec operations. Callers validate offset <= size and
// width <= size - offset (2 or 4 bytes) before access. Keep those checks in
// the codecs: they own protocol bounds and first-error codes/offsets.
[[nodiscard]] constexpr std::uint16_t read_u16_be(
    std::span<const std::uint8_t> input,
    std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(input[offset]) << 8U) |
        static_cast<std::uint16_t>(input[offset + 1]));
}

[[nodiscard]] constexpr std::uint32_t read_u32_be(
    std::span<const std::uint8_t> input,
    std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(input[offset]) << 24U) |
           (static_cast<std::uint32_t>(input[offset + 1]) << 16U) |
           (static_cast<std::uint32_t>(input[offset + 2]) << 8U) |
           static_cast<std::uint32_t>(input[offset + 3]);
}

constexpr void write_u16_be(
    std::span<std::uint8_t> output,
    std::size_t offset,
    std::uint16_t value) noexcept {
    output[offset] = static_cast<std::uint8_t>(value >> 8U);
    output[offset + 1] = static_cast<std::uint8_t>(value);
}

constexpr void write_u32_be(
    std::span<std::uint8_t> output,
    std::size_t offset,
    std::uint32_t value) noexcept {
    output[offset] = static_cast<std::uint8_t>(value >> 24U);
    output[offset + 1] = static_cast<std::uint8_t>(value >> 16U);
    output[offset + 2] = static_cast<std::uint8_t>(value >> 8U);
    output[offset + 3] = static_cast<std::uint8_t>(value);
}

}  // namespace yume::ytp1::detail
