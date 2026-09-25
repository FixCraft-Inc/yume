/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "modules/relay/base64.hpp"

#include <array>
#include <cstdint>

namespace yume::relay {
namespace {

constexpr std::string_view kAlphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// 0..63 for alphabet characters, 64 for anything else.
constexpr std::array<std::uint8_t, 256> MakeDecodeTable() {
    std::array<std::uint8_t, 256> table{};
    for (auto& value : table) value = 64;
    for (std::size_t index = 0; index < kAlphabet.size(); ++index) {
        table[static_cast<unsigned char>(kAlphabet[index])] =
            static_cast<std::uint8_t>(index);
    }
    return table;
}

constexpr auto kDecode = MakeDecodeTable();

}  // namespace

std::string base64_encode(std::string_view raw) {
    std::string out;
    out.reserve(((raw.size() + 2U) / 3U) * 4U);
    std::size_t index = 0;
    for (; index + 3U <= raw.size(); index += 3U) {
        const std::uint32_t group =
            (static_cast<std::uint32_t>(static_cast<unsigned char>(raw[index])) << 16U) |
            (static_cast<std::uint32_t>(static_cast<unsigned char>(raw[index + 1U])) << 8U) |
            static_cast<std::uint32_t>(static_cast<unsigned char>(raw[index + 2U]));
        out.push_back(kAlphabet[(group >> 18U) & 63U]);
        out.push_back(kAlphabet[(group >> 12U) & 63U]);
        out.push_back(kAlphabet[(group >> 6U) & 63U]);
        out.push_back(kAlphabet[group & 63U]);
    }
    const std::size_t rest = raw.size() - index;
    if (rest == 1U) {
        const std::uint32_t group =
            static_cast<std::uint32_t>(static_cast<unsigned char>(raw[index])) << 16U;
        out.push_back(kAlphabet[(group >> 18U) & 63U]);
        out.push_back(kAlphabet[(group >> 12U) & 63U]);
        out += "==";
    } else if (rest == 2U) {
        const std::uint32_t group =
            (static_cast<std::uint32_t>(static_cast<unsigned char>(raw[index])) << 16U) |
            (static_cast<std::uint32_t>(static_cast<unsigned char>(raw[index + 1U])) << 8U);
        out.push_back(kAlphabet[(group >> 18U) & 63U]);
        out.push_back(kAlphabet[(group >> 12U) & 63U]);
        out.push_back(kAlphabet[(group >> 6U) & 63U]);
        out.push_back('=');
    }
    return out;
}

std::optional<std::string> base64_decode(std::string_view text) {
    if (text.size() % 4U != 0U) return std::nullopt;
    std::string out;
    out.reserve((text.size() / 4U) * 3U);
    for (std::size_t index = 0; index < text.size(); index += 4U) {
        const bool last = index + 4U == text.size();
        const std::uint8_t a = kDecode[static_cast<unsigned char>(text[index])];
        const std::uint8_t b = kDecode[static_cast<unsigned char>(text[index + 1U])];
        if (a == 64 || b == 64) return std::nullopt;
        const char third = text[index + 2U];
        const char fourth = text[index + 3U];
        if (last && third == '=' && fourth == '=') {
            // One byte: the low four bits of b must be zero.
            if ((b & 15U) != 0U) return std::nullopt;
            out.push_back(static_cast<char>((a << 2U) | (b >> 4U)));
            break;
        }
        const std::uint8_t c = kDecode[static_cast<unsigned char>(third)];
        if (c == 64) return std::nullopt;
        if (last && fourth == '=') {
            // Two bytes: the low two bits of c must be zero.
            if ((c & 3U) != 0U) return std::nullopt;
            out.push_back(static_cast<char>((a << 2U) | (b >> 4U)));
            out.push_back(static_cast<char>(((b & 15U) << 4U) | (c >> 2U)));
            break;
        }
        const std::uint8_t d = kDecode[static_cast<unsigned char>(fourth)];
        if (d == 64) return std::nullopt;
        out.push_back(static_cast<char>((a << 2U) | (b >> 4U)));
        out.push_back(static_cast<char>(((b & 15U) << 4U) | (c >> 2U)));
        out.push_back(static_cast<char>(((c & 3U) << 6U) | d));
    }
    return out;
}

}  // namespace yume::relay
