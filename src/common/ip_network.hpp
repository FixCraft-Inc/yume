/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace yume::common {

enum class IpFamily : std::uint8_t {
    V4,
    V6,
};

// One address prefix. IPv4 uses the first four address bytes. Every bit after
// the prefix is zero, so equal networks have equal values.
struct IpNetwork final {
    IpFamily family{IpFamily::V4};
    std::array<std::uint8_t, 16> address{};
    std::uint8_t prefix_length{0U};

    friend bool operator==(const IpNetwork&, const IpNetwork&) = default;
};

// "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
inline constexpr std::size_t kMaxIpNetworkTextBytes = 43U;

namespace detail {

inline constexpr std::size_t ip_address_bytes(IpFamily family) noexcept {
    return family == IpFamily::V4 ? 4U : 16U;
}

// Decimal without sign or leading zeros, at most three digits.
inline std::optional<unsigned> parse_ip_decimal(std::string_view text,
                                                unsigned maximum) noexcept {
    if (text.empty() || text.size() > 3U ||
        (text.size() > 1U && text.front() == '0')) {
        return std::nullopt;
    }
    unsigned value = 0U;
    for (const char ch : text) {
        if (ch < '0' || ch > '9') return std::nullopt;
        value = value * 10U + static_cast<unsigned>(ch - '0');
    }
    if (value > maximum) return std::nullopt;
    return value;
}

inline bool parse_ipv4(std::string_view text,
                       std::array<std::uint8_t, 16>& out) noexcept {
    for (std::size_t octet = 0U; octet < 4U; ++octet) {
        const std::size_t dot = text.find('.');
        const bool last = octet == 3U;
        if (last != (dot == std::string_view::npos)) return false;
        const auto value =
            parse_ip_decimal(last ? text : text.substr(0U, dot), 255U);
        if (!value) return false;
        out[octet] = static_cast<std::uint8_t>(*value);
        if (!last) text.remove_prefix(dot + 1U);
    }
    return true;
}

inline int ip_hex_digit(char ch) noexcept {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return -1;
}

// Lowercase hexadecimal groups with at most one "::". Dotted IPv4 suffixes
// and zone identifiers are refused. Canonical form is checked separately.
inline bool parse_ipv6(std::string_view text,
                       std::array<std::uint8_t, 16>& out) noexcept {
    std::array<std::uint16_t, 8> groups{};
    std::size_t count = 0U;
    std::optional<std::size_t> gap;
    std::size_t index = 0U;
    if (text.size() >= 2U && text[0] == ':' && text[1] == ':') {
        gap = 0U;
        index = 2U;
    } else if (!text.empty() && text[0] == ':') {
        return false;
    }
    while (index < text.size()) {
        const std::size_t start = index;
        unsigned value = 0U;
        while (index < text.size()) {
            const int digit = ip_hex_digit(text[index]);
            if (digit < 0) break;
            if (index - start == 4U) return false;
            value = value * 16U + static_cast<unsigned>(digit);
            ++index;
        }
        if (index == start || count == groups.size()) return false;
        groups[count++] = static_cast<std::uint16_t>(value);
        if (index == text.size()) break;
        if (text[index] != ':') return false;
        ++index;
        if (index < text.size() && text[index] == ':') {
            if (gap) return false;
            gap = count;
            ++index;
        } else if (index == text.size()) {
            return false;
        }
    }
    if (gap) {
        if (count > 7U) return false;
        const std::size_t tail = count - *gap;
        for (std::size_t offset = tail; offset > 0U; --offset) {
            groups[8U - tail + offset - 1U] = groups[*gap + offset - 1U];
        }
        for (std::size_t position = *gap; position < 8U - tail; ++position) {
            groups[position] = 0U;
        }
    } else if (count != 8U) {
        return false;
    }
    for (std::size_t group = 0U; group < groups.size(); ++group) {
        out[group * 2U] = static_cast<std::uint8_t>(groups[group] >> 8U);
        out[group * 2U + 1U] = static_cast<std::uint8_t>(groups[group] & 0xffU);
    }
    return true;
}

inline std::size_t append_ip_decimal(unsigned value, char* out) noexcept {
    std::array<char, 3> digits{};
    std::size_t count = 0U;
    do {
        digits[count++] = static_cast<char>('0' + value % 10U);
        value /= 10U;
    } while (value != 0U);
    for (std::size_t index = 0U; index < count; ++index) {
        out[index] = digits[count - index - 1U];
    }
    return count;
}

// RFC 5952: lowercase, no leading zeros, and the first longest run of at
// least two zero groups compressed to "::".
inline std::size_t format_ipv6(const std::array<std::uint8_t, 16>& address,
                               char* out) noexcept {
    std::array<unsigned, 8> groups{};
    for (std::size_t group = 0U; group < groups.size(); ++group) {
        groups[group] = (static_cast<unsigned>(address[group * 2U]) << 8U) |
                        address[group * 2U + 1U];
    }
    std::size_t best_start = groups.size();
    std::size_t best_length = 0U;
    for (std::size_t index = 0U; index < groups.size();) {
        if (groups[index] != 0U) {
            ++index;
            continue;
        }
        std::size_t end = index;
        while (end < groups.size() && groups[end] == 0U) ++end;
        if (end - index > best_length) {
            best_start = index;
            best_length = end - index;
        }
        index = end;
    }
    if (best_length < 2U) {
        best_start = groups.size();
        best_length = 0U;
    }
    static constexpr char kHex[] = "0123456789abcdef";
    std::size_t size = 0U;
    for (std::size_t index = 0U; index < groups.size();) {
        if (index == best_start) {
            out[size++] = ':';
            out[size++] = ':';
            index += best_length;
            continue;
        }
        if (index != 0U && index != best_start + best_length) out[size++] = ':';
        bool leading = true;
        for (int shift = 12; shift >= 0; shift -= 4) {
            const unsigned nibble = (groups[index] >> shift) & 0xfU;
            if (leading && nibble == 0U && shift != 0) continue;
            leading = false;
            out[size++] = kHex[nibble];
        }
        ++index;
    }
    return size;
}

inline bool ip_host_bits_zero(const IpNetwork& network) noexcept {
    const std::size_t bytes = ip_address_bytes(network.family);
    for (std::size_t bit = network.prefix_length; bit < bytes * 8U; ++bit) {
        if ((network.address[bit / 8U] >> (7U - bit % 8U)) & 1U) return false;
    }
    return true;
}

}  // namespace detail

// Writes the canonical text: dotted decimal for IPv4, RFC 5952 for IPv6.
inline std::size_t format_ip_network(
    const IpNetwork& network,
    std::array<char, kMaxIpNetworkTextBytes>& out) noexcept {
    std::size_t size = 0U;
    if (network.family == IpFamily::V4) {
        for (std::size_t octet = 0U; octet < 4U; ++octet) {
            if (octet != 0U) out[size++] = '.';
            size += detail::append_ip_decimal(network.address[octet],
                                              out.data() + size);
        }
    } else {
        size = detail::format_ipv6(network.address, out.data());
    }
    out[size++] = '/';
    size += detail::append_ip_decimal(network.prefix_length, out.data() + size);
    return size;
}

// Accepts only the canonical text of a network whose host bits are zero.
// Configuration authors and the independent doctor then compare prefixes as
// identical bytes, without equivalent spellings.
inline std::optional<IpNetwork> parse_canonical_ip_network(
    std::string_view text) noexcept {
    if (text.size() > kMaxIpNetworkTextBytes) return std::nullopt;
    const std::size_t slash = text.find('/');
    if (slash == std::string_view::npos) return std::nullopt;
    IpNetwork network;
    const std::string_view address = text.substr(0U, slash);
    unsigned maximum = 32U;
    if (address.find(':') != std::string_view::npos) {
        network.family = IpFamily::V6;
        maximum = 128U;
        if (!detail::parse_ipv6(address, network.address)) return std::nullopt;
    } else if (!detail::parse_ipv4(address, network.address)) {
        return std::nullopt;
    }
    const auto prefix =
        detail::parse_ip_decimal(text.substr(slash + 1U), maximum);
    if (!prefix) return std::nullopt;
    network.prefix_length = static_cast<std::uint8_t>(*prefix);
    if (!detail::ip_host_bits_zero(network)) return std::nullopt;
    std::array<char, kMaxIpNetworkTextBytes> canonical{};
    const std::size_t size = format_ip_network(network, canonical);
    if (std::string_view(canonical.data(), size) != text) return std::nullopt;
    return network;
}

inline bool ip_network_contains(const IpNetwork& network,
                                IpFamily family,
                                std::span<const std::uint8_t> address) noexcept {
    if (family != network.family ||
        address.size() != detail::ip_address_bytes(family)) {
        return false;
    }
    const std::size_t whole = network.prefix_length / 8U;
    for (std::size_t index = 0U; index < whole; ++index) {
        if (address[index] != network.address[index]) return false;
    }
    const unsigned remaining = network.prefix_length % 8U;
    if (remaining == 0U) return true;
    const auto mask = static_cast<std::uint8_t>(0xffU << (8U - remaining));
    return (address[whole] & mask) == network.address[whole];
}

}  // namespace yume::common
