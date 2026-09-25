/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace yume::common {

enum class IpPacketVersion : std::uint8_t { Ipv4, Ipv6 };

struct IpPacketInfo final {
    IpPacketVersion version{IpPacketVersion::Ipv4};
    // IPv4 uses the first four bytes; remaining bytes are zero.
    std::array<std::byte, 16U> source{};
    std::array<std::byte, 16U> destination{};
    std::size_t packet_size{0U};
    std::size_t header_size{0U};
};

// Structural inspection only: no checksum, transport or extension-header
// validation. Trailing storage is permitted and reported by packet_size;
// datagram callers must separately require exact size. IPv6 jumbograms are
// outside the 65535-byte packet transport bound and are not recognized.
inline std::optional<IpPacketInfo> inspect_ip_packet(
    std::span<const std::byte> packet) noexcept {
    if (packet.empty()) return std::nullopt;
    const auto byte = [&](std::size_t offset) {
        return std::to_integer<std::uint8_t>(packet[offset]);
    };
    const auto length = [&](std::size_t offset) {
        return (static_cast<std::size_t>(byte(offset)) << 8U) |
               static_cast<std::size_t>(byte(offset + 1U));
    };
    IpPacketInfo info;
    if ((byte(0U) >> 4U) == 4U) {
        if (packet.size() < 20U) return std::nullopt;
        info.header_size = static_cast<std::size_t>(byte(0U) & 0x0fU) * 4U;
        info.packet_size = length(2U);
        if (info.header_size < 20U || info.packet_size < info.header_size ||
            info.packet_size > packet.size()) return std::nullopt;
        std::copy_n(packet.begin() + 12U, 4U, info.source.begin());
        std::copy_n(packet.begin() + 16U, 4U, info.destination.begin());
    } else if ((byte(0U) >> 4U) == 6U) {
        if (packet.size() < 40U) return std::nullopt;
        info.version = IpPacketVersion::Ipv6;
        info.header_size = 40U;
        info.packet_size = 40U + length(4U);
        if (info.packet_size > packet.size()) return std::nullopt;
        std::copy_n(packet.begin() + 8U, 16U, info.source.begin());
        std::copy_n(packet.begin() + 24U, 16U, info.destination.begin());
    } else {
        return std::nullopt;
    }
    return info;
}

// Inspect a complete datagram before applying policy to its base IP addresses.
// Reject IPv4 source-route options and IPv6 Routing/Home Address/SHIM6 forms
// that can change the addresses used after forwarding or local processing.
// IPv6 options, fragment and AH headers are walked with bounded lengths. ESP,
// Mobility, HIP, SHIM6 and experimental extension formats fail closed because
// this inspector cannot establish that property for them. Ordinary fragments
// with an upper-layer next header remain usable.
//
// This does not check checksums, upper-layer payloads, IPsec authentication or
// fragment reassembly, and does not establish policy for nested/decapsulated IP.
// header_size retains inspect_ip_packet's base-header meaning. That structural
// helper intentionally remains available to callers with a different contract.
inline std::optional<IpPacketInfo> inspect_ip_packet_for_address_policy(
    std::span<const std::byte> packet) noexcept {
    const auto info = inspect_ip_packet(packet);
    if (!info || info->packet_size != packet.size()) return std::nullopt;
    const auto byte = [&](std::size_t offset) { return std::to_integer<std::uint8_t>(packet[offset]); };
    if (info->version == IpPacketVersion::Ipv4) {
        for (std::size_t offset = 20U; offset < info->header_size;) {
            const auto type = byte(offset);
            if (type == 0U) {
                // End-of-options padding consists of zero bytes.
                for (; offset < info->header_size; ++offset) if (byte(offset) != 0U) return std::nullopt;
                break;
            }
            if (type == 1U) { ++offset; continue; } // NOP has no length byte.
            if (type == 131U || type == 137U) return std::nullopt; // LSRR, SSRR.
            if (info->header_size - offset < 2U) return std::nullopt;
            const auto length = static_cast<std::size_t>(byte(offset + 1U));
            if (length < 2U || length > info->header_size - offset) return std::nullopt;
            offset += length;
        }
        return info;
    }

    const auto known_extension = [](std::uint8_t next) {
        switch (next) {
        case 0U: case 43U: case 44U: case 50U: case 51U: case 60U:
        case 135U: case 139U: case 140U: case 253U: case 254U: return true;
        default: return false;
        }
    };
    std::size_t offset = 40U;
    auto next = byte(6U);
    bool fragment_seen = false;
    bool authentication_seen = false;
    unsigned destination_headers = 0U;
    constexpr unsigned kMaxExtensionHeaders = 8U;
    for (unsigned headers = 0U; headers < kMaxExtensionHeaders; ++headers) {
        if (!known_extension(next)) return info;
        if (next == 43U || next == 50U || next == 135U || next == 139U || next == 140U ||
            next == 253U || next == 254U) return std::nullopt;
        if (packet.size() - offset < 8U) return std::nullopt;
        const auto following = byte(offset);
        std::size_t length = 8U;
        if (next == 44U) {
            if (fragment_seen || byte(offset + 1U) != 0U) return std::nullopt;
            fragment_seen = true;
            const auto fragment = (static_cast<unsigned>(byte(offset + 2U)) << 8U) | byte(offset + 3U);
            if ((fragment & 6U) != 0U) return std::nullopt;
            const auto payload_size = packet.size() - offset - length;
            if ((fragment & 1U) != 0U && (payload_size == 0U || payload_size % 8U != 0U)) return std::nullopt;
            // Later fragments cannot expose an extension header in their
            // payload. Refuse such chains in every fragment rather than
            // authorizing addresses a hidden header could replace.
            if (fragment != 0U && known_extension(following)) return std::nullopt;
            if ((fragment & 0xfff8U) != 0U) return payload_size != 0U ? info : std::nullopt;
        } else if (next == 51U) {
            if (authentication_seen || byte(offset + 2U) != 0U || byte(offset + 3U) != 0U) return std::nullopt;
            authentication_seen = true;
            length = (static_cast<std::size_t>(byte(offset + 1U)) + 2U) * 4U;
            if (length < 12U || length % 8U != 0U || length > packet.size() - offset) return std::nullopt;
        } else {
            if (next == 0U && offset != 40U) return std::nullopt; // Hop-by-Hop is first.
            if (next == 60U && ++destination_headers > 2U) return std::nullopt;
            length = (static_cast<std::size_t>(byte(offset + 1U)) + 1U) * 8U;
            if (length > packet.size() - offset) return std::nullopt;
            for (std::size_t option = offset + 2U; option < offset + length;) {
                const auto type = byte(option);
                if (type == 0U) { ++option; continue; } // Pad1.
                if (type == 201U || type == 194U) return std::nullopt; // Home Address, Jumbo Payload.
                if (offset + length - option < 2U) return std::nullopt;
                const auto data_size = static_cast<std::size_t>(byte(option + 1U));
                if (data_size > offset + length - option - 2U) return std::nullopt;
                if (type == 1U) {
                    for (std::size_t i = 0U; i < data_size; ++i) if (byte(option + 2U + i) != 0U) return std::nullopt;
                }
                option += 2U + data_size;
            }
        }
        offset += length;
        next = following;
    }
    return known_extension(next) ? std::nullopt : info;
}

}  // namespace yume::common
