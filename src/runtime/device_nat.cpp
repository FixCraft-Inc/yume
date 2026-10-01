/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/device_nat.hpp"

#include <cstring>
#include <utility>

namespace yume::runtime {
namespace {

constexpr std::uint8_t kTcp = 6U;
constexpr std::uint8_t kUdp = 17U;
constexpr std::uint8_t kFin = 0x01U;
constexpr std::uint8_t kSyn = 0x02U;
constexpr std::uint8_t kRst = 0x04U;
constexpr std::uint8_t kAck = 0x10U;
constexpr std::size_t kIpv4Header = 20U;
constexpr std::size_t kIpv6Header = 40U;
constexpr std::size_t kTcpHeader = 20U;
constexpr std::size_t kUdpHeader = 8U;
constexpr std::uint16_t kFirstPort = 1024U;
constexpr std::uint8_t kHopLimit = 64U;

std::uint16_t get16(const std::uint8_t* at) noexcept {
    return static_cast<std::uint16_t>((std::uint16_t{at[0]} << 8U) | at[1]);
}

std::uint32_t get32(const std::uint8_t* at) noexcept {
    return (std::uint32_t{at[0]} << 24U) | (std::uint32_t{at[1]} << 16U) |
           (std::uint32_t{at[2]} << 8U) | at[3];
}

void put16(std::uint8_t* at, std::uint16_t value) noexcept {
    at[0] = static_cast<std::uint8_t>(value >> 8U);
    at[1] = static_cast<std::uint8_t>(value);
}

void put32(std::uint8_t* at, std::uint32_t value) noexcept {
    at[0] = static_cast<std::uint8_t>(value >> 24U);
    at[1] = static_cast<std::uint8_t>(value >> 16U);
    at[2] = static_cast<std::uint8_t>(value >> 8U);
    at[3] = static_cast<std::uint8_t>(value);
}

std::uint16_t fold(std::uint64_t sum) noexcept {
    while ((sum >> 16U) != 0U) sum = (sum & 0xffffU) + (sum >> 16U);
    return static_cast<std::uint16_t>(sum);
}

// The one's complement sum of bytes as 16-bit words, unfolded.
std::uint64_t sum_words(std::span<const std::uint8_t> bytes) noexcept {
    std::uint64_t sum = 0U;
    std::size_t index = 0U;
    for (; index + 1U < bytes.size(); index += 2U) {
        sum += get16(bytes.data() + index);
    }
    if (index < bytes.size()) sum += std::uint64_t{bytes[index]} << 8U;
    return sum;
}

// What replacing `before` with `after` adds to a checksum's sum (RFC 1624).
// Both hold whole 16-bit words at an even offset of the covered data.
std::uint64_t replacement(std::span<const std::uint8_t> before,
                          std::span<const std::uint8_t> after) noexcept {
    std::uint64_t delta = 0U;
    for (std::size_t index = 0U; index + 1U < before.size(); index += 2U) {
        delta += static_cast<std::uint16_t>(~get16(before.data() + index));
        delta += get16(after.data() + index);
    }
    return delta;
}

// HC' = ~(~HC + ~m + m'), with delta holding the last two terms.
void adjust(std::uint8_t* checksum, std::uint64_t delta) noexcept {
    const std::uint64_t sum =
        static_cast<std::uint16_t>(~get16(checksum)) + delta;
    put16(checksum, static_cast<std::uint16_t>(~fold(sum)));
}

std::uint16_t finish(std::uint64_t sum) noexcept {
    return static_cast<std::uint16_t>(~fold(sum));
}

std::size_t address_bytes(bool ipv6) noexcept {
    return ipv6 ? 16U : 4U;
}
std::size_t source_offset(bool ipv6) noexcept {
    return ipv6 ? 8U : 12U;
}
std::size_t destination_offset(bool ipv6) noexcept {
    return ipv6 ? 24U : 16U;
}

bool same(const std::uint8_t* left, const DeviceAddress& right,
          bool ipv6) noexcept {
    return std::memcmp(left, right.data(), address_bytes(ipv6)) == 0;
}

// The sum of the pseudo header a transport checksum covers.
std::uint64_t pseudo_sum(bool ipv6, const std::uint8_t* source,
                         const std::uint8_t* destination, std::uint8_t protocol,
                         std::size_t length) noexcept {
    const std::size_t bytes = address_bytes(ipv6);
    return sum_words({source, bytes}) + sum_words({destination, bytes}) +
           protocol + length;
}

// Writes an IP header for a packet the bridge originates. body is what
// follows it.
void write_ip_header(bool ipv6, std::uint8_t* packet, std::uint8_t protocol,
                     std::size_t body, const DeviceAddress& source,
                     const DeviceAddress& destination,
                     std::uint16_t identification) noexcept {
    if (ipv6) {
        packet[0] = 0x60U;
        packet[1] = packet[2] = packet[3] = 0U;
        put16(packet + 4U, static_cast<std::uint16_t>(body));
        packet[6] = protocol;
        packet[7] = kHopLimit;
        std::memcpy(packet + 8U, source.data(), 16U);
        std::memcpy(packet + 24U, destination.data(), 16U);
        return;
    }
    packet[0] = 0x45U;
    packet[1] = 0U;
    put16(packet + 2U, static_cast<std::uint16_t>(kIpv4Header + body));
    put16(packet + 4U, identification);
    put16(packet + 6U, 0x4000U);  // do not fragment
    packet[8] = kHopLimit;
    packet[9] = protocol;
    put16(packet + 10U, 0U);
    std::memcpy(packet + 12U, source.data(), 4U);
    std::memcpy(packet + 16U, destination.data(), 4U);
    put16(packet + 10U, finish(sum_words({packet, kIpv4Header})));
}

}  // namespace

std::size_t device_nat_detail::KeyHash::operator()(
    const Key& key) const noexcept {
    std::uint64_t hash = UINT64_C(0xcbf29ce484222325);
    const auto mix = [&hash](std::uint8_t byte) noexcept {
        hash = (hash ^ byte) * UINT64_C(0x100000001b3);
    };
    for (const std::uint8_t byte : key.destination) mix(byte);
    mix(static_cast<std::uint8_t>(key.source_port >> 8U));
    mix(static_cast<std::uint8_t>(key.source_port));
    mix(static_cast<std::uint8_t>(key.destination_port >> 8U));
    mix(static_cast<std::uint8_t>(key.destination_port));
    return static_cast<std::size_t>(hash);
}

DeviceNat::DeviceNat(std::optional<DeviceAddressPair> ipv4,
                     std::optional<DeviceAddressPair> ipv6,
                     DeviceNatLimits limits)
    : limits_(limits) {
    if (ipv4) {
        ipv4_.emplace();
        ipv4_->addresses = *ipv4;
    }
    if (ipv6) {
        ipv6_.emplace();
        ipv6_->ipv6 = true;
        ipv6_->addresses = *ipv6;
    }
}

void DeviceNat::set_listener_ports(std::uint16_t ipv4,
                                   std::uint16_t ipv6) noexcept {
    if (ipv4_) ipv4_->listener_port = ipv4;
    if (ipv6_) ipv6_->listener_port = ipv6;
}

DeviceNat::Family* DeviceNat::family(bool ipv6) noexcept {
    auto& chosen = ipv6 ? ipv6_ : ipv4_;
    return chosen ? &*chosen : nullptr;
}

// Not const: the const accessor would be code only this observer reaches.
std::size_t DeviceNat::connections(bool ipv6) noexcept {
    const Family* chosen = family(ipv6);
    return chosen ? chosen->entries.size() : 0U;
}

DevicePacket DeviceNat::translate(std::span<std::uint8_t> packet,
                                  Clock::time_point now,
                                  std::span<std::uint8_t>& written,
                                  DeviceDatagram& datagram) {
    if (packet.empty()) return DevicePacket::Drop;
    const std::uint8_t version = packet[0] >> 4U;
    const bool ipv6 = version == 6U;
    Family* chosen = family(ipv6);
    if ((version != 4U && version != 6U) || chosen == nullptr) {
        return DevicePacket::Drop;
    }
    std::size_t header = 0U;
    std::size_t total = 0U;
    std::uint8_t protocol = 0U;
    if (ipv6) {
        if (packet.size() < kIpv6Header) return DevicePacket::Drop;
        header = kIpv6Header;
        total = kIpv6Header + get16(packet.data() + 4U);
        // Only a transport header directly after the fixed header. Extension
        // headers, fragments among them, are not carried.
        protocol = packet[6];
    } else {
        if (packet.size() < kIpv4Header) return DevicePacket::Drop;
        header = static_cast<std::size_t>(packet[0] & 0x0fU) * 4U;
        total = get16(packet.data() + 2U);
        // More-fragments or a fragment offset.
        if ((get16(packet.data() + 6U) & 0x3fffU) != 0U) {
            return DevicePacket::Drop;
        }
        protocol = packet[9];
    }
    if (header < (ipv6 ? kIpv6Header : kIpv4Header) || total < header ||
        total > packet.size()) {
        return DevicePacket::Drop;
    }
    const auto body = packet.first(total);
    if (!same(body.data() + source_offset(ipv6), chosen->addresses.device,
              ipv6)) {
        return DevicePacket::Drop;
    }
    if (protocol == kTcp) {
        return translate_tcp(*chosen, body, header, now, written);
    }
    if (protocol != kUdp || total - header < kUdpHeader) {
        return DevicePacket::Drop;
    }
    const std::uint8_t* udp = body.data() + header;
    const std::size_t length = get16(udp + 4U);
    const std::uint8_t* destination = body.data() + destination_offset(ipv6);
    // A YTP packet record cannot be empty, and the bridge's own addresses
    // are not destinations.
    if (length <= kUdpHeader || length > total - header ||
        same(destination, chosen->addresses.peer, ipv6) ||
        same(destination, chosen->addresses.device, ipv6)) {
        return DevicePacket::Drop;
    }
    datagram = DeviceDatagram{};
    datagram.ipv6 = ipv6;
    datagram.source_port = get16(udp);
    datagram.destination_port = get16(udp + 2U);
    std::memcpy(datagram.destination.data(), destination, address_bytes(ipv6));
    datagram.payload =
        std::span<const std::uint8_t>(udp + kUdpHeader, length - kUdpHeader);
    if (datagram.source_port == 0U || datagram.destination_port == 0U) {
        return DevicePacket::Drop;
    }
    return DevicePacket::Datagram;
}

DevicePacket DeviceNat::translate_tcp(Family& chosen,
                                      std::span<std::uint8_t> packet,
                                      std::size_t header, Clock::time_point now,
                                      std::span<std::uint8_t>& written) {
    const bool ipv6 = chosen.ipv6;
    const std::size_t bytes = address_bytes(ipv6);
    if (packet.size() - header < kTcpHeader || chosen.listener_port == 0U) {
        return DevicePacket::Drop;
    }
    std::uint8_t* const source = packet.data() + source_offset(ipv6);
    std::uint8_t* const destination = packet.data() + destination_offset(ipv6);
    std::uint8_t* const tcp = packet.data() + header;
    const std::uint16_t source_port = get16(tcp);
    const std::uint16_t destination_port = get16(tcp + 2U);
    const std::uint8_t flags = tcp[13];

    DeviceAddress new_source{};
    DeviceAddress new_destination = chosen.addresses.device;
    std::uint16_t new_source_port = 0U;
    std::uint16_t new_destination_port = 0U;
    if (same(destination, chosen.addresses.peer, ipv6)) {
        // The listener's answer to a translated connection.
        if (source_port != chosen.listener_port) return DevicePacket::Drop;
        const auto entry = chosen.entries.find(destination_port);
        if (entry == chosen.entries.end()) return DevicePacket::Drop;
        new_source = entry->second.key.destination;
        new_source_port = entry->second.key.destination_port;
        new_destination_port = entry->second.key.source_port;
    } else {
        if (same(destination, chosen.addresses.device, ipv6) ||
            source_port == 0U || destination_port == 0U) {
            return DevicePacket::Drop;
        }
        Key key;
        key.source_port = source_port;
        key.destination_port = destination_port;
        std::memcpy(key.destination.data(), destination, bytes);
        const bool opening = (flags & (kSyn | kAck | kRst)) == kSyn;
        std::uint16_t port = 0U;
        if (const auto known = chosen.ports.find(key);
            known != chosen.ports.end()) {
            port = known->second;
            Entry& entry = chosen.entries.at(port);
            if (opening && entry.phase == Phase::Lingering) {
                entry.phase = Phase::Pending;
                entry.expires = now + limits_.pending;
            }
        } else if (opening) {
            const auto allocated = allocate(chosen, key, now);
            if (!allocated) return DevicePacket::Drop;
            port = *allocated;
        } else {
            // Nothing here knows this connection. Answer as the destination
            // would for a segment out of nowhere (RFC 9293, 3.10.7.1), so the
            // application's socket ends now instead of timing out.
            if ((flags & kRst) != 0U) return DevicePacket::Drop;
            const std::size_t offset =
                static_cast<std::size_t>(tcp[12] >> 4U) * 4U;
            if (offset < kTcpHeader || offset > packet.size() - header) {
                return DevicePacket::Drop;
            }
            std::uint32_t length =
                static_cast<std::uint32_t>(packet.size() - header - offset);
            if ((flags & kSyn) != 0U) ++length;
            if ((flags & kFin) != 0U) ++length;
            const bool acked = (flags & kAck) != 0U;
            const std::uint32_t sequence = acked ? get32(tcp + 8U) : 0U;
            const std::uint32_t acknowledgement =
                acked ? 0U : get32(tcp + 4U) + length;
            const DeviceAddress from = key.destination;
            const std::size_t ip_header = ipv6 ? kIpv6Header : kIpv4Header;
            write_ip_header(ipv6, packet.data(), kTcp, kTcpHeader, from,
                            chosen.addresses.device, next_identification_++);
            std::uint8_t* const reset = packet.data() + ip_header;
            put16(reset, destination_port);
            put16(reset + 2U, source_port);
            put32(reset + 4U, sequence);
            put32(reset + 8U, acknowledgement);
            reset[12] = 0x50U;
            reset[13] = acked ? kRst : static_cast<std::uint8_t>(kRst | kAck);
            put16(reset + 14U, 0U);
            put16(reset + 16U, 0U);
            put16(reset + 18U, 0U);
            put16(reset + 16U, finish(pseudo_sum(ipv6, from.data(),
                                                 chosen.addresses.device.data(),
                                                 kTcp, kTcpHeader) +
                                      sum_words({reset, kTcpHeader})));
            written = packet.first(ip_header + kTcpHeader);
            return DevicePacket::Write;
        }
        new_source = chosen.addresses.peer;
        new_source_port = port;
        new_destination_port = chosen.listener_port;
    }

    std::uint8_t ports[4];
    put16(ports, new_source_port);
    put16(ports + 2U, new_destination_port);
    const std::uint64_t addresses =
        replacement({source, bytes}, {new_source.data(), bytes}) +
        replacement({destination, bytes}, {new_destination.data(), bytes});
    const std::uint64_t all = addresses + replacement({tcp, 4U}, {ports, 4U});
    if (!ipv6) adjust(packet.data() + 10U, addresses);
    adjust(tcp + 16U, all);
    std::memcpy(source, new_source.data(), bytes);
    std::memcpy(destination, new_destination.data(), bytes);
    std::memcpy(tcp, ports, 4U);
    written = packet;
    return DevicePacket::Write;
}

std::optional<std::uint16_t> DeviceNat::allocate(Family& chosen, const Key& key,
                                                 Clock::time_point now) {
    if (chosen.entries.size() >= limits_.max_connections) return std::nullopt;
    for (std::size_t tries = 0U; tries <= 0xffffU - kFirstPort; ++tries) {
        const std::uint16_t port = chosen.next_port;
        chosen.next_port = port == 0xffffU
                               ? kFirstPort
                               : static_cast<std::uint16_t>(port + 1U);
        if (chosen.entries.contains(port)) continue;
        chosen.entries.emplace(
            port, Entry{key, Phase::Pending, now + limits_.pending});
        try {
            chosen.ports.emplace(key, port);
        } catch (...) {
            chosen.entries.erase(port);
            throw;
        }
        return port;
    }
    return std::nullopt;
}

std::optional<DeviceTcpOrigin> DeviceNat::accept(bool ipv6,
                                                 std::uint16_t peer_port) {
    Family* chosen = family(ipv6);
    if (chosen == nullptr) return std::nullopt;
    const auto entry = chosen->entries.find(peer_port);
    if (entry == chosen->entries.end()) return std::nullopt;
    entry->second.phase = Phase::Accepted;
    DeviceTcpOrigin origin;
    origin.ipv6 = ipv6;
    origin.destination = entry->second.key.destination;
    origin.destination_port = entry->second.key.destination_port;
    origin.source_port = entry->second.key.source_port;
    return origin;
}

void DeviceNat::release(bool ipv6, std::uint16_t peer_port,
                        Clock::time_point now) noexcept {
    Family* chosen = family(ipv6);
    if (chosen == nullptr) return;
    const auto entry = chosen->entries.find(peer_port);
    if (entry == chosen->entries.end()) return;
    entry->second.phase = Phase::Lingering;
    entry->second.expires = now + limits_.linger;
}

void DeviceNat::sweep(Clock::time_point now) noexcept {
    for (auto* chosen : {family(false), family(true)}) {
        if (chosen == nullptr) continue;
        for (auto entry = chosen->entries.begin();
             entry != chosen->entries.end();) {
            if (entry->second.phase != Phase::Accepted &&
                entry->second.expires <= now) {
                chosen->ports.erase(entry->second.key);
                entry = chosen->entries.erase(entry);
            } else {
                ++entry;
            }
        }
    }
}

std::size_t DeviceNat::build_reply(bool ipv6, const DeviceAddress& source,
                                   std::uint16_t source_port,
                                   std::uint16_t destination_port,
                                   std::span<const std::uint8_t> payload,
                                   std::size_t mtu,
                                   std::span<std::uint8_t> out) {
    const Family* chosen = family(ipv6);
    const std::size_t header = ipv6 ? kIpv6Header : kIpv4Header;
    const std::size_t body = kUdpHeader + payload.size();
    const std::size_t total = header + body;
    // An IPv4 total length and an IPv6 payload length are 16 bits each.
    if (chosen == nullptr || payload.empty() || total > mtu ||
        total > out.size() || (ipv6 ? body : total) > 0xffffU) {
        return 0U;
    }
    write_ip_header(ipv6, out.data(), kUdp, body, source,
                    chosen->addresses.device, next_identification_++);
    std::uint8_t* const udp = out.data() + header;
    put16(udp, source_port);
    put16(udp + 2U, destination_port);
    put16(udp + 4U, static_cast<std::uint16_t>(body));
    put16(udp + 6U, 0U);
    std::memcpy(udp + kUdpHeader, payload.data(), payload.size());
    std::uint16_t checksum =
        finish(pseudo_sum(ipv6, source.data(), chosen->addresses.device.data(),
                          kUdp, body) +
               sum_words({udp, body}));
    // Zero means "no checksum" in UDP, so a computed zero is sent as all ones.
    if (checksum == 0U) checksum = 0xffffU;
    put16(udp + 6U, checksum);
    return total;
}

}  // namespace yume::runtime
