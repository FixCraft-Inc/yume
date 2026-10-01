/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/device_nat.hpp"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <random>
#include <vector>

namespace {

using namespace std::chrono_literals;
using yume::runtime::DeviceAddress;
using yume::runtime::DeviceAddressPair;
using yume::runtime::DeviceDatagram;
using yume::runtime::DeviceNat;
using yume::runtime::DeviceNatLimits;
using yume::runtime::DevicePacket;
using Bytes = std::vector<std::uint8_t>;

int g_failures = 0;

#define CHECK(condition)                                        \
    do {                                                        \
        if (!(condition)) {                                     \
            std::cerr << __FILE__ << ':' << __LINE__            \
                      << ": check failed: " #condition << '\n'; \
            ++g_failures;                                       \
        }                                                       \
    } while (false)

constexpr std::uint8_t kFin = 0x01U;
constexpr std::uint8_t kSyn = 0x02U;
constexpr std::uint8_t kRst = 0x04U;
constexpr std::uint8_t kPsh = 0x08U;
constexpr std::uint8_t kAck = 0x10U;

DeviceAddress v4(std::uint8_t a, std::uint8_t b, std::uint8_t c,
                 std::uint8_t d) {
    DeviceAddress address{};
    address[0] = a;
    address[1] = b;
    address[2] = c;
    address[3] = d;
    return address;
}

DeviceAddress v6(std::uint8_t first, std::uint8_t last) {
    DeviceAddress address{};
    address[0] = first;
    address[1] = 0x71U;
    address[15] = last;
    return address;
}

const DeviceAddress kDevice4 = v4(10, 71, 0, 1);
const DeviceAddress kPeer4 = v4(10, 71, 0, 2);
const DeviceAddress kRemote4 = v4(203, 0, 113, 9);
const DeviceAddress kDevice6 = v6(0xfdU, 1U);
const DeviceAddress kPeer6 = v6(0xfdU, 2U);
const DeviceAddress kRemote6 = v6(0x20U, 9U);
constexpr std::uint16_t kListener4 = 40001U;
constexpr std::uint16_t kListener6 = 40002U;

std::uint16_t get16(const std::uint8_t* at) {
    return static_cast<std::uint16_t>((at[0] << 8U) | at[1]);
}

std::uint32_t get32(const std::uint8_t* at) {
    return (std::uint32_t{at[0]} << 24U) | (std::uint32_t{at[1]} << 16U) |
           (std::uint32_t{at[2]} << 8U) | at[3];
}

void put16(std::uint8_t* at, std::uint16_t value) {
    at[0] = static_cast<std::uint8_t>(value >> 8U);
    at[1] = static_cast<std::uint8_t>(value);
}

void put32(std::uint8_t* at, std::uint32_t value) {
    put16(at, static_cast<std::uint16_t>(value >> 16U));
    put16(at + 2U, static_cast<std::uint16_t>(value));
}

// A plain full computation, independent of the translator's incremental one.
std::uint16_t checksum(const Bytes& data) {
    std::uint32_t sum = 0U;
    for (std::size_t index = 0U; index < data.size(); index += 2U) {
        const std::uint32_t low =
            index + 1U < data.size() ? data[index + 1U] : 0U;
        sum += (std::uint32_t{data[index]} << 8U) | low;
    }
    while ((sum >> 16U) != 0U) sum = (sum & 0xffffU) + (sum >> 16U);
    return static_cast<std::uint16_t>(~sum);
}

std::size_t ip_header_size(const Bytes& packet) {
    return (packet[0] >> 4U) == 6U
               ? 40U
               : static_cast<std::size_t>(packet[0] & 0x0fU) * 4U;
}

// Whether the transport checksum of packet verifies, and for IPv4 the header
// checksum too.
bool checksums_hold(const Bytes& packet) {
    const bool ipv6 = (packet[0] >> 4U) == 6U;
    const std::size_t header = ip_header_size(packet);
    if (!ipv6 &&
        checksum(Bytes(packet.begin(),
                       packet.begin() + static_cast<std::ptrdiff_t>(header))) !=
            0U) {
        return false;
    }
    Bytes covered;
    const std::size_t addresses = ipv6 ? 32U : 8U;
    const std::size_t at = ipv6 ? 8U : 12U;
    covered.insert(
        covered.end(), packet.begin() + static_cast<std::ptrdiff_t>(at),
        packet.begin() + static_cast<std::ptrdiff_t>(at + addresses));
    const std::size_t length = packet.size() - header;
    covered.push_back(0U);
    covered.push_back(ipv6 ? packet[6] : packet[9]);
    covered.push_back(static_cast<std::uint8_t>(length >> 8U));
    covered.push_back(static_cast<std::uint8_t>(length));
    covered.insert(covered.end(),
                   packet.begin() + static_cast<std::ptrdiff_t>(header),
                   packet.end());
    return checksum(covered) == 0U;
}

void seal_transport(Bytes& packet, std::size_t checksum_offset) {
    const bool ipv6 = (packet[0] >> 4U) == 6U;
    const std::size_t header = ip_header_size(packet);
    put16(packet.data() + header + checksum_offset, 0U);
    Bytes covered;
    const std::size_t addresses = ipv6 ? 32U : 8U;
    const std::size_t at = ipv6 ? 8U : 12U;
    covered.insert(
        covered.end(), packet.begin() + static_cast<std::ptrdiff_t>(at),
        packet.begin() + static_cast<std::ptrdiff_t>(at + addresses));
    const std::size_t length = packet.size() - header;
    covered.push_back(0U);
    covered.push_back(ipv6 ? packet[6] : packet[9]);
    covered.push_back(static_cast<std::uint8_t>(length >> 8U));
    covered.push_back(static_cast<std::uint8_t>(length));
    covered.insert(covered.end(),
                   packet.begin() + static_cast<std::ptrdiff_t>(header),
                   packet.end());
    put16(packet.data() + header + checksum_offset, checksum(covered));
}

Bytes ip_packet(bool ipv6, std::uint8_t protocol, const DeviceAddress& source,
                const DeviceAddress& destination, const Bytes& body,
                std::size_t options = 0U) {
    Bytes packet;
    if (ipv6) {
        packet.assign(40U, 0U);
        packet[0] = 0x60U;
        put16(packet.data() + 4U, static_cast<std::uint16_t>(body.size()));
        packet[6] = protocol;
        packet[7] = 64U;
        std::memcpy(packet.data() + 8U, source.data(), 16U);
        std::memcpy(packet.data() + 24U, destination.data(), 16U);
    } else {
        const std::size_t header = 20U + options;
        packet.assign(header, 0U);
        packet[0] = static_cast<std::uint8_t>(0x40U | (header / 4U));
        put16(packet.data() + 2U,
              static_cast<std::uint16_t>(header + body.size()));
        put16(packet.data() + 4U, 0x1234U);
        put16(packet.data() + 6U, 0x4000U);
        packet[8] = 64U;
        packet[9] = protocol;
        std::memcpy(packet.data() + 12U, source.data(), 4U);
        std::memcpy(packet.data() + 16U, destination.data(), 4U);
        // No-operation options, which a translator must carry unchanged.
        for (std::size_t index = 20U; index < header; ++index) {
            packet[index] = 1U;
        }
        put16(packet.data() + 10U, checksum(packet));
    }
    packet.insert(packet.end(), body.begin(), body.end());
    return packet;
}

Bytes tcp_segment(bool ipv6, const DeviceAddress& source,
                  std::uint16_t source_port, const DeviceAddress& destination,
                  std::uint16_t destination_port, std::uint8_t flags,
                  std::uint32_t sequence, std::uint32_t acknowledgement,
                  const Bytes& payload = {}, std::size_t ip_options = 0U) {
    Bytes body(20U, 0U);
    put16(body.data(), source_port);
    put16(body.data() + 2U, destination_port);
    put32(body.data() + 4U, sequence);
    put32(body.data() + 8U, acknowledgement);
    body[12] = 0x50U;
    body[13] = flags;
    put16(body.data() + 14U, 0xfaf0U);
    body.insert(body.end(), payload.begin(), payload.end());
    Bytes packet = ip_packet(ipv6, 6U, source, destination, body, ip_options);
    seal_transport(packet, 16U);
    return packet;
}

Bytes udp_datagram(bool ipv6, const DeviceAddress& source,
                   std::uint16_t source_port, const DeviceAddress& destination,
                   std::uint16_t destination_port, const Bytes& payload) {
    Bytes body(8U, 0U);
    put16(body.data(), source_port);
    put16(body.data() + 2U, destination_port);
    put16(body.data() + 4U, static_cast<std::uint16_t>(8U + payload.size()));
    body.insert(body.end(), payload.begin(), payload.end());
    Bytes packet = ip_packet(ipv6, 17U, source, destination, body);
    seal_transport(packet, 6U);
    return packet;
}

bool address_is(const Bytes& packet, bool source,
                const DeviceAddress& expected) {
    const bool ipv6 = (packet[0] >> 4U) == 6U;
    const std::size_t at = ipv6 ? (source ? 8U : 24U) : (source ? 12U : 16U);
    return std::memcmp(packet.data() + at, expected.data(), ipv6 ? 16U : 4U) ==
           0;
}

std::uint16_t port_of(const Bytes& packet, bool source) {
    return get16(packet.data() + ip_header_size(packet) + (source ? 0U : 2U));
}

DeviceNat nat(DeviceNatLimits limits = {}) {
    DeviceNat translator(DeviceAddressPair{kDevice4, kPeer4},
                         DeviceAddressPair{kDevice6, kPeer6}, limits);
    translator.set_listener_ports(kListener4, kListener6);
    return translator;
}

struct Outcome final {
    DevicePacket kind{DevicePacket::Drop};
    Bytes written;
    DeviceDatagram datagram;
    // Keeps the datagram's payload view alive.
    Bytes storage;
};

Outcome run(DeviceNat& translator, const Bytes& packet,
            DeviceNat::Clock::time_point now = {}) {
    Outcome outcome;
    outcome.storage = packet;
    std::span<std::uint8_t> written;
    outcome.kind =
        translator.translate(outcome.storage, now, written, outcome.datagram);
    if (outcome.kind == DevicePacket::Write) {
        outcome.written.assign(written.begin(), written.end());
    }
    return outcome;
}

void test_connection_round_trip(bool ipv6, std::size_t ip_options) {
    const DeviceAddress& device = ipv6 ? kDevice6 : kDevice4;
    const DeviceAddress& peer = ipv6 ? kPeer6 : kPeer4;
    const DeviceAddress& remote = ipv6 ? kRemote6 : kRemote4;
    const std::uint16_t listener = ipv6 ? kListener6 : kListener4;
    DeviceNat translator = nat();

    const Bytes payload{'h', 'e', 'l', 'l', 'o'};
    const auto opened =
        run(translator, tcp_segment(ipv6, device, 50123U, remote, 443U, kSyn,
                                    1000U, 0U, {}, ip_options));
    CHECK(opened.kind == DevicePacket::Write);
    CHECK(checksums_hold(opened.written));
    CHECK(address_is(opened.written, true, peer));
    CHECK(address_is(opened.written, false, device));
    CHECK(port_of(opened.written, false) == listener);
    const std::uint16_t translated = port_of(opened.written, true);
    CHECK(translated >= 1024U);
    CHECK(translator.connections(ipv6) == 1U);

    // A retransmitted SYN keeps its port.
    const auto again =
        run(translator, tcp_segment(ipv6, device, 50123U, remote, 443U, kSyn,
                                    1000U, 0U, {}, ip_options));
    CHECK(again.kind == DevicePacket::Write);
    CHECK(port_of(again.written, true) == translated);
    CHECK(translator.connections(ipv6) == 1U);

    const auto origin = translator.accept(ipv6, translated);
    CHECK(origin.has_value());
    if (origin) {
        CHECK(origin->ipv6 == ipv6);
        CHECK(origin->destination == remote);
        CHECK(origin->destination_port == 443U);
        CHECK(origin->source_port == 50123U);
    }
    CHECK(!translator.accept(ipv6, static_cast<std::uint16_t>(translated + 1U))
               .has_value());
    CHECK(!translator.accept(!ipv6, translated).has_value());

    // The listener's answer returns as the destination's.
    const auto answered =
        run(translator, tcp_segment(ipv6, device, listener, peer, translated,
                                    kSyn | kAck, 7000U, 1001U, {}, ip_options));
    CHECK(answered.kind == DevicePacket::Write);
    CHECK(checksums_hold(answered.written));
    CHECK(address_is(answered.written, true, remote));
    CHECK(address_is(answered.written, false, device));
    CHECK(port_of(answered.written, true) == 443U);
    CHECK(port_of(answered.written, false) == 50123U);

    // Data keeps every other byte.
    const Bytes data =
        tcp_segment(ipv6, device, 50123U, remote, 443U, kPsh | kAck, 1001U,
                    7001U, payload, ip_options);
    const auto sent = run(translator, data);
    CHECK(sent.kind == DevicePacket::Write);
    CHECK(checksums_hold(sent.written));
    CHECK(sent.written.size() == data.size());
    const std::size_t tail = ip_header_size(data) + 4U;
    CHECK(std::equal(data.begin() + static_cast<std::ptrdiff_t>(tail),
                     data.begin() + static_cast<std::ptrdiff_t>(tail + 12U),
                     sent.written.begin() + static_cast<std::ptrdiff_t>(tail)));
    CHECK(std::equal(data.end() - 5, data.end(), sent.written.end() - 5));

    // An answer from a port that is not the listener's is not the bridge's.
    CHECK(run(translator, tcp_segment(ipv6, device,
                                      static_cast<std::uint16_t>(listener + 1U),
                                      peer, translated, kAck, 1U, 1U))
              .kind == DevicePacket::Drop);
    // Nor is an answer to a port the bridge did not translate.
    CHECK(
        run(translator, tcp_segment(ipv6, device, listener, peer,
                                    static_cast<std::uint16_t>(translated + 7U),
                                    kAck, 1U, 1U))
            .kind == DevicePacket::Drop);
}

void test_reset_for_unknown_connection(bool ipv6) {
    const DeviceAddress& device = ipv6 ? kDevice6 : kDevice4;
    const DeviceAddress& remote = ipv6 ? kRemote6 : kRemote4;
    DeviceNat translator = nat();

    // An acknowledged segment: the reset takes its sequence number from the
    // acknowledgement and carries no acknowledgement of its own.
    const auto acked = run(
        translator, tcp_segment(ipv6, device, 50999U, remote, 80U, kPsh | kAck,
                                500U, 900U, Bytes{1U, 2U, 3U}, ipv6 ? 0U : 8U));
    CHECK(acked.kind == DevicePacket::Write);
    CHECK(checksums_hold(acked.written));
    CHECK(acked.written.size() == (ipv6 ? 60U : 40U));
    CHECK(address_is(acked.written, true, remote));
    CHECK(address_is(acked.written, false, device));
    CHECK(port_of(acked.written, true) == 80U);
    CHECK(port_of(acked.written, false) == 50999U);
    const std::uint8_t* tcp =
        acked.written.data() + ip_header_size(acked.written);
    CHECK(tcp[13] == kRst);
    CHECK(get32(tcp + 4U) == 900U);
    CHECK(get32(tcp + 8U) == 0U);
    CHECK(translator.connections(ipv6) == 0U);

    // Without an acknowledgement the reset acknowledges what arrived.
    const auto bare =
        run(translator, tcp_segment(ipv6, device, 50999U, remote, 80U, kFin,
                                    500U, 0U, Bytes{1U, 2U, 3U}));
    CHECK(bare.kind == DevicePacket::Write);
    CHECK(checksums_hold(bare.written));
    tcp = bare.written.data() + ip_header_size(bare.written);
    CHECK(tcp[13] == (kRst | kAck));
    CHECK(get32(tcp + 4U) == 0U);
    CHECK(get32(tcp + 8U) == 504U);

    // A reset is never answered with one.
    CHECK(run(translator, tcp_segment(ipv6, device, 50999U, remote, 80U,
                                      kRst | kAck, 1U, 1U))
              .kind == DevicePacket::Drop);
}

void test_what_is_dropped() {
    DeviceNat translator = nat();
    Outcome outcome;
    CHECK(run(translator, {}).kind == DevicePacket::Drop);
    CHECK(run(translator, Bytes{0x45U}).kind == DevicePacket::Drop);
    // Another source than the device's address.
    CHECK(run(translator,
              tcp_segment(false, kRemote4, 1U, kRemote4, 2U, kSyn, 1U, 0U))
              .kind == DevicePacket::Drop);
    // To the device's own address.
    CHECK(run(translator,
              tcp_segment(false, kDevice4, 1U, kDevice4, 2U, kSyn, 1U, 0U))
              .kind == DevicePacket::Drop);
    // ICMP.
    CHECK(run(translator, ip_packet(false, 1U, kDevice4, kRemote4,
                                    Bytes{8U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}))
              .kind == DevicePacket::Drop);
    // A fragment.
    Bytes fragment =
        tcp_segment(false, kDevice4, 5U, kRemote4, 6U, kSyn, 1U, 0U);
    put16(fragment.data() + 6U, 0x2000U);
    CHECK(run(translator, fragment).kind == DevicePacket::Drop);
    // A total length beyond the bytes read.
    Bytes truncated =
        tcp_segment(false, kDevice4, 5U, kRemote4, 6U, kSyn, 1U, 0U);
    truncated.pop_back();
    CHECK(run(translator, truncated).kind == DevicePacket::Drop);
    // An IPv6 extension header.
    Bytes extended =
        tcp_segment(true, kDevice6, 5U, kRemote6, 6U, kSyn, 1U, 0U);
    extended[6] = 0U;
    CHECK(run(translator, extended).kind == DevicePacket::Drop);
    // A TCP header that is cut short.
    CHECK(run(translator,
              ip_packet(false, 6U, kDevice4, kRemote4, Bytes(12U, 0U)))
              .kind == DevicePacket::Drop);
    CHECK(translator.connections(false) == 0U);
    CHECK(translator.connections(true) == 0U);

    // Before the listeners are bound, and for a family without addresses.
    DeviceNat unbound(DeviceAddressPair{kDevice4, kPeer4}, std::nullopt);
    CHECK(run(unbound,
              tcp_segment(false, kDevice4, 5U, kRemote4, 6U, kSyn, 1U, 0U))
              .kind == DevicePacket::Drop);
    unbound.set_listener_ports(kListener4, 0U);
    CHECK(run(unbound,
              tcp_segment(false, kDevice4, 5U, kRemote4, 6U, kSyn, 1U, 0U))
              .kind == DevicePacket::Write);
    CHECK(run(unbound,
              tcp_segment(true, kDevice6, 5U, kRemote6, 6U, kSyn, 1U, 0U))
              .kind == DevicePacket::Drop);
}

void test_table_bounds_and_expiry() {
    DeviceNatLimits limits;
    limits.max_connections = 2U;
    DeviceNat translator = nat(limits);
    const DeviceNat::Clock::time_point start{};

    const auto first = run(
        translator,
        tcp_segment(false, kDevice4, 100U, kRemote4, 80U, kSyn, 1U, 0U), start);
    const auto second = run(
        translator,
        tcp_segment(false, kDevice4, 101U, kRemote4, 80U, kSyn, 1U, 0U), start);
    CHECK(first.kind == DevicePacket::Write);
    CHECK(second.kind == DevicePacket::Write);
    const std::uint16_t first_port = port_of(first.written, true);
    const std::uint16_t second_port = port_of(second.written, true);
    CHECK(first_port != second_port);
    // A full table drops a new connection and keeps the ones it has.
    CHECK(run(translator,
              tcp_segment(false, kDevice4, 102U, kRemote4, 80U, kSyn, 1U, 0U),
              start)
              .kind == DevicePacket::Drop);
    CHECK(translator.connections(false) == 2U);

    CHECK(translator.accept(false, first_port).has_value());
    // The connection nothing accepted loses its port after the pending time.
    translator.sweep(start + 59s);
    CHECK(translator.connections(false) == 2U);
    translator.sweep(start + 60s);
    CHECK(translator.connections(false) == 1U);
    // An accepted one stays for as long as it is open.
    translator.sweep(start + 24h);
    CHECK(translator.connections(false) == 1U);

    // Once closed it lingers, still translating its last segments.
    translator.release(false, first_port, start + 24h);
    CHECK(run(translator,
              tcp_segment(false, kDevice4, 100U, kRemote4, 80U, kFin | kAck, 9U,
                          9U),
              start + 24h + 1s)
              .kind == DevicePacket::Write);
    translator.sweep(start + 24h + 14s);
    CHECK(translator.connections(false) == 1U);

    // A new SYN on the same endpoints makes it pending again with its port.
    const auto reopened =
        run(translator,
            tcp_segment(false, kDevice4, 100U, kRemote4, 80U, kSyn, 50U, 0U),
            start + 24h + 14s);
    CHECK(reopened.kind == DevicePacket::Write);
    CHECK(port_of(reopened.written, true) == first_port);
    translator.sweep(start + 24h + 20s);
    CHECK(translator.connections(false) == 1U);
    translator.sweep(start + 24h + 14s + 60s);
    CHECK(translator.connections(false) == 0U);

    // release() and accept() of unknown ports change nothing.
    translator.release(false, 7U, start);
    translator.release(true, 7U, start);
    CHECK(translator.connections(false) == 0U);
}

void test_datagrams(bool ipv6) {
    const DeviceAddress& device = ipv6 ? kDevice6 : kDevice4;
    const DeviceAddress& peer = ipv6 ? kPeer6 : kPeer4;
    const DeviceAddress& remote = ipv6 ? kRemote6 : kRemote4;
    DeviceNat translator = nat();

    const Bytes payload{9U, 8U, 7U};
    const auto sent = run(
        translator, udp_datagram(ipv6, device, 5353U, remote, 53U, payload));
    CHECK(sent.kind == DevicePacket::Datagram);
    CHECK(sent.datagram.ipv6 == ipv6);
    CHECK(sent.datagram.source_port == 5353U);
    CHECK(sent.datagram.destination_port == 53U);
    CHECK(sent.datagram.destination == remote);
    CHECK(Bytes(sent.datagram.payload.begin(), sent.datagram.payload.end()) ==
          payload);

    // An empty datagram, one to the bridge's own addresses and one whose
    // length field exceeds the packet are not carried.
    CHECK(run(translator, udp_datagram(ipv6, device, 5353U, remote, 53U, {}))
              .kind == DevicePacket::Drop);
    CHECK(run(translator, udp_datagram(ipv6, device, 5353U, peer, 53U, payload))
              .kind == DevicePacket::Drop);
    Bytes long_length = udp_datagram(ipv6, device, 5353U, remote, 53U, payload);
    put16(long_length.data() + ip_header_size(long_length) + 4U, 100U);
    CHECK(run(translator, long_length).kind == DevicePacket::Drop);

    Bytes reply(128U, 0U);
    const std::size_t size =
        translator.build_reply(ipv6, remote, 53U, 5353U, payload, 1500U, reply);
    CHECK(size == (ipv6 ? 40U : 20U) + 8U + payload.size());
    reply.resize(size);
    CHECK(checksums_hold(reply));
    CHECK(address_is(reply, true, remote));
    CHECK(address_is(reply, false, device));
    CHECK(port_of(reply, true) == 53U);
    CHECK(port_of(reply, false) == 5353U);
    CHECK(Bytes(reply.end() - 3, reply.end()) == payload);

    // A reply that does not fit the MTU or the storage is not built.
    Bytes small(16U, 0U);
    CHECK(translator.build_reply(ipv6, remote, 53U, 5353U, payload, 1500U,
                                 small) == 0U);
    Bytes large(128U, 0U);
    CHECK(translator.build_reply(ipv6, remote, 53U, 5353U, payload, 20U,
                                 large) == 0U);
    CHECK(translator.build_reply(ipv6, remote, 53U, 5353U, {}, 1500U, large) ==
          0U);
}

// Incremental checksum updates must agree with a full computation whatever
// the segment holds, odd lengths and all-ones words included.
void test_checksums_over_random_segments() {
    // A fixed seed, so a failure reproduces.
    std::mt19937 engine(0x59554d45U);
    const auto random = [&engine]() noexcept {
        return static_cast<std::uint32_t>(engine());
    };
    for (int round = 0; round < 2000; ++round) {
        const bool ipv6 = (round % 2) == 1;
        DeviceNat translator = nat();
        Bytes payload(random() % 97U);
        for (auto& byte : payload) {
            byte =
                (round % 5) == 0 ? 0xffU : static_cast<std::uint8_t>(random());
        }
        DeviceAddress remote = ipv6 ? kRemote6 : kRemote4;
        for (std::size_t index = 0U; index < (ipv6 ? 16U : 4U); ++index) {
            remote[index] =
                (round % 7) == 0 ? 0xffU : static_cast<std::uint8_t>(random());
        }
        // Not one of the bridge's own addresses.
        remote[0] = ipv6 ? 0x20U : 0xc6U;
        const std::uint16_t source_port =
            static_cast<std::uint16_t>(1U + random() % 65535U);
        const std::uint16_t destination_port =
            static_cast<std::uint16_t>(1U + random() % 65535U);
        const auto out =
            run(translator,
                tcp_segment(ipv6, ipv6 ? kDevice6 : kDevice4, source_port,
                            remote, destination_port, kSyn, random(), 0U,
                            payload, ipv6 ? 0U : (random() % 3U) * 4U));
        if (out.kind != DevicePacket::Write || !checksums_hold(out.written)) {
            CHECK(out.kind == DevicePacket::Write);
            CHECK(checksums_hold(out.written));
            return;
        }
        const std::uint16_t translated = port_of(out.written, true);
        const auto back = run(
            translator,
            tcp_segment(ipv6, ipv6 ? kDevice6 : kDevice4,
                        ipv6 ? kListener6 : kListener4, ipv6 ? kPeer6 : kPeer4,
                        translated, kSyn | kAck, random(), random(), payload));
        if (back.kind != DevicePacket::Write || !checksums_hold(back.written)) {
            CHECK(back.kind == DevicePacket::Write);
            CHECK(checksums_hold(back.written));
            return;
        }
    }
}

}  // namespace

int main() {
    test_connection_round_trip(false, 0U);
    test_connection_round_trip(false, 8U);
    test_connection_round_trip(true, 0U);
    test_reset_for_unknown_connection(false);
    test_reset_for_unknown_connection(true);
    test_what_is_dropped();
    test_table_bounds_and_expiry();
    test_datagrams(false);
    test_datagrams(true);
    test_checksums_over_random_segments();
    if (g_failures != 0) {
        std::cerr << g_failures << " check(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "device NAT tests passed\n";
    return EXIT_SUCCESS;
}
