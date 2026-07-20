/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/packet/channel.hpp"

#include <cassert>

namespace {

yume::client::packet::Bytes ipv4_packet(std::uint32_t source,
                                        std::uint32_t destination,
                                        std::size_t size = 20) {
    yume::client::packet::Bytes packet(size, 0);
    packet[0] = 0x45;
    packet[2] = static_cast<std::uint8_t>(size >> 8);
    packet[3] = static_cast<std::uint8_t>(size);
    for (int i = 0; i < 4; ++i) {
        packet[12 + i] = static_cast<std::uint8_t>(source >> (24 - i * 8));
        packet[16 + i] = static_cast<std::uint8_t>(destination >> (24 - i * 8));
    }
    return packet;
}

}  // namespace

int main() {
    using namespace yume::client::packet;
    assert(!has_packet_bulk_capability({"something_else"}));
    assert(has_packet_bulk_capability({"something_else", "packet_bulk_v1"}));

    Assignment assignment;
    std::string error;
    assert(parse_packet_assignment(
        R"({"proto":"packet-bulk-v1","capability":"packet_bulk_v1","ipv4":"10.89.0.2","mtu":1420,"dns":["1.1.1.1"]})",
        &assignment, &error));
    assert(assignment.ipv4_be == 0x0a590002U);
    assert(assignment.mtu == 1420);
    assert(!parse_packet_assignment(
        R"({"proto":"packet-bulk-v1","capability":"packet_bulk_v1","ipv4":"10.89.0.2","mtu":1420,"dns":["::1"]})",
        &assignment, &error));

    assignment.ipv4 = "10.89.0.2";
    assignment.ipv4_be = 0x0a590002U;
    assignment.mtu = 1420;
    auto outbound = ipv4_packet(assignment.ipv4_be, 0x08080808U);
    assert(validate_assigned_ipv4_packet(
        assignment, outbound, true, &error));
    outbound[12] = 0x7f;
    assert(!validate_assigned_ipv4_packet(
        assignment, outbound, true, &error));

    auto inbound = ipv4_packet(0x08080808U, assignment.ipv4_be);
    assert(validate_assigned_ipv4_packet(
        assignment, inbound, false, &error));
    inbound[0] = 0x60;
    assert(!validate_assigned_ipv4_packet(
        assignment, inbound, false, &error));

    auto oversized = ipv4_packet(
        assignment.ipv4_be, 0x08080808U, assignment.mtu + 1U);
    assert(!validate_assigned_ipv4_packet(
        assignment, oversized, true, &error));
    return 0;
}
