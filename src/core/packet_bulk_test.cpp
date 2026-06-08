/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "core/packet_bulk.hpp"

#include <cassert>
#include <iostream>
#include <stdexcept>

using yume::protocol::packet_bulk::Batch;
using yume::protocol::packet_bulk::Bytes;

namespace packet_bulk = yume::protocol::packet_bulk;

int main() {
    Batch batch;
    batch.sequence = 7;
    batch.packets = {
        Bytes{0x45, 0x00, 0x00, 0x14},
        Bytes{0x45, 0x00, 0x00, 0x15, 0x00},
    };
    const auto encoded = packet_bulk::encode_batch(batch);
    const auto decoded = packet_bulk::decode_batch(encoded);
    assert(decoded.has_value());
    assert(decoded->sequence == 7);
    assert(decoded->packets.size() == 2);
    assert(decoded->packets[0] == batch.packets[0]);
    assert(decoded->packets[1] == batch.packets[1]);

    Bytes truncated = encoded;
    truncated.pop_back();
    std::string error;
    assert(!packet_bulk::decode_batch(truncated, &error).has_value());
    assert(!error.empty());

    assert(packet_bulk::can_append_packet(packet_bulk::kHeaderBytes, 0, 1200));
    assert(!packet_bulk::can_append_packet(packet_bulk::kHeaderBytes, packet_bulk::kMaxPacketsPerBatch, 1200));
    assert(!packet_bulk::can_append_packet(packet_bulk::kHeaderBytes, 0, 0));
    assert(!packet_bulk::can_append_packet(packet_bulk::kHeaderBytes, 0, packet_bulk::kMaxPacketBytes + 1));

    Batch too_many;
    too_many.sequence = 1;
    too_many.packets.assign(packet_bulk::kMaxPacketsPerBatch + 1, Bytes{0x45});
    bool rejected = false;
    try {
        (void)packet_bulk::encode_batch(too_many);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    assert(rejected);

    std::cout << "packet_bulk_test ok\n";
    return 0;
}
