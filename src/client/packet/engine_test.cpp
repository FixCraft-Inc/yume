/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/packet/engine.hpp"

#include <cassert>
#include <chrono>
#include <thread>

namespace {

using yume::client::packet::Bytes;
using yume::client::packet::PacketBatchEngine;
using yume::client::packet::QueueResult;

void test_batch_limits_and_sequences() {
    PacketBatchEngine engine;
    std::vector<Bytes> packets(65, Bytes(32, 0x42));
    assert(engine.enqueue_outbound(packets) == QueueResult::ok);

    Bytes first;
    assert(engine.take_outbound_payload(&first, std::chrono::milliseconds(0)) ==
           QueueResult::ok);
    auto decoded_first = yume::protocol::packet_bulk::decode_batch(first);
    assert(decoded_first.has_value());
    assert(decoded_first->sequence == 0);
    assert(decoded_first->packets.size() == 64);

    Bytes second;
    assert(engine.take_outbound_payload(&second, std::chrono::milliseconds(0)) ==
           QueueResult::ok);
    auto decoded_second = yume::protocol::packet_bulk::decode_batch(second);
    assert(decoded_second.has_value());
    assert(decoded_second->sequence == 1);
    assert(decoded_second->packets.size() == 1);
}

void test_inbound_sequence_and_buffer_sizing() {
    PacketBatchEngine engine;
    yume::protocol::packet_bulk::Batch batch;
    batch.sequence = 0;
    batch.packets = {Bytes(20, 0x11)};
    const Bytes payload = yume::protocol::packet_bulk::encode_batch(batch);
    assert(engine.accept_inbound_payload(payload) == QueueResult::ok);
    assert(engine.accept_inbound_payload(payload) == QueueResult::invalid);

    std::vector<Bytes> packets;
    std::size_t required = 0;
    assert(engine.read_inbound(1, 19, std::chrono::milliseconds(0),
                               &packets, &required) ==
           QueueResult::buffer_too_small);
    assert(required == 20);
    assert(engine.read_inbound(1, 20, std::chrono::milliseconds(0),
                               &packets, &required) == QueueResult::ok);
    assert(packets.size() == 1 && packets.front().size() == 20);
}

void test_queue_admission_is_all_or_none() {
    PacketBatchEngine engine({2, 16});
    assert(engine.enqueue_outbound({Bytes(8, 1), Bytes(8, 2)}) == QueueResult::ok);
    assert(engine.enqueue_outbound({Bytes(1, 3)}) == QueueResult::would_block);
    const auto stats = engine.stats();
    assert(stats.outbound_queue_packets == 2);
    assert(stats.outbound_queue_bytes == 16);
}

void test_stop_interrupts_blocking_read() {
    PacketBatchEngine engine;
    QueueResult result = QueueResult::ok;
    std::thread reader([&] {
        std::vector<Bytes> packets;
        result = engine.read_inbound(1, 64, std::chrono::seconds(10), &packets);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    engine.stop("test stop");
    reader.join();
    assert(result == QueueResult::stopped);
}

}  // namespace

int main() {
    test_batch_limits_and_sequences();
    test_inbound_sequence_and_buffer_sizing();
    test_queue_admission_is_all_or_none();
    test_stop_interrupts_blocking_read();
    return 0;
}
