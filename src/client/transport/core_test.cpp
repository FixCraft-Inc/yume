/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/transport/core.hpp"
#include "core/protocol/packet_bulk.hpp"

#include <cassert>
#include <string>
#include <utility>
#include <vector>

namespace {

struct Recorder {
    std::vector<std::vector<uint8_t>> writes;
    std::string close_reason;

    yume::client::TransportCore::WriteHandler writer() {
        return [this](std::shared_ptr<std::vector<uint8_t>> data,
                      yume::client::TransportCore::WriteCompletion completion) {
            writes.push_back(*data);
            if (completion) {
                completion(true, data->size(), {});
            }
        };
    }

    std::function<void(const std::string&)> closer() {
        return [this](const std::string& reason) {
            close_reason = reason;
        };
    }
};

void test_open_round_trip() {
    Recorder recorder;
    yume::client::TransportCore core(recorder.writer(), recorder.closer());
    core.start();

    bool open_called = false;
    bool open_ok = false;
    core.open_stream(7, "example.com", 443, [&](bool ok, const std::string&) {
        open_called = true;
        open_ok = ok;
    });

    assert(recorder.writes.size() == 1);
    auto ack = yume::protocol::encode_frame(yume::protocol::OPEN, 7, yume::protocol::kFlagOpenOk, {});
    core.feed_tls_bytes(ack.data(), 3);
    assert(!open_called);
    core.feed_tls_bytes(ack.data() + 3, ack.size() - 3);
    assert(open_called);
    assert(open_ok);
}

void test_inner_crypto_round_trip() {
#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    Recorder recorder;
    yume::client::TransportCore core(recorder.writer(), recorder.closer());
    core.start();
    core.set_inner_key({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32});

    std::vector<uint8_t> received;
    bool delivered = false;
    core.register_stream(9,
                         [&](const std::vector<uint8_t>& data) {
                             delivered = true;
                             received = data;
                         },
                         [&](const std::string&) {});

    const std::vector<uint8_t> payload{'h', 'e', 'l', 'l', 'o'};
    core.send_data(9, payload);

    assert(recorder.writes.size() == 1);
    const auto frame = yume::protocol::decode_frame(recorder.writes.back());
    assert((frame.header.flags & yume::protocol::kFlagInnerEncrypted) != 0);
    assert(frame.payload != payload);

    core.feed_tls_bytes(recorder.writes.back());
    assert(delivered);
    assert(received == payload);
#endif
}

void test_padded_frame_round_trip() {
    using namespace yume::protocol;
    // Pick a payload whose size is *not* a multiple of any test M.
    const std::vector<uint8_t> payload{0xDE, 0xAD, 0xBE, 0xEF, 0x42};

    for (uint16_t m : {uint16_t{1}, uint16_t{16}, uint16_t{32}, uint16_t{64}, uint16_t{256}}) {
        auto wire = encode_frame(DATA, /*stream_id=*/7, /*flags=*/0, payload, m);
        // Header carries kFlagPadded; on-wire payload length is a multiple of m.
        const uint32_t wire_len =
            (uint32_t(wire[0]) << 24) | (uint32_t(wire[1]) << 16) |
            (uint32_t(wire[2]) << 8)  |  uint32_t(wire[3]);
        const uint16_t flags = uint16_t(wire[6] << 8) | uint16_t(wire[7]);
        assert((flags & kFlagPadded) != 0);
        if (m > 1) {
            assert(wire_len % m == 0);
        }
        // Decode strips the padding transparently and clears the flag.
        const auto frame = decode_frame(wire);
        assert((frame.header.flags & kFlagPadded) == 0);
        assert(frame.payload == payload);
    }

    // pad_multiple = 0 keeps the legacy byte-for-byte encoding.
    auto legacy = encode_frame(DATA, 7, 0, payload, 0);
    const uint16_t legacy_flags = uint16_t(legacy[6] << 8) | uint16_t(legacy[7]);
    assert((legacy_flags & kFlagPadded) == 0);
    assert(legacy.size() == 8 + payload.size());
    const auto legacy_frame = decode_frame(legacy);
    assert(legacy_frame.payload == payload);
}

void test_padded_frame_rejects_bad_length() {
    using namespace yume::protocol;
    // Hand-craft a frame with kFlagPadded set but a length byte that
    // claims to consume more than the payload itself. decode_frame must
    // throw rather than producing a Frame with a negative-size payload.
    std::vector<uint8_t> wire;
    const uint8_t payload_size = 4;
    wire = {0, 0, 0, payload_size, uint8_t(DATA), 0, uint8_t(kFlagPadded >> 8), uint8_t(kFlagPadded & 0xFF),
            0, 0, 0, 99};  // length byte 99 > payload_size - 1
    bool threw = false;
    try { (void)decode_frame(wire); } catch (const std::runtime_error&) { threw = true; }
    assert(threw);
}

void test_packet_bulk_round_trip() {
    using namespace yume::protocol::packet_bulk;
    Batch batch;
    batch.sequence = 42;
    batch.flags = 3;
    batch.packets = {
        Bytes{0x45, 0x00, 0x00, 0x14},
        Bytes{0x60, 0x00, 0x00, 0x00, 0x00},
    };

    const auto encoded = encode_batch(batch);
    assert(encoded.size() == encoded_size(batch));
    assert(can_append_packet(0, 0, batch.packets.front().size()));

    std::string error;
    const auto decoded = decode_batch(encoded, &error);
    assert(decoded.has_value());
    assert(error.empty());
    assert(decoded->sequence == batch.sequence);
    assert(decoded->flags == batch.flags);
    assert(decoded->packets == batch.packets);
}

void test_packet_bulk_rejects_malformed_payload() {
    using namespace yume::protocol::packet_bulk;
    Batch batch;
    batch.sequence = 1;
    batch.packets = {Bytes{0x45, 0x00, 0x00, 0x14}};
    auto encoded = encode_batch(batch);
    encoded.pop_back();

    std::string error;
    const auto decoded = decode_batch(encoded, &error);
    assert(!decoded.has_value());
    assert(!error.empty());
}

void test_shutdown_closes_registered_streams() {
    Recorder recorder;
    yume::client::TransportCore core(recorder.writer(), recorder.closer());
    core.start();

    bool closed = false;
    std::string close_reason;
    core.register_stream(5,
                         [&](const std::vector<uint8_t>&) {},
                         [&](const std::string& reason) {
                             closed = true;
                             close_reason = reason;
                         });

    auto callbacks = core.shutdown();
    assert(callbacks.size() == 1);
    callbacks.front()("test shutdown");
    assert(closed);
    assert(close_reason == "test shutdown");
}

}  // namespace

int main() {
    test_open_round_trip();
    test_inner_crypto_round_trip();
    test_padded_frame_round_trip();
    test_padded_frame_rejects_bad_length();
    test_packet_bulk_round_trip();
    test_packet_bulk_rejects_malformed_payload();
    test_shutdown_closes_registered_streams();
    return 0;
}
