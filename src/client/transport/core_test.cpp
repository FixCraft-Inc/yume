/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/transport/core.hpp"
#include "core/protocol/packet_bulk.hpp"

#include <cassert>
#include <deque>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

struct Recorder {
    std::vector<std::vector<uint8_t>> writes;
    std::vector<yume::client::TransportCore::WriteCompletion> completions;
    std::string close_reason;
    bool complete_immediately{true};

    yume::client::TransportCore::WriteHandler writer() {
        return [this](std::shared_ptr<std::vector<uint8_t>> data,
                      yume::client::TransportCore::WriteCompletion completion) {
            writes.push_back(*data);
            if (completion && complete_immediately) {
                completion(true, data->size(), {});
            } else if (completion) {
                completions.push_back(std::move(completion));
            }
        };
    }

    std::function<void(const std::string&)> closer() {
        return [this](const std::string& reason) {
            close_reason = reason;
        };
    }
};

struct DeferredLink {
    struct Write {
        std::vector<uint8_t> wire;
        yume::client::TransportCore::WriteCompletion completion;
    };

    std::deque<Write> writes;

    yume::client::TransportCore::WriteHandler writer() {
        return [this](std::shared_ptr<std::vector<uint8_t>> data,
                      yume::client::TransportCore::WriteCompletion completion) {
            writes.push_back({*data, std::move(completion)});
        };
    }
};

std::vector<yume::protocol::Frame> decode_all_frames(const std::vector<uint8_t>& wire) {
    std::vector<yume::protocol::Frame> out;
    std::size_t offset = 0;
    while (offset < wire.size()) {
        assert(wire.size() - offset >= 8);
        const uint32_t len =
            (uint32_t(wire[offset]) << 24) |
            (uint32_t(wire[offset + 1]) << 16) |
            (uint32_t(wire[offset + 2]) << 8) |
            uint32_t(wire[offset + 3]);
        const std::size_t frame_size = 8U + static_cast<std::size_t>(len);
        assert(offset + frame_size <= wire.size());
        std::vector<uint8_t> one(wire.begin() + static_cast<std::ptrdiff_t>(offset),
                                 wire.begin() + static_cast<std::ptrdiff_t>(offset + frame_size));
        out.push_back(yume::protocol::decode_frame(one));
        offset += frame_size;
    }
    return out;
}

void test_open_round_trip() {
    Recorder recorder;
    yume::client::TransportCore core(recorder.writer(), recorder.closer());
    core.start();

    bool open_called = false;
    bool open_ok = false;
    std::string open_payload;
    core.open_stream(7, "example.com", 443, [&](bool ok, const std::string& payload) {
        open_called = true;
        open_ok = ok;
        open_payload = payload;
    });

    assert(recorder.writes.size() == 1);
    const std::vector<uint8_t> ack_payload{'{', '"', 'o', 'k', '"', ':', '1', '}'};
    auto ack = yume::protocol::encode_frame(
        yume::protocol::OPEN, 7, yume::protocol::kFlagOpenOk, ack_payload);
    core.feed_tls_bytes(ack.data(), 3);
    assert(!open_called);
    core.feed_tls_bytes(ack.data() + 3, ack.size() - 3);
    assert(open_called);
    assert(open_ok);
    assert(open_payload == "{\"ok\":1}");
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

void test_incremental_frame_decoder_handles_fragmented_concatenated_frames() {
    Recorder recorder;
    yume::client::TransportCore core(recorder.writer(), recorder.closer());
    core.start();

    std::vector<std::vector<std::uint8_t>> received;
    core.register_stream(
        7,
        [&](const std::vector<std::uint8_t>& payload) {
            received.push_back(payload);
        },
        [&](const std::string&) {});

    std::vector<std::uint8_t> first(256U * 1024U);
    for (std::size_t i = 0; i < first.size(); ++i) {
        first[i] = static_cast<std::uint8_t>((i * 29U + 7U) & 0xffU);
    }
    const std::vector<std::uint8_t> second{0x10, 0x20, 0x30, 0x40};
    auto wire = yume::protocol::encode_frame(
        yume::protocol::DATA, 7, 0, first);
    auto tail = yume::protocol::encode_frame(
        yume::protocol::DATA, 7, 0, second);
    wire.insert(wire.end(), tail.begin(), tail.end());

    const std::array<std::size_t, 5> fragments{1, 7, 4093, 16381, 65537};
    std::size_t offset = 0;
    std::size_t fragment = 0;
    while (offset < wire.size()) {
        const std::size_t bytes = std::min(
            fragments[fragment++ % fragments.size()], wire.size() - offset);
        core.feed_tls_bytes(wire.data() + offset, bytes);
        offset += bytes;
    }

    assert(received.size() == 2);
    assert(received[0] == first);
    assert(received[1] == second);
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

void test_write_scheduler_prioritizes_control_without_reordering_stream() {
    Recorder recorder;
    recorder.complete_immediately = false;
    yume::client::TransportCore core(recorder.writer(), recorder.closer());
    core.start();

    core.send_data(1, std::vector<uint8_t>(64 * 1024, 0x11));
    assert(recorder.writes.size() == 1);
    assert(recorder.completions.size() == 1);

    core.send_data(5, std::vector<uint8_t>{0x22});
    core.send_close(5, "done");
    core.send_control_json({{"cmd", "scheduler.test"}});
    core.send_data(6, std::vector<uint8_t>(64 * 1024, 0x33));
    assert(recorder.writes.size() == 1);

    auto completion = std::move(recorder.completions.front());
    recorder.completions.clear();
    completion(true, recorder.writes.front().size(), {});

    assert(recorder.writes.size() == 2);
    const auto frames = decode_all_frames(recorder.writes.back());
    assert(frames.size() >= 4);
    assert(frames[0].header.type == yume::protocol::CONTROL);

    std::size_t data5_index = frames.size();
    std::size_t close5_index = frames.size();
    for (std::size_t i = 0; i < frames.size(); ++i) {
        if (frames[i].header.stream_id == 5 && frames[i].header.type == yume::protocol::DATA) {
            data5_index = i;
        }
        if (frames[i].header.stream_id == 5 && frames[i].header.type == yume::protocol::CLOSE) {
            close5_index = i;
        }
    }
    assert(data5_index < close5_index);
}

void test_transport_bulk_backpressure_is_bounded() {
    Recorder recorder;
    recorder.complete_immediately = false;
    yume::client::TransportCore core(recorder.writer(), recorder.closer());
    core.start();

    std::size_t accepted = 0;
    std::size_t rejected = 0;
    for (std::size_t i = 0; i < 449; ++i) {
        const bool ok = core.try_send_data(
            static_cast<std::uint8_t>((i % 200) + 1),
            std::vector<uint8_t>{0x41},
            [&](bool completion_ok, std::size_t, const std::string&) {
                if (!completion_ok) ++rejected;
            });
        if (ok) ++accepted;
    }
    assert(accepted == 448);
    assert(rejected == 1);
}

void test_shutdown_completes_queued_and_inflight_writes_once() {
    Recorder recorder;
    recorder.complete_immediately = false;
    yume::client::TransportCore core(recorder.writer(), recorder.closer());
    core.start();

    int first_calls = 0;
    int second_calls = 0;
    bool first_ok = true;
    bool second_ok = true;
    core.send_data(1, std::vector<uint8_t>{1},
                   [&](bool ok, std::size_t, const std::string&) {
                       ++first_calls;
                       first_ok = ok;
                   });
    core.send_data(2, std::vector<uint8_t>{2},
                   [&](bool ok, std::size_t, const std::string&) {
                       ++second_calls;
                       second_ok = ok;
                   });
    assert(recorder.completions.size() == 1);
    (void)core.shutdown();
    assert(second_calls == 1);
    assert(!second_ok);
    assert(first_calls == 0);

    auto completion = std::move(recorder.completions.front());
    completion(true, recorder.writes.front().size(), {});
    assert(first_calls == 1);
    assert(!first_ok);
    assert(second_calls == 1);
}

void test_ratchet_batches_cross_rekeys_in_wire_order() {
#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    constexpr std::size_t kStreams = 16;
    // 16 streams * 15 frames * 64 KiB exactly fills the 15 MiB bulk
    // reservation while leaving the required 1 MiB control reserve intact.
    constexpr std::size_t kFramesPerStream = 15;
    constexpr std::size_t kPayloadBytes = 64U * 1024U;

    DeferredLink client_to_server;
    DeferredLink server_to_client;
    std::string client_close;
    std::string server_close;
    yume::client::TransportCore client(
        client_to_server.writer(),
        [&](const std::string& reason) { client_close = reason; });
    yume::client::TransportCore server(
        server_to_client.writer(),
        [&](const std::string& reason) { server_close = reason; });

    const yume::ratchet::Bytes root(32, 0x51);
    const yume::ratchet::Bytes psk(32, 0x62);
    client.set_ratchet(std::make_unique<yume::ratchet::SessionRatchet>(
        yume::ratchet::EndpointRole::Client, root, psk));
    server.set_ratchet(std::make_unique<yume::ratchet::SessionRatchet>(
        yume::ratchet::EndpointRole::Server, root, psk));
    client.start();
    server.start();

    std::size_t completions = 0;
    for (std::size_t frame = 0; frame < kFramesPerStream; ++frame) {
        for (std::size_t stream = 1; stream <= kStreams; ++stream) {
            const bool accepted = client.try_send_data(
                static_cast<std::uint8_t>(stream),
                std::vector<uint8_t>(kPayloadBytes,
                                     static_cast<std::uint8_t>(stream)),
                [&](bool ok, std::size_t, const std::string&) {
                    assert(ok);
                    ++completions;
                });
            assert(accepted);
        }
    }

    std::size_t pump_steps = 0;
    while ((!client_to_server.writes.empty() ||
            !server_to_client.writes.empty()) &&
           client_close.empty() && server_close.empty()) {
        if (!client_to_server.writes.empty()) {
            auto write = std::move(client_to_server.writes.front());
            client_to_server.writes.pop_front();
            server.feed_tls_bytes(write.wire);
            if (write.completion) {
                write.completion(true, write.wire.size(), {});
            }
        }
        if (!server_to_client.writes.empty()) {
            auto write = std::move(server_to_client.writes.front());
            server_to_client.writes.pop_front();
            client.feed_tls_bytes(write.wire);
            if (write.completion) {
                write.completion(true, write.wire.size(), {});
            }
        }
        assert(++pump_steps < 10000);
    }

    assert(client_close.empty());
    assert(server_close.empty());
    assert(completions == kStreams * kFramesPerStream);
#endif
}

}  // namespace

int main() {
    test_open_round_trip();
    test_inner_crypto_round_trip();
    test_incremental_frame_decoder_handles_fragmented_concatenated_frames();
    test_padded_frame_round_trip();
    test_padded_frame_rejects_bad_length();
    test_packet_bulk_round_trip();
    test_packet_bulk_rejects_malformed_payload();
    test_shutdown_closes_registered_streams();
    test_write_scheduler_prioritizes_control_without_reordering_stream();
    test_transport_bulk_backpressure_is_bounded();
    test_shutdown_completes_queued_and_inflight_writes_once();
    test_ratchet_batches_cross_rekeys_in_wire_order();
    return 0;
}
