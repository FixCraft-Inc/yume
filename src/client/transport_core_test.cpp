/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/transport_core.hpp"

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
    test_shutdown_closes_registered_streams();
    return 0;
}
