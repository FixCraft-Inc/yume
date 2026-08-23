/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/packet/channel.hpp"
#include "client/transport/client_stream.hpp"
#include "client/transport/tunnel.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl/context.hpp>

namespace yume::client::packet {

struct PacketChannelTestPeer {
    template <typename WaitSend>
    static QueueResult wait_for_transport_capacity(
        Bytes* payload,
        WaitSend&& wait_send,
        const std::atomic<bool>& closed,
        std::string* error) {
        return PacketChannel::wait_for_transport_capacity(
            payload, std::forward<WaitSend>(wait_send), closed, error);
    }

    static std::shared_ptr<PacketChannel> make_join_fixture() {
        return std::shared_ptr<PacketChannel>(new PacketChannel({}, {}));
    }

    static void start_sender(PacketChannel& channel,
                             std::function<void()> work) {
        channel.sender_ = std::thread(std::move(work));
    }
};

}  // namespace yume::client::packet

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

std::shared_ptr<yume::client::Tunnel> dormant_tunnel(
    boost::asio::io_context& io,
    boost::asio::ssl::context& tls_context) {
    yume::client::ClientTransportStream::OpenSslStream tls_stream(
        io, tls_context);
    yume::client::ClientTransportStream stream(std::move(tls_stream));
    return std::make_shared<yume::client::Tunnel>(std::move(stream));
}

void test_open_reports_typed_preflight_failures() {
    using namespace yume::client::packet;

    std::string error;
    OpenResult open_result;
    auto channel = PacketChannel::open(
        {}, {"packet_bulk_v1"}, std::chrono::milliseconds{1},
        &error, {}, &open_result);
    assert(!channel);
    assert(open_result.status == OpenStatus::invalid_argument);
    assert(open_result.detail == error);

    boost::asio::io_context io;
    boost::asio::ssl::context tls_context(
        boost::asio::ssl::context::tls_client);
    auto tunnel = dormant_tunnel(io, tls_context);
    channel = PacketChannel::open(
        tunnel, {"packet_bulk_v1"}, std::chrono::milliseconds{-1},
        &error, {}, &open_result);
    assert(!channel);
    assert(open_result.status == OpenStatus::invalid_argument);
    assert(open_result.detail == error);

    channel = PacketChannel::open(
        tunnel, {}, std::chrono::milliseconds{1},
        &error, {}, &open_result);
    assert(!channel);
    assert(open_result.status == OpenStatus::capability_unavailable);
    assert(open_result.detail == error);

    auto inactive_gate = std::make_shared<yume::client::RuntimeLifetimeGate>();
    channel = PacketChannel::open(
        tunnel, {"packet_bulk_v1"}, std::chrono::milliseconds{1},
        &error, inactive_gate, &open_result);
    assert(!channel);
    assert(open_result.status == OpenStatus::not_running);
    assert(open_result.detail == error);

    // With no executor running, the request remains pending until its exact
    // deadline. This pins timeout independently from peer rejection.
    channel = PacketChannel::open(
        tunnel, {"packet_bulk_v1"}, std::chrono::milliseconds{1},
        &error, {}, &open_result);
    assert(!channel);
    assert(open_result.status == OpenStatus::timeout);
    assert(open_result.detail == error);

    // The timed-out OPEN crossed the wire and permanently tombstones its id
    // for this connection. Exactly 254 other ids remain; reusing the first one
    // would let a delayed packet ACK/DATA alias a new channel.
    for (std::size_t i = 0; i < 254; ++i) {
        assert(tunnel->reserve_stream_id() != 0);
    }
    channel = PacketChannel::open(
        tunnel, {"packet_bulk_v1"}, std::chrono::milliseconds{1},
        &error, {}, &open_result);
    assert(!channel);
    assert(open_result.status == OpenStatus::resource_exhausted);
    assert(open_result.detail == error);
}

void test_sender_retains_payload_through_saturation_and_recovery() {
    using namespace yume::client::packet;

    Bytes payload{0x01, 0x23, 0x45, 0x67};
    const Bytes expected = payload;
    Bytes accepted;
    std::atomic<bool> closed{false};
    std::size_t calls = 0;
    std::string error = "stale";
    const auto result = PacketChannelTestPeer::wait_for_transport_capacity(
        &payload,
        [&](Bytes&& candidate, std::chrono::milliseconds timeout) {
            assert(timeout > std::chrono::milliseconds::zero());
            assert(candidate == expected);
            ++calls;
            if (calls == 1) return QueueResult::would_block;
            if (calls == 2) return QueueResult::timeout;
            accepted = std::move(candidate);
            return QueueResult::ok;
        },
        closed, &error);

    assert(result == QueueResult::ok);
    assert(calls == 3);
    assert(accepted == expected);
    assert(payload.empty());
    assert(error.empty());
}

void test_sender_distinguishes_terminal_transport_results() {
    using namespace yume::client::packet;

    const Bytes expected{0x89, 0xab};
    std::atomic<bool> closed{false};
    for (const auto terminal : {QueueResult::stopped, QueueResult::invalid}) {
        Bytes payload = expected;
        std::size_t calls = 0;
        std::string error;
        const auto result = PacketChannelTestPeer::wait_for_transport_capacity(
            &payload,
            [&](Bytes&& candidate, std::chrono::milliseconds) {
                ++calls;
                assert(candidate == expected);
                return terminal;
            },
            closed, &error);

        assert(result == terminal);
        assert(calls == 1);
        assert(payload == expected);
        assert(error == (terminal == QueueResult::stopped
            ? "packet transport stopped"
            : "packet transport rejected packet payload"));
    }
}

void test_sender_stop_interrupts_retry_loop() {
    using namespace yume::client::packet;

    Bytes payload{0xcd, 0xef};
    const Bytes expected = payload;
    std::atomic<bool> closed{false};
    std::mutex mutex;
    std::condition_variable cv;
    bool entered = false;
    bool release = false;
    std::size_t calls = 0;
    QueueResult result = QueueResult::invalid;
    std::string error;

    std::thread sender([&] {
        result = PacketChannelTestPeer::wait_for_transport_capacity(
            &payload,
            [&](Bytes&& candidate, std::chrono::milliseconds timeout) {
                assert(timeout > std::chrono::milliseconds::zero());
                assert(candidate == expected);
                std::unique_lock<std::mutex> lock(mutex);
                ++calls;
                entered = true;
                cv.notify_all();
                cv.wait(lock, [&] { return release; });
                return QueueResult::timeout;
            },
            closed, &error);
    });

    {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [&] { return entered; });
        closed.store(true, std::memory_order_release);
        release = true;
    }
    cv.notify_all();
    sender.join();

    assert(result == QueueResult::stopped);
    assert(calls == 1);
    assert(payload == expected);
    assert(error == "packet channel is stopping");
}

void test_concurrent_close_serializes_one_bounded_join() {
    using namespace yume::client::packet;

    auto channel = PacketChannelTestPeer::make_join_fixture();
    std::mutex mutex;
    std::condition_variable cv;
    bool entered = false;
    bool release = false;
    std::atomic<int> closes_finished{0};
    PacketChannelTestPeer::start_sender(*channel, [&] {
        std::unique_lock<std::mutex> lock(mutex);
        entered = true;
        cv.notify_all();
        cv.wait(lock, [&] { return release; });
    });
    {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [&] { return entered; });
    }

    std::thread first([&] {
        channel->close("first close");
        closes_finished.fetch_add(1, std::memory_order_release);
    });
    std::thread second([&] {
        channel->close("second close");
        closes_finished.fetch_add(1, std::memory_order_release);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds{20});
    assert(closes_finished.load(std::memory_order_acquire) == 0);
    {
        std::lock_guard<std::mutex> lock(mutex);
        release = true;
    }
    cv.notify_all();
    first.join();
    second.join();
    assert(closes_finished.load(std::memory_order_acquire) == 2);
}

}  // namespace

int main() {
    using namespace yume::client::packet;
    test_open_reports_typed_preflight_failures();
    test_sender_retains_payload_through_saturation_and_recovery();
    test_sender_distinguishes_terminal_transport_results();
    test_sender_stop_interrupts_retry_loop();
    test_concurrent_close_serializes_one_bounded_join();

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
