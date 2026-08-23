/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/proxy/forward.hpp"
#include "client/proxy/socks.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace yume::client {

constexpr int kForcedSocketBufferBytes = 64 * 1024;

struct ReverseForwardSessionTestPeer {
    static void attach_local_socket(ReverseForwardSession& session,
                                    boost::asio::ip::tcp::socket socket) {
        boost::system::error_code error;
        socket.set_option(
            boost::asio::socket_base::send_buffer_size(
                kForcedSocketBufferBytes),
            error);
        assert(!error);
        session.local_ = std::move(socket);
        session.open_confirmed_ = true;
    }

    static void deliver(
        ReverseForwardSession& session,
        const Tunnel::Bytes& data,
        Tunnel::InboundCredit inbound_credit = {}) {
        session.deliver_from_tunnel(data, std::move(inbound_credit));
    }

    static bool writer_idle(const ReverseForwardSession& session) {
        return !session.write_in_flight_ && session.write_queue_.empty();
    }

    static bool write_in_flight(const ReverseForwardSession& session) {
        return session.write_in_flight_;
    }

    static std::size_t queued_writes(const ReverseForwardSession& session) {
        return session.write_queue_.size();
    }

    static std::size_t pending_write_frames(
            const ReverseForwardSession& session) {
        return session.write_budget_.queued_frames();
    }

    static std::size_t pending_write_bytes(
            const ReverseForwardSession& session) {
        return session.write_budget_.queued_bytes();
    }

    static bool closed(const ReverseForwardSession& session) {
        return session.closed_;
    }
};

struct UdpForwardServerTestPeer {
    static void add_mapping(
        UdpForwardServer& server,
        std::uint8_t stream_id,
        const boost::asio::ip::udp::endpoint& client) {
        auto mapping = std::make_shared<UdpForwardServer::UdpMapping>(
            server.udp_pending_budget_);
        mapping->client = client;
        mapping->stream_id = stream_id;
        server.by_client_[udp_endpoint_key_for_test(client)] = mapping;
        server.by_stream_[stream_id] = std::move(mapping);
    }

    static bool queue_before_open(
        UdpForwardServer& server,
        std::uint8_t stream_id,
        Tunnel::Bytes data) {
        auto it = server.by_stream_.find(stream_id);
        assert(it != server.by_stream_.end());
        return it->second->pending.try_push(std::move(data));
    }

    static std::optional<Tunnel::Bytes> pop_before_open(
        UdpForwardServer& server,
        std::uint8_t stream_id) {
        auto it = server.by_stream_.find(stream_id);
        assert(it != server.by_stream_.end());
        return it->second->pending.pop_front();
    }

    static void pause_local_sends(UdpForwardServer& server) {
        server.udp_send_in_flight_ = true;
    }

    static void resume_local_sends(UdpForwardServer& server) {
        server.udp_send_in_flight_ = false;
        server.do_udp_send();
    }

    static void deliver(
        UdpForwardServer& server,
        std::uint8_t stream_id,
        const Tunnel::Bytes& data,
        Tunnel::InboundCredit inbound_credit = {}) {
        server.deliver_from_tunnel(
            stream_id, data, std::move(inbound_credit));
    }

    static void close_mapping(
        UdpForwardServer& server,
        std::uint8_t stream_id) {
        server.close_stream(stream_id, "test cleanup");
    }

    static std::size_t pending_datagrams(
        const UdpForwardServer& server) {
        return server.udp_pending_budget_.queued_datagrams();
    }

    static std::size_t local_datagrams(
        const UdpForwardServer& server) {
        return server.udp_local_send_budget_.queued_datagrams();
    }

    static std::size_t queued_local_sends(
        const UdpForwardServer& server) {
        return server.udp_send_queue_.size();
    }

private:
    static std::string udp_endpoint_key_for_test(
        const boost::asio::ip::udp::endpoint& endpoint) {
        return endpoint.address().to_string() + ":" +
               std::to_string(endpoint.port());
    }
};

struct SocksSessionTestPeer {
    static void add_assoc(
        SocksSession& session,
        std::uint8_t stream_id,
        std::string host,
        int port) {
        auto assoc = std::make_shared<SocksSession::UdpAssoc>(
            session.udp_pending_budget_);
        assoc->host = std::move(host);
        assoc->port = port;
        assoc->stream_id = stream_id;
        session.udp_assoc_[assoc->host + "|" + std::to_string(port)] = assoc;
        session.udp_assoc_by_stream_[stream_id] = std::move(assoc);
    }

    static bool queue_before_open(
        SocksSession& session,
        std::uint8_t stream_id,
        Tunnel::Bytes data) {
        auto it = session.udp_assoc_by_stream_.find(stream_id);
        assert(it != session.udp_assoc_by_stream_.end());
        return it->second->pending.try_push(std::move(data));
    }

    static std::optional<Tunnel::Bytes> pop_before_open(
        SocksSession& session,
        std::uint8_t stream_id) {
        auto it = session.udp_assoc_by_stream_.find(stream_id);
        assert(it != session.udp_assoc_by_stream_.end());
        return it->second->pending.pop_front();
    }

    static void activate_udp(
        SocksSession& session,
        const boost::asio::ip::udp::endpoint& client) {
        using boost::asio::ip::udp;
        boost::system::error_code error;
        session.udp_socket_.open(udp::v4(), error);
        assert(!error);
        session.udp_socket_.bind(
            {boost::asio::ip::address_v4::loopback(), 0}, error);
        assert(!error);
        session.udp_client_endpoint_ = client;
        session.udp_active_ = true;
    }

    static void pause_local_sends(SocksSession& session) {
        session.udp_send_in_flight_ = true;
    }

    static void resume_local_sends(SocksSession& session) {
        session.udp_send_in_flight_ = false;
        session.do_udp_send();
    }

    static void deliver(
        SocksSession& session,
        std::uint8_t stream_id,
        const Tunnel::Bytes& data,
        Tunnel::InboundCredit inbound_credit = {}) {
        session.deliver_udp(
            stream_id, data, std::move(inbound_credit));
    }

    static void close(SocksSession& session) { session.close(); }

    static std::size_t pending_datagrams(const SocksSession& session) {
        return session.udp_pending_budget_.queued_datagrams();
    }

    static std::size_t local_datagrams(const SocksSession& session) {
        return session.udp_local_send_budget_.queued_datagrams();
    }

    static std::size_t queued_local_sends(const SocksSession& session) {
        return session.udp_send_queue_.size();
    }
};

namespace {

Tunnel::Bytes make_frame(std::size_t size, std::uint8_t seed) {
    Tunnel::Bytes frame(size);
    for (std::size_t i = 0; i < frame.size(); ++i) {
        frame[i] = static_cast<std::uint8_t>(seed + (i * 31U));
    }
    return frame;
}

std::shared_ptr<Tunnel> make_unstarted_tunnel(
        boost::asio::io_context& io,
        boost::asio::ssl::context& tls_context) {
    ClientTransportStream::OpenSslStream tls_stream(io, tls_context);
    ClientTransportStream stream(std::move(tls_stream));
    return std::make_shared<Tunnel>(std::move(stream));
}

std::vector<Tunnel::Bytes> receive_udp_datagrams(
    boost::asio::ip::udp::socket& receiver,
    std::size_t count) {
    std::vector<Tunnel::Bytes> received;
    received.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        std::array<std::uint8_t, 65535> buffer{};
        boost::asio::ip::udp::endpoint sender;
        boost::system::error_code error;
        const std::size_t bytes = receiver.receive_from(
            boost::asio::buffer(buffer), sender, 0, error);
        assert(!error);
        received.emplace_back(buffer.begin(), buffer.begin() + bytes);
    }
    return received;
}

void test_udp_budget_bounds_bytes_and_recovers() {
    detail::UdpQueueBudget budget;
    detail::BudgetedUdpDatagramQueue queue(budget);
    const Tunnel::Bytes datagram(64U * 1024U, 0x5a);

    constexpr std::size_t kDatagramsAtByteLimit =
        detail::kMaxUdpQueuedBytes / (64U * 1024U);
    for (std::size_t i = 0; i < kDatagramsAtByteLimit; ++i) {
        assert(queue.try_push(datagram));
    }
    assert(budget.queued_bytes() == detail::kMaxUdpQueuedBytes);
    assert(!queue.try_push(Tunnel::Bytes{0x01}));

    auto drained = queue.pop_front();
    assert(drained && drained->size() == datagram.size());
    assert(queue.try_push(Tunnel::Bytes{0x02}));

    budget.close();
    assert(!queue.try_push(Tunnel::Bytes{0x03}));
    queue.clear();
    assert(budget.queued_datagrams() == 0U);
    assert(budget.queued_bytes() == 0U);
}

void test_udp_forward_delayed_open_and_local_send_recovery() {
    using boost::asio::ip::udp;

    boost::asio::io_context io;
    boost::asio::ssl::context tls_context(boost::asio::ssl::context::tls_client);
    auto tunnel = make_unstarted_tunnel(io, tls_context);

    udp::socket receiver(io, {boost::asio::ip::address_v4::loopback(), 0});
    auto server = std::make_shared<UdpForwardServer>(
        io, "127.0.0.1", 0, "198.51.100.10", 443, tunnel, true);
    constexpr std::uint8_t kStreamOne = 1;
    constexpr std::uint8_t kStreamTwo = 2;
    UdpForwardServerTestPeer::add_mapping(
        *server, kStreamOne, receiver.local_endpoint());
    UdpForwardServerTestPeer::add_mapping(
        *server, kStreamTwo, receiver.local_endpoint());

    const Tunnel::Bytes pending_payload{0x10, 0x20, 0x30};
    for (std::size_t i = 0; i < detail::kMaxUdpQueuedDatagrams; ++i) {
        const auto stream_id = (i % 2U == 0U) ? kStreamOne : kStreamTwo;
        assert(UdpForwardServerTestPeer::queue_before_open(
            *server, stream_id, pending_payload));
    }
    assert(!UdpForwardServerTestPeer::queue_before_open(
        *server, kStreamOne, pending_payload));
    assert(UdpForwardServerTestPeer::pending_datagrams(*server) ==
           detail::kMaxUdpQueuedDatagrams);

    auto drained = UdpForwardServerTestPeer::pop_before_open(
        *server, kStreamOne);
    assert(drained && *drained == pending_payload);
    assert(UdpForwardServerTestPeer::queue_before_open(
        *server, kStreamOne, Tunnel::Bytes{0x99}));
    UdpForwardServerTestPeer::close_mapping(*server, kStreamOne);
    UdpForwardServerTestPeer::close_mapping(*server, kStreamTwo);
    assert(UdpForwardServerTestPeer::pending_datagrams(*server) == 0U);

    constexpr std::uint8_t kLocalStream = 3;
    UdpForwardServerTestPeer::add_mapping(
        *server, kLocalStream, receiver.local_endpoint());
    UdpForwardServerTestPeer::pause_local_sends(*server);
    std::vector<Tunnel::Bytes> expected;
    expected.reserve(detail::kMaxUdpQueuedDatagrams);
    for (std::size_t i = 0; i < detail::kMaxUdpQueuedDatagrams; ++i) {
        auto datagram = make_frame(32U, static_cast<std::uint8_t>(i));
        expected.push_back(datagram);
        UdpForwardServerTestPeer::deliver(*server, kLocalStream, datagram);
    }
    UdpForwardServerTestPeer::deliver(
        *server, kLocalStream, Tunnel::Bytes{0xff});
    assert(UdpForwardServerTestPeer::local_datagrams(*server) ==
           detail::kMaxUdpQueuedDatagrams);

    io.poll();
    assert(UdpForwardServerTestPeer::queued_local_sends(*server) ==
           detail::kMaxUdpQueuedDatagrams);
    UdpForwardServerTestPeer::resume_local_sends(*server);
    assert(UdpForwardServerTestPeer::local_datagrams(*server) ==
           detail::kMaxUdpQueuedDatagrams);
    assert(UdpForwardServerTestPeer::queued_local_sends(*server) ==
           detail::kMaxUdpQueuedDatagrams - 1U);
    io.restart();
    io.run();

    const auto received = receive_udp_datagrams(
        receiver, detail::kMaxUdpQueuedDatagrams);
    assert(received == expected);
    assert(UdpForwardServerTestPeer::local_datagrams(*server) == 0U);
    assert(UdpForwardServerTestPeer::queued_local_sends(*server) == 0U);

    const Tunnel::Bytes recovery{0xa1, 0xb2, 0xc3};
    UdpForwardServerTestPeer::deliver(*server, kLocalStream, recovery);
    io.restart();
    io.run();
    const auto recovered = receive_udp_datagrams(receiver, 1U);
    assert(recovered.front() == recovery);
    assert(UdpForwardServerTestPeer::local_datagrams(*server) == 0U);

    assert(UdpForwardServerTestPeer::queue_before_open(
        *server, kLocalStream, Tunnel::Bytes{0xe1, 0xe2}));
    UdpForwardServerTestPeer::pause_local_sends(*server);
    UdpForwardServerTestPeer::deliver(
        *server, kLocalStream, Tunnel::Bytes{0xe3, 0xe4});
    io.restart();
    io.poll();
    assert(UdpForwardServerTestPeer::pending_datagrams(*server) == 1U);
    assert(UdpForwardServerTestPeer::local_datagrams(*server) == 1U);
    assert(UdpForwardServerTestPeer::queued_local_sends(*server) == 1U);

    std::weak_ptr<UdpForwardServer> weak_server = server;
    server.reset();
    assert(weak_server.expired());
}

void test_socks_udp_delayed_open_send_recovery_and_close_cleanup() {
    using boost::asio::ip::tcp;
    using boost::asio::ip::udp;

    boost::asio::io_context io;
    boost::asio::ssl::context tls_context(boost::asio::ssl::context::tls_client);
    auto tunnel = make_unstarted_tunnel(io, tls_context);
    tunnel->cancel_runtime_operations("UDP proxy unit test");

    tcp::acceptor acceptor(io, {tcp::v4(), 0});
    tcp::socket session_socket(io);
    session_socket.connect(acceptor.local_endpoint());
    tcp::socket peer_socket(io);
    acceptor.accept(peer_socket);

    udp::socket receiver(io, {boost::asio::ip::address_v4::loopback(), 0});
    auto session = std::make_shared<SocksSession>(
        std::move(session_socket), tunnel, true);
    constexpr std::uint8_t kStreamId = 7;
    SocksSessionTestPeer::add_assoc(
        *session, kStreamId, "127.0.0.1", 53);

    const Tunnel::Bytes pending_payload{0x40, 0x41};
    for (std::size_t i = 0; i < detail::kMaxUdpQueuedDatagrams; ++i) {
        assert(SocksSessionTestPeer::queue_before_open(
            *session, kStreamId, pending_payload));
    }
    assert(!SocksSessionTestPeer::queue_before_open(
        *session, kStreamId, pending_payload));
    auto drained = SocksSessionTestPeer::pop_before_open(*session, kStreamId);
    assert(drained && *drained == pending_payload);
    assert(SocksSessionTestPeer::queue_before_open(
        *session, kStreamId, Tunnel::Bytes{0x42}));
    while (SocksSessionTestPeer::pop_before_open(*session, kStreamId)) {
    }
    assert(SocksSessionTestPeer::pending_datagrams(*session) == 0U);

    SocksSessionTestPeer::activate_udp(*session, receiver.local_endpoint());
    SocksSessionTestPeer::pause_local_sends(*session);
    std::vector<Tunnel::Bytes> expected_payloads;
    expected_payloads.reserve(detail::kMaxUdpQueuedDatagrams);
    for (std::size_t i = 0; i < detail::kMaxUdpQueuedDatagrams; ++i) {
        auto datagram = make_frame(24U, static_cast<std::uint8_t>(0x80U + i));
        expected_payloads.push_back(datagram);
        SocksSessionTestPeer::deliver(*session, kStreamId, datagram);
    }
    SocksSessionTestPeer::deliver(
        *session, kStreamId, Tunnel::Bytes{0xee});
    assert(SocksSessionTestPeer::local_datagrams(*session) ==
           detail::kMaxUdpQueuedDatagrams);

    io.poll();
    assert(SocksSessionTestPeer::queued_local_sends(*session) ==
           detail::kMaxUdpQueuedDatagrams);
    SocksSessionTestPeer::resume_local_sends(*session);
    assert(SocksSessionTestPeer::local_datagrams(*session) ==
           detail::kMaxUdpQueuedDatagrams);
    assert(SocksSessionTestPeer::queued_local_sends(*session) ==
           detail::kMaxUdpQueuedDatagrams - 1U);
    io.restart();
    io.run();

    const auto received = receive_udp_datagrams(
        receiver, detail::kMaxUdpQueuedDatagrams);
    assert(received.size() == expected_payloads.size());
    for (std::size_t i = 0; i < received.size(); ++i) {
        // RSV(2), FRAG, ATYP, IPv4, and port occupy ten bytes.
        assert(received[i].size() == expected_payloads[i].size() + 10U);
        assert(std::equal(
            expected_payloads[i].begin(), expected_payloads[i].end(),
            received[i].begin() + 10));
    }
    assert(SocksSessionTestPeer::local_datagrams(*session) == 0U);

    const Tunnel::Bytes recovery{0xd1, 0xd2};
    SocksSessionTestPeer::deliver(*session, kStreamId, recovery);
    io.restart();
    io.run();
    const auto recovered = receive_udp_datagrams(receiver, 1U);
    assert(recovered.front().size() == recovery.size() + 10U);
    assert(std::equal(
        recovery.begin(), recovery.end(), recovered.front().begin() + 10));

    assert(SocksSessionTestPeer::queue_before_open(
        *session, kStreamId, pending_payload));
    SocksSessionTestPeer::pause_local_sends(*session);
    SocksSessionTestPeer::deliver(
        *session, kStreamId, Tunnel::Bytes{0xf0, 0xf1});
    io.restart();
    io.poll();
    assert(SocksSessionTestPeer::pending_datagrams(*session) == 1U);
    assert(SocksSessionTestPeer::local_datagrams(*session) == 1U);
    SocksSessionTestPeer::close(*session);
    assert(SocksSessionTestPeer::pending_datagrams(*session) == 0U);
    assert(SocksSessionTestPeer::local_datagrams(*session) == 0U);
    assert(SocksSessionTestPeer::queued_local_sends(*session) == 0U);
}

void test_reverse_writes_own_and_serialize_backpressured_buffers() {
    using boost::asio::ip::tcp;

    boost::asio::io_context io;
    boost::asio::ssl::context tls_context(boost::asio::ssl::context::tls_client);
    auto tunnel = make_unstarted_tunnel(io, tls_context);
    auto session = std::make_shared<ReverseForwardSession>(
        tunnel, 1, "127.0.0.1", 1);

    tcp::acceptor acceptor(io, {tcp::v4(), 0});
    tcp::socket session_socket(io);
    session_socket.connect(acceptor.local_endpoint());
    tcp::socket receiver(io);
    acceptor.accept(receiver);
    boost::system::error_code buffer_error;
    receiver.set_option(
        boost::asio::socket_base::receive_buffer_size(
            kForcedSocketBufferBytes),
        buffer_error);
    assert(!buffer_error);
    ReverseForwardSessionTestPeer::attach_local_socket(
        *session, std::move(session_socket));

    constexpr std::array<std::uint8_t, 4> kSeeds{0x11, 0x47, 0x83, 0xd9};
    constexpr std::size_t kFrameSize = 512U * 1024U;
    Tunnel::Bytes expected;
    expected.reserve(kSeeds.size() * kFrameSize);
    std::size_t released_credit = 0U;
    std::size_t expected_credit = 0U;
    for (const std::uint8_t seed : kSeeds) {
        auto frame = make_frame(kFrameSize, seed);
        expected.insert(expected.end(), frame.begin(), frame.end());
        const std::size_t frame_credit = frame.size() + 8U;
        expected_credit += frame_credit;
        ReverseForwardSessionTestPeer::deliver(
            *session, frame,
            Tunnel::InboundCredit(
                frame_credit,
                [&](std::size_t bytes) { released_credit += bytes; }));

        // The tunnel callback's storage is not guaranteed to survive the post.
        // Reuse it immediately so the session must retain its own bytes.
        std::fill(frame.begin(), frame.end(), 0);
    }

    // Run only the delivery posts while the peer is not reading. The first
    // large write cannot complete through the deliberately small socket
    // buffers, so every later frame must remain in the owning queue.
    io.poll();
    assert(ReverseForwardSessionTestPeer::write_in_flight(*session));
    assert(ReverseForwardSessionTestPeer::queued_writes(*session) ==
           kSeeds.size() - 1);
    assert(ReverseForwardSessionTestPeer::pending_write_frames(*session) ==
           kSeeds.size());
    assert(ReverseForwardSessionTestPeer::pending_write_bytes(*session) ==
           expected.size());
    assert(released_credit == 0U);

    Tunnel::Bytes received(expected.size());
    boost::system::error_code read_error;
    std::size_t read_bytes = 0;
    bool timed_out = false;

    boost::asio::steady_timer timeout(io);
    timeout.expires_after(std::chrono::seconds(10));
    timeout.async_wait([&](const boost::system::error_code& error) {
        if (!error) {
            timed_out = true;
            io.stop();
        }
    });
    boost::asio::async_read(
        receiver,
        boost::asio::buffer(received),
        [&](const boost::system::error_code& error, std::size_t bytes) {
            read_error = error;
            read_bytes = bytes;
            boost::system::error_code ignored;
            timeout.cancel(ignored);
        });

    io.run();

    assert(!timed_out);
    assert(!read_error);
    assert(read_bytes == expected.size());
    assert(received == expected);
    assert(ReverseForwardSessionTestPeer::writer_idle(*session));
    assert(ReverseForwardSessionTestPeer::pending_write_frames(*session) == 0U);
    assert(ReverseForwardSessionTestPeer::pending_write_bytes(*session) == 0U);
    assert(released_credit == expected_credit);
}

void test_reverse_write_backlog_is_bounded() {
    using boost::asio::ip::tcp;
    using yume::runtime::kMaxInboundQueuedFrames;

    boost::asio::io_context io;
    boost::asio::ssl::context tls_context(boost::asio::ssl::context::tls_client);
    auto tunnel = make_unstarted_tunnel(io, tls_context);
    auto session = std::make_shared<ReverseForwardSession>(
        tunnel, 1, "127.0.0.1", 1);

    tcp::acceptor acceptor(io, {tcp::v4(), 0});
    tcp::socket session_socket(io);
    session_socket.connect(acceptor.local_endpoint());
    tcp::socket receiver(io);
    acceptor.accept(receiver);
    ReverseForwardSessionTestPeer::attach_local_socket(
        *session, std::move(session_socket));

    const auto frame = make_frame(256U * 1024U, 0x5a);
    for (std::size_t i = 0; i <= kMaxInboundQueuedFrames; ++i) {
        ReverseForwardSessionTestPeer::deliver(*session, frame);
    }
    io.poll();

    assert(ReverseForwardSessionTestPeer::closed(*session));
    assert(ReverseForwardSessionTestPeer::queued_writes(*session) == 0U);
    assert(ReverseForwardSessionTestPeer::pending_write_frames(*session) == 0U);
    assert(ReverseForwardSessionTestPeer::pending_write_bytes(*session) == 0U);
}

}  // namespace
}  // namespace yume::client

int main() {
    yume::client::test_udp_budget_bounds_bytes_and_recovers();
    yume::client::test_udp_forward_delayed_open_and_local_send_recovery();
    yume::client::test_socks_udp_delayed_open_send_recovery_and_close_cleanup();
    yume::client::test_reverse_writes_own_and_serialize_backpressured_buffers();
    yume::client::test_reverse_write_backlog_is_bounded();
    return 0;
}
