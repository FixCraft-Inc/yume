/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/connect/auth.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/local/connect_pair.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include "client/transport/client_stream.hpp"
#include "core/protocol/protocol.hpp"
#include "core/stealth/h2_carrier.hpp"

namespace {

using namespace std::chrono_literals;
using yume::obfs::H2Bytes;
using yume::obfs::H2Carrier;
using yume::obfs::H2CarrierRole;

void Expect(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void Pump(H2Carrier& from, H2Carrier& to) {
    for (int iteration = 0; iteration < 32; ++iteration) {
        auto wire = from.TakeOutbound();
        if (wire.empty()) return;
        to.Feed(wire);
        Expect(!to.failed(), "HTTP/2 test carrier failed while pumping");
    }
    throw std::runtime_error("HTTP/2 test carriers did not quiesce");
}

void OpenCarrier(H2Carrier& client, H2Carrier& server) {
    Expect(client.StartClient("cover.example"),
           "failed to start test client carrier");
    Pump(client, server);
    Pump(server, client);

    auto requests = server.TakeRequests();
    Expect(requests.size() == 1,
           "test carrier did not receive the priming request");
    Expect(server.RespondHttp(
               requests[0].stream_id, 200,
               {{"content-type", "text/html"}}, {}),
           "failed to answer the priming request");
    Pump(server, client);
    Pump(client, server);

    requests = server.TakeRequests();
    Expect(requests.size() == 2,
           "test carrier did not receive both asset requests");
    for (const auto& request : requests) {
        Expect(server.RespondHttp(
                   request.stream_id, 200,
                   {{"content-type", "application/octet-stream"}}, {}),
               "failed to answer a priming asset request");
    }
    Pump(server, client);
    Pump(client, server);
    Expect(client.priming_complete(),
           "test client did not finish carrier priming");

    Expect(client.SubmitExtendedConnect("/carrier"),
           "failed to submit the test carrier CONNECT");
    Pump(client, server);
    requests = server.TakeRequests();
    Expect(requests.size() == 1,
           "test server did not receive the carrier CONNECT");
    Expect(server.AcceptCarrier(requests[0].stream_id),
           "failed to accept the test carrier");
    Pump(server, client);
    Pump(client, server);
    Expect(client.carrier_active() && server.carrier_active(),
           "test carrier did not become active");
}

bool HasWindowUpdate(const H2Bytes& wire, std::uint32_t stream_id) {
    for (std::size_t offset = 0; offset < wire.size();) {
        if (wire.size() - offset < 9) return false;
        const std::size_t length =
            (static_cast<std::size_t>(wire[offset]) << 16U) |
            (static_cast<std::size_t>(wire[offset + 1]) << 8U) |
            static_cast<std::size_t>(wire[offset + 2]);
        if (length + 9U > wire.size() - offset) return false;
        const auto type = wire[offset + 3];
        const auto id =
            (static_cast<std::uint32_t>(wire[offset + 5] & 0x7fU) << 24U) |
            (static_cast<std::uint32_t>(wire[offset + 6]) << 16U) |
            (static_cast<std::uint32_t>(wire[offset + 7]) << 8U) |
            static_cast<std::uint32_t>(wire[offset + 8]);
        if (type == 0x08 && id == stream_id) return true;
        offset += 9U + length;
    }
    return false;
}

void AuthReadRetiresOnlyDecodedCreditAndFlushesUpdate() {
    H2Carrier client(H2CarrierRole::Client);
    H2Carrier server(H2CarrierRole::Server);
    OpenCarrier(client, server);

    // Cross half of Chrome's 6-MiB stream receive window so retiring this
    // frame deterministically queues a stream WINDOW_UPDATE. The second frame
    // shares the final WebSocket message and therefore arrives prefetched.
    std::vector<std::uint8_t> first_payload(4U * 1024U * 1024U, 0x61);
    const auto first = yume::protocol::encode_frame(
        yume::protocol::AUTH, 0, 0, first_payload);
    const std::vector<std::uint8_t> second_payload{0x62, 0x63, 0x64};
    const auto second = yume::protocol::encode_frame(
        yume::protocol::ANON, 0, 0, second_payload);

    H2Bytes tunnel_bytes;
    tunnel_bytes.reserve(first.size() + second.size());
    tunnel_bytes.insert(tunnel_bytes.end(), first.begin(), first.end());
    tunnel_bytes.insert(tunnel_bytes.end(), second.begin(), second.end());
    Expect(server.SendBinary(tunnel_bytes),
           "failed to queue test authentication frames");
    auto server_wire = server.TakeOutbound();
    Expect(!server_wire.empty() && server.queued_output_bytes() == 0,
           "test authentication frames exceeded the peer receive window");

    boost::asio::io_context io;
    boost::asio::local::stream_protocol::socket local(io);
    boost::asio::local::stream_protocol::socket peer(io);
    boost::asio::local::connect_pair(local, peer);
    yume::client::ClientTransportStream stream(std::move(local), {}, {});

    std::exception_ptr writer_error;
    std::thread writer([&]() {
        try {
            boost::asio::write(peer, boost::asio::buffer(server_wire));
        } catch (...) {
            writer_error = std::current_exception();
        }
    });

    std::vector<std::uint8_t> prefetched;
    yume::protocol::Frame decoded;
    try {
        decoded = yume::client::read_frame_over_h2_with_timeout(
            stream, io, client, &prefetched, 5s, "test AUTH frame",
            "cover.example", 443);
    } catch (...) {
        stream.cancel_and_close();
        writer.join();
        throw;
    }
    writer.join();
    if (writer_error) std::rethrow_exception(writer_error);

    Expect(decoded.header.type == yume::protocol::AUTH &&
               decoded.payload == first_payload,
           "authentication reader decoded the wrong first frame");
    Expect(prefetched == second,
           "authentication reader did not preserve the prefetched tail");
    Expect(client.unconsumed_tunnel_bytes() == second.size(),
           "authentication reader retired prefetched tunnel credit");

    boost::system::error_code error;
    const auto available = peer.available(error);
    Expect(!error && available != 0,
           "authentication reader did not flush its H2 credit update");
    H2Bytes replies(available);
    const auto received = boost::asio::read(
        peer, boost::asio::buffer(replies), error);
    Expect(!error && received == replies.size(),
           "failed to read the flushed H2 credit update");
    Expect(HasWindowUpdate(
               replies,
               static_cast<std::uint32_t>(client.carrier_stream_id())),
           "authentication reader omitted the carrier WINDOW_UPDATE");

    auto decoded_tail = yume::client::read_frame_over_h2_with_timeout(
        stream, io, client, &prefetched, 5s, "test prefetched frame",
        "cover.example", 443);
    Expect(decoded_tail.header.type == yume::protocol::ANON &&
               decoded_tail.payload == second_payload,
           "authentication reader decoded the wrong prefetched frame");
    Expect(prefetched.empty() && client.unconsumed_tunnel_bytes() == 0,
           "authentication reader leaked prefetched receive credit");
}

void AuthH2ReadCancellationDrainsIo() {
    H2Carrier client(H2CarrierRole::Client);
    H2Carrier server(H2CarrierRole::Server);
    OpenCarrier(client, server);

    boost::asio::io_context io;
    boost::asio::local::stream_protocol::socket local(io);
    boost::asio::local::stream_protocol::socket peer(io);
    boost::asio::local::connect_pair(local, peer);
    yume::client::ClientTransportStream stream(std::move(local), {}, {});
    std::atomic<bool> stop_requested{false};
    std::thread interrupter([&]() {
        std::this_thread::sleep_for(30ms);
        stop_requested.store(true, std::memory_order_release);
    });

    std::vector<std::uint8_t> prefetched;
    bool cancelled = false;
    const auto started = std::chrono::steady_clock::now();
    try {
        (void)yume::client::read_frame_over_h2_with_timeout(
            stream, io, client, &prefetched, 2s, "test AUTH challenge",
            "cover.example", 443,
            [&]() { return stop_requested.load(std::memory_order_acquire); });
    } catch (const yume::client::FatalError& error) {
        cancelled = std::string(error.what()).find("cancelled") !=
                    std::string::npos;
    }
    const auto elapsed = std::chrono::steady_clock::now() - started;
    interrupter.join();
    Expect(cancelled, "stalled H2 AUTH read did not report cancellation");
    Expect(elapsed < 500ms, "stalled H2 AUTH read did not cancel promptly");
    io.restart();
    Expect(io.poll() == 0,
           "H2 AUTH cancellation left completion handlers queued");
}

}  // namespace

int main() {
    AuthReadRetiresOnlyDecodedCreditAndFlushesUpdate();
    AuthH2ReadCancellationDrainsIo();
    return 0;
}
