/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/connect/io.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <thread>

#include <boost/asio/ssl.hpp>

namespace {

void TestAlreadyCancelledResolve() {
    boost::asio::io_context io;
    boost::asio::ip::tcp::resolver resolver(io);
    const auto result = yume::client::resolve_with_timeout(
        resolver, io, "localhost", "443", std::chrono::seconds(2),
        [] { return true; });
    if (!result.cancelled || result.timed_out || !result.endpoints.empty()) {
        throw std::runtime_error("cancelled resolve did not stop before work");
    }
}

void TestBlockedReadCancellation() {
    using boost::asio::ip::tcp;
    using namespace std::chrono_literals;

    boost::asio::io_context io;
    tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 0));
    tcp::socket peer(io);
    tcp::socket client(io);
    client.connect(acceptor.local_endpoint());
    peer = acceptor.accept();

    std::atomic<bool> stop{false};
    std::thread canceller([&]() {
        std::this_thread::sleep_for(30ms);
        stop.store(true, std::memory_order_release);
    });
    std::array<std::uint8_t, 1> byte{};
    const auto started = std::chrono::steady_clock::now();
    const auto result = yume::client::read_some_with_timeout(
        client, io, boost::asio::buffer(byte), 2s,
        [&]() {
            boost::system::error_code ignored;
            client.cancel(ignored);
            client.close(ignored);
        },
        [&]() { return stop.load(std::memory_order_acquire); });
    const auto elapsed = std::chrono::steady_clock::now() - started;
    canceller.join();
    if (!result.cancelled || result.timed_out || elapsed >= 500ms) {
        throw std::runtime_error("blocked read cancellation was not prompt");
    }
}

void TestTlsHandshakeCancellation() {
    using boost::asio::ip::tcp;
    using namespace std::chrono_literals;

    boost::asio::io_context server_io;
    tcp::acceptor acceptor(server_io, tcp::endpoint(tcp::v4(), 0));
    std::atomic<bool> release_server{false};
    std::thread server([&]() {
        boost::system::error_code error;
        tcp::socket peer(server_io);
        acceptor.accept(peer, error);
        while (!error && !release_server.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(1ms);
        }
    });

    boost::asio::io_context client_io;
    boost::asio::ssl::context context(boost::asio::ssl::context::tls_client);
    context.set_verify_mode(boost::asio::ssl::verify_none);
    boost::asio::ssl::stream<tcp::socket> stream(client_io, context);
    stream.lowest_layer().connect(acceptor.local_endpoint());

    std::atomic<bool> stop{false};
    std::thread canceller([&]() {
        std::this_thread::sleep_for(30ms);
        stop.store(true, std::memory_order_release);
    });
    const auto started = std::chrono::steady_clock::now();
    const auto result = yume::client::handshake_with_timeout(
        stream, client_io, 2s,
        [&]() { return stop.load(std::memory_order_acquire); });
    const auto elapsed = std::chrono::steady_clock::now() - started;
    canceller.join();
    release_server.store(true, std::memory_order_release);
    server.join();
    if (!result.cancelled || result.timed_out || elapsed >= 500ms) {
        throw std::runtime_error("TLS handshake cancellation was not prompt");
    }
}

}  // namespace

int main() {
    using boost::asio::ip::tcp;
    using namespace std::chrono_literals;

    boost::asio::io_context server_io;
    tcp::acceptor acceptor(server_io, tcp::endpoint(tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();
    std::thread server([&]() {
        boost::system::error_code ec;
        tcp::socket accepted(server_io);
        acceptor.accept(accepted, ec);
    });

    boost::asio::io_context client_io;
    tcp::resolver resolver(client_io);
    auto endpoints = resolver.resolve(
        tcp::v4(), "127.0.0.1", std::to_string(port));
    tcp::socket socket(client_io);
    std::atomic<int> protect_calls{0};
    auto connected = yume::client::connect_with_timeout(
        socket, endpoints, client_io, 2s,
        [&](std::intptr_t handle) {
            ++protect_calls;
            return handle >= 0;
        });
    if (connected.ec || connected.timed_out || protect_calls.load() != 1) {
        std::cerr << "protected connect failed\n";
        socket.close();
        acceptor.close();
        server.join();
        return 1;
    }
    socket.close();
    server.join();

    tcp::socket denied_socket(client_io);
    auto denied = yume::client::connect_with_timeout(
        denied_socket, endpoints, client_io, 2s,
        [](std::intptr_t) { return false; });
    if (!denied.ec || denied.timed_out || denied_socket.is_open() ||
        denied.ec != boost::system::errc::make_error_code(
                         boost::system::errc::permission_denied)) {
        std::cerr << "denied socket did not fail closed\n";
        return 2;
    }
    TestAlreadyCancelledResolve();
    TestBlockedReadCancellation();
    TestTlsHandshakeCancellation();
    return 0;
}
