/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/connect/io.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <thread>

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
    return 0;
}
