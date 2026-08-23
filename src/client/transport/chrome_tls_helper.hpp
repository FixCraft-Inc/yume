/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include "client/transport/client_stream.hpp"

namespace yume::client {

struct ChromeTlsHelperOptions {
    std::filesystem::path helper_path;
    std::string server_name;
    std::filesystem::path ca_path;
    std::vector<std::uint8_t> leaf_pin;
    std::chrono::milliseconds handshake_timeout{12000};
    // Polled while waiting for the helper's READY response. The predicate
    // must be non-blocking; true aborts and reaps the helper before return.
    std::function<bool()> should_stop;
};

// The caller establishes and routes the TCP socket first. On success this
// function transfers that connected descriptor to one pinned helper process
// and returns the private authenticated-plaintext side of a Unix socketpair.
ClientTransportStream LaunchChromeTlsHelper(
    boost::asio::io_context& io,
    boost::asio::ip::tcp::socket&& connected_socket,
    const ChromeTlsHelperOptions& options);

std::filesystem::path DiscoverChromeTlsHelper(
    const std::filesystem::path& client_executable);

}  // namespace yume::client
