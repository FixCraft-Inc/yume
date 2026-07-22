/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Outbound SOCKS5 client: dial through a SOCKS5 proxy (Tor, sshuttle,
 * stunnel, etc.) to reach the Yume server. The destination hostname is
 * carried as a SOCKS5 ATYP_DOMAIN so that .onion addresses resolve on
 * the proxy side (Tor never does plain-DNS for .onion).
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <string>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "client/transport/socket_protection.hpp"

namespace yume::client::outbound_proxy {

enum class Type {
    None,    // direct TCP connect, no proxy
    Socks5,  // SOCKS5 (RFC 1928 + RFC 1929 username/password)
};

struct Config {
    Type type{Type::None};
    std::string host;      // proxy host (e.g. "127.0.0.1")
    int         port{0};   // proxy port (e.g. 9050 for Tor)
    std::string username;  // optional, RFC 1929 auth
    std::string password;
};

struct DialResult {
    bool        ok{false};
    bool        timed_out{false};
    std::string error;
};

// Connects `sock` to `cfg.host:cfg.port` and then performs the SOCKS5
// handshake telling the proxy to forward to `target_host:target_port`.
// `target_host` is sent verbatim as ATYP_DOMAIN; for .onion targets
// that's exactly what Tor expects. Synchronous (drives `io` internally)
// so it slots into the existing connect_with_timeout pattern. The
// caller's resolved endpoints / direct-connect path is unaffected when
// cfg.type == Type::None — that branch is handled in entry.cpp.
DialResult socks5_dial(boost::asio::ip::tcp::socket& sock,
                       boost::asio::io_context& io,
                       Config const& cfg,
                       std::string const& target_host,
                       int target_port,
                       std::chrono::milliseconds timeout,
                       const SocketProtectCallback& protect_socket = {});

// "socks5://[user[:pass]@]host:port" — parse helper used by both the
// CLI flag and the JSON config loader. Returns false (and fills err)
// when the URL doesn't fit the supported shape.
bool parse_proxy_url(std::string const& url, Config& out, std::string* err = nullptr);

}  // namespace yume::client::outbound_proxy
