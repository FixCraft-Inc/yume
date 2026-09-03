/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/ssl.h>

namespace yume::obfs {

boost::asio::ssl::context create_server_context(const std::string& cert_path,
                                               const std::string& key_path,
                                               bool allow_h2 = true);
boost::asio::ssl::context create_client_context();
void configure_alpn(boost::asio::ssl::context& ctx, bool is_server, bool allow_h2 = true);
std::vector<std::string> carrier_alpn_protocols(bool allow_h2 = true);
std::vector<unsigned char> carrier_alpn_wire(bool allow_h2 = true);
std::string select_carrier_alpn(const unsigned char* peer_protos,
                                unsigned int peer_protos_len,
                                bool allow_h2 = true);
std::string selected_alpn(const SSL* ssl);

// Profile-driven HTTP disguise (404 responses) lives in
// Session::send_disguise_404 (server/session/carrier.cpp), not here.
//
// Per-write traffic shaping (jitter, frame-level padding) is NOT in
// this header. Send-side jitter lives in:
//   - Session::do_write (server) gated on cfg_.obfs_jitter_ms
//   - Tunnel::set_obfs_shape (client) consumed in the write_handler
// Frame-level padding lives on the wire as protocol::kFlagPadded. See
// protocol::encode_frame's pad_multiple parameter. Operators enable both
// through the obfs_jitter_ms / obfs_pad_multiple config keys. There are no
// command-line flags for either.

}  // namespace yume::obfs
