#pragma once

#include <string>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace yume::obfs {

boost::asio::ssl::context create_server_context(const std::string& cert_path,
                                               const std::string& key_path,
                                               bool allow_h2 = true);
boost::asio::ssl::context create_client_context();
void configure_alpn(boost::asio::ssl::context& ctx, bool is_server, bool allow_h2 = true);

// Sends a profile-driven 404 response and returns. `profile_name`
// is a yume::http_profile::ServerProfile key (e.g. "nginx", "apache",
// "yumed"). Empty string or unknown name falls back to "yumed" so a
// typo can't take down a connection.
//
// Per-write traffic shaping (jitter, frame-level padding) is NOT in
// this header. Send-side jitter lives in:
//   - Session::do_write (server) gated on cfg_.obfs_jitter_ms
//   - Tunnel::set_obfs_shape (client) consumed in the write_handler
// Frame-level padding lives on the wire as protocol::kFlagPadded; see
// protocol::encode_frame's pad_multiple parameter. Operators enable
// both via the --obfs-jitter-ms / --obfs-pad-multiple flags.
void send_dummy_http_response(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                              const std::string& profile_name = "yumed");

}  // namespace yume::obfs
