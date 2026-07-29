/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "core/security/crypto.hpp"
#include "core/security/inner_crypto.hpp"
#include "core/security/secret_file.hpp"
#include "core/protocol/protocol.hpp"
#include "core/stealth/h2_carrier.hpp"
#include "core/security/session_ratchet.hpp"

namespace yume::client {

inline constexpr std::chrono::milliseconds kConnectTimeout{10000};
inline constexpr std::chrono::milliseconds kHandshakeTimeout{12000};
inline constexpr std::chrono::milliseconds kAuthChallengeTimeout{6000};
inline constexpr std::chrono::milliseconds kServerInfoTimeout{6000};
inline constexpr std::chrono::milliseconds kServerInfoTimeoutInner{20000};
inline constexpr std::chrono::milliseconds kServerInfoTimeoutInnerHeavy{45000};

protocol::Frame read_auth_challenge(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                                    boost::asio::io_context& io,
                                    const std::string& server_host,
                                    int server_port,
                                    std::vector<uint8_t>* prefetched = nullptr,
                                    obfs::H2Carrier* carrier = nullptr);

inner::Argon2Limits parse_auth_challenge_argon2_limits(const protocol::Frame& challenge);
std::string describe_argon2_limits(const inner::Argon2Limits& limits);

void send_auth_response(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                        const std::string& identity_path,
                        const protocol::Frame& challenge,
                        const std::optional<crypto::Bytes>& pq_ciphertext,
                        const std::optional<crypto::Bytes>& pq_salt,
                        const std::optional<std::string>& inner_mode,
                        const std::optional<bool>& inner_hop,
                        const std::optional<inner::KdfParams>& inner_kdf,
                        boost::asio::io_context* io = nullptr,
                        obfs::H2Carrier* carrier = nullptr);

std::unique_ptr<ratchet::SessionRatchet> send_auth_v2_response(
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
    boost::asio::io_context& io,
    const std::string& identity_path,
    const protocol::Frame& challenge,
    const security::Secret32& inner_psk,
    obfs::H2Carrier& carrier,
    std::uint16_t rekey_window);

protocol::Frame open_auth_ok_v2(ratchet::SessionRatchet& ratchet,
                                const protocol::Frame& protected_frame);

protocol::Frame read_frame_over_h2_with_timeout(
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
    boost::asio::io_context& io,
    obfs::H2Carrier& carrier,
    std::vector<uint8_t>* prefetched,
    std::chrono::milliseconds timeout,
    const char* what,
    const std::string& server_host,
    int server_port);

void send_frame_over_h2_with_timeout(
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
    boost::asio::io_context& io,
    obfs::H2Carrier& carrier,
    const protocol::Frame& frame,
    std::chrono::milliseconds timeout,
    const char* what);

void require_h2_carrier_alpn(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                             const std::string& server_host,
                             int server_port);

void perform_h2_carrier_handshake(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                                  boost::asio::io_context& io,
                                  const std::string& server_host,
                                  int server_port,
                                  const security::Secret32& obfs_secret,
                                  std::string_view user_agent,
                                  std::vector<uint8_t>* prefetched = nullptr,
                                  std::unique_ptr<obfs::H2Carrier>* carrier_out = nullptr);

}  // namespace yume::client
