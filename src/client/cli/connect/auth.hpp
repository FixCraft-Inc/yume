/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "core/security/crypto.hpp"
#include "core/security/inner_crypto.hpp"
#include "core/protocol/protocol.hpp"

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
                                    std::vector<uint8_t>* prefetched = nullptr);

inner::Argon2Limits parse_auth_challenge_argon2_limits(const protocol::Frame& challenge);
std::string describe_argon2_limits(const inner::Argon2Limits& limits);

void send_auth_response(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                        const std::string& identity_path,
                        const protocol::Frame& challenge,
                        const std::optional<crypto::Bytes>& pq_ciphertext,
                        const std::optional<crypto::Bytes>& pq_salt,
                        const std::optional<std::string>& inner_mode,
                        const std::optional<bool>& inner_hop,
                        const std::optional<inner::KdfParams>& inner_kdf);

void require_h2_carrier_alpn(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                             const std::string& server_host,
                             int server_port);

void perform_h2_carrier_handshake(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                                  boost::asio::io_context& io,
                                  const std::string& server_host,
                                  int server_port,
                                  const std::string& obfs_secret,
                                  std::string_view user_agent,
                                  std::vector<uint8_t>* prefetched = nullptr);

}  // namespace yume::client
