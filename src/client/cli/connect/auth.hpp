/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <boost/asio.hpp>
#include "client/transport/client_stream.hpp"
#include "core/security/crypto.hpp"
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

protocol::Frame read_auth_challenge(ClientTransportStream& stream,
                                    boost::asio::io_context& io,
                                    const std::string& server_host,
                                    int server_port,
                                    std::vector<uint8_t>* prefetched = nullptr,
                                    obfs::H2Carrier* carrier = nullptr);

std::unique_ptr<ratchet::SessionRatchet> send_auth_v2_response(
    ClientTransportStream& stream,
    boost::asio::io_context& io,
    const std::string& identity_path,
    const protocol::Frame& challenge,
    const security::Secret32& inner_psk,
    crypto::Bytes channel_binding,
    obfs::H2Carrier& carrier,
    std::uint16_t rekey_window,
    const ratchet::RatchetPolicy& ratchet_policy);

protocol::Frame open_auth_ok_v2(ratchet::SessionRatchet& ratchet,
                                const protocol::Frame& protected_frame);

protocol::Frame read_frame_over_h2_with_timeout(
    ClientTransportStream& stream,
    boost::asio::io_context& io,
    obfs::H2Carrier& carrier,
    std::vector<uint8_t>* prefetched,
    std::chrono::milliseconds timeout,
    const char* what,
    const std::string& server_host,
    int server_port);

void send_frame_over_h2_with_timeout(
    ClientTransportStream& stream,
    boost::asio::io_context& io,
    obfs::H2Carrier& carrier,
    const protocol::Frame& frame,
    std::chrono::milliseconds timeout,
    const char* what);

void require_h2_carrier_alpn(ClientTransportStream& stream,
                             const std::string& server_host,
                             int server_port);

void perform_h2_carrier_handshake(ClientTransportStream& stream,
                                  boost::asio::io_context& io,
                                  const std::string& server_host,
                                  int server_port,
                                  const security::Secret32& obfs_secret,
                                  std::vector<uint8_t>* prefetched = nullptr,
                                  std::unique_ptr<obfs::H2Carrier>* carrier_out = nullptr,
                                  std::shared_ptr<obfs::OuterCarrierTrace> outer_trace = {});

}  // namespace yume::client
