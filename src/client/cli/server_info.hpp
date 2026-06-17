/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/protocol/protocol.hpp"

namespace yume::client {

struct ServerInfoPayload {
    std::string version;
    std::string error;
    std::string mode = "normal";
    std::string hash;
    std::string sig;
    std::string ts;
    std::string nonce;
    std::string certfp;
    std::string ca_sig;
    std::string ca_alg;
    std::string sub_sig;
    std::string sub_alg;
    std::string sub_cert_b64;
    std::string pq_pub_b64;
    std::string pq_sig;
    std::string pq_alg;
    std::vector<std::string> announced_proof_sources;

    bool have_inner_caps = false;
    bool server_inner_supported = false;
    bool server_inner_required = false;
    bool server_inner_dual = false;
    bool server_inner_active = false;
    std::string server_inner_mode;
    bool server_cap_pq = false;
    bool server_cap_argon2 = false;
    bool server_cap_pbkdf2 = false;
    bool server_hop_enabled = false;
    std::uint32_t server_hop_interval_ms = 0;
    std::int64_t server_time_ms = 0;
};

ServerInfoPayload parse_server_info_payload(const protocol::Frame& frame);

}  // namespace yume::client
