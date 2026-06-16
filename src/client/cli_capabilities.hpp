/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <cstdint>
#include <string>

namespace yume::client {

struct ServerCapabilityInput {
    std::string server_version;
    std::string server_inner_mode;
    std::string inner_kdf_name;
    bool inner_crypto_requested = false;
    bool inner_disabled_for_session = false;
    bool inner_heavy = false;
    bool inner_hop = false;
    bool inner_key_established = false;
    bool have_inner_caps = false;
    bool server_inner_supported = false;
    bool server_inner_required = false;
    bool server_inner_dual = false;
    bool server_cap_pq = false;
    bool server_cap_argon2 = false;
    bool server_cap_pbkdf2 = false;
    bool server_hop_enabled = false;
    std::uint32_t client_hop_interval_ms = 0;
    std::uint32_t server_hop_interval_ms = 0;
    std::int64_t server_time_ms = 0;
};

struct ServerCapabilityResult {
    std::string error;
    bool want_inner = false;
    bool hop_enabled = false;
    std::uint32_t hop_interval_ms = 0;
    std::int64_t hop_offset_ms = 0;
};

ServerCapabilityResult evaluate_server_capabilities(const ServerCapabilityInput& input);

}  // namespace yume::client
