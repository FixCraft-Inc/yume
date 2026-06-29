/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>

namespace yume::server {
struct ServerConfig;
}

namespace yume::server_cli {

struct ServerConfigOverrides {
    bool obfuscation = false;
    bool inner_crypto = false;
    bool inner_dual = false;
    bool inner_required = false;
    bool inner_hop = false;
    bool hop_interval = false;
    bool anonym = false;
    bool anonym_proof_mode = false;
    bool pq_auto_generate = false;
    bool allow_embedded_master = false;
    bool tls_handshake_timeout = false;
    bool max_sessions = false;
    bool accept_rate_limit = false;
    bool egress_mbps = false;
    bool client_filter_mode = false;
    bool egress_filter_mode = false;
    bool filter_geolite = false;
    bool filter_memory_mib = false;
    bool packet_egress = false;
    bool packet_tun_name = false;
    bool packet_cidr = false;
    bool packet_mtu = false;
    bool relay_enable = false;
    bool directory_enable = false;
};

struct ServerConfigLoadContext {
    std::string config_path{"config/yumed.json"};
    bool config_specified{false};
    std::string exe_dir;
    std::string config_dir;
};

bool load_server_config_file_and_resolve_paths(yume::server::ServerConfig& cfg,
                                               ServerConfigLoadContext& context,
                                               const ServerConfigOverrides& overrides);

}  // namespace yume::server_cli
