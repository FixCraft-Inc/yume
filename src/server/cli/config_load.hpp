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

namespace yume::server::cli {

struct ServerConfigOverrides {
    bool listen = false;
    bool threads = false;
    bool obfuscation = false;
    bool inner_crypto = false;
    bool pq_auto_generate = false;
    bool anonym = false;
    bool anonym_proof_mode = false;
    bool allow_embedded_master = false;
    bool tls_handshake_timeout = false;
    bool max_sessions = false;
    bool bulk_key_max_sessions = false;
    bool rekey_window = false;
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
    bool host_mode = false;
    bool accept_yume_clients = false;
    bool client_deny_action = false;
    bool exposure_check_hostname = false;
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

}  // namespace yume::server::cli
