/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <string>

namespace yume::server {
struct ServerConfig;
}

namespace yume::server_cli {

struct StartupCheckOptions {
    bool tls_handshake_timeout_overridden{false};
    bool max_sessions_overridden{false};
    bool accept_rate_limit_overridden{false};
    bool key_management_only{false};
    std::string default_secret_path;
};

bool prepare_server_startup_config(yume::server::ServerConfig& cfg,
                                   const StartupCheckOptions& options);

}  // namespace yume::server_cli
