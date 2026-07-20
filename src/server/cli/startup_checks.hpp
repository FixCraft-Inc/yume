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

struct StartupCheckOptions {
    bool tls_handshake_timeout_overridden{false};
    bool accept_rate_limit_overridden{false};
    bool key_management_only{false};
    std::string default_secret_path;
};

bool prepare_server_startup_config(yume::server::ServerConfig& cfg,
                                   const StartupCheckOptions& options);

}  // namespace yume::server::cli
