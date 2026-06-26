/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <string>

#include "server/cli/config_load.hpp"
#include "server/cli/key.hpp"

namespace yume::server {
struct ServerConfig;
}

namespace yume::server_cli {

struct ServerCliParseResult {
    bool handled{false};
    int exit_code{0};

    ServerConfigLoadContext config_context;
    ServerConfigOverrides config_overrides;
    ServerKeyCommand key_command;

    bool inner_heavy_override{false};
    bool inner_heavy_value{true};
    bool inner_hop_override{false};
    bool inner_hop_value{true};
    bool attach_local{false};
    bool keep_root{false};
};

bool parse_server_cli_args(int argc,
                           char** argv,
                           const std::string& cli_cwd,
                           yume::server::ServerConfig& cfg,
                           ServerCliParseResult* out);

}  // namespace yume::server_cli
