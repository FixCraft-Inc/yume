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

bool prompt_attach_existing(const std::string& kind);
bool stdin_is_tty();
std::string effective_server_instance_key(const yume::server::ServerConfig& cfg, const std::string& config_path);
int run_local_server_attach(const std::string& socket_path, bool non_interactive);

}  // namespace yume::server_cli
