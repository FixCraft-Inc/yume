/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

namespace yume::server {
struct ServerConfig;
}

namespace yume::server::cli {

int prepare_server_runtime_files(yume::server::ServerConfig& cfg, const char* argv0, bool key_command_active);

}  // namespace yume::server::cli
