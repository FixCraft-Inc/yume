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

struct ServerKeyCommand {
    std::string add;
    std::string remove;
    std::string alias;
    std::string alias_value;
    std::string generate_prefix;
    bool list = false;
    bool generate_and_add = false;
    bool ui = false;

    bool has_action() const;
};

struct CliCommandResult {
    bool handled = false;
    int exit_code = 0;
};

bool file_readable(const std::string& path);
bool ensure_dir(const std::string& dir);
std::string load_or_create_secret(const std::string& path);
bool generate_ed25519_keypair(const std::string& priv_path, const std::string& pub_path);
std::string auth_keys_write_hint(const std::string& path);
bool append_authorized_public_key(const yume::server::ServerConfig& cfg,
                                  const std::string& public_key_path,
                                  const std::string& alias,
                                  std::string* out_fingerprint = nullptr);
CliCommandResult run_server_manager_ui(yume::server::ServerConfig& cfg, ServerKeyCommand& command);
CliCommandResult run_server_key_command(yume::server::ServerConfig& cfg, const ServerKeyCommand& command);

}  // namespace yume::server_cli
