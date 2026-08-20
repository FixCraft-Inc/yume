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

struct ServerKeyCommand {
    std::string add;
    std::string remove;
    std::string alias;
    std::string alias_value;
    std::string generate_prefix;
    bool list = false;
    bool generate_and_add = false;
    // Enrol into the separate admin store rather than the visitor store.
    // Applies to --keys-add and --keys-gen-add.
    bool admin = false;
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
// Mints a composite Ed25519 + ML-DSA-87 identity. Both files hold the two PEM
// blocks concatenated in that fixed order.
bool generate_composite_keypair(const std::string& priv_path, const std::string& pub_path);

bool append_authorized_public_key(const yume::server::ServerConfig& cfg,
                                  const std::string& public_key_path,
                                  const std::string& alias,
                                  std::string* out_fingerprint = nullptr,
                                  bool to_admin_store = false);
CliCommandResult run_server_manager_ui(yume::server::ServerConfig& cfg, ServerKeyCommand& command);
CliCommandResult run_server_key_command(yume::server::ServerConfig& cfg, const ServerKeyCommand& command);

}  // namespace yume::server::cli
