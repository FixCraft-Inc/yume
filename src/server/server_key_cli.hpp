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

bool file_readable(const std::string& path);
bool ensure_dir(const std::string& dir);
std::string load_or_create_secret(const std::string& path);
bool generate_ed25519_keypair(const std::string& priv_path, const std::string& pub_path);
std::string auth_keys_write_hint(const std::string& path);
bool append_authorized_public_key(const yume::server::ServerConfig& cfg,
                                  const std::string& public_key_path,
                                  const std::string& alias,
                                  std::string* out_fingerprint = nullptr);

}  // namespace yume::server_cli
