/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <string>

namespace yume::server_cli {

std::string read_file_bytes(const std::string& path);
std::string cert_fingerprint_sha256(const std::string& cert_path);
std::string sha256_hex(const std::string& data);
std::string get_self_path(const char* argv0);
std::string resolve_filter_list_spec_path(const std::string& spec,
                                          const std::string& base_dir,
                                          const std::string& exe_dir);

}  // namespace yume::server_cli
