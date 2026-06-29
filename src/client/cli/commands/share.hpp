/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>

namespace yume::client {

struct ClientConfig;

int run_export_share(const std::string& out_path,
                     const ClientConfig& cfg,
                     bool password_stdin);
int run_import_share(const std::string& in_path, bool password_stdin);

}  // namespace yume::client
