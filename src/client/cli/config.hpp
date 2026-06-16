/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <string>

#include "client/cli.hpp"
#include "client/cli/args.hpp"

namespace yume::client {

void resolve_config_path(ParsedArgs* args, const std::string& exe_dir);
void load_client_config_file(const ParsedArgs& args,
                             const std::string& exe_dir,
                             ClientConfig* cfg);
void apply_cli_config_overrides(const ParsedArgs& args,
                                const std::string& cli_cwd,
                                ClientConfig* cfg);
void save_client_config_file(const ParsedArgs& args, const ClientConfig& cfg);

}  // namespace yume::client
