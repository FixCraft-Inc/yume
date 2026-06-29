/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>

namespace yume::client {

struct ClientConfig;
struct ParsedArgs;

bool prompt_attach_existing(const std::string& kind);
std::string effective_client_instance_key(const ClientConfig& cfg, const ParsedArgs& args);
int run_local_client_attach(const std::string& socket_path, const ParsedArgs& args, const ClientConfig& cfg);

}  // namespace yume::client
