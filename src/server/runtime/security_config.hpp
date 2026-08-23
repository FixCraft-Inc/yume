/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>

namespace yume::server {

struct ServerConfig;

// Validate the mandatory YUME 2.0 carrier/inner-security inputs and load both
// secret files into wipeable material. This is a runtime invariant, not a CLI
// convenience: every server entry point (CLI, facade, or C ABI) must cross it
// before constructing sessions.
bool prepare_v2_security_config(ServerConfig& cfg,
                                bool key_management_only,
                                std::string* error);

}  // namespace yume::server
