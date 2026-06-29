/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>

namespace yume::client {

struct ClientConfig;

bool resolve_relay_secret(const ClientConfig& cfg,
                          const std::string& explicit_password,
                          const std::string& purpose,
                          std::string* relay_secret_b64,
                          std::string* error);

}  // namespace yume::client
