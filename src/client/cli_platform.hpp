/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <string>

namespace yume::client {

std::string get_self_path(const char* argv0);
std::string get_system_hostname();

}  // namespace yume::client
