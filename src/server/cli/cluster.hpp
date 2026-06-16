/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <string>

namespace yume::server_cli {

std::string expand_cluster_join_spec(const std::string& spec);

}  // namespace yume::server_cli
