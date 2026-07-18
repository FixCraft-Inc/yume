/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>

namespace yume::server::cli {

std::string expand_cluster_join_spec(const std::string& spec);

}  // namespace yume::server::cli
