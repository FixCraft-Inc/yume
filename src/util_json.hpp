/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

// Split out of util.hpp so the ~136k preprocessed lines of nlohmann/json.hpp
// are paid only by the two call sites that actually read a JSON config, not by
// every translation unit that wanted log_info().

#include <string>

#include <nlohmann/json.hpp>

namespace yume::util {

nlohmann::json read_json_config(const std::string& path);

}  // namespace yume::util
