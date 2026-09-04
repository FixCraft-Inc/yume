/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/config/config_io.hpp"

#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

#include "core/runtime/atomic_file.hpp"
#include "facade/config/detail.hpp"
#include "facade/config/keys.hpp"

namespace yume::facade::config_io {

using nlohmann::json;
using detail::read_opt;
namespace cfg_key = keys;

std::filesystem::path default_data_dir() {
    return detail::home_dir() / ".yume";
}

std::filesystem::path default_client_config_path() {
    return default_data_dir() / "client.json";
}

std::filesystem::path default_server_config_path() {
    return default_data_dir() / "server.json";
}

}  // namespace yume::facade::config_io
