/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/config/config_io.hpp"

#include <filesystem>
#include <fstream>
#include <system_error>

#include <nlohmann/json.hpp>

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

std::filesystem::path default_gui_preferences_path() {
    return default_data_dir() / "gui.json";
}

GuiPreferences load_gui_preferences() {
    GuiPreferences out;
    std::ifstream in(default_gui_preferences_path());
    if (!in) return out;
    try {
        json j;
        in >> j;
        if (j.is_object()) {
            read_opt(j, cfg_key::dark_mode, out.dark_mode);
            read_opt(j, cfg_key::minimize_to_tray_on_close, out.minimize_to_tray_on_close);
        }
    } catch (...) {
        // Malformed JSON: fall back to defaults silently. The next save
        // rewrites the preferences file cleanly.
    }
    return out;
}

bool save_gui_preferences(GuiPreferences const& prefs) {
    const auto path = default_gui_preferences_path();
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    json j = {{cfg_key::dark_mode, prefs.dark_mode},
              {cfg_key::minimize_to_tray_on_close, prefs.minimize_to_tray_on_close}};
    std::ofstream out(path);
    if (!out) return false;
    out << j.dump(2);
    return out.good();
}

}  // namespace yume::facade::config_io
