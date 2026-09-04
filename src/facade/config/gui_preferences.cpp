/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/config/gui_preferences.hpp"

#include <fstream>

#include <nlohmann/json.hpp>

#include "core/runtime/atomic_file.hpp"
#include "facade/config/config_io.hpp"
#include "facade/config/detail.hpp"
#include "facade/config/keys.hpp"

namespace yume::facade::config_io {

using nlohmann::json;
using detail::read_opt;
namespace cfg_key = keys;

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
    json j = {{cfg_key::dark_mode, prefs.dark_mode},
              {cfg_key::minimize_to_tray_on_close, prefs.minimize_to_tray_on_close}};
    return yume::runtime::AtomicWriteFile(
        path, j.dump(2), nullptr,
        yume::runtime::ParentDirectoryPolicy::Create);
}

}  // namespace yume::facade::config_io
