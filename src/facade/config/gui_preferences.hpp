/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <filesystem>

// Desktop application preferences. These belong to yume_facade rather than
// yume_embed: an embedder has no theme and no tray, and the shared library
// must not carry either.
namespace yume::facade::config_io {

// Unknown JSON keys are ignored on load, and missing keys fall back to the
// defaults below.
struct GuiPreferences {
    bool dark_mode{true};
    bool minimize_to_tray_on_close{true};
};

std::filesystem::path default_gui_preferences_path();
GuiPreferences load_gui_preferences();
bool save_gui_preferences(GuiPreferences const& prefs);

}  // namespace yume::facade::config_io
