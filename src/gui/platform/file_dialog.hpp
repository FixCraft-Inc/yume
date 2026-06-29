/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace yume::gui::platform {

// GLFW window used for nested ImGui picker loops when no native dialog exists.
void set_dialog_parent_window(void* glfw_window);

std::optional<std::filesystem::path> open_file_dialog(std::string const& title,
                                                       std::string* err = nullptr);

// Save-as picker. `default_name` pre-fills the filename field (e.g.
// "yume-backup.yss"); pass empty to leave it blank. On systems that
// don't ship a native picker (no zenity / kdialog / yad on PATH),
// returns nullopt and sets *err.
std::optional<std::filesystem::path> save_file_dialog(std::string const& title,
                                                       std::string const& default_name,
                                                       std::string* err = nullptr);

}  // namespace yume::gui::platform
