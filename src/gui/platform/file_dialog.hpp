/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace yume::gui::platform {

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
