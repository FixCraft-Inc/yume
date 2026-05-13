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

}  // namespace yume::gui::platform
