/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "platform/tray.hpp"

namespace yume::gui::tray_icon {

constexpr int kIconSize = 64;

struct Px {
    std::uint8_t r, g, b, a;
};

std::filesystem::path icon_directory();
std::vector<std::uint8_t> rasterise_base(int size);
void paint_status_dots(std::uint8_t* pixels, int size, TrayStatus const& st);
std::string write_status_png(TrayStatus const& st,
                             std::filesystem::path const& dir,
                             std::string const& digest);
std::string status_digest(TrayStatus const& st);

}  // namespace yume::gui::tray_icon
