/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>

namespace yume::gui::platform {

// Writes a top-left-origin RGBA8 image to `path` as PNG.
//
// This lives in its own translation unit because BaseFWX's image cipher also
// compiles stb_image_write, and two implementations in one link produce
// duplicate symbols. Here the implementation is compiled with static linkage
// so the two copies cannot collide.
bool write_png_rgba(std::string const& path,
                    int width,
                    int height,
                    unsigned char const* pixels);

}  // namespace yume::gui::platform
