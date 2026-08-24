/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "platform/png_writer.hpp"

// STATIC keeps every stb symbol internal to this object file. BaseFWX's
// image cipher compiles the same header, and without this the two
// implementations collide at link time.
#define STB_IMAGE_WRITE_STATIC
#define STB_IMAGE_WRITE_IMPLEMENTATION

#if defined(__GNUC__) || defined(__clang__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wunused-function"
#  pragma GCC diagnostic ignored "-Wsign-compare"
#  pragma GCC diagnostic ignored "-Wsign-conversion"
#  pragma GCC diagnostic ignored "-Wconversion"
#  pragma GCC diagnostic ignored "-Wold-style-cast"
#  pragma GCC diagnostic ignored "-Wcast-qual"
#  pragma GCC diagnostic ignored "-Wdouble-promotion"
#  pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

#include "third_party/stb/stb_image_write.h"

#if defined(__GNUC__) || defined(__clang__)
#  pragma GCC diagnostic pop
#endif

namespace yume::gui::platform {

bool write_png_rgba(std::string const& path,
                    int width,
                    int height,
                    unsigned char const* pixels) {
    if (width <= 0 || height <= 0 || pixels == nullptr) return false;
    return stbi_write_png(path.c_str(), width, height, 4, pixels,
                          width * 4) != 0;
}

}  // namespace yume::gui::platform
