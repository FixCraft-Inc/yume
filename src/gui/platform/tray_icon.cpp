/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "platform/tray_icon.hpp"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#define STB_IMAGE_WRITE_STATIC
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb/stb_image_write.h"

#include <nanosvg.h>
#include <nanosvgrast.h>

#include "app_icon_data.hpp"
#include "facade/config/config_io.hpp"

namespace yume::gui::tray_icon {

namespace {

void paint_pixel(Px& dst, Px const& src) {
    const float a = src.a / 255.0f;
    const float inv = 1.0f - a;
    dst.r = static_cast<std::uint8_t>(src.r * a + dst.r * inv);
    dst.g = static_cast<std::uint8_t>(src.g * a + dst.g * inv);
    dst.b = static_cast<std::uint8_t>(src.b * a + dst.b * inv);
    dst.a = std::max<std::uint8_t>(dst.a, src.a);
}

void paint_dot(std::uint8_t* pixels, int size, int cx, int cy, int r, Px fill) {
    const float feather = 1.2f;
    const float r_outer = static_cast<float>(r);
    const float r_inner = r_outer - feather;
    for (int y = cy - r - 2; y <= cy + r + 2; ++y) {
        if (y < 0 || y >= size) continue;
        for (int x = cx - r - 2; x <= cx + r + 2; ++x) {
            if (x < 0 || x >= size) continue;
            const float dx = static_cast<float>(x - cx) + 0.5f;
            const float dy = static_cast<float>(y - cy) + 0.5f;
            const float d = std::sqrt(dx * dx + dy * dy);
            if (d > r_outer + 0.5f) continue;
            float a;
            if (d <= r_inner) a = 1.0f;
            else a = std::max(0.0f, 1.0f - (d - r_inner) / feather);
            const auto idx = static_cast<size_t>(y) * static_cast<size_t>(size) +
                             static_cast<size_t>(x);
            Px* p = reinterpret_cast<Px*>(pixels) + idx;
            Px src = fill;
            src.a = static_cast<std::uint8_t>(255.0f * a);
            paint_pixel(*p, src);
        }
    }
    const float ring_w = 1.0f;
    for (int y = cy - r - 2; y <= cy + r + 2; ++y) {
        if (y < 0 || y >= size) continue;
        for (int x = cx - r - 2; x <= cx + r + 2; ++x) {
            if (x < 0 || x >= size) continue;
            const float dx = static_cast<float>(x - cx) + 0.5f;
            const float dy = static_cast<float>(y - cy) + 0.5f;
            const float d = std::sqrt(dx * dx + dy * dy);
            const float ring_dist = std::fabs(d - r_outer);
            if (ring_dist > ring_w) continue;
            const float a = std::max(0.0f, 1.0f - ring_dist / ring_w);
            const auto idx = static_cast<size_t>(y) * static_cast<size_t>(size) +
                             static_cast<size_t>(x);
            Px* p = reinterpret_cast<Px*>(pixels) + idx;
            Px outline{0, 0, 0, static_cast<std::uint8_t>(150.0f * a)};
            paint_pixel(*p, outline);
        }
    }
}

Px state_color(TrayServiceState s) {
    switch (s) {
        case TrayServiceState::Connecting: return Px{0xF2, 0xB9, 0x50, 255};
        case TrayServiceState::Connected:  return Px{0x53, 0xD1, 0x7C, 255};
        case TrayServiceState::Error:      return Px{0xFF, 0x6F, 0x6B, 255};
        case TrayServiceState::Off:
        default: return Px{0, 0, 0, 0};
    }
}

std::string state_tag(TrayServiceState s) {
    switch (s) {
        case TrayServiceState::Connecting: return "y";
        case TrayServiceState::Connected:  return "g";
        case TrayServiceState::Error:      return "r";
        case TrayServiceState::Off:
        default: return "o";
    }
}

}  // namespace

std::filesystem::path icon_directory() {
    if (char const* xdg = std::getenv("XDG_RUNTIME_DIR")) {
        if (*xdg) {
            return std::filesystem::path(xdg) / "yume-gui" / "tray";
        }
    }
    return facade::config_io::default_data_dir() / "tray-icons";
}

std::string status_digest(TrayStatus const& st) {
    return state_tag(st.client) + state_tag(st.server);
}

std::vector<std::uint8_t> rasterise_base(int size) {
    std::vector<std::uint8_t> pixels(static_cast<size_t>(size) * size * 4, 0);
    std::string svg(reinterpret_cast<char const*>(platform::kIconSvgBytes),
                    platform::kIconSvgSize);
    NSVGimage* image = nsvgParse(svg.data(), "px", 96.0f);
    if (!image) return pixels;
    NSVGrasterizer* rast = nsvgCreateRasterizer();
    if (!rast) {
        nsvgDelete(image);
        return pixels;
    }
    const float scale = static_cast<float>(size) /
                        ((image->width > 0) ? image->width : 256.0f);
    nsvgRasterize(rast, image, 0.0f, 0.0f, scale, pixels.data(), size, size, size * 4);
    nsvgDeleteRasterizer(rast);
    nsvgDelete(image);
    return pixels;
}

void paint_status_dots(std::uint8_t* pixels, int size, TrayStatus const& st) {
    const int dot_r = std::max(6, size / 7);
    const int gap = dot_r / 2;
    int next_cx = size - dot_r - 2;
    int next_cy = size - dot_r - 2;
    auto plot = [&](TrayServiceState s) {
        if (s == TrayServiceState::Off) return;
        paint_dot(pixels, size, next_cx, next_cy, dot_r, state_color(s));
        next_cx -= (2 * dot_r + gap);
    };
    plot(st.client);
    plot(st.server);
}

std::string write_status_png(TrayStatus const& st,
                             std::filesystem::path const& dir,
                             std::string const& digest) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    const auto path = (dir / ("yume-tray-" + digest + ".png")).string();
    if (std::filesystem::exists(path)) return path;

    auto pixels = rasterise_base(kIconSize);
    if (pixels.empty()) return {};
    paint_status_dots(pixels.data(), kIconSize, st);
    if (!stbi_write_png(path.c_str(), kIconSize, kIconSize, 4, pixels.data(),
                        kIconSize * 4)) {
        return {};
    }
    return path;
}

}  // namespace yume::gui::tray_icon
