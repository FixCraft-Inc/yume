/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 *
 * Linux system tray via libayatana-appindicator. The icon is the same
 * SVG that ships with the app, rasterised at 64x64 RGBA and composited
 * with up to two small status-overlay dots (client / server) before
 * being written to /tmp/yume-gui-tray-<digest>.png. App-indicator
 * picks the icon up by file path so we don't depend on installing into
 * the system icon theme to update the live tray.
 *
 * Windows / macOS paths are stubs — the public interface stays so the
 * caller can compile regardless of platform.
 */

#include "platform/tray.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#if YUME_GUI_TRAY
#  include <libayatana-appindicator/app-indicator.h>
#  include <gtk/gtk.h>
#endif

// NanoSVG's IMPLEMENTATION is emitted exactly once in app_icon.cpp; here
// we only need the declarations to call its API.
#include <nanosvg.h>
#include <nanosvgrast.h>

// stb_image_write is only used here, so we own its single IMPLEMENTATION.
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb/stb_image_write.h"

#include "app_icon_data.hpp"

namespace yume::gui {

namespace {

constexpr int kIconSize = 64;

// One pixel of an 8-bit RGBA buffer.
struct Px {
    std::uint8_t r, g, b, a;
};

std::vector<std::uint8_t> rasterise_icon(int size) {
    std::vector<std::uint8_t> pixels(static_cast<size_t>(size) * size * 4, 0);
    std::string svg(reinterpret_cast<const char*>(platform::kIconSvgBytes),
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
    nsvgRasterize(rast, image, 0.0f, 0.0f, scale,
                  pixels.data(), size, size, size * 4);
    nsvgDeleteRasterizer(rast);
    nsvgDelete(image);
    return pixels;
}

// Premultiplied-alpha-ish in-place blend of src over dst. `src` is the
// dot we're painting; `dst` is the icon buffer we're drawing into. The
// alpha is straight (NanoSVG output) so we use the standard "over"
// composite: out = src + dst*(1-src.a).
void paint_pixel(Px& dst, Px const& src) {
    const float a = src.a / 255.0f;
    const float inv = 1.0f - a;
    dst.r = static_cast<std::uint8_t>(src.r * a + dst.r * inv);
    dst.g = static_cast<std::uint8_t>(src.g * a + dst.g * inv);
    dst.b = static_cast<std::uint8_t>(src.b * a + dst.b * inv);
    dst.a = std::max<std::uint8_t>(dst.a, src.a);  // keep most opaque
}

// Paint a filled circle of radius r (px) centred at (cx, cy) into the
// RGBA buffer `pixels` of `size x size`. Antialiases the rim with a
// 1.2px feather. Adds a thin dark outline for readability against light
// tray themes.
void paint_dot(std::uint8_t* pixels, int size, int cx, int cy, int r,
               Px fill) {
    const float feather = 1.2f;
    const float r_outer = static_cast<float>(r);
    const float r_inner = r_outer - feather;
    for (int y = cy - r - 2; y <= cy + r + 2; ++y) {
        if (y < 0 || y >= size) continue;
        for (int x = cx - r - 2; x <= cx + r + 2; ++x) {
            if (x < 0 || x >= size) continue;
            const float dx = static_cast<float>(x - cx) + 0.5f;
            const float dy = static_cast<float>(y - cy) + 0.5f;
            const float d  = std::sqrt(dx * dx + dy * dy);
            if (d > r_outer + 0.5f) continue;
            // Soft alpha on the outer rim.
            float a;
            if (d <= r_inner) a = 1.0f;
            else a = std::max(0.0f, 1.0f - (d - r_inner) / feather);
            const auto idx = static_cast<size_t>(y) * size + static_cast<size_t>(x);
            Px* p = reinterpret_cast<Px*>(pixels) + idx;
            Px src = fill;
            src.a = static_cast<std::uint8_t>(255.0f * a);
            paint_pixel(*p, src);
        }
    }
    // Thin dark outline at r_outer for readability on light backgrounds.
    const float ring_w = 1.0f;
    for (int y = cy - r - 2; y <= cy + r + 2; ++y) {
        if (y < 0 || y >= size) continue;
        for (int x = cx - r - 2; x <= cx + r + 2; ++x) {
            if (x < 0 || x >= size) continue;
            const float dx = static_cast<float>(x - cx) + 0.5f;
            const float dy = static_cast<float>(y - cy) + 0.5f;
            const float d  = std::sqrt(dx * dx + dy * dy);
            const float ring_dist = std::fabs(d - r_outer);
            if (ring_dist > ring_w) continue;
            const float a = std::max(0.0f, 1.0f - ring_dist / ring_w);
            const auto idx = static_cast<size_t>(y) * size + static_cast<size_t>(x);
            Px* p = reinterpret_cast<Px*>(pixels) + idx;
            Px outline{0, 0, 0, static_cast<std::uint8_t>(150.0f * a)};
            paint_pixel(*p, outline);
        }
    }
}

Px state_color(TrayServiceState s) {
    switch (s) {
        case TrayServiceState::Connecting: return Px{0xF2, 0xB9, 0x50, 255}; // amber
        case TrayServiceState::Connected:  return Px{0x53, 0xD1, 0x7C, 255}; // green
        case TrayServiceState::Error:      return Px{0xFF, 0x6F, 0x6B, 255}; // red
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

std::string write_icon_for_status(TrayStatus const& st) {
    // Cache key by client+server state, so we don't rewrite the file
    // every frame. The file path itself doubles as the cache key.
    const std::string digest = state_tag(st.client) + state_tag(st.server);
    const std::string path = "/tmp/yume-gui-tray-" + digest + ".png";
    if (std::filesystem::exists(path)) return path;

    auto pixels = rasterise_icon(kIconSize);
    if (pixels.empty()) return {};

    // Two overlay dots in the lower-right corner so the SVG glyph
    // stays mostly clear. Client first (slightly higher), server next
    // to it. Each is ~22% of the icon size — readable at 22 px tray.
    const int dot_r = std::max(6, kIconSize / 7);
    const int gap   = dot_r / 2;
    int next_cx = kIconSize - dot_r - 2;
    int next_cy = kIconSize - dot_r - 2;

    auto plot = [&](TrayServiceState s) {
        if (s == TrayServiceState::Off) return;
        const Px c = state_color(s);
        paint_dot(pixels.data(), kIconSize, next_cx, next_cy, dot_r, c);
        // Stack the second dot to the left of the first by 2r + gap.
        next_cx -= (2 * dot_r + gap);
    };
    plot(st.client);
    plot(st.server);

    // Best-effort write. If /tmp is unwritable for some reason just
    // return an empty path — the caller falls back to the bare icon.
    if (!stbi_write_png(path.c_str(), kIconSize, kIconSize, 4,
                        pixels.data(), kIconSize * 4)) {
        return {};
    }
    return path;
}

}  // namespace

#if YUME_GUI_TRAY

struct Tray::Impl {
    std::string name;
    Callbacks callbacks;
    AppIndicator* indicator{nullptr};
    GtkWidget* menu{nullptr};
    GtkWidget* show_item{nullptr};
    GtkWidget* quit_item{nullptr};
    TrayStatus last_status;
    std::string last_icon_path;
    bool available{false};
    bool gtk_initialised_by_us{false};
};

Tray::Tray(std::string app_name, Callbacks cb)
    : impl_(std::make_unique<Impl>()) {
    impl_->name = std::move(app_name);
    impl_->callbacks = std::move(cb);

    // gtk_init can be called multiple times safely if it returns FALSE
    // we treat the tray as unavailable. Pass nullptr to avoid mutating
    // the app's argv.
    if (!gtk_init_check(nullptr, nullptr)) {
        impl_->available = false;
        return;
    }
    impl_->gtk_initialised_by_us = true;

    // Initial icon = bare SVG composite with no overlay dots. The
    // app-indicator library expects the icon to be in an icon theme by
    // default but we use the file-path form which is more flexible.
    const std::string initial = write_icon_for_status(TrayStatus{});
    // app_indicator_new is marked deprecated in newer ayatana headers but
    // it's still the only documented entry point; the suggested
    // replacement landed only in very recent versions.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    impl_->indicator = app_indicator_new(
        "yume-gui",
        initial.empty() ? "yume-gui" : initial.c_str(),
        APP_INDICATOR_CATEGORY_APPLICATION_STATUS);
#pragma GCC diagnostic pop
    if (!impl_->indicator) {
        impl_->available = false;
        return;
    }
    if (!initial.empty()) {
        // Setting icon_full with a path makes appindicator skip the icon
        // theme lookup and load directly from disk.
        app_indicator_set_icon_full(impl_->indicator, initial.c_str(), "Yume");
    }
    app_indicator_set_status(impl_->indicator, APP_INDICATOR_STATUS_ACTIVE);
    app_indicator_set_title(impl_->indicator, "Yume");

    impl_->menu = gtk_menu_new();
    impl_->show_item = gtk_menu_item_new_with_label("Show Yume");
    // Stateless lambdas decay to plain C function pointers, which is
    // what g_signal_connect wants. They're defined inside this member
    // function so they have access to Tray's private nested Impl type.
    g_signal_connect(impl_->show_item, "activate",
                     G_CALLBACK(+[](GtkMenuItem*, gpointer data) {
                         auto* i = static_cast<Impl*>(data);
                         if (i && i->callbacks.on_show_window) {
                             i->callbacks.on_show_window();
                         }
                     }),
                     impl_.get());
    gtk_menu_shell_append(GTK_MENU_SHELL(impl_->menu), impl_->show_item);

    GtkWidget* sep = gtk_separator_menu_item_new();
    gtk_menu_shell_append(GTK_MENU_SHELL(impl_->menu), sep);

    impl_->quit_item = gtk_menu_item_new_with_label("Quit Yume");
    g_signal_connect(impl_->quit_item, "activate",
                     G_CALLBACK(+[](GtkMenuItem*, gpointer data) {
                         auto* i = static_cast<Impl*>(data);
                         if (i && i->callbacks.on_quit) {
                             i->callbacks.on_quit();
                         }
                     }),
                     impl_.get());
    gtk_menu_shell_append(GTK_MENU_SHELL(impl_->menu), impl_->quit_item);

    gtk_widget_show_all(impl_->menu);
    app_indicator_set_menu(impl_->indicator, GTK_MENU(impl_->menu));

    impl_->available = true;
    impl_->last_icon_path = initial;
}

Tray::~Tray() {
    if (impl_ && impl_->indicator) {
        // app-indicator owns the menu reference; nullify to detach.
        app_indicator_set_status(impl_->indicator, APP_INDICATOR_STATUS_PASSIVE);
        // No app_indicator_free in the public API; the object is owned
        // by glib refcount. Drop the only ref we hold by g_object_unref.
        g_object_unref(impl_->indicator);
        impl_->indicator = nullptr;
    }
}

bool Tray::available() const {
    return impl_ && impl_->available;
}

void Tray::set_status(TrayStatus const& status) {
    if (!impl_ || !impl_->available || !impl_->indicator) return;
    if (status.client == impl_->last_status.client &&
        status.server == impl_->last_status.server) {
        return;  // no change
    }
    impl_->last_status = status;
    const std::string path = write_icon_for_status(status);
    if (path.empty()) return;
    impl_->last_icon_path = path;
    app_indicator_set_icon_full(impl_->indicator, path.c_str(), "Yume");
}

void Tray::pump_events() {
    if (!impl_ || !impl_->available) return;
    // Non-blocking iteration: drain whatever GTK has pending and return.
    int budget = 32;  // cap so a flood can't stall the GLFW frame
    while (budget-- > 0 && gtk_events_pending()) {
        gtk_main_iteration_do(FALSE);
    }
}

#else   // YUME_GUI_TRAY == 0 — stub when appindicator unavailable -------

struct Tray::Impl {
    std::string name;
    Callbacks callbacks;
    TrayStatus last_status;
    bool available{false};
};

Tray::Tray(std::string app_name, Callbacks cb)
    : impl_(std::make_unique<Impl>()) {
    impl_->name = std::move(app_name);
    impl_->callbacks = std::move(cb);
    impl_->available = false;
}

Tray::~Tray() = default;
bool Tray::available() const { return false; }
void Tray::set_status(TrayStatus const& /*status*/) {}
void Tray::pump_events() {}

#endif

}  // namespace yume::gui
