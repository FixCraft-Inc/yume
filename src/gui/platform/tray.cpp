/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
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

// NanoSVG IMPLEMENTATION lives in app_icon.cpp; here we just consume.
#include <nanosvg.h>
#include <nanosvgrast.h>

#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb/stb_image_write.h"

#include "app_icon_data.hpp"

namespace yume::gui {

namespace {

constexpr int kIconSize = 64;

struct Px { std::uint8_t r, g, b, a; };

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

void paint_pixel(Px& dst, Px const& src) {
    const float a = src.a / 255.0f;
    const float inv = 1.0f - a;
    dst.r = static_cast<std::uint8_t>(src.r * a + dst.r * inv);
    dst.g = static_cast<std::uint8_t>(src.g * a + dst.g * inv);
    dst.b = static_cast<std::uint8_t>(src.b * a + dst.b * inv);
    dst.a = std::max<std::uint8_t>(dst.a, src.a);
}

// Filled circle with a soft rim + thin dark outline for readability on
// light tray themes.
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
    const std::string digest = state_tag(st.client) + state_tag(st.server);
    const std::string path = "/tmp/yume-gui-tray-" + digest + ".png";
    if (std::filesystem::exists(path)) return path;

    auto pixels = rasterise_icon(kIconSize);
    if (pixels.empty()) return {};

    const int dot_r = std::max(6, kIconSize / 7);
    const int gap   = dot_r / 2;
    int next_cx = kIconSize - dot_r - 2;
    int next_cy = kIconSize - dot_r - 2;

    auto plot = [&](TrayServiceState s) {
        if (s == TrayServiceState::Off) return;
        paint_dot(pixels.data(), kIconSize, next_cx, next_cy, dot_r, state_color(s));
        next_cx -= (2 * dot_r + gap);
    };
    plot(st.client);
    plot(st.server);

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
    // Info-line widgets are owned by the menu (gtk_container_add). We
    // hold raw pointers only so the next set_info() can destroy the
    // previous batch before adding new lines.
    std::vector<GtkWidget*> info_items;
    TrayStatus last_status;
    TrayInfo   last_info;
    std::string last_info_digest;
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

    // libayatana-appindicator prints "libayatana-appindicator is
    // deprecated, please use libayatana-appindicator-glib" via GLib's
    // log machinery on every load. Swallow that one domain.
    g_log_set_handler(
        "libayatana-appindicator",
        static_cast<GLogLevelFlags>(G_LOG_LEVEL_WARNING |
                                    G_LOG_LEVEL_MESSAGE |
                                    G_LOG_LEVEL_INFO |
                                    G_LOG_LEVEL_DEBUG |
                                    G_LOG_FLAG_FATAL |
                                    G_LOG_FLAG_RECURSION),
        +[](const gchar*, GLogLevelFlags, const gchar*, gpointer) {},
        nullptr);

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

    // Secondary activate (middle-click) bound to Show Yume, so users on
    // desktops that don't open the menu on left-click still have a fast
    // way back to the window without going through the menu.
    app_indicator_set_secondary_activate_target(impl_->indicator,
                                                impl_->show_item);

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

void Tray::set_info(TrayInfo const& info) {
    if (!impl_ || !impl_->available || !impl_->menu) return;

    // Hash via concatenation: cheap and stable, and avoids rebuilding
    // the menu while the popup might be open if nothing actually
    // changed.
    std::string digest;
    digest.reserve(256);
    auto add = [&](std::string const& v) { digest.append(v); digest.push_back('\x1f'); };
    add(info.client_state);
    add(info.client_server);
    add(info.client_profile);
    add(info.exit_ip);
    add(info.exit_country);
    add(info.client_rates);
    add(info.server_state);
    if (digest == impl_->last_info_digest) return;
    impl_->last_info_digest = digest;
    impl_->last_info = info;

    // Drop any info widgets from the previous render. They live between
    // show_item and the separator/quit pair, owned by the menu shell.
    for (GtkWidget* w : impl_->info_items) {
        gtk_widget_destroy(w);
    }
    impl_->info_items.clear();

    // Insert info lines right after Show Yume (position 1).
    int pos = 1;
    auto append_separator = [&]() {
        GtkWidget* sep = gtk_separator_menu_item_new();
        gtk_menu_shell_insert(GTK_MENU_SHELL(impl_->menu), sep, pos++);
        gtk_widget_set_sensitive(sep, FALSE);
        gtk_widget_show(sep);
        impl_->info_items.push_back(sep);
    };
    auto append_line = [&](std::string const& text) {
        if (text.empty()) return;
        GtkWidget* item = gtk_menu_item_new_with_label(text.c_str());
        // Insensitive = greyed/non-clickable; we only want these lines
        // for display. gtk_menu_item_new_with_label uses the system
        // label widget so it picks up the menu's font.
        gtk_widget_set_sensitive(item, FALSE);
        gtk_menu_shell_insert(GTK_MENU_SHELL(impl_->menu), item, pos++);
        gtk_widget_show(item);
        impl_->info_items.push_back(item);
    };

    bool any = false;
    if (!info.client_state.empty())   { append_separator(); append_line("Yume: " + info.client_state); any = true; }
    if (!info.client_server.empty())  { append_line("Server: " + info.client_server); }
    if (!info.client_profile.empty()) { append_line("Profile: " + info.client_profile); }
    if (!info.exit_country.empty())   { append_line("Exit: " + info.exit_country); }
    if (!info.exit_ip.empty())        { append_line("Exit IP: " + info.exit_ip); }
    if (!info.client_rates.empty())   { append_line(info.client_rates); }
    if (!info.server_state.empty()) {
        if (any) append_separator();
        else     append_separator();
        append_line("Local daemon: " + info.server_state);
    }
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
void Tray::set_info(TrayInfo const& /*info*/) {}
void Tray::pump_events() {}

#endif

}  // namespace yume::gui
