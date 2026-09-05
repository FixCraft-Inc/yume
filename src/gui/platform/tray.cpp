/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "platform/tray.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

// Platform-specific gates. YUME_GUI_TRAY=1 is the build-time switch
// (set by CMake when prerequisites are present); the per-platform branch
// is picked here based on the target OS, so we can carry Linux,
// Windows, and macOS implementations in this single file without each
// pulling in the others' headers.
#if YUME_GUI_TRAY && defined(__linux__)
#  define YUME_GUI_TRAY_LINUX 1
#  include <libayatana-appindicator/app-indicator.h>
#  include <gtk/gtk.h>
#elif YUME_GUI_TRAY && defined(_WIN32)
#  define YUME_GUI_TRAY_WIN32 1
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <shellapi.h>
#elif YUME_GUI_TRAY && defined(__APPLE__)
#  define YUME_GUI_TRAY_MACOS 1
#endif

#include "platform/tray_icon.hpp"

namespace yume::gui {

namespace {

// Only the Linux AppIndicator path writes per-status icon files. The Windows
// and macOS paths carry their own icon handling, and the no-tray stub has
// none, so defining these unconditionally left them orphaned on any build
// without the Linux tray and broke it under -Werror=unused-function.
#if YUME_GUI_TRAY_LINUX

std::string write_icon_for_status(TrayStatus const& st,
                                  std::filesystem::path const& icon_dir) {
    return tray_icon::write_status_png(st, icon_dir,
                                       tray_icon::status_digest(st));
}

void remove_icon_files(std::vector<std::string> const& paths) {
    for (auto const& p : paths) {
        std::error_code ec;
        std::filesystem::remove(p, ec);
    }
}

#endif  // YUME_GUI_TRAY_LINUX

}  // namespace

#if YUME_GUI_TRAY_LINUX

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
    std::filesystem::path icon_dir;
    std::vector<std::string> temp_icons;
    bool available{false};
    bool gtk_initialised_by_us{false};
};

Tray::Tray(std::string app_name, Callbacks cb)
    : impl_(std::make_unique<Impl>()) {
    impl_->name = std::move(app_name);
    impl_->callbacks = std::move(cb);
    impl_->icon_dir = tray_icon::icon_directory();

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
    const std::string initial = write_icon_for_status(TrayStatus{}, impl_->icon_dir);
    if (!initial.empty()) {
        impl_->temp_icons.push_back(initial);
    }
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
    if (impl_) {
        remove_icon_files(impl_->temp_icons);
    }
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
    const std::string path = write_icon_for_status(status, impl_->icon_dir);
    if (path.empty()) return;
    if (std::find(impl_->temp_icons.begin(), impl_->temp_icons.end(), path) ==
        impl_->temp_icons.end()) {
        impl_->temp_icons.push_back(path);
    }
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

#elif defined(YUME_GUI_TRAY_WIN32)
// ----- Windows implementation (Shell_NotifyIcon) ------------------------

namespace {

// Convert RGBA pixels into an HICON via a DIB section + a 1bpp AND mask.
// CreateIconIndirect is the modern path and takes the colour bitmap
// directly; mask is required but a fully-transparent mask is fine since
// the colour bitmap carries the alpha.
HICON hicon_from_rgba(std::vector<std::uint8_t> const& rgba, int size) {
    BITMAPV5HEADER bi{};
    bi.bV5Size        = sizeof(bi);
    bi.bV5Width       = size;
    bi.bV5Height      = -size;            // top-down
    bi.bV5Planes      = 1;
    bi.bV5BitCount    = 32;
    bi.bV5Compression = BI_BITFIELDS;
    bi.bV5RedMask     = 0x00FF0000;
    bi.bV5GreenMask   = 0x0000FF00;
    bi.bV5BlueMask    = 0x000000FF;
    bi.bV5AlphaMask   = 0xFF000000;

    HDC hdc = GetDC(nullptr);
    void* bits = nullptr;
    HBITMAP color = CreateDIBSection(hdc, reinterpret_cast<BITMAPINFO*>(&bi),
                                     DIB_RGB_COLORS, &bits, nullptr, 0);
    ReleaseDC(nullptr, hdc);
    if (!color || !bits) {
        if (color) DeleteObject(color);
        return nullptr;
    }
    // Convert RGBA → BGRA in-place during the copy.
    auto* dst = static_cast<std::uint8_t*>(bits);
    for (int i = 0; i < size * size; ++i) {
        dst[i * 4 + 0] = rgba[i * 4 + 2];
        dst[i * 4 + 1] = rgba[i * 4 + 1];
        dst[i * 4 + 2] = rgba[i * 4 + 0];
        dst[i * 4 + 3] = rgba[i * 4 + 3];
    }
    HBITMAP mask = CreateBitmap(size, size, 1, 1, nullptr);
    ICONINFO ii{};
    ii.fIcon    = TRUE;
    ii.hbmColor = color;
    ii.hbmMask  = mask;
    HICON hicon = CreateIconIndirect(&ii);
    DeleteObject(color);
    DeleteObject(mask);
    return hicon;
}

constexpr UINT WM_YUME_TRAY = WM_APP + 1;
constexpr UINT_PTR ID_TRAY  = 1;
// Menu command IDs. Reserved range [100, 200) for info lines so we don't
// clash with Show / Quit.
constexpr UINT CMD_SHOW = 1;
constexpr UINT CMD_QUIT = 2;

}  // namespace

struct Tray::Impl {
    std::string name;
    Callbacks callbacks;
    HWND     hwnd{nullptr};
    HICON    hicon{nullptr};
    NOTIFYICONDATAW nid{};
    TrayStatus last_status;
    TrayInfo   last_info;
    std::string last_info_digest;
    bool available{false};
};

static LRESULT CALLBACK tray_wnd_proc(HWND h, UINT m, WPARAM w, LPARAM l);

Tray::Tray(std::string app_name, Callbacks cb)
    : impl_(std::make_unique<Impl>()) {
    impl_->name = std::move(app_name);
    impl_->callbacks = std::move(cb);

    static ATOM cls = 0;
    if (!cls) {
        WNDCLASSEXW wc{};
        wc.cbSize        = sizeof(wc);
        wc.lpfnWndProc   = tray_wnd_proc;
        wc.hInstance     = GetModuleHandleW(nullptr);
        wc.lpszClassName = L"YumeTrayWnd";
        cls = RegisterClassExW(&wc);
        if (!cls) return;
    }
    // HWND_MESSAGE makes it a message-only window: no taskbar entry,
    // no visible frame; perfect for receiving WM_YUME_TRAY callbacks.
    impl_->hwnd = CreateWindowExW(0, L"YumeTrayWnd", L"YumeTray",
                                  0, 0, 0, 0, 0,
                                  HWND_MESSAGE, nullptr,
                                  GetModuleHandleW(nullptr), impl_.get());
    if (!impl_->hwnd) return;

    auto pixels = tray_icon::rasterise_base(32);
    impl_->hicon = hicon_from_rgba(pixels, 32);
    NOTIFYICONDATAW& nid = impl_->nid;
    nid.cbSize           = sizeof(nid);
    nid.hWnd             = impl_->hwnd;
    nid.uID              = static_cast<UINT>(ID_TRAY);
    nid.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_YUME_TRAY;
    // IDI_APPLICATION expands via MAKEINTRESOURCE; on MinGW (no UNICODE
    // by default) that resolves to MAKEINTRESOURCEA returning char*,
    // which the W-suffixed loader rejects. Pin the wide form by hand.
    nid.hIcon            = impl_->hicon ? impl_->hicon
                                        : LoadIconW(nullptr,
                                                    MAKEINTRESOURCEW(32512));
    {
        std::wstring tip = L"Yume";
        const std::size_t cap = sizeof(nid.szTip) / sizeof(nid.szTip[0]);
        const std::size_t n = std::min(tip.size(), cap - 1);
        std::memcpy(nid.szTip, tip.c_str(), n * sizeof(wchar_t));
        nid.szTip[n] = 0;
    }
    impl_->available = Shell_NotifyIconW(NIM_ADD, &nid) != FALSE;
}

Tray::~Tray() {
    if (impl_ && impl_->available) {
        Shell_NotifyIconW(NIM_DELETE, &impl_->nid);
        impl_->available = false;
    }
    if (impl_ && impl_->hicon) {
        DestroyIcon(impl_->hicon);
        impl_->hicon = nullptr;
    }
    if (impl_ && impl_->hwnd) {
        DestroyWindow(impl_->hwnd);
        impl_->hwnd = nullptr;
    }
}

bool Tray::available() const { return impl_ && impl_->available; }

void Tray::set_status(TrayStatus const& status) {
    if (!impl_ || !impl_->available) return;
    if (status.client == impl_->last_status.client &&
        status.server == impl_->last_status.server) {
        return;
    }
    impl_->last_status = status;
    auto pixels = tray_icon::rasterise_base(64);
    tray_icon::paint_status_dots(pixels.data(), 64, status);
    HICON fresh = hicon_from_rgba(pixels, 64);
    if (!fresh) return;
    if (impl_->hicon) DestroyIcon(impl_->hicon);
    impl_->hicon = fresh;
    impl_->nid.hIcon = fresh;
    impl_->nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    Shell_NotifyIconW(NIM_MODIFY, &impl_->nid);
}

void Tray::set_info(TrayInfo const& info) {
    if (!impl_ || !impl_->available) return;
    // We render info inline in the right-click popup (built on demand
    // in WM_RBUTTONUP), so set_info just caches the latest snapshot
    // and refreshes the tooltip with a one-line summary.
    std::string digest;
    digest.reserve(256);
    auto add = [&](std::string const& v) { digest.append(v); digest.push_back('\x1f'); };
    add(info.client_state); add(info.client_server); add(info.client_profile);
    add(info.exit_ip);      add(info.exit_country);  add(info.client_rates);
    add(info.server_state);
    if (digest == impl_->last_info_digest) return;
    impl_->last_info_digest = digest;
    impl_->last_info = info;

    std::wstring tip = L"Yume";
    if (!info.client_state.empty()) {
        tip += L" - ";
        tip += std::wstring(info.client_state.begin(), info.client_state.end());
    }
    const std::size_t cap = sizeof(impl_->nid.szTip) / sizeof(wchar_t);
    if (tip.size() >= cap) tip.resize(cap - 1);
    std::memcpy(impl_->nid.szTip, tip.c_str(), tip.size() * sizeof(wchar_t));
    impl_->nid.szTip[tip.size()] = 0;
    impl_->nid.uFlags = NIF_TIP;
    Shell_NotifyIconW(NIM_MODIFY, &impl_->nid);
}

void Tray::pump_events() {
    if (!impl_ || !impl_->hwnd) return;
    MSG msg;
    while (PeekMessageW(&msg, impl_->hwnd, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

// Window proc handles tray messages dispatched by the shell. Left-click
// shows the window; right-click pops a menu seeded from the cached
// TrayInfo.
static LRESULT CALLBACK tray_wnd_proc(HWND h, UINT m, WPARAM w, LPARAM l) {
    auto* impl = reinterpret_cast<Tray::Impl*>(
        GetWindowLongPtrW(h, GWLP_USERDATA));
    if (m == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(l);
        SetWindowLongPtrW(h, GWLP_USERDATA,
                          reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        return DefWindowProcW(h, m, w, l);
    }
    if (m == WM_YUME_TRAY && impl) {
        const UINT event = LOWORD(l);
        if (event == WM_LBUTTONUP) {
            if (impl->callbacks.on_show_window) impl->callbacks.on_show_window();
            return 0;
        }
        if (event == WM_RBUTTONUP || event == WM_CONTEXTMENU) {
            POINT pt; GetCursorPos(&pt);
            HMENU menu = CreatePopupMenu();
            UINT id = 100;
            auto add_line = [&](std::wstring const& text) {
                if (text.empty()) return;
                AppendMenuW(menu, MF_STRING | MF_GRAYED, id++, text.c_str());
            };
            auto to_w = [](std::string const& s) {
                return std::wstring(s.begin(), s.end());
            };
            AppendMenuW(menu, MF_STRING, CMD_SHOW, L"Show Yume");
            auto const& info = impl->last_info;
            bool any = false;
            if (!info.client_state.empty()) {
                AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
                add_line(L"Yume: " + to_w(info.client_state)); any = true;
            }
            if (!info.client_server.empty())  add_line(L"Server: " + to_w(info.client_server));
            if (!info.client_profile.empty()) add_line(L"Profile: " + to_w(info.client_profile));
            if (!info.exit_country.empty())   add_line(L"Exit: " + to_w(info.exit_country));
            if (!info.exit_ip.empty())        add_line(L"Exit IP: " + to_w(info.exit_ip));
            if (!info.client_rates.empty())   add_line(to_w(info.client_rates));
            if (!info.server_state.empty()) {
                AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
                add_line(L"Local daemon: " + to_w(info.server_state));
            }
            (void)any;
            AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(menu, MF_STRING, CMD_QUIT, L"Quit Yume");
            SetForegroundWindow(h);  // required for TrackPopupMenu to close on focus loss
            UINT cmd = TrackPopupMenu(menu,
                                      TPM_RIGHTBUTTON | TPM_RETURNCMD,
                                      pt.x, pt.y, 0, h, nullptr);
            DestroyMenu(menu);
            if (cmd == CMD_SHOW && impl->callbacks.on_show_window) impl->callbacks.on_show_window();
            if (cmd == CMD_QUIT && impl->callbacks.on_quit)        impl->callbacks.on_quit();
            return 0;
        }
    }
    return DefWindowProcW(h, m, w, l);
}

#elif defined(YUME_GUI_TRAY_MACOS)
// macOS Tray implementation lives in tray_macos.mm.

#else

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
