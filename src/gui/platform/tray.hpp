/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <functional>
#include <memory>
#include <string>

namespace yume::gui {

// Per-service state shown as a small overlay dot on the tray icon. Two
// dots can be active at once (client + server). Off means no overlay.
enum class TrayServiceState {
    Off,         // no dot
    Connecting,  // amber/yellow dot
    Connected,   // green dot
    Error,       // red dot
};

struct TrayStatus {
    TrayServiceState client{TrayServiceState::Off};
    TrayServiceState server{TrayServiceState::Off};
};

// Free-form, human-readable lines shown in the tray menu so a right-
// click gives the user the same status surface as the Android
// notification. Empty strings collapse: any field set to "" simply
// drops its menu item. Update on every status change; the Tray will
// rebuild the menu in place.
struct TrayInfo {
    std::string client_state;     // "Connected", "Connecting", "Idle"
    std::string client_server;    // "vpn.example.com:443"
    std::string client_profile;   // "chrome / off"
    std::string exit_ip;          // "203.0.113.42"
    std::string exit_country;     // "Japan 🇯🇵"
    std::string client_rates;     // "↑ 2.1 MB/s · ↓ 8.4 MB/s"
    std::string server_state;     // "Running on 0.0.0.0:443" / "Stopped"
};

// Cross-platform system tray icon. Construction installs the icon and
// returns immediately; the menu actions fire on the platform's UI
// thread. On Linux this uses libayatana-appindicator (the modern
// StatusNotifierItem path that works on KDE, Plasma, and GNOME with the
// AppIndicator extension). Windows / macOS paths are placeholders.
class Tray {
public:
    struct Callbacks {
        std::function<void()> on_show_window;
        std::function<void()> on_quit;
    };

    Tray(std::string app_name, Callbacks cb);
    ~Tray();

    Tray(Tray const&) = delete;
    Tray& operator=(Tray const&) = delete;

    // True if the tray was successfully created and is visible on the
    // current desktop. False if libayatana-appindicator failed to attach
    // (no StatusNotifierItem host, etc.). The caller should treat false
    // as "no tray available — keep the window's close = quit semantics".
    bool available() const;

    // Update the status-overlay dots. Idempotent / cheap to call every
    // frame — internally we cache by status digest and only rebuild the
    // composite PNG when the state actually changes.
    void set_status(TrayStatus const& status);

    // Rebuild the rich-status section of the menu. Called whenever a
    // displayed line changes (state, exit IP, country, rates). Empty
    // lines are skipped. Cheap: we hash the joined string and bail
    // when the menu would render identically.
    void set_info(TrayInfo const& info);

    // Pump GTK events. Must be called from the same thread as
    // construction (typically the GUI main thread), once per frame.
    // No-op if the tray failed to initialise.
    void pump_events();

    // Opaque per-platform state. Declared public so the Windows tray's
    // free-function WndProc (tray_wnd_proc in tray.cpp) can reach the
    // callbacks + cached info without a friend declaration that would
    // require pulling <windows.h> into this header.
    struct Impl;

private:
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::gui
