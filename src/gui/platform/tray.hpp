/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
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

    // Pump GTK events. Must be called from the same thread as
    // construction (typically the GUI main thread), once per frame.
    // No-op if the tray failed to initialise.
    void pump_events();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::gui
