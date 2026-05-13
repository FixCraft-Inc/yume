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

// Cross-platform system tray icon. Construction installs the icon and
// returns immediately; the menu actions fire on the platform's UI
// thread (Cocoa NSStatusItem on macOS, Shell_NotifyIcon on Windows,
// libayatana-appindicator on Linux).
class Tray {
public:
    struct Callbacks {
        std::function<void()> on_show_window;
        std::function<void()> on_hide_window;
        std::function<void()> on_disconnect;
        std::function<void()> on_quit;
    };

    Tray(std::string app_name, Callbacks cb);
    ~Tray();

    Tray(Tray const&) = delete;
    Tray& operator=(Tray const&) = delete;

    void set_status(std::string text);
    void notify(std::string title, std::string body);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::gui
