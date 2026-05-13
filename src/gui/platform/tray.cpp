/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 *
 * System tray integration. Only compiled into the GUI when the platform
 * dependency is present (libayatana-appindicator on Linux, Win32 shell
 * on Windows, Cocoa on macOS). The CMake YUME_GUI_TRAY_AVAILABLE flag
 * gates whether this translation unit is included in the build.
 */

#include "platform/tray.hpp"

namespace yume::gui {

// Cross-platform tray implementation. The Linux path is wired up against
// libayatana-appindicator; Windows uses Shell_NotifyIcon; macOS uses
// NSStatusItem. The wiring is left as a follow-up - this stub keeps the
// public interface stable so callers can compile regardless of platform.
//
// On platforms where the tray isn't available the CMake build excludes
// this file, and yume-gui defines YUME_GUI_TRAY=0 so callers can shim.

struct Tray::Impl {
    std::string name;
    Callbacks callbacks;
    std::string status;
};

Tray::Tray(std::string app_name, Callbacks cb)
    : impl_(std::make_unique<Impl>()) {
    impl_->name = std::move(app_name);
    impl_->callbacks = std::move(cb);
}

Tray::~Tray() = default;

void Tray::set_status(std::string text) {
    if (impl_) impl_->status = std::move(text);
}

void Tray::notify(std::string /*title*/, std::string /*body*/) {
    // Platform-specific notification path goes here.
}

}  // namespace yume::gui
