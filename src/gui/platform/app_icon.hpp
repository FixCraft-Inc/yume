/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

struct GLFWwindow;

namespace yume::gui::platform {

// App-id used by both Wayland (xdg_toplevel.app_id) and X11 (WM_CLASS).
// Must match the basename of the .desktop file we install so compositors
// can resolve the window to its icon.
constexpr const char* kAppId = "yume-gui";

// Linux only. Must be called AFTER glfwInit() and BEFORE
// glfwCreateWindow() — these are GLFW 3.4 *window* hints. No-op on other
// OSes (Win/macOS provide the icon via packaging).
void install_app_id_hints();

// Rasterises the embedded SVG at 32/48/64/128/256 and applies them via
// glfwSetWindowIcon. On Wayland this is a no-op — the compositor uses the
// icon installed on disk via XDG and matched by app_id. Safe to call
// regardless of session type.
void apply_window_icon(GLFWwindow* window);

// First-run convenience: copies the embedded SVG + a .desktop file into
// ~/.local/share/icons/hicolor/scalable/apps/ and
// ~/.local/share/applications/ so a Wayland compositor (or any DE that
// follows XDG) can render the icon next to the window. Safe to call on
// every launch — files are only rewritten when their content differs.
// Linux only; no-op elsewhere.
void install_to_user_xdg();

}  // namespace yume::gui::platform
