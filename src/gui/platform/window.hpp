/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <string>

struct GLFWwindow;

namespace yume::gui {

// Thin owner over a GLFW window plus the GL context. Construction sets up
// OpenGL 3.3 core, vsync, and creates the window. Destruction tears
// everything down deterministically.
class Window {
public:
    Window(std::string title, int width, int height);
    ~Window();

    Window(Window const&) = delete;
    Window& operator=(Window const&) = delete;

    bool should_close() const;
    void poll_events();
    void wait_events_with_timeout(double seconds);
    void swap_buffers();
    void framebuffer_size(int& w, int& h) const;
    float content_scale() const;
    void clear(float r, float g, float b, float a) const;

    void show();
    void hide();
    bool visible() const;

    GLFWwindow* raw() const noexcept { return win_; }

    // Returns the path to the executable (for locating data files
    // installed alongside the binary).
    static std::string executable_dir();

private:
    GLFWwindow* win_{nullptr};
    bool visible_{true};
};

}  // namespace yume::gui
