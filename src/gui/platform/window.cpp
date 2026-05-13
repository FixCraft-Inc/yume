/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "platform/window.hpp"

#include <filesystem>
#include <stdexcept>

#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>

#if defined(_WIN32)
#  include <windows.h>
#elif defined(__APPLE__)
#  include <mach-o/dyld.h>
#  include <climits>
#else
#  include <unistd.h>
#  include <climits>
#endif

namespace yume::gui {

namespace {
void glfw_error_callback(int code, const char* desc) {
    std::fprintf(stderr, "[glfw] error %d: %s\n", code, desc ? desc : "");
}
}  // namespace

Window::Window(std::string title, int width, int height) {
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) {
        throw std::runtime_error("glfwInit failed");
    }

    // OpenGL 3.3 core profile - broadest cross-platform support without
    // dragging in a heavier Vulkan stack.
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GLFW_TRUE);
    glfwWindowHint(GLFW_VISIBLE, GLFW_TRUE);
    glfwWindowHint(GLFW_RESIZABLE, GLFW_TRUE);
    glfwWindowHint(GLFW_DOUBLEBUFFER, GLFW_TRUE);

    win_ = glfwCreateWindow(width, height, title.c_str(), nullptr, nullptr);
    if (!win_) {
        glfwTerminate();
        throw std::runtime_error("glfwCreateWindow failed");
    }
    glfwMakeContextCurrent(win_);
    glfwSwapInterval(1);  // vsync - caps CPU and keeps frame timing stable
}

Window::~Window() {
    if (win_) {
        glfwDestroyWindow(win_);
        win_ = nullptr;
    }
    glfwTerminate();
}

bool Window::should_close() const {
    return win_ && glfwWindowShouldClose(win_);
}

void Window::poll_events() {
    glfwPollEvents();
}

void Window::wait_events_with_timeout(double seconds) {
    glfwWaitEventsTimeout(seconds);
}

void Window::swap_buffers() {
    if (win_) glfwSwapBuffers(win_);
}

void Window::framebuffer_size(int& w, int& h) const {
    if (win_) glfwGetFramebufferSize(win_, &w, &h);
    else { w = 0; h = 0; }
}

float Window::content_scale() const {
    if (!win_) return 1.0f;
    float sx = 1.0f;
    float sy = 1.0f;
    glfwGetWindowContentScale(win_, &sx, &sy);
    return sx > sy ? sx : sy;
}

void Window::clear(float r, float g, float b, float a) const {
    // We delegate to GL via opengl3 ImGui backend; calling glClear here
    // would require a GL loader. Instead the App caller issues clear
    // through the backend's helper after ImGui::Render(). Kept here for
    // a future refactor where Window owns the loader.
    (void)r; (void)g; (void)b; (void)a;
}

void Window::show() {
    if (win_) {
        glfwShowWindow(win_);
        visible_ = true;
    }
}

void Window::hide() {
    if (win_) {
        glfwHideWindow(win_);
        visible_ = false;
    }
}

bool Window::visible() const {
    return visible_;
}

std::string Window::executable_dir() {
    std::filesystem::path p;
#if defined(_WIN32)
    char buf[MAX_PATH];
    const DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        p = std::filesystem::path(buf).parent_path();
    }
#elif defined(__APPLE__)
    char buf[PATH_MAX];
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) == 0) {
        p = std::filesystem::path(buf).parent_path();
    }
#else
    char buf[PATH_MAX];
    const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = 0;
        p = std::filesystem::path(buf).parent_path();
    }
#endif
    return p.string();
}

}  // namespace yume::gui
