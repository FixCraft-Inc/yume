/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 *
 * Window-icon plumbing for both X11/Win32/Cocoa (rasterise SVG + push
 * via glfwSetWindowIcon) and Wayland (XDG install + app_id hint so the
 * compositor can resolve our window to a .desktop entry). Wayland
 * intentionally forbids per-window icon updates at runtime; the right
 * way there is the .desktop + icon-theme lookup we set up below.
 */

#include "platform/app_icon.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>

#define NANOSVG_IMPLEMENTATION
#include <nanosvg.h>
#define NANOSVGRAST_IMPLEMENTATION
#include <nanosvgrast.h>

#include "app_icon_data.hpp"

namespace yume::gui::platform {

namespace {

// Decoded SVG image at a specific raster size. RGBA8, premultiplied alpha
// off (NanoSVG produces straight alpha which is what GLFW expects).
struct RasterisedIcon {
    int width{0};
    int height{0};
    std::vector<unsigned char> pixels;  // size = width*height*4
};

RasterisedIcon rasterise(int size) {
    RasterisedIcon out;
    // Parse a copy of the SVG bytes — nsvgParse mutates the buffer.
    std::string svg(reinterpret_cast<const char*>(kIconSvgBytes), kIconSvgSize);
    NSVGimage* image = nsvgParse(svg.data(), "px", 96.0f);
    if (!image) return out;
    NSVGrasterizer* rast = nsvgCreateRasterizer();
    if (!rast) {
        nsvgDelete(image);
        return out;
    }
    out.width = size;
    out.height = size;
    out.pixels.assign(static_cast<size_t>(size) * size * 4, 0);
    const float scale = static_cast<float>(size) /
                        ((image->width > 0) ? image->width : 256.0f);
    nsvgRasterize(rast, image, 0.0f, 0.0f, scale,
                  out.pixels.data(), size, size, size * 4);
    nsvgDeleteRasterizer(rast);
    nsvgDelete(image);
    return out;
}

#if defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||      \
    defined(__NetBSD__)
constexpr bool kIsLinuxLike = true;
#else
constexpr bool kIsLinuxLike = false;
#endif

#ifdef __linux__
std::filesystem::path xdg_data_home() {
    if (const char* xdg = std::getenv("XDG_DATA_HOME"); xdg && *xdg) {
        return std::filesystem::path(xdg);
    }
    if (const char* home = std::getenv("HOME"); home && *home) {
        return std::filesystem::path(home) / ".local" / "share";
    }
    return {};
}

// Write `content` to `path` only if the file is missing or its content
// differs. Returns true on success (write happened or already up-to-date).
bool write_if_changed(std::filesystem::path const& path,
                      const void* data, size_t size) {
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (std::filesystem::exists(path)) {
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        if (in) {
            const auto existing_size = static_cast<std::streamsize>(in.tellg());
            if (existing_size == static_cast<std::streamsize>(size)) {
                in.seekg(0);
                std::vector<char> buf(size);
                if (in.read(buf.data(), size) &&
                    std::memcmp(buf.data(), data, size) == 0) {
                    return true;  // unchanged
                }
            }
        }
    }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
    return static_cast<bool>(out);
}

// The .desktop file content we want installed for the user. Keep this in
// sync with src/gui/packaging/yume-gui.desktop; we duplicate it here so
// the app can self-install even when run straight out of build/.
constexpr const char kUserDesktopFile[] =
    "[Desktop Entry]\n"
    "Type=Application\n"
    "Name=Yume\n"
    "GenericName=Post-quantum Transport\n"
    "Comment=Manage Yume client connections, server hosting, keys and relay channels\n"
    "Exec=yume-gui\n"
    "Icon=yume-gui\n"
    "Terminal=false\n"
    "Categories=Network;Security;\n"
    "Keywords=vpn;proxy;tls;post-quantum;privacy;\n"
    "StartupNotify=true\n"
    "StartupWMClass=yume-gui\n";
#endif

}  // namespace

void install_app_id_hints() {
#ifdef __linux__
    // Must be called AFTER glfwInit() but BEFORE glfwCreateWindow. GLFW 3.4
    // added these as window hints (not init hints) — they set the Wayland
    // xdg_toplevel.app_id and the X11 WM_CLASS so the compositor / WM can
    // resolve our window to the yume-gui.desktop entry we install below
    // and from there to the icon at hicolor/scalable/apps/yume-gui.svg.
#ifdef GLFW_WAYLAND_APP_ID
    glfwWindowHintString(GLFW_WAYLAND_APP_ID, kAppId);
#endif
#ifdef GLFW_X11_CLASS_NAME
    glfwWindowHintString(GLFW_X11_CLASS_NAME, kAppId);
#endif
#ifdef GLFW_X11_INSTANCE_NAME
    glfwWindowHintString(GLFW_X11_INSTANCE_NAME, kAppId);
#endif
#endif
}

void apply_window_icon(GLFWwindow* window) {
    if (!window) return;
    // Rasterise at a handful of sizes so the compositor / WM can pick the
    // best one for taskbar / titlebar / alt-tab thumbnails.
    constexpr int kSizes[] = {256, 128, 64, 48, 32};
    std::vector<RasterisedIcon> icons;
    icons.reserve(std::size(kSizes));
    for (int s : kSizes) {
        auto r = rasterise(s);
        if (!r.pixels.empty()) icons.push_back(std::move(r));
    }
    if (icons.empty()) return;

    std::vector<GLFWimage> images;
    images.reserve(icons.size());
    for (auto& r : icons) {
        GLFWimage img{};
        img.width = r.width;
        img.height = r.height;
        img.pixels = r.pixels.data();
        images.push_back(img);
    }
    // No-op on Wayland by design; the XDG install below covers that case.
    glfwSetWindowIcon(window, static_cast<int>(images.size()), images.data());
}

void install_to_user_xdg() {
#ifdef __linux__
    auto data_home = xdg_data_home();
    if (data_home.empty()) return;

    // Icon: ~/.local/share/icons/hicolor/scalable/apps/yume-gui.svg
    const auto icon_path = data_home / "icons" / "hicolor" / "scalable" /
                           "apps" / "yume-gui.svg";
    write_if_changed(icon_path, kIconSvgBytes, kIconSvgSize);

    // .desktop: ~/.local/share/applications/yume-gui.desktop
    const auto desktop_path = data_home / "applications" / "yume-gui.desktop";
    write_if_changed(desktop_path, kUserDesktopFile,
                     std::strlen(kUserDesktopFile));

    // Best-effort icon cache refresh. update-desktop-database is also
    // useful for app launchers but is not strictly required for the
    // window icon path to work. We swallow exit codes.
    (void)std::system("update-desktop-database "
                      "\"$HOME/.local/share/applications\" "
                      ">/dev/null 2>&1 &");
    (void)std::system("gtk-update-icon-cache "
                      "-q -t \"$HOME/.local/share/icons/hicolor\" "
                      ">/dev/null 2>&1 &");
#else
    (void)kIsLinuxLike;  // suppress unused warning on non-Linux
#endif
}

}  // namespace yume::gui::platform
