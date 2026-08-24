/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <cstdio>
#include <cstring>
#include <exception>
#include <string>

#include "app.hpp"

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

namespace {

#ifdef _WIN32
// The GUI links as a Windows-subsystem binary so double-clicking it does not
// flash a console. That also means it starts with no stdout/stderr at all, so
// --help, --headless and the capture modes would run and print nothing when
// invoked from a terminal. Adopt the launching terminal's console when there
// is one; when launched from Explorer there is none and this is a no-op.
void attach_parent_console() {
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) return;
#  ifdef _MSC_VER
    FILE* stream = nullptr;
    (void)freopen_s(&stream, "CONOUT$", "w", stdout);
    (void)freopen_s(&stream, "CONOUT$", "w", stderr);
#  else
    // MinGW does not reliably provide the Annex K freopen_s.
    (void)std::freopen("CONOUT$", "w", stdout);
    (void)std::freopen("CONOUT$", "w", stderr);
#  endif
}
#else
void attach_parent_console() {}
#endif


void print_help() {
    std::printf(
        "yume-gui - desktop UI for the Yume post-quantum transport\n\n"
        "Usage:\n"
        "  yume-gui [options]\n\n"
        "Options:\n"
        "  --headless                Run without a window; exercise facade start/stop\n"
        "  --start-minimized         Open hidden; show via tray menu\n"
        "  --no-tray                 Disable the system tray icon\n"
        "  --client-config <path>    Path to the client JSON config\n"
        "  --server-config <path>    Path to the server JSON config\n"
        "  --page <name>             Open on this page (e.g. Server, Logs)\n"
        "  --capture <path.png>      Render one page to a PNG and exit\n"
        "  --capture-all <dir>       Render every page to <dir> and exit\n"
        "  -h, --help                Show this help\n");
}

}  // namespace

int main(int argc, char** argv) {
    yume::gui::Options opts;

    // Any invocation that reports through stdio needs a console on Windows.
    // Do this before parsing so even the unknown-argument diagnostic is seen.
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "-h" || a == "--help" || a == "--headless" ||
            a == "--capture" || a == "--capture-all") {
            attach_parent_console();
            break;
        }
    }

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "-h" || a == "--help") {
            print_help();
            return 0;
        } else if (a == "--headless") {
            opts.headless = true;
        } else if (a == "--start-minimized") {
            opts.start_minimized = true;
        } else if (a == "--no-tray") {
            opts.no_tray = true;
        } else if (a == "--client-config" && i + 1 < argc) {
            opts.client_config_path = argv[++i];
        } else if (a == "--server-config" && i + 1 < argc) {
            opts.server_config_path = argv[++i];
        } else if (a == "--page" && i + 1 < argc) {
            opts.page = argv[++i];
        } else if (a == "--capture" && i + 1 < argc) {
            opts.capture_path = argv[++i];
        } else if (a == "--capture-all" && i + 1 < argc) {
            opts.capture_all_dir = argv[++i];
        } else {
            std::fprintf(stderr, "yume-gui: unknown argument '%s'\n", a.c_str());
            print_help();
            return 2;
        }
    }

    try {
        if (opts.headless) {
            return yume::gui::run_headless(opts);
        }
        yume::gui::App app(std::move(opts));
        return app.run();
    } catch (std::exception const& e) {
        std::fprintf(stderr, "yume-gui: fatal: %s\n", e.what());
        return 1;
    }
}
