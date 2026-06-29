/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include <cstdio>
#include <cstring>
#include <exception>
#include <string>

#include "app.hpp"

namespace {

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
        "  -h, --help                Show this help\n");
}

}  // namespace

int main(int argc, char** argv) {
    yume::gui::Options opts;

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
