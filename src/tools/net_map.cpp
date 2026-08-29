/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// yume-net-map — ASCII visualization of the local yumed's federation
// topology. Connects to the local admin socket, reads federation.topology,
// and draws the reporting node with its peers.
//
// The daemon owns the graph and server/federation/topology_render owns the
// layout, so this binary is only discovery plus argument handling. The yumed
// attach console draws the same cluster through the same renderer.
//
// Intentionally separate binary so it can be dropped onto a server
// without pulling in the rest of the yumed CLI surface, and so it
// can't accidentally mutate runtime state — it only reads.

#include "core/runtime/local_runtime.hpp"
#include "server/federation/topology_render.hpp"
#include "server/runtime/local_runtime.hpp"

#include <nlohmann/json.hpp>

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

namespace {

struct Cli {
    std::string socket;
    bool ascii_only{false};
    bool json_out{false};
};

void print_usage() {
    std::cout <<
        "yume-net-map - ASCII visualization of a yumed cluster\n"
        "\n"
        "Usage:\n"
        "  yume-net-map [--socket <path>] [--ascii] [--json]\n"
        "\n"
        "Options:\n"
        "  --socket <path>    Yumed admin socket. Default: $YUME_IPC if set,\n"
        "                     otherwise auto-discover the local server.\n"
        "  --ascii            Use pure ASCII box chars (default: Unicode).\n"
        "  --json             Print the raw federation.topology document\n"
        "                     instead of the diagram.\n"
        "  -h, --help         This message.\n"
        "\n"
        "Reads only. Never sends mutating ops to the daemon.\n";
}

bool parse_cli(int argc, char** argv, Cli& cli) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage();
            std::exit(0);
        }
        if (arg == "--ascii") {
            cli.ascii_only = true;
        } else if (arg == "--json") {
            cli.json_out = true;
        } else if (arg == "--socket" && i + 1 < argc) {
            cli.socket = argv[++i];
        } else {
            std::cerr << "yume-net-map: unknown argument: " << arg << "\n\n";
            print_usage();
            return false;
        }
    }
    if (cli.socket.empty()) {
        if (const char* env = std::getenv("YUME_IPC")) {
            cli.socket = env;
        }
    }
    return true;
}

// Discovers the first available local-server socket by trying the
// default path-conventions. Returns empty if none reachable.
std::string discover_socket() {
    // The server-side socket path is derived from the instance key, which
    // we don't know without reading the server's config. As a fallback,
    // scan the standard runtime dir for any socket whose role-prefix is
    // "server-".
    std::vector<std::filesystem::path> candidates;
    const char* xdg = std::getenv("XDG_RUNTIME_DIR");
    if (xdg && *xdg) {
        candidates.emplace_back(std::filesystem::path(xdg) / "yume");
    }
    candidates.emplace_back("/run/yume");
    candidates.emplace_back("/tmp/yume");
    for (const auto& dir : candidates) {
        std::error_code ec;
        if (!std::filesystem::is_directory(dir, ec)) continue;
        for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
            const auto name = entry.path().filename().string();
            if (name.rfind("server-", 0) != 0) continue;
            if (yume::server::LocalRuntime::available(entry.path().string())) {
                return entry.path().string();
            }
        }
    }
    return {};
}

// Reads federation.topology, the daemon's single description of its own view
// of the cluster.
std::optional<nlohmann::json> fetch_topology(const std::string& socket_path,
                                             std::string* error) {
    auto response = yume::server::LocalRuntime::request(
        socket_path,
        {{"op", "federation.topology"}, {"args", nlohmann::json::object()}},
        error, 5000);
    if (!error->empty() || !response.value("ok", false)) {
        if (error->empty()) {
            *error = response.value("error", "federation.topology failed");
        }
        return std::nullopt;
    }
    if (!response.contains("result") || !response["result"].is_object()) {
        *error = "federation.topology returned no result object";
        return std::nullopt;
    }
    return response["result"];
}

}  // namespace

int main(int argc, char** argv) {
    Cli cli;
    if (!parse_cli(argc, argv, cli)) {
        return 1;
    }

    if (cli.socket.empty()) {
        cli.socket = discover_socket();
    }
    if (cli.socket.empty()) {
        std::cerr << "yume-net-map: could not locate a yumed admin socket.\n"
                     "  Pass --socket <path> or set YUME_IPC=<path>.\n"
                     "  Default discovery: $XDG_RUNTIME_DIR/yume, /run/yume, /tmp/yume.\n";
        return 1;
    }
    if (!yume::server::LocalRuntime::available(cli.socket)) {
        std::cerr << "yume-net-map: socket not reachable: " << cli.socket << '\n';
        return 1;
    }

    std::string error;
    auto topology = fetch_topology(cli.socket, &error);
    if (!topology) {
        std::cerr << "yume-net-map: " << error << '\n';
        return 1;
    }

    // --json is the daemon's own topology document, not a reduction of it, so
    // a script reading this tool and a consumer reading the op see one shape.
    if (cli.json_out) {
        std::cout << topology->dump(2) << '\n';
        return 0;
    }

    yume::server::render_topology(
        yume::server::topology_boxes(*topology), cli.ascii_only, std::cout);
    return 0;
}
