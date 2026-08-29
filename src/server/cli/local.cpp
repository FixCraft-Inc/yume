/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/local.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <iostream>

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

#include <nlohmann/json.hpp>

#include "core/security/identity.hpp"
#include "server/federation/topology_render.hpp"
#include "server/federation/types.hpp"
#include "server/runtime/local_runtime.hpp"
#include "server/runtime/manager.hpp"
#include "util.hpp"

namespace yume::server::cli {
namespace {

// Renders a federation.status result. Peer rows carry a nested `configuration`
// object only for accepted unique entries. Invalid or duplicate `--peer`
// strings may not have an unambiguous safe id, so they are reported only as a
// count rather than as nameless rows.
void print_federation_status(const nlohmann::json& result, std::ostream& out) {
    const bool enabled = result.value("enabled", false);
    if (!enabled) {
        out << "federation disabled\n";
    }
    const auto invalid = result.value("invalid_peer_entries", std::size_t{0});
    if (invalid > 0) {
        out << invalid << " peer entr" << (invalid == 1 ? "y" : "ies")
            << " rejected as invalid or duplicate; see the startup log\n";
    }
    if (!result.contains("peers") || result["peers"].empty()) {
        if (enabled) {
            out << "federation enabled, no peers configured\n";
        }
        return;
    }
    for (const auto& peer : result["peers"]) {
        out << peer.value("peer_id", "")
            << " state=" << peer.value("state", "")
            << " ready=" << (peer.value("ready", false) ? "yes" : "no")
            << " channels=" << peer.value("channels_active", 0)
            << " last_handshake_ms=" << peer.value("last_handshake_ms", 0LL);
        if (peer.contains("configuration") && peer["configuration"].is_object()) {
            const auto& configuration = peer["configuration"];
            out << " dial=" << format_federation_host_port(
                                    configuration.value("host", ""),
                                    configuration.value("port", 0))
                << " pin=" << (configuration.value("tls_pin_present", false) ? "yes" : "no");
        }
        const std::string last_error = peer.value("last_error", "");
        if (!last_error.empty()) {
            out << " error=" << last_error;
        }
        out << '\n';
    }
}

std::string trim_copy(std::string s) {
    auto is_space = [](unsigned char ch) { return std::isspace(ch) != 0; };
    while (!s.empty() && is_space(static_cast<unsigned char>(s.front()))) {
        s.erase(s.begin());
    }
    while (!s.empty() && is_space(static_cast<unsigned char>(s.back()))) {
        s.pop_back();
    }
    return s;
}

nlohmann::json request_local_server_runtime(const std::string& socket_path,
                                           const std::string& op,
                                           const nlohmann::json& args,
                                           std::string* error) {
    return yume::server::LocalRuntime::request(
        socket_path,
        nlohmann::json{{"op", op}, {"args", args}},
        error,
        10000);
}

}  // namespace

bool prompt_attach_existing(const std::string& kind) {
#if defined(_WIN32)
    if (_isatty(_fileno(stdin)) == 0) {
        return false;
    }
#else
    if (isatty(fileno(stdin)) == 0) {
        return false;
    }
#endif
    std::cout << kind << " is already running. Attach to the existing instance? [Y/n] " << std::flush;
    std::string answer;
    if (!std::getline(std::cin, answer)) {
        return true;
    }
    answer = trim_copy(answer);
    if (answer.empty()) {
        return true;
    }
    std::transform(answer.begin(), answer.end(), answer.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return answer == "y" || answer == "yes";
}

bool stdin_is_tty() {
#if defined(_WIN32)
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(fileno(stdin)) != 0;
#endif
}

std::string effective_server_instance_key(const yume::server::ServerConfig& cfg, const std::string& config_path) {
    if (!cfg.ipc_path.empty()) {
        return cfg.ipc_path;
    }
    if (!cfg.server_id.empty()) {
        return cfg.server_id;
    }
    return yume::identity::derive_instance_key(
        std::to_string(cfg.listen_port) + "|" + cfg.tls_cert + "|" + cfg.auth_keys + "|" + config_path);
}

int run_local_server_attach(const std::string& socket_path, bool non_interactive) {
    std::string error;
    if (non_interactive) {
        auto resp = request_local_server_runtime(socket_path, "runtime.status", nlohmann::json::object(), &error);
        if (!error.empty() || !resp.value("ok", false)) {
            yume::util::log_error(error.empty() ? resp.value("error", "status failed") : error);
            return 1;
        }
        std::cout << resp["result"].dump(2) << std::endl;
        return 0;
    }

    yume::util::log_info("Attached to existing yumed runtime");
    yume::util::log_info("Attached console: help | status | sessions | directory | peers | federation | topology | disconnect <endpoint-id> | stop | quit");
    for (;;) {
        std::string line;
        if (!std::getline(std::cin, line)) {
            return 0;
        }
        line = trim_copy(line);
        if (line.empty()) {
            continue;
        }
        if (line == "help") {
            yume::util::log_info("Commands: help | status | sessions | directory | peers | federation | topology | disconnect <endpoint-id> | stop | quit");
            continue;
        }
        if (line == "quit" || line == "exit") {
            return 0;
        }
        if (line == "status") {
            auto resp = request_local_server_runtime(socket_path, "runtime.status", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                yume::util::log_warn(error.empty() ? resp.value("error", "status failed") : error);
                error.clear();
            } else {
                std::cout << resp["result"].dump(2) << std::endl;
            }
            continue;
        }
        if (line == "sessions") {
            auto resp = request_local_server_runtime(socket_path, "runtime.sessions", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                yume::util::log_warn(error.empty() ? resp.value("error", "sessions failed") : error);
                error.clear();
            } else {
                std::cout << resp["result"].dump(2) << std::endl;
            }
            continue;
        }
        if (line == "directory") {
            auto resp = request_local_server_runtime(socket_path, "directory.list", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                yume::util::log_warn(error.empty() ? resp.value("error", "directory failed") : error);
                error.clear();
                continue;
            }
            for (const auto& entry : resp["result"]) {
                std::cout << entry.value("endpoint_id", "") << " "
                          << entry.value("display_name", "")
                          << " kind=" << entry.value("endpoint_kind", "")
                          << " relay=" << entry.value("relay_mode", "")
                          << std::endl;
            }
            continue;
        }
        if (line == "peers" || line == "federation") {
            auto resp = request_local_server_runtime(socket_path, "federation.status", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                yume::util::log_warn(error.empty() ? resp.value("error", "federation failed") : error);
                error.clear();
                continue;
            }
            print_federation_status(resp["result"], std::cout);
            continue;
        }
        if (line == "topology") {
            auto resp = request_local_server_runtime(socket_path, "federation.topology", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                yume::util::log_warn(error.empty() ? resp.value("error", "topology failed") : error);
                error.clear();
                continue;
            }
            // Same document and same renderer yume-net-map uses, so the two
            // views of one cluster cannot disagree.
            render_topology(topology_boxes(resp["result"]),
                            /*ascii_only=*/false, std::cout);
            continue;
        }
        if (line.rfind("disconnect ", 0) == 0) {
            auto resp = request_local_server_runtime(socket_path, "runtime.disconnect",
                                                     {{"endpoint_id", trim_copy(line.substr(11))}}, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                yume::util::log_warn(error.empty() ? resp.value("error", "disconnect failed") : error);
                error.clear();
            }
            continue;
        }
        if (line == "stop") {
            auto resp = request_local_server_runtime(socket_path, "runtime.stop", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                yume::util::log_warn(error.empty() ? resp.value("error", "stop failed") : error);
                error.clear();
            }
            return 0;
        }
        yume::util::log_warn("unknown command: " + line);
    }
}

}  // namespace yume::server::cli
