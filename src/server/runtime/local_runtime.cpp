/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/local_runtime.hpp"

#include "server/runtime/manager.hpp"

#include <array>
#include <cstdint>
#include <exception>
#include <limits>
#include <string_view>
#include <utility>

#include "server/federation/topology.hpp"

namespace yume::server {

namespace {

// The reporting node's own row in the federation graph. `local_endpoints`
// deliberately excludes federated entries: it answers "how many endpoints does
// this node itself serve", which is what a cluster viewer draws on the self box.
FederationSelfNode federation_self_node(const Manager& manager) {
    const auto& cfg = manager.config_snapshot();
    FederationSelfNode self;
    self.server_id = manager.server_id();
    self.server_name = manager.server_name();
    self.listen_port = cfg.listen_port;
    self.local_endpoints = manager.list_local_endpoints().size();
    self.federation_enabled = cfg.federation_enable;
    return self;
}

constexpr std::uint64_t kMaxRuntimeEventRows = 512U;

}  // namespace

LocalRuntime::LocalRuntime(std::string path, Manager* manager, std::function<void()> stop_callback)
    : manager_(manager)
    , stop_callback_(std::move(stop_callback))
    , server_(std::move(path), [this](const nlohmann::json& request) { return handle_request(request); }) {}

bool LocalRuntime::start(std::string* error) {
    return server_.start(error);
}

void LocalRuntime::stop() {
    server_.stop();
}

bool LocalRuntime::running() const {
    return server_.running();
}

const std::string& LocalRuntime::path() const {
    return server_.path();
}

std::string LocalRuntime::socket_path_for(const std::string& instance_key) {
    return yume::local_runtime::socket_path("server", instance_key);
}

bool LocalRuntime::available(const std::string& path) {
    return yume::local_runtime::Server::endpoint_available(path);
}

nlohmann::json LocalRuntime::request(const std::string& path,
                                     const nlohmann::json& request,
                                     std::string* error,
                                     int timeout_ms) {
    return yume::local_runtime::Server::request(path, request, error, timeout_ms);
}

nlohmann::json LocalRuntime::handle_request(
    const nlohmann::json& request) try {
    if (!request.is_object()) {
        return {{"ok", false}, {"error", "request must be a JSON object"}};
    }
    const auto op_it = request.find("op");
    if (op_it == request.end() || !op_it->is_string() ||
        op_it->get_ref<const std::string&>().empty()) {
        return {{"ok", false},
                {"error", "request op must be a non-empty string"}};
    }
    const std::string op = op_it->get<std::string>();
    nlohmann::json args = nlohmann::json::object();
    if (const auto args_it = request.find("args"); args_it != request.end()) {
        if (!args_it->is_object()) {
            return {{"ok", false},
                    {"error", "request args must be a JSON object"}};
        }
        args = *args_it;
    }
    if (op == "runtime.stop") {
        if (!args.empty()) {
            return {{"ok", false},
                    {"error", "runtime.stop does not accept arguments"}};
        }
        if (!stop_callback_) {
            return {{"ok", false},
                    {"error", "server runtime stop callback is unavailable"}};
        }
        try {
            stop_callback_();
        } catch (const std::exception& ex) {
            return {{"ok", false},
                    {"error", "server runtime stop callback failed: " +
                                  std::string(ex.what())}};
        } catch (...) {
            return {{"ok", false},
                    {"error", "server runtime stop callback failed"}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (!manager_) {
        return {{"ok", false}, {"error", "manager unavailable"}};
    }
    if (op == "runtime.info" || op == "runtime.status") {
        if (!args.empty()) {
            return {{"ok", false},
                    {"error", op + " does not accept arguments"}};
        }
        const auto& cfg = manager_->config_snapshot();
        nlohmann::json result{
            {"server_id", cfg.server_id},
            {"server_name", cfg.server_name},
            {"listen_port", cfg.listen_port},
            {"relay_enable", cfg.relay_enable},
            {"directory_enable", cfg.directory_enable},
            {"endpoints", manager_->list_endpoints().size()},
            {"channels", manager_->list_active_channels().size()},
        };
        result["host"] = manager_->host_runtime_info();
        result["endpoint_statuses"] = nlohmann::json::array();
        for (const auto& status : manager_->list_endpoint_statuses()) {
            result["endpoint_statuses"].push_back(control::endpoint_runtime_status_to_json(status, true));
        }
        return {{"ok", true}, {"result", result}};
    }
    if (op == "directory.list") {
        if (!args.empty()) {
            return {{"ok", false},
                    {"error", "directory.list does not accept arguments"}};
        }
        nlohmann::json result = nlohmann::json::array();
        for (const auto& endpoint : manager_->list_endpoints()) {
            result.push_back(control::endpoint_to_json(endpoint, true));
        }
        return {{"ok", true}, {"result", result}};
    }
    if (op == "runtime.sessions") {
        if (!args.empty()) {
            return {{"ok", false},
                    {"error", "runtime.sessions does not accept arguments"}};
        }
        nlohmann::json result = nlohmann::json::array();
        for (const auto& channel : manager_->list_active_channels()) {
            result.push_back({
                {"channel_id", channel.channel_id},
                {"channel_kind", control::to_string(channel.channel_kind)},
                {"left_endpoint_id", channel.left_endpoint_id},
                {"right_endpoint_id", channel.right_endpoint_id},
                {"left_stream_id", channel.left_stream_id},
                {"right_stream_id", channel.right_stream_id},
                {"e2ee_required", channel.e2ee_required},
                {"pending", channel.pending},
                {"federated", channel.federated},
                {"route_hops", channel.route_hops},
            });
        }
        return {{"ok", true}, {"result", result}};
    }
    if (op == "runtime.events") {
        if (args.size() > 1U ||
            (args.size() == 1U && !args.contains("limit"))) {
            return {{"ok", false},
                    {"error", "runtime.events accepts only an optional limit"}};
        }
        std::size_t limit = 200U;
        if (const auto limit_it = args.find("limit");
            limit_it != args.end()) {
            std::uint64_t requested = 0;
            if (limit_it->is_number_unsigned()) {
                requested = limit_it->get<std::uint64_t>();
            } else if (limit_it->is_number_integer()) {
                const auto signed_limit = limit_it->get<std::int64_t>();
                if (signed_limit < 0) {
                    return {{"ok", false},
                            {"error", "runtime.events limit must be non-negative"}};
                }
                requested = static_cast<std::uint64_t>(signed_limit);
            } else {
                return {{"ok", false},
                        {"error", "runtime.events limit must be an integer"}};
            }
            if (requested > kMaxRuntimeEventRows) {
                return {{"ok", false},
                        {"error", "runtime.events limit must be in 0..512"}};
            }
            limit = static_cast<std::size_t>(requested);
        }
        nlohmann::json result = nlohmann::json::array();
        for (const auto& event : manager_->list_recent_lifecycle_events(limit)) {
            result.push_back(control::lifecycle_event_to_json(event));
        }
        return {{"ok", true}, {"result", result}};
    }
    if (op == "runtime.disconnect") {
        const auto endpoint_id = args.find("endpoint_id");
        if (args.size() != 1U || endpoint_id == args.end() ||
            !endpoint_id->is_string() ||
            endpoint_id->get_ref<const std::string&>().empty()) {
            return {{"ok", false},
                    {"error", "runtime.disconnect requires exactly one "
                              "non-empty endpoint_id string"}};
        }
        std::string error;
        if (!manager_->disconnect_endpoint(
                endpoint_id->get_ref<const std::string&>(), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "runtime.sessions.kill") {
        constexpr std::array<std::pair<std::string_view,
                                       RuntimeSessionSelector>, 3>
            selectors{{
                {"session_id", RuntimeSessionSelector::SessionId},
                {"endpoint_id", RuntimeSessionSelector::EndpointId},
                {"ip", RuntimeSessionSelector::ClientIp},
            }};
        const std::string* selected_value = nullptr;
        RuntimeSessionSelector selected_kind =
            RuntimeSessionSelector::SessionId;
        for (const auto& [name, kind] : selectors) {
            const auto found = args.find(std::string(name));
            if (found == args.end()) continue;
            if (!found->is_string() ||
                found->get_ref<const std::string&>().empty()) {
                return {{"ok", false},
                        {"error", std::string(name) +
                                      " must be a non-empty string"}};
            }
            if (selected_value != nullptr) {
                return {{"ok", false},
                        {"error", "runtime.sessions.kill accepts exactly one "
                                  "of session_id, endpoint_id, or ip"}};
            }
            selected_value = &found->get_ref<const std::string&>();
            selected_kind = kind;
        }
        if (selected_value == nullptr || args.size() != 1U) {
            return {{"ok", false},
                    {"error", "runtime.sessions.kill accepts exactly one of "
                              "session_id, endpoint_id, or ip"}};
        }
        std::string error;
        if (!manager_->kill_sessions(selected_kind, *selected_value, &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "runtime.rules.reload") {
        if (!args.empty()) {
            return {{"ok", false},
                    {"error", "runtime.rules.reload does not accept arguments"}};
        }
        std::string error;
        if (!manager_->reload_client_filter(&error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "federation.status") {
        if (!args.empty()) {
            return {{"ok", false},
                    {"error", "federation.status does not accept arguments"}};
        }
        return {{"ok", true},
                {"result", build_federation_status_json(
                     federation_self_node(*manager_),
                     manager_->federation_configured_peers(),
                     manager_->federation_statuses())}};
    }
    if (op == "federation.topology") {
        if (!args.empty()) {
            return {{"ok", false},
                    {"error", "federation.topology does not accept arguments"}};
        }
        return {{"ok", true},
                {"result", build_federation_topology_json(
                     federation_self_node(*manager_),
                     manager_->federation_configured_peers(),
                     manager_->federation_statuses(),
                     manager_->federation_remote_endpoints(),
                     manager_->list_active_channels())}};
    }
    return {{"ok", false}, {"error", "unsupported op"}};
} catch (const nlohmann::json::exception& ex) {
    return {{"ok", false},
            {"error", "invalid operation arguments: " +
                          std::string(ex.what())}};
} catch (const std::exception& ex) {
    return {{"ok", false},
            {"error", "operation failed: " + std::string(ex.what())}};
} catch (...) {
    return {{"ok", false}, {"error", "operation failed"}};
}

}  // namespace yume::server
