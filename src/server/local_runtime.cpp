#include "server/local_runtime.hpp"

#include "server/manager.hpp"

#include <algorithm>

namespace yume::server {

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

nlohmann::json LocalRuntime::handle_request(const nlohmann::json& request) {
    if (!manager_) {
        return {{"ok", false}, {"error", "manager unavailable"}};
    }
    const std::string op = request.value("op", "");
    const auto args = request.value("args", nlohmann::json::object());
    if (op == "runtime.info" || op == "runtime.status") {
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
        result["endpoint_statuses"] = nlohmann::json::array();
        for (const auto& status : manager_->list_endpoint_statuses()) {
            result["endpoint_statuses"].push_back(control::endpoint_runtime_status_to_json(status, true));
        }
        return {{"ok", true}, {"result", result}};
    }
    if (op == "directory.list") {
        nlohmann::json result = nlohmann::json::array();
        for (const auto& endpoint : manager_->list_endpoints()) {
            result.push_back(control::endpoint_to_json(endpoint, true));
        }
        return {{"ok", true}, {"result", result}};
    }
    if (op == "runtime.sessions") {
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
        const auto limit = std::max(0, args.value("limit", 200));
        nlohmann::json result = nlohmann::json::array();
        for (const auto& event : manager_->list_recent_lifecycle_events(static_cast<std::size_t>(limit))) {
            result.push_back(control::lifecycle_event_to_json(event));
        }
        return {{"ok", true}, {"result", result}};
    }
    if (op == "runtime.disconnect") {
        std::string error;
        if (!manager_->disconnect_endpoint(args.value("endpoint_id", ""), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "federation.status") {
        nlohmann::json result{
            {"enabled", manager_->config_snapshot().federation_enable},
            {"peers", manager_->config_snapshot().federation_peers},
        };
        result["peer_status"] = nlohmann::json::array();
        for (const auto& peer : manager_->federation_statuses()) {
            result["peer_status"].push_back({
                {"id", peer.id},
                {"state", peer.state},
                {"ready", peer.ready},
                {"last_error", peer.last_error},
                {"last_handshake_ts", peer.last_handshake_ts},
                {"channels_active", peer.channels_active},
            });
        }
        return {{"ok", true}, {"result", result}};
    }
    if (op == "runtime.stop") {
        if (stop_callback_) {
            stop_callback_();
        }
        return {{"ok", true}, {"result", true}};
    }
    return {{"ok", false}, {"error", "unsupported op"}};
}

}  // namespace yume::server
