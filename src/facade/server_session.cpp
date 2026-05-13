/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "facade/server_session.hpp"

#include <mutex>
#include <utility>

#include "facade/keys.hpp"
#include "facade/log_sink.hpp"
#include "facade/traffic_meter.hpp"
#include "server/runtime_controller.hpp"

namespace yume::facade {

struct ServerSession::Impl {
    mutable std::mutex mtx;
    server::ServerConfig cfg;
    server::RuntimeController runtime;
    TrafficMeter traffic;
    StatusCallback status_cb;

    StatusCallback status_callback() const { return status_cb; }
};

namespace {

ServerStatus to_facade_status(server::RuntimeController::Status const& runtime,
                              TrafficMeter const& traffic,
                              server::ServerConfig const& cfg) {
    ServerStatus s;
    s.running = runtime.running;
    s.listen_endpoint = runtime.listen_endpoint.empty()
                            ? ("0.0.0.0:" + std::to_string(cfg.listen_port))
                            : runtime.listen_endpoint;
    s.ipc_path = runtime.ipc_path;
    s.message = runtime.message;
    s.active_sessions = runtime.active_sessions;
    s.started = runtime.started;
    s.bytes_in = traffic.total_rx();
    s.bytes_out = traffic.total_tx();
    if (!cfg.auth_keys.empty()) {
        s.authorized_keys_count =
            keys::list_authorized(cfg.auth_keys, cfg.auth_keys_meta).size();
    }
    return s;
}

void push_server_log(LogLevel level, std::string message) {
    LogEntry entry;
    entry.ts = std::chrono::system_clock::now();
    entry.level = level;
    entry.component = "facade.server";
    entry.message = std::move(message);
    LogSink::instance().push(std::move(entry));
}

}  // namespace

ServerSession::ServerSession(server::ServerConfig cfg)
    : impl_(std::make_unique<Impl>()) {
    impl_->cfg = std::move(cfg);
}

ServerSession::~ServerSession() {
    stop();
}

bool ServerSession::start(std::string* err) {
    server::ServerConfig cfg;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        cfg = impl_->cfg;
    }

    std::string local_error;
    const bool ok = impl_->runtime.start(cfg, &local_error);
    if (err) *err = local_error;

    StatusCallback cb;
    ServerStatus snapshot;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        snapshot = to_facade_status(impl_->runtime.status(), impl_->traffic, impl_->cfg);
        if (!ok) {
            snapshot.running = false;
            snapshot.message = local_error.empty() ? "server start failed" : local_error;
        }
        cb = impl_->status_callback();
    }

    if (ok) {
        push_server_log(LogLevel::Info,
                        "server started on " + snapshot.listen_endpoint);
    } else {
        push_server_log(LogLevel::Error,
                        "server start failed: " + snapshot.message);
    }
    if (cb) cb(snapshot);
    return ok;
}

void ServerSession::stop() {
    if (!impl_->runtime.stop()) return;

    StatusCallback cb;
    ServerStatus snapshot;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        snapshot = to_facade_status(impl_->runtime.status(), impl_->traffic, impl_->cfg);
        snapshot.running = false;
        snapshot.message = "stopped";
        cb = impl_->status_callback();
    }
    push_server_log(LogLevel::Info, "server stopped");
    if (cb) cb(snapshot);
}

bool ServerSession::running() const noexcept {
    return impl_->runtime.running();
}

ServerStatus ServerSession::status() const {
    server::ServerConfig cfg;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        cfg = impl_->cfg;
    }
    return to_facade_status(impl_->runtime.status(), impl_->traffic, cfg);
}

TrafficMeter const& ServerSession::traffic() const noexcept {
    return impl_->traffic;
}

void ServerSession::set_config(server::ServerConfig cfg) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->cfg = std::move(cfg);
}

server::ServerConfig ServerSession::config() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->cfg;
}

std::vector<ServerSession::ConnectedSession> ServerSession::list_sessions() const {
    std::vector<ConnectedSession> out;
    for (auto const& s : impl_->runtime.sessions()) {
        ConnectedSession row;
        row.endpoint_id = s.endpoint_id;
        row.display_name = s.display_name;
        row.peer_address = s.client_platform;
        row.authenticated = true;
        out.push_back(std::move(row));
    }
    return out;
}

void ServerSession::set_status_callback(StatusCallback cb) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->status_cb = std::move(cb);
}

}  // namespace yume::facade
