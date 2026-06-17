/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "facade/session/server_session.hpp"

#include <atomic>
#include <mutex>
#include <thread>
#include <utility>

#include "facade/keys/keys.hpp"
#include "facade/logging/log_sink.hpp"
#include "facade/metrics/traffic_meter.hpp"
#include "server/runtime/controller.hpp"

namespace yume::facade {

struct ServerSession::Impl {
    mutable std::mutex mtx;
    server::ServerConfig cfg;
    server::RuntimeController runtime;
    TrafficMeter traffic;
    StatusCallback status_cb;

    // Worker for blocking start/stop; same pattern as ClientSession::Impl.
    std::thread worker;
    std::atomic<bool> worker_busy{false};

    StatusCallback status_callback() const { return status_cb; }

    void join_previous_worker() {
        if (worker.joinable()) worker.join();
    }
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
    LogSink::instance().push(level, "facade.server", std::move(message));
}

}  // namespace

ServerSession::ServerSession(server::ServerConfig cfg)
    : impl_(std::make_unique<Impl>()) {
    impl_->cfg = std::move(cfg);
}

ServerSession::~ServerSession() {
    stop();
    impl_->join_previous_worker();
}

bool ServerSession::start(std::string* err) {
    server::ServerConfig cfg;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        if (impl_->runtime.running() || impl_->worker_busy.load()) {
            if (err) *err = "server runtime is already running";
            return false;
        }
        cfg = impl_->cfg;
    }

    // Optimistic immediate status update so the UI shows "Starting" right away.
    {
        StatusCallback cb;
        ServerStatus snap;
        {
            std::lock_guard<std::mutex> lock(impl_->mtx);
            snap = to_facade_status(impl_->runtime.status(), impl_->traffic, impl_->cfg);
            snap.message = "starting server";
            cb = impl_->status_callback();
        }
        if (cb) cb(snap);
    }

    impl_->join_previous_worker();
    impl_->worker_busy.store(true);

    // Run the blocking yumed spawn + IPC wait on a worker so the GUI thread
    // doesn't stall. The optional out-param err can't carry async failures;
    // callers should poll status() or subscribe via set_status_callback().
    impl_->worker = std::thread([this, cfg = std::move(cfg)]() {
        std::string local_error;
        const bool ok = impl_->runtime.start(cfg, &local_error);

        StatusCallback cb;
        ServerStatus snap;
        {
            std::lock_guard<std::mutex> lock(impl_->mtx);
            snap = to_facade_status(impl_->runtime.status(), impl_->traffic, impl_->cfg);
            if (!ok) {
                snap.running = false;
                snap.message = local_error.empty() ? "server start failed" : local_error;
            }
            cb = impl_->status_callback();
        }
        if (ok) {
            push_server_log(LogLevel::Info,
                            "server started on " + snap.listen_endpoint);
        } else {
            push_server_log(LogLevel::Error,
                            "server start failed: " + snap.message);
        }
        if (cb) cb(snap);
        impl_->worker_busy.store(false);
    });

    if (err) err->clear();
    return true;  // kickoff succeeded; outcome arrives via status callback
}

void ServerSession::stop() {
    if (!impl_->runtime.running() && !impl_->worker_busy.load()) return;

    // Immediate optimistic status flip so the UI shows "stopping".
    {
        StatusCallback cb;
        ServerStatus snap;
        {
            std::lock_guard<std::mutex> lock(impl_->mtx);
            snap = to_facade_status(impl_->runtime.status(), impl_->traffic, impl_->cfg);
            snap.message = "stopping server";
            cb = impl_->status_callback();
        }
        if (cb) cb(snap);
    }

    impl_->join_previous_worker();
    impl_->worker_busy.store(true);

    impl_->worker = std::thread([this]() {
        impl_->runtime.stop();
        StatusCallback cb;
        ServerStatus snap;
        {
            std::lock_guard<std::mutex> lock(impl_->mtx);
            snap = to_facade_status(impl_->runtime.status(), impl_->traffic, impl_->cfg);
            snap.running = false;
            snap.message = "stopped";
            cb = impl_->status_callback();
        }
        push_server_log(LogLevel::Info, "server stopped");
        if (cb) cb(snap);
        impl_->worker_busy.store(false);
    });
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
