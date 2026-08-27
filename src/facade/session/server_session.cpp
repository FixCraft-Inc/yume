/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/session/server_session.hpp"

#include <atomic>
#include <cstdint>
#include <exception>
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

    // Blocking controller work stays off facade callers. Admission and thread
    // object ownership are serialized separately from user-visible state.
    std::thread worker;
    std::atomic<bool> worker_busy{false};
    std::thread stop_worker;
    std::atomic<bool> stop_busy{false};
    std::mutex lifecycle_mtx;
    std::recursive_mutex notification_mtx;
    std::atomic<std::uint64_t> lifecycle_generation{0};

    StatusCallback status_callback() const { return status_cb; }

    bool current_start(std::uint64_t generation) const noexcept {
        return lifecycle_generation.load(std::memory_order_acquire) == generation &&
               !stop_busy.load(std::memory_order_acquire);
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

void push_server_log(LogLevel level, std::string message) noexcept {
    try {
        LogSink::instance().push(
            level, "facade.server", std::move(message));
    } catch (...) {
        // Log subscribers are embedder callbacks. Lifecycle state and status
        // delivery must remain reliable even when one of them throws.
    }
}

void notify_server_status(ServerSession::StatusCallback const& callback,
                          ServerStatus const& status) noexcept {
    if (!callback) return;
    try {
        callback(status);
    } catch (std::exception const& ex) {
        try {
            push_server_log(
                LogLevel::Error,
                std::string("server status callback threw: ") + ex.what());
        } catch (...) {
        }
    } catch (...) {
        try {
            push_server_log(
                LogLevel::Error,
                "server status callback threw an unknown exception");
        } catch (...) {
        }
    }
}

}  // namespace

ServerSession::ServerSession(server::ServerConfig cfg)
    : impl_(std::make_unique<Impl>()) {
    impl_->cfg = std::move(cfg);
}

ServerSession::~ServerSession() {
    {
        std::lock_guard<std::recursive_mutex> notification_lock(
            impl_->notification_mtx);
        std::lock_guard<std::mutex> lock(impl_->mtx);
        impl_->status_cb = {};
    }
    stop();

    std::thread stop_worker;
    {
        std::lock_guard<std::mutex> lifecycle_lock(impl_->lifecycle_mtx);
        if (impl_->stop_worker.joinable()) {
            stop_worker = std::move(impl_->stop_worker);
        }
    }
    if (stop_worker.joinable()) stop_worker.join();

    impl_->runtime.stop();
    std::thread start_worker;
    {
        std::lock_guard<std::mutex> lifecycle_lock(impl_->lifecycle_mtx);
        if (impl_->worker.joinable()) {
            start_worker = std::move(impl_->worker);
        }
    }
    if (start_worker.joinable()) start_worker.join();
}

bool ServerSession::start(std::string* err) {
    server::ServerConfig cfg;
    std::uint64_t generation = 0;
    {
        std::lock_guard<std::mutex> lifecycle_lock(impl_->lifecycle_mtx);
        if (impl_->runtime.running() || impl_->worker_busy.load() ||
            impl_->stop_busy.load(std::memory_order_acquire)) {
            if (err) {
                *err = impl_->stop_busy.load(std::memory_order_relaxed)
                    ? "server runtime is still stopping"
                    : "server runtime is already running";
            }
            return false;
        }
        if (impl_->stop_worker.joinable()) impl_->stop_worker.join();
        if (impl_->worker.joinable()) impl_->worker.join();
        generation = impl_->lifecycle_generation.fetch_add(
            1, std::memory_order_acq_rel) + 1;
        impl_->worker_busy.store(true, std::memory_order_release);
    }

    // Optimistic immediate status update so the UI shows "Starting" right away.
    {
        std::lock_guard<std::recursive_mutex> notification_lock(
            impl_->notification_mtx);
        if (!impl_->current_start(generation)) {
            impl_->worker_busy.store(false, std::memory_order_release);
            if (err) err->clear();
            return true;
        }
        StatusCallback cb;
        ServerStatus snap;
        {
            std::lock_guard<std::mutex> lock(impl_->mtx);
            cfg = impl_->cfg;
            snap = to_facade_status(impl_->runtime.status(), impl_->traffic, impl_->cfg);
            snap.message = "starting server";
            cb = impl_->status_callback();
        }
        notify_server_status(cb, snap);
    }

    // Run the blocking yumed spawn + IPC wait on a worker so the GUI thread
    // doesn't stall. The optional out-param err can't carry async failures;
    // callers should poll status() or subscribe via set_status_callback().
    try {
        std::lock_guard<std::mutex> lifecycle_lock(impl_->lifecycle_mtx);
        if (!impl_->current_start(generation)) {
            impl_->worker_busy.store(false, std::memory_order_release);
            if (err) err->clear();
            return true;
        }
        impl_->worker = std::thread(
            [this, cfg = std::move(cfg), generation]() mutable {
                std::string local_error;
                bool ok = false;
                try {
                    ok = impl_->runtime.start(cfg, &local_error);
                } catch (std::exception const& ex) {
                    local_error = std::string("server startup exception: ") +
                                  ex.what();
                } catch (...) {
                    local_error = "server startup exception: unknown error";
                }

                std::lock_guard<std::recursive_mutex> notification_lock(
                    impl_->notification_mtx);
                if (!impl_->current_start(generation)) {
                    if (ok) impl_->runtime.stop();
                    impl_->worker_busy.store(false, std::memory_order_release);
                    return;
                }

                StatusCallback cb;
                ServerStatus snap;
                {
                    std::lock_guard<std::mutex> lock(impl_->mtx);
                    snap = to_facade_status(
                        impl_->runtime.status(), impl_->traffic, impl_->cfg);
                    if (!ok) {
                        snap.running = false;
                        snap.message = local_error.empty()
                            ? "server start failed"
                            : local_error;
                    }
                    cb = impl_->status_callback();
                }
                if (ok) {
                    try {
                        push_server_log(
                            LogLevel::Info,
                            "server started on " + snap.listen_endpoint);
                    } catch (...) {
                    }
                } else {
                    try {
                        push_server_log(
                            LogLevel::Error,
                            "server start failed: " + snap.message);
                    } catch (...) {
                    }
                }
                notify_server_status(cb, snap);
                impl_->worker_busy.store(false, std::memory_order_release);
            });
    } catch (std::exception const& ex) {
        impl_->worker_busy.store(false, std::memory_order_release);
        const std::string failure =
            std::string("failed to start server lifecycle worker: ") + ex.what();
        if (err) *err = failure;
        std::lock_guard<std::recursive_mutex> notification_lock(
            impl_->notification_mtx);
        if (impl_->current_start(generation)) {
            StatusCallback cb;
            ServerStatus snap;
            {
                std::lock_guard<std::mutex> lock(impl_->mtx);
                snap = to_facade_status(
                    impl_->runtime.status(), impl_->traffic, impl_->cfg);
                snap.running = false;
                snap.message = failure;
                cb = impl_->status_callback();
            }
            notify_server_status(cb, snap);
        }
        return false;
    } catch (...) {
        impl_->worker_busy.store(false, std::memory_order_release);
        if (err) *err = "failed to start server lifecycle worker";
        return false;
    }

    if (err) err->clear();
    return true;  // kickoff succeeded; outcome arrives via status callback
}

void ServerSession::stop() {
    std::unique_lock<std::recursive_mutex> notification_lock(
        impl_->notification_mtx);
    {
        std::lock_guard<std::mutex> lifecycle_lock(impl_->lifecycle_mtx);
        if (impl_->stop_busy.load(std::memory_order_acquire)) return;
        if (!impl_->runtime.running() && !impl_->worker_busy.load() &&
            !impl_->worker.joinable()) {
            return;
        }
        impl_->lifecycle_generation.fetch_add(1, std::memory_order_acq_rel);
        impl_->stop_busy.store(true, std::memory_order_release);
        if (impl_->stop_worker.joinable()) impl_->stop_worker.join();
    }

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
        notify_server_status(cb, snap);
    }
    notification_lock.unlock();

    try {
        std::lock_guard<std::mutex> lifecycle_lock(impl_->lifecycle_mtx);
        impl_->stop_worker = std::thread([this]() {
            impl_->runtime.stop();

            std::thread start_worker;
            {
                std::lock_guard<std::mutex> lifecycle_lock(
                    impl_->lifecycle_mtx);
                if (impl_->worker.joinable()) {
                    start_worker = std::move(impl_->worker);
                }
            }
            if (start_worker.joinable()) start_worker.join();

            std::lock_guard<std::recursive_mutex> notification_lock(
                impl_->notification_mtx);
            StatusCallback cb;
            ServerStatus snap;
            {
                std::lock_guard<std::mutex> lock(impl_->mtx);
                snap = to_facade_status(
                    impl_->runtime.status(), impl_->traffic, impl_->cfg);
                snap.running = false;
                snap.message = "stopped";
                cb = impl_->status_callback();
            }
            push_server_log(LogLevel::Info, "server stopped");
            impl_->worker_busy.store(false, std::memory_order_release);
            notify_server_status(cb, snap);
            impl_->stop_busy.store(false, std::memory_order_release);
        });
    } catch (...) {
        // Fail closed if the asynchronous teardown worker cannot be created.
        impl_->runtime.stop();
        std::thread start_worker;
        {
            std::lock_guard<std::mutex> lifecycle_lock(impl_->lifecycle_mtx);
            if (impl_->worker.joinable()) {
                start_worker = std::move(impl_->worker);
            }
        }
        if (start_worker.joinable()) start_worker.join();
        impl_->worker_busy.store(false, std::memory_order_release);
        impl_->stop_busy.store(false, std::memory_order_release);
    }
}

bool ServerSession::running() const noexcept {
    return impl_->runtime.running();
}

bool ServerSession::busy() const noexcept {
    // Mirrors exactly what start() admits on.
    return impl_->runtime.running() ||
           impl_->worker_busy.load(std::memory_order_acquire) ||
           impl_->stop_busy.load(std::memory_order_acquire);
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
        row.state = s.state;
        row.client_platform = s.client_platform;
        row.client_version = s.client_version;
        row.authenticated = true;
        out.push_back(std::move(row));
    }
    return out;
}

void ServerSession::set_status_callback(StatusCallback cb) {
    std::lock_guard<std::recursive_mutex> notification_lock(
        impl_->notification_mtx);
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->status_cb = std::move(cb);
}

}  // namespace yume::facade
