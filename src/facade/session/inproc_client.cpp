/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/session/inproc_client.hpp"

#include <cstdio>
#include <exception>
#include <algorithm>
#include <utility>
#include <vector>

#include <boost/asio/post.hpp>

#include "client/relay/runtime.hpp"
#include "client/transport/tunnel.hpp"
#include "facade/logging/log_sink.hpp"
#include <boost/asio/io_context.hpp>

namespace yume::facade {

namespace {

std::string latest_startup_error(std::chrono::system_clock::time_point since) {
    try {
        auto logs = LogSink::instance().snapshot(32);
        for (auto it = logs.rbegin(); it != logs.rend(); ++it) {
            if (it->ts < since) {
                continue;
            }
            if (it->level == LogLevel::Error ||
                it->level == LogLevel::Critical ||
                it->level == LogLevel::Warn) {
                return it->message;
            }
        }
    } catch (...) {
    }
    return {};
}

void push_runtime_error(std::string const& message) noexcept {
    try {
        LogSink::instance().push(
            LogLevel::Error, "client.runtime", message);
    } catch (...) {
    }
}

}  // namespace

struct InProcClient::Impl {
    enum class LifecycleState {
        Idle,
        Starting,
        Running,
        Stopping,
    };

    struct RequestWaitState {
        ~RequestWaitState() {
            client::wipe_relay_request_secrets(request);
        }
        std::mutex mutex;
        std::condition_variable cv;
        bool ready{false};
        bool started{false};
        bool cancelled{false};
        runtime::OperationStatus operation_status{
            runtime::OperationStatus::InternalError};
        std::string operation_error;
        client::RuntimeLifetimeGate::Lease runtime_lease;
        nlohmann::json request;
        nlohmann::json value;
    };

    std::thread cli_thread;
    std::atomic<bool> running{false};
    std::mutex lifecycle_mtx;
    std::condition_variable lifecycle_cv;
    LifecycleState lifecycle_state{LifecycleState::Idle};
    bool join_in_progress{false};

    // Filled on Cli's worker thread when the runtime-ready callback
    // fires. Protected by ready_mtx so start() can block on the
    // condition variable without racing the worker.
    std::mutex ready_mtx;
    std::condition_variable ready_cv;
    bool ready{false};
    std::string ready_error;

    // Held only while Cli's connected-session executor is alive. RuntimeAccess
    // leases prevent teardown from crossing an in-flight operation; the
    // pointers themselves are released before the io_context is destroyed.
    std::shared_ptr<client::Tunnel> tunnel;
    std::shared_ptr<client::RelayRuntime> relay;
    // True only while Tunnel's executor and its strand service are alive.
    // The connected-session scope clears this under ready_mtx before its
    // io_context can be destroyed.
    bool runtime_executor_active{false};
    std::shared_ptr<client::RuntimeLifetimeGate> runtime_gate;
    std::string server_tls_fingerprint_sha256;
    std::vector<std::string> server_capabilities;
    std::shared_ptr<std::atomic<bool>> cancel_requested;
    std::vector<std::weak_ptr<RequestWaitState>> pending_requests;

    Status     last_status;
    std::atomic<int> exit_code{0};
    std::chrono::system_clock::time_point started;
};

InProcClient::InProcClient() : impl_(std::make_unique<Impl>()) {}

InProcClient::~InProcClient() {
    stop();
}

bool InProcClient::running() const noexcept {
    return impl_->running.load(std::memory_order_acquire);
}

InProcClient::Status InProcClient::status() const {
    {
        std::lock_guard<std::mutex> lock(impl_->ready_mtx);
        Status s = impl_->last_status;
        s.running       = impl_->running.load(std::memory_order_acquire);
        s.exit_code     = impl_->exit_code.load(std::memory_order_acquire);
        s.started       = impl_->started;
        s.ipc_available = impl_->runtime_executor_active &&
                          static_cast<bool>(impl_->relay);
        s.server_tls_fingerprint_sha256 =
            impl_->server_tls_fingerprint_sha256;
        s.server_capabilities = impl_->server_capabilities;
        return s;
    }
}

std::optional<InProcClient::RuntimeAccess> InProcClient::acquire_runtime() const {
    std::lock_guard<std::mutex> lock(impl_->ready_mtx);
    if (!impl_->runtime_executor_active || !impl_->runtime_gate ||
        !impl_->tunnel || !impl_->relay) {
        return std::nullopt;
    }
    auto lease = impl_->runtime_gate->try_acquire();
    if (!lease) return std::nullopt;
    return RuntimeAccess(
        std::move(lease), impl_->runtime_gate, impl_->tunnel, impl_->relay,
        impl_->server_capabilities);
}

bool InProcClient::start(client::ClientConfig cfg, std::string* error,
                         std::chrono::milliseconds wait,
                         runtime::OperationStatus* operation_status,
                         std::shared_ptr<std::atomic<bool>> admission_cancel) {
    if (error) error->clear();
    runtime::SetOperationStatus(
        operation_status, runtime::OperationStatus::InternalError);
    std::unique_lock<std::mutex> lifecycle_lock(impl_->lifecycle_mtx);
    // Embedders may have admitted a start before doing comparatively slow
    // configuration I/O.  Check their cancellation token while holding the
    // same mutex that publishes Starting.  A concurrent stop therefore either
    // wins here, or observes Starting after this critical section and cancels
    // the newly-created worker through request_stop().
    if (admission_cancel &&
        admission_cancel->load(std::memory_order_acquire)) {
        if (error) *error = "in-process client startup was cancelled";
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::NotRunning);
        return false;
    }
    if (impl_->lifecycle_state != Impl::LifecycleState::Idle ||
        impl_->join_in_progress) {
        const bool stopping =
            impl_->lifecycle_state == Impl::LifecycleState::Stopping;
        if (error) {
            *error = stopping ? "in-process client is still stopping"
                              : "in-process client is already running";
        }
        runtime::SetOperationStatus(
            operation_status,
            stopping ? runtime::OperationStatus::WouldBlock
                     : runtime::OperationStatus::AlreadyRunning);
        return false;
    }
    // Idle is published only at the very end of the worker. A joinable thread
    // in this state has therefore already returned and is safe to reap while
    // lifecycle admission remains serialized.
    if (impl_->cli_thread.joinable()) {
        impl_->cli_thread.join();
    }
    impl_->lifecycle_state = Impl::LifecycleState::Starting;
    impl_->running.store(true, std::memory_order_release);
    auto fail_worker_start = [&](const char* detail) noexcept {
        // No replacement thread exists on this path. Clear the admission flag
        // before any diagnostic cleanup that could itself allocate or lock.
        impl_->running.store(false, std::memory_order_release);
        impl_->lifecycle_state = Impl::LifecycleState::Idle;
        try {
            std::lock_guard<std::mutex> lock(impl_->ready_mtx);
            if (impl_->cancel_requested) {
                impl_->cancel_requested->store(true, std::memory_order_release);
            }
            impl_->tunnel.reset();
            impl_->relay.reset();
            impl_->runtime_executor_active = false;
            impl_->runtime_gate.reset();
            impl_->server_tls_fingerprint_sha256.clear();
            impl_->server_capabilities.clear();
            impl_->cancel_requested.reset();
            impl_->ready = false;
            impl_->ready_error.clear();
            impl_->started = {};
        } catch (...) {
        }
        if (error) {
            try {
                *error = "failed to start in-process client worker";
                if (detail && *detail) {
                    error->append(": ");
                    error->append(detail);
                }
            } catch (...) {
                error->clear();
            }
        }
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::InternalError);
        impl_->lifecycle_cv.notify_all();
        return false;
    };

    try {
        {
            std::lock_guard<std::mutex> lock(impl_->ready_mtx);
            impl_->ready       = false;
            impl_->ready_error.clear();
            impl_->tunnel.reset();
            impl_->relay.reset();
            impl_->runtime_executor_active = false;
            impl_->runtime_gate =
                std::make_shared<client::RuntimeLifetimeGate>();
            impl_->server_tls_fingerprint_sha256.clear();
            impl_->server_capabilities.clear();
            impl_->cancel_requested = admission_cancel
                ? std::move(admission_cancel)
                : std::make_shared<std::atomic<bool>>(false);
            impl_->started = std::chrono::system_clock::now();
            impl_->last_status = Status{};
            impl_->last_status.message = "starting in-process client";
            impl_->exit_code.store(0, std::memory_order_release);
        }

        auto cancel_requested = impl_->cancel_requested;
        impl_->cli_thread = std::thread([this, cfg = std::move(cfg), cancel_requested]() mutable {
            client::Cli cli;
            try {
                (void)LogSink::instance();
            } catch (...) {
            }
            // Suppress the colour-coded banner Cli prints after auth — the
            // same details are surfaced in the GUI's status panes, and we
            // don't want them duplicated into stdout/stderr of whatever
            // terminal launched the GUI.
            cli.set_silent(true);
            cli.set_external_stop_flag(cancel_requested);
            cli.set_runtime_ready_callback(
                [this, cancel_requested](std::shared_ptr<client::Tunnel> tunnel,
                       std::shared_ptr<client::RelayRuntime> relay,
                       client::RuntimeReadyInfo ready_info) {
                    bool cancelled = false;
                    {
                        std::lock_guard<std::mutex> lock(impl_->ready_mtx);
                        // Recheck while holding the same lock as request_stop().
                        // Otherwise stop can observe no tunnel between the first
                        // check and publication, and this callback can publish a
                        // late ready state after cancellation.
                        cancelled = cancel_requested->load(
                            std::memory_order_acquire);
                        if (!cancelled) {
                            impl_->tunnel = tunnel;
                            impl_->relay = std::move(relay);
                            impl_->server_tls_fingerprint_sha256 = std::move(
                                ready_info.server_tls_fingerprint_sha256);
                            impl_->server_capabilities = std::move(
                                ready_info.server_capabilities);
                            impl_->last_status.message =
                                "in-process client runtime is ready";
                            impl_->ready = true;
                        }
                    }
                    if (cancelled && tunnel) tunnel->stop("interrupt");
                    impl_->ready_cv.notify_all();
                });
            cli.set_runtime_active_callback(
                [this, cancel_requested](boost::asio::io_context* io,
                       std::shared_ptr<client::Tunnel> tunnel,
                       std::shared_ptr<client::RelayRuntime> relay,
                       std::function<void(const std::string&)>) {
                    std::shared_ptr<client::Tunnel> expired_tunnel;
                    std::shared_ptr<client::RelayRuntime> expired_relay;
                    std::shared_ptr<client::RuntimeLifetimeGate> gate;
                    std::vector<std::shared_ptr<Impl::RequestWaitState>> pending;
                    std::unique_lock<std::mutex> lock(impl_->ready_mtx);
                    if (!io) {
                        impl_->runtime_executor_active = false;
                        gate = impl_->runtime_gate;
                        if (gate) gate->revoke();
                        expired_relay = std::move(impl_->relay);
                        expired_tunnel = std::move(impl_->tunnel);
                        for (auto& weak : impl_->pending_requests) {
                            if (auto state = weak.lock()) {
                                pending.push_back(std::move(state));
                            }
                        }
                        impl_->pending_requests.clear();
                        lock.unlock();
                        for (const auto& state : pending) {
                            {
                                std::lock_guard<std::mutex> state_lock(
                                    state->mutex);
                                if (!state->ready) {
                                    state->cancelled = true;
                                    state->operation_status =
                                        runtime::OperationStatus::NotRunning;
                                    state->operation_error =
                                        "in-process runtime disconnected";
                                    if (!state->started) {
                                        state->runtime_lease.release();
                                    }
                                    state->value = {
                                        {"ok", false},
                                        {"error", "in-process runtime disconnected"},
                                    };
                                    state->ready = true;
                                }
                            }
                            state->cv.notify_all();
                        }
                        // Cli may have stopped its io_context before this scope
                        // reset runs. Synchronously settle stream OPENs, packet
                        // handles, and capacity waiters without posting more
                        // work onto that executor.
                        if (expired_tunnel) {
                            expired_tunnel->cancel_runtime_operations(
                                "in-process runtime disconnected");
                        }
                        // Release executor-bound objects while the connected
                        // session's io_context is still alive.
                        expired_relay.reset();
                        expired_tunnel.reset();
                        if (gate) gate->wait_for_quiescence();
                        return;
                    }
                    if (cancel_requested->load(std::memory_order_acquire)) {
                        // The connected-session boundary rechecks cancellation
                        // around publication, but stop can still win after its
                        // final check and before this callback takes ready_mtx.
                        // Do not make a cancelled executor observable even
                        // transiently; Cli still owns and tears down the tunnel.
                        impl_->runtime_executor_active = false;
                        lock.unlock();
                        if (tunnel) tunnel->stop("interrupt");
                        return;
                    }
                    if (!impl_->runtime_gate ||
                        !impl_->runtime_gate->activate()) {
                        impl_->runtime_executor_active = false;
                        return;
                    }
                    impl_->runtime_executor_active = true;
                    if (tunnel) {
                        impl_->tunnel = std::move(tunnel);
                    }
                    if (relay) {
                        impl_->relay = std::move(relay);
                    }
                });

            int rc = 1;
            std::string unhandled_error;
            try {
                rc = cli.run_config(std::move(cfg));
            } catch (std::exception const& ex) {
                unhandled_error = std::string("in-process client exception: ") + ex.what();
            } catch (...) {
                unhandled_error = "in-process client exception: unknown error";
            }
            impl_->exit_code.store(rc, std::memory_order_release);

            if (!unhandled_error.empty()) {
                push_runtime_error(unhandled_error);
            }

            // Cli::run has returned. If we got here without ever signalling
            // ready, surface the exit code to start()'s caller; otherwise
            // it's a normal disconnect after a healthy run.
            {
                std::lock_guard<std::mutex> lock(impl_->ready_mtx);
                // Defensive fallback for exits before a connected-session scope
                // was installed. Normal connected exits clear this earlier,
                // before their io_context is destroyed.
                impl_->runtime_executor_active = false;
                if (!impl_->ready) {
                    std::string detail = unhandled_error.empty()
                        ? latest_startup_error(impl_->started)
                        : unhandled_error;
                    if (detail.empty()) {
                        char buf[64];
                        std::snprintf(buf, sizeof(buf),
                                      "Cli::run exited rc=%d before tunnel was ready", rc);
                        detail = buf;
                    }
                    impl_->ready_error = std::move(detail);
                    impl_->last_status.message = impl_->ready_error;
                    impl_->ready       = true;  // unblock start()'s wait
                }
            }
            impl_->ready_cv.notify_all();
            impl_->running.store(false, std::memory_order_release);
            {
                std::lock_guard<std::mutex> lifecycle_guard(
                    impl_->lifecycle_mtx);
                if (impl_->lifecycle_state !=
                    Impl::LifecycleState::Stopping) {
                    impl_->lifecycle_state = Impl::LifecycleState::Idle;
                }
            }
            impl_->lifecycle_cv.notify_all();
        });
    } catch (std::exception const& ex) {
        return fail_worker_start(ex.what());
    } catch (...) {
        return fail_worker_start("unknown error");
    }

    lifecycle_lock.unlock();

    std::unique_lock<std::mutex> lock(impl_->ready_mtx);
    if (!impl_->ready_cv.wait_for(lock, wait, [this] {
            return impl_->ready ||
                   (impl_->cancel_requested &&
                    impl_->cancel_requested->load(std::memory_order_acquire));
        })) {
        // Timed out waiting for the tunnel. The thread is still running -
        // tear it down so the next start() has a clean slate.
        lock.unlock();
        stop();
        if (error) *error = "timed out waiting for in-process client to become ready";
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::Timeout);
        return false;
    }
    if (impl_->cancel_requested &&
        impl_->cancel_requested->load(std::memory_order_acquire)) {
        lock.unlock();
        stop(nullptr, "startup cancelled");
        if (error) *error = "in-process client startup was cancelled";
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::NotRunning);
        return false;
    }
    if (!impl_->relay || !impl_->tunnel) {
        std::string captured = impl_->ready_error;
        lock.unlock();
        stop();
        if (error) *error = captured.empty()
            ? "in-process client did not produce a tunnel"
            : captured;
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::InternalError);
        return false;
    }
    lock.unlock();
    bool startup_was_cancelled = false;
    {
        std::lock_guard<std::mutex> lifecycle_guard(impl_->lifecycle_mtx);
        if (impl_->lifecycle_state != Impl::LifecycleState::Starting) {
            startup_was_cancelled = true;
        } else {
            impl_->lifecycle_state = Impl::LifecycleState::Running;
        }
    }
    if (startup_was_cancelled) {
        stop(nullptr, "startup cancelled");
        if (error) *error = "in-process client startup was cancelled";
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::NotRunning);
        return false;
    }
    runtime::SetOperationStatus(
        operation_status, runtime::OperationStatus::Success);
    return true;
}

void InProcClient::request_stop(std::string const& reason) noexcept {
    try {
        std::shared_ptr<std::atomic<bool>> cancel_requested;
        {
            std::lock_guard<std::mutex> lifecycle_lock(impl_->lifecycle_mtx);
            if (impl_->lifecycle_state == Impl::LifecycleState::Idle &&
                !impl_->cli_thread.joinable()) {
                return;
            }
            impl_->lifecycle_state = Impl::LifecycleState::Stopping;
        }
        {
            std::lock_guard<std::mutex> lock(impl_->ready_mtx);
            cancel_requested = impl_->cancel_requested;
            if (cancel_requested) {
                cancel_requested->store(true, std::memory_order_release);
            }
            if (impl_->runtime_executor_active && impl_->tunnel) {
                // Preserve the existing ABI distinction: an embedder-forced
                // stop is an interrupted runtime, not peer clean EOF.
                impl_->tunnel->stop("interrupt");
            }
            impl_->last_status.message = reason.empty()
                ? "client stopping"
                : reason;
        }
        impl_->ready_cv.notify_all();
        impl_->lifecycle_cv.notify_all();
    } catch (...) {
        // Cancellation is best-effort and noexcept. The synchronous stop()
        // still joins and performs unconditional state cleanup.
    }
}

void InProcClient::stop(std::string* error, std::string const& reason) {
    if (error) error->clear();
    request_stop(reason);
    std::thread worker;
    {
        std::unique_lock<std::mutex> lifecycle_lock(impl_->lifecycle_mtx);
        impl_->lifecycle_cv.wait(lifecycle_lock, [this] {
            return !impl_->join_in_progress;
        });
        if (impl_->cli_thread.joinable()) {
            impl_->join_in_progress = true;
            worker = std::move(impl_->cli_thread);
        } else {
            impl_->lifecycle_state = Impl::LifecycleState::Idle;
        }
    }
    if (worker.joinable()) {
        worker.join();
    }
    {
        std::lock_guard<std::mutex> lock(impl_->ready_mtx);
        impl_->tunnel.reset();
        impl_->relay.reset();
        impl_->runtime_executor_active = false;
        impl_->runtime_gate.reset();
        impl_->server_tls_fingerprint_sha256.clear();
        impl_->server_capabilities.clear();
        impl_->cancel_requested.reset();
        impl_->pending_requests.clear();
        impl_->ready = false;
        impl_->ready_error.clear();
        impl_->last_status.message = "stopped";
    }
    impl_->running.store(false, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lifecycle_lock(impl_->lifecycle_mtx);
        impl_->join_in_progress = false;
        impl_->lifecycle_state = Impl::LifecycleState::Idle;
    }
    impl_->lifecycle_cv.notify_all();
}

nlohmann::json InProcClient::request(std::string const& op,
                                     nlohmann::json const& args,
                                     std::string* error,
                                     int timeout_ms,
                                     runtime::OperationStatus* operation_status) {
    if (error) error->clear();
    runtime::SetOperationStatus(
        operation_status, runtime::OperationStatus::InternalError);
    auto state = std::make_shared<Impl::RequestWaitState>();
    std::shared_ptr<client::RuntimeLifetimeGate> runtime_gate;
    std::shared_ptr<client::Tunnel> runtime_tunnel;
    std::shared_ptr<client::RelayRuntime> runtime_relay;
    bool posted = false;
    {
        std::lock_guard<std::mutex> lock(impl_->ready_mtx);
        if (!impl_->runtime_executor_active || !impl_->runtime_gate ||
            !impl_->relay || !impl_->tunnel ||
            (impl_->cancel_requested &&
             impl_->cancel_requested->load(std::memory_order_acquire))) {
            if (error) *error = "in-process client not running";
            runtime::SetOperationStatus(
                operation_status, runtime::OperationStatus::NotRunning);
            return nlohmann::json{{"ok", false}, {"error", "not running"}};
        }
        runtime_gate = impl_->runtime_gate;
        state->runtime_lease = runtime_gate->try_acquire();
        if (!state->runtime_lease) {
            if (error) *error = "in-process runtime is stopping";
            runtime::SetOperationStatus(
                operation_status, runtime::OperationStatus::NotRunning);
            return nlohmann::json{{"ok", false}, {"error", "stopping"}};
        }
        runtime_tunnel = impl_->tunnel;
        runtime_relay = impl_->relay;
        impl_->pending_requests.emplace_back(state);
        const std::weak_ptr<client::RelayRuntime> weak_relay = runtime_relay;
        try {
            state->request = {{"op", op}, {"args", args}};
            // Posting while holding ready_mtx prevents the connected-session
            // teardown callback from destroying the executor concurrently.
            boost::asio::post(
                runtime_tunnel->get_executor(),
                [weak_relay, state]() {
                    {
                        std::lock_guard<std::mutex> state_lock(state->mutex);
                        if (state->cancelled) {
                            state->runtime_lease.release();
                            return;
                        }
                        state->started = true;
                    }
                    nlohmann::json value;
                    client::RelayRequestSecretsWiper request_wiper(
                        state->request);
                    runtime::OperationStatus completed_status =
                        runtime::OperationStatus::Success;
                    std::string completed_error;
                    auto relay = weak_relay.lock();
                    if (relay) {
                        try {
                            value = relay->handle_local_request(state->request);
                        } catch (std::exception const& ex) {
                            completed_status =
                                runtime::OperationStatus::InternalError;
                            completed_error =
                                std::string("inproc request threw: ") + ex.what();
                            value = {
                                {"ok", false},
                                {"error", completed_error},
                            };
                        } catch (...) {
                            completed_status =
                                runtime::OperationStatus::InternalError;
                            completed_error =
                                "inproc request threw: unknown error";
                            value = {
                                {"ok", false},
                                {"error", completed_error},
                            };
                        }
                    } else {
                        completed_status =
                            runtime::OperationStatus::NotRunning;
                        completed_error =
                            "in-process runtime disconnected";
                        value = {
                            {"ok", false},
                            {"error", completed_error},
                        };
                    }
                    // Release executor-bound ownership before releasing the
                    // lease that permits connected-session teardown to finish.
                    relay.reset();
                    {
                        std::lock_guard<std::mutex> state_lock(state->mutex);
                        if (!state->ready) {
                            state->value = std::move(value);
                            state->operation_status = completed_status;
                            state->operation_error =
                                std::move(completed_error);
                            state->ready = true;
                        }
                        state->runtime_lease.release();
                    }
                    state->cv.notify_all();
                });
            posted = true;
        } catch (std::exception const& ex) {
            if (error) {
                *error = std::string("failed to post in-process request: ") +
                         ex.what();
            }
        } catch (...) {
            if (error) *error = "failed to post in-process request";
        }
    }

    // The posted handler either owns the operation lease or was cancelled.
    // Do not retain executor-bound objects on the waiting caller thread.
    runtime_relay.reset();
    runtime_tunnel.reset();
    runtime_gate.reset();

    if (!posted) {
        {
            std::lock_guard<std::mutex> state_lock(state->mutex);
            state->cancelled = true;
            state->runtime_lease.release();
        }
        std::lock_guard<std::mutex> lock(impl_->ready_mtx);
        impl_->pending_requests.erase(
            std::remove_if(impl_->pending_requests.begin(),
                           impl_->pending_requests.end(),
                           [&state](const auto& weak) {
                               auto item = weak.lock();
                               return !item || item == state;
                           }),
            impl_->pending_requests.end());
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::InternalError);
        return nlohmann::json{{"ok", false}, {"error", "request post failed"}};
    }

    std::unique_lock<std::mutex> state_lock(state->mutex);
    if (!state->cv.wait_for(
            state_lock,
            std::chrono::milliseconds(std::max(timeout_ms, 0)),
            [&state] { return state->ready; })) {
        state->cancelled = true;
        if (!state->started) {
            state->runtime_lease.release();
        }
        state_lock.unlock();
        if (error) *error = "in-process request timed out";
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::Timeout);
    } else {
        auto value = std::move(state->value);
        const auto completed_status = state->operation_status;
        auto completed_error = std::move(state->operation_error);
        state_lock.unlock();
        std::lock_guard<std::mutex> lock(impl_->ready_mtx);
        impl_->pending_requests.erase(
            std::remove_if(impl_->pending_requests.begin(),
                           impl_->pending_requests.end(),
                           [&state](const auto& weak) {
                               auto item = weak.lock();
                               return !item || item == state;
                           }),
            impl_->pending_requests.end());
        runtime::SetOperationStatus(operation_status, completed_status);
        if (error && completed_status != runtime::OperationStatus::Success) {
            *error = completed_error.empty()
                ? "in-process request failed"
                : std::move(completed_error);
        }
        return value;
    }

    std::lock_guard<std::mutex> lock(impl_->ready_mtx);
    impl_->pending_requests.erase(
        std::remove_if(impl_->pending_requests.begin(),
                       impl_->pending_requests.end(),
                       [&state](const auto& weak) {
                           auto item = weak.lock();
                           return !item || item == state;
                       }),
        impl_->pending_requests.end());
    return nlohmann::json{{"ok", false}, {"error", "timed out"}};
}

}  // namespace yume::facade
