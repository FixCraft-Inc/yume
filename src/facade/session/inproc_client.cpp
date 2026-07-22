/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/session/inproc_client.hpp"

#include <cstdio>
#include <exception>
#include <future>
#include <utility>
#include <vector>

#include <boost/asio/post.hpp>

#include "client/relay/runtime.hpp"
#include "client/transport/tunnel.hpp"
#include "facade/logging/log_sink.hpp"

namespace yume::facade {

namespace {

std::string latest_startup_error(std::chrono::system_clock::time_point since) {
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
    return {};
}

}  // namespace

struct InProcClient::Impl {
    std::thread cli_thread;
    std::atomic<bool> running{false};

    // Filled on Cli's worker thread when the runtime-ready callback
    // fires. Protected by ready_mtx so start() can block on the
    // condition variable without racing the worker.
    std::mutex ready_mtx;
    std::condition_variable ready_cv;
    bool ready{false};
    std::string ready_error;

    // Held after the tunnel is up. Both pointers keep the network
    // primitives alive even after Cli::run returns (the worker thread
    // exit drops Cli's local shared_ptrs; ours persist until stop()).
    std::shared_ptr<client::Tunnel> tunnel;
    std::shared_ptr<client::RelayRuntime> relay;
    // True only while Tunnel's executor and its strand service are alive.
    // The connected-session scope clears this under ready_mtx before its
    // io_context can be destroyed.
    bool runtime_executor_active{false};
    std::string server_tls_fingerprint_sha256;
    std::vector<std::string> server_capabilities;
    std::shared_ptr<std::atomic<bool>> cancel_requested;

    LogCallback log_callback;
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
        s.ipc_available = static_cast<bool>(impl_->relay);
        s.server_tls_fingerprint_sha256 =
            impl_->server_tls_fingerprint_sha256;
        return s;
    }
}

std::shared_ptr<client::Tunnel> InProcClient::primary_tunnel() const {
    std::lock_guard<std::mutex> lock(impl_->ready_mtx);
    return impl_->tunnel;
}

std::vector<std::string> InProcClient::server_capabilities() const {
    std::lock_guard<std::mutex> lock(impl_->ready_mtx);
    return impl_->server_capabilities;
}

void InProcClient::set_log_callback(LogCallback cb) {
    impl_->log_callback = std::move(cb);
}

bool InProcClient::start(client::ClientConfig cfg, std::string* error,
                         std::chrono::seconds wait) {
    if (impl_->running.exchange(true, std::memory_order_acq_rel)) {
        if (error) *error = "in-process client is already running";
        return false;
    }
    // A completed Cli worker remains joinable until its owner reaps it. Joining
    // before assigning a replacement is mandatory: assigning over a joinable
    // std::thread terminates the process after a natural disconnect/reconnect.
    if (impl_->cli_thread.joinable()) {
        impl_->cli_thread.join();
    }
    {
        std::lock_guard<std::mutex> lock(impl_->ready_mtx);
        impl_->ready       = false;
        impl_->ready_error.clear();
        impl_->tunnel.reset();
        impl_->relay.reset();
        impl_->runtime_executor_active = false;
        impl_->server_tls_fingerprint_sha256.clear();
        impl_->server_capabilities.clear();
        impl_->cancel_requested = std::make_shared<std::atomic<bool>>(false);
        impl_->started = std::chrono::system_clock::now();
    }

    auto cancel_requested = impl_->cancel_requested;
    impl_->cli_thread = std::thread([this, cfg = std::move(cfg), cancel_requested]() mutable {
        client::Cli cli;
        (void)LogSink::instance();
        // Suppress the colour-coded banner Cli prints after auth — the
        // same details are surfaced in the GUI's status panes, and we
        // don't want them duplicated into stdout/stderr of whatever
        // terminal launched the GUI.
        cli.set_silent(true);
        cli.set_external_stop_flag(cancel_requested);
        cli.set_runtime_ready_callback(
            [this](std::shared_ptr<client::Tunnel> tunnel,
                   std::shared_ptr<client::RelayRuntime> relay,
                   client::RuntimeReadyInfo ready_info) {
                {
                    std::lock_guard<std::mutex> lock(impl_->ready_mtx);
                    impl_->tunnel = std::move(tunnel);
                    impl_->relay  = std::move(relay);
                    impl_->server_tls_fingerprint_sha256 =
                        std::move(ready_info.server_tls_fingerprint_sha256);
                    impl_->server_capabilities =
                        std::move(ready_info.server_capabilities);
                    impl_->ready  = true;
                }
                impl_->ready_cv.notify_all();
            });
        cli.set_runtime_active_callback(
            [this](boost::asio::io_context* io,
                   std::shared_ptr<client::Tunnel> tunnel,
                   std::shared_ptr<client::RelayRuntime> relay,
                   std::function<void(const std::string&)>) {
                std::lock_guard<std::mutex> lock(impl_->ready_mtx);
                if (!io) {
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
            LogSink::instance().push(
                LogLevel::Error, "client.runtime", unhandled_error);
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
                impl_->ready       = true;  // unblock start()'s wait
            }
        }
        impl_->ready_cv.notify_all();
        impl_->running.store(false, std::memory_order_release);
    });

    std::unique_lock<std::mutex> lock(impl_->ready_mtx);
    if (!impl_->ready_cv.wait_for(lock, wait, [this] { return impl_->ready; })) {
        // Timed out waiting for the tunnel. The thread is still running -
        // tear it down so the next start() has a clean slate.
        lock.unlock();
        stop();
        if (error) *error = "timed out waiting for in-process client to become ready";
        return false;
    }
    if (!impl_->relay || !impl_->tunnel) {
        std::string captured = impl_->ready_error;
        lock.unlock();
        stop();
        if (error) *error = captured.empty()
            ? "in-process client did not produce a tunnel"
            : captured;
        return false;
    }
    return true;
}

void InProcClient::stop(std::string* /*error*/, std::string const& reason) {
    std::shared_ptr<std::atomic<bool>> cancel_requested;
    {
        std::lock_guard<std::mutex> lock(impl_->ready_mtx);
        cancel_requested = impl_->cancel_requested;
        if (cancel_requested) {
            cancel_requested->store(true, std::memory_order_release);
        }
        // Posting and the connected-session executor reset share ready_mtx.
        // This prevents an EOF teardown from destroying Asio's strand mutex
        // between the active check and Tunnel::stop().
        constexpr const char* kForcedCloseReason = "interrupt";
        (void)reason;
        if (impl_->runtime_executor_active && impl_->tunnel) {
            impl_->tunnel->stop(kForcedCloseReason);
        }
    }
    if (impl_->cli_thread.joinable()) {
        impl_->cli_thread.join();
    }
    {
        std::lock_guard<std::mutex> lock(impl_->ready_mtx);
        impl_->tunnel.reset();
        impl_->relay.reset();
        impl_->runtime_executor_active = false;
        impl_->server_tls_fingerprint_sha256.clear();
        impl_->server_capabilities.clear();
        impl_->cancel_requested.reset();
        impl_->ready = false;
        impl_->ready_error.clear();
    }
    impl_->running.store(false, std::memory_order_release);
}

nlohmann::json InProcClient::request(std::string const& op,
                                     nlohmann::json const& args,
                                     std::string* error,
                                     int timeout_ms) {
    std::shared_ptr<client::RelayRuntime> relay;
    std::shared_ptr<client::Tunnel>       tunnel;
    {
        std::lock_guard<std::mutex> lock(impl_->ready_mtx);
        relay  = impl_->relay;
        tunnel = impl_->tunnel;
    }
    if (!relay || !tunnel) {
        if (error) *error = "in-process client not running";
        return nlohmann::json{{"ok", false}, {"error", "not running"}};
    }

    // RelayRuntime::handle_local_request was designed for the IPC
    // server, which always calls it from Cli's io_context worker.
    // To preserve that invariant we don't call it directly from the
    // caller's thread - we post onto the tunnel's executor (which is
    // tied to the same io_context) and wait for the promise.
    auto promise = std::make_shared<std::promise<nlohmann::json>>();
    auto future  = promise->get_future();

    nlohmann::json req = {{"op", op}, {"args", args}};
    boost::asio::post(tunnel->get_executor(),
                      [relay, req, promise]() {
                          try {
                              promise->set_value(relay->handle_local_request(req));
                          } catch (std::exception const& ex) {
                              promise->set_value(nlohmann::json{
                                  {"ok", false},
                                  {"error", std::string("inproc request threw: ") + ex.what()}
                              });
                          }
                      });

    auto status = future.wait_for(std::chrono::milliseconds(timeout_ms));
    if (status != std::future_status::ready) {
        if (error) *error = "in-process request timed out";
        return nlohmann::json{{"ok", false}, {"error", "timed out"}};
    }
    return future.get();
}

}  // namespace yume::facade
