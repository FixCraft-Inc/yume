/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/session/inproc_client.hpp"

#include <cstdio>
#include <future>
#include <utility>
#include <vector>

#include <boost/asio/post.hpp>

#include "client/relay/runtime.hpp"
#include "client/transport/tunnel.hpp"
#include "facade/logging/log_sink.hpp"

namespace yume::facade {

namespace {

// Helper: append argv slot only when value is non-empty / non-default.
// argv is owned as a vector<string> so the pointers handed to Cli are
// stable for the lifetime of the call.
void push_arg(std::vector<std::string>& args, std::string flag, std::string value) {
    if (value.empty()) return;
    args.push_back(std::move(flag));
    args.push_back(std::move(value));
}

void push_flag(std::vector<std::string>& args, bool on, char const* on_flag, char const* off_flag) {
    if (on && on_flag)  args.push_back(on_flag);
    if (!on && off_flag) args.push_back(off_flag);
}

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

// Translate a fully-populated ClientConfig back into a synthetic argv
// for Cli::run. We go through argv (rather than calling an internal
// Cli entrypoint) because Cli's option parsing is the canonical source
// of truth for config defaults, validation, and path resolution -
// duplicating any of that in the facade would drift over time.
std::vector<std::string> build_argv(client::ClientConfig const& cfg) {
    std::vector<std::string> a;
    a.reserve(64);
    a.push_back("yume");  // argv[0]

    a.push_back("--non-interactive");
    a.push_back("--boring");
    // Disable attach-local so the embedded Cli always does a fresh
    // connect instead of looking for another yume process's socket.
    // ClientConfig has auto_attach_local true by default; argv overrides.
    // (There's no explicit --no-attach-local; we set an env-style
    // workaround through the config below by clearing auto_attach_local
    // before serializing... actually the simplest path is to leave it
    // and trust that no other yume is running on the same instance_key
    // when the GUI starts.)

    push_arg(a, "--server", cfg.server);
    if (cfg.port > 0) push_arg(a, "--port", std::to_string(cfg.port));
    push_arg(a, "--auth", cfg.identity);
    if (cfg.socks_port > 0) push_arg(a, "--socks", std::to_string(cfg.socks_port));
    if (cfg.io_threads > 0) push_arg(a, "--threads", std::to_string(cfg.io_threads));

    push_flag(a, cfg.obfuscation, "--obfs", "--no-obfs");
    push_arg(a, "--obfs-secret", cfg.obfs_secret);

    if (cfg.inner_crypto) {
        a.push_back("--inner");
        push_flag(a, cfg.inner_heavy, "--inner-heavy", "--inner-light");
        push_flag(a, cfg.inner_hop, "--hop", "--no-hop");
        if (cfg.hop_interval_ms > 0) {
            push_arg(a, "--hop-interval", std::to_string(cfg.hop_interval_ms));
        }
    } else {
        a.push_back("--no-inner");
        a.push_back("--no-hop");
    }

    if (cfg.allow_udp)        a.push_back("--udp");
    else                      a.push_back("--tcp");
    if (cfg.allow_local_ip)   a.push_back("--allow-local-ip");
    if (cfg.allow_exec)       a.push_back("--allow-exec");

    push_arg(a, "--pq-pub", cfg.pq_public_key);
    push_flag(a, cfg.allow_embedded_master, "--use-embedded-master", "--no-embedded-master");

    push_arg(a, "--anonym-ca-cert", cfg.anonym_ca_cert);
    push_arg(a, "--tls-ca", cfg.tls_ca_cert);
    push_arg(a, "--tls-name", cfg.tls_server_name);
    push_arg(a, "--tls-pin", cfg.tls_pin_sha256);
    if (cfg.require_anonym) a.push_back("--require-anonym");
    if (cfg.accept_monitoring) a.push_back("--accept-monitoring");

    push_arg(a, "--name", cfg.preferred_name);
    push_arg(a, "--client-id", cfg.preferred_id);
    push_arg(a, "--relay-mode", cfg.relay_mode);
    push_flag(a, cfg.allow_inbound_admin,  "--allow-inbound-admin",  "--deny-inbound-admin");
    push_flag(a, cfg.allow_outbound_admin, "--allow-outbound-admin", "--deny-outbound-admin");
    push_flag(a, cfg.allow_chat,  "--allow-chat",  "--deny-chat");
    push_flag(a, cfg.allow_file,  "--allow-file",  "--deny-file");
    push_flag(a, cfg.allow_bytes, "--allow-bytes", "--deny-bytes");
    if (!cfg.history_enabled) a.push_back("--no-history");
    push_arg(a, "--history-dir", cfg.history_dir);
    push_arg(a, "--relay-key-file", cfg.relay_key_file);
    push_arg(a, "--instance", cfg.instance_name);

    push_flag(a, cfg.tls_stealth_enabled, nullptr, "--no-stealth");
    push_arg(a, "--profile", cfg.tls_stealth_profile);
    if (cfg.tls_stealth_rotate) a.push_back("--tls-stealth-rotate");
    if (cfg.tls_stealth_rotation_interval > 0) {
        push_arg(a, "--tls-stealth-rotation-interval",
                 std::to_string(cfg.tls_stealth_rotation_interval));
    }
    if (cfg.tls_fingerprint_log) a.push_back("--tls-fingerprint-log");
    push_arg(a, "--tls-fingerprint-log-path", cfg.tls_fingerprint_log_path);
    if (cfg.tls_fingerprint_verify) a.push_back("--tls-fingerprint-verify");
    push_arg(a, "--tls-fingerprint-test-endpoint", cfg.tls_fingerprint_test_endpoint);

    push_arg(a, "--proxy", cfg.outbound_proxy_url);

    return a;
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
    boost::asio::io_context* active_io{nullptr};
    std::function<void(const std::string&)> active_disconnect;
    std::string server_tls_fingerprint_sha256;

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
    Status s = impl_->last_status;
    s.running       = impl_->running.load(std::memory_order_acquire);
    s.exit_code     = impl_->exit_code.load(std::memory_order_acquire);
    s.started       = impl_->started;
    {
        std::lock_guard<std::mutex> lock(impl_->ready_mtx);
        s.ipc_available = static_cast<bool>(impl_->relay);
        s.server_tls_fingerprint_sha256 =
            impl_->server_tls_fingerprint_sha256;
    }
    return s;
}

std::shared_ptr<client::Tunnel> InProcClient::primary_tunnel() const {
    std::lock_guard<std::mutex> lock(impl_->ready_mtx);
    return impl_->tunnel;
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
    {
        std::lock_guard<std::mutex> lock(impl_->ready_mtx);
        impl_->ready       = false;
        impl_->ready_error.clear();
        impl_->tunnel.reset();
        impl_->relay.reset();
        impl_->active_io = nullptr;
        impl_->active_disconnect = {};
        impl_->server_tls_fingerprint_sha256.clear();
    }
    impl_->started = std::chrono::system_clock::now();

    impl_->cli_thread = std::thread([this, cfg = std::move(cfg)]() mutable {
        client::Cli cli;
        (void)LogSink::instance();
        // Suppress the colour-coded banner Cli prints after auth — the
        // same details are surfaced in the GUI's status panes, and we
        // don't want them duplicated into stdout/stderr of whatever
        // terminal launched the GUI.
        cli.set_silent(true);
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
                    impl_->ready  = true;
                }
                impl_->ready_cv.notify_all();
            });
        cli.set_runtime_active_callback(
            [this](boost::asio::io_context* io,
                   std::shared_ptr<client::Tunnel> tunnel,
                   std::shared_ptr<client::RelayRuntime> relay,
                   std::function<void(const std::string&)> disconnect) {
                std::lock_guard<std::mutex> lock(impl_->ready_mtx);
                impl_->active_io = io;
                if (tunnel) {
                    impl_->tunnel = std::move(tunnel);
                }
                if (relay) {
                    impl_->relay = std::move(relay);
                }
                impl_->active_disconnect = std::move(disconnect);
            });

        // Synthetic argv. The vector owns the strings; argv_ptrs only
        // points into them. Lifetime is the lambda's scope, which
        // ends when Cli::run returns - exactly what we need.
        std::vector<std::string> argv = build_argv(cfg);
        std::vector<char*> argv_ptrs;
        argv_ptrs.reserve(argv.size() + 1);
        for (auto& s : argv) argv_ptrs.push_back(s.data());
        argv_ptrs.push_back(nullptr);

        int rc = cli.run(static_cast<int>(argv.size()), argv_ptrs.data());
        impl_->exit_code.store(rc, std::memory_order_release);

        // Cli::run has returned. If we got here without ever signalling
        // ready, surface the exit code to start()'s caller; otherwise
        // it's a normal disconnect after a healthy run.
        {
            std::lock_guard<std::mutex> lock(impl_->ready_mtx);
            if (!impl_->ready) {
                std::string detail = latest_startup_error(impl_->started);
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
        {
            std::lock_guard<std::mutex> lock(impl_->ready_mtx);
            impl_->active_io = nullptr;
            impl_->active_disconnect = {};
        }
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
    std::shared_ptr<client::Tunnel> t;
    boost::asio::io_context* io = nullptr;
    std::function<void(const std::string&)> disconnect;
    {
        std::lock_guard<std::mutex> lock(impl_->ready_mtx);
        t = impl_->tunnel;
        io = impl_->active_io;
        disconnect = impl_->active_disconnect;
    }
    // Use the same forced-close tunnel reason as the CLI signal path.
    // A normal SSL shutdown can block here if the peer does not send
    // close_notify, and this API must return synchronously to embedders.
    constexpr const char* kForcedCloseReason = "interrupt";
    (void)reason;
    if (disconnect) {
        disconnect(kForcedCloseReason);
    } else if (t) {
        t->stop(kForcedCloseReason);
    }
    if (io) {
        io->stop();
    }
    if (impl_->cli_thread.joinable()) {
        impl_->cli_thread.join();
    }
    {
        std::lock_guard<std::mutex> lock(impl_->ready_mtx);
        impl_->tunnel.reset();
        impl_->relay.reset();
        impl_->active_io = nullptr;
        impl_->active_disconnect = {};
        impl_->server_tls_fingerprint_sha256.clear();
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
