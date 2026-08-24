/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/session/client_session.hpp"

#include <algorithm>
#include <atomic>
#include <exception>
#include <filesystem>
#include <mutex>
#include <thread>
#include <unordered_map>

#include <nlohmann/json.hpp>

#include "facade/config/config_io.hpp"
#include "facade/session/inproc_client.hpp"
#include "facade/logging/log_sink.hpp"
#include "facade/security/secure_materials.hpp"
#include "facade/metrics/traffic_meter.hpp"
#include "client/relay/secret.hpp"
#include "util.hpp"

namespace yume::facade {

namespace {

std::string endpoint_for(client::ClientConfig const& cfg) {
    if (cfg.server.empty()) return {};
    return cfg.server + ":" + std::to_string(cfg.port);
}

bool resolve_secure_materials(client::ClientConfig& cfg, std::string* err) {
    namespace sm = secure_materials;

    if (!cfg.anonym_ca_material_id.empty()) {
        std::string material_error;
        auto path = sm::material_path(cfg.anonym_ca_material_id, &material_error);
        if (!path) {
            if (err) *err = material_error.empty()
                ? "selected operator CA material is unavailable"
                : material_error;
            return false;
        }
        cfg.anonym_ca_cert = path->string();
    }

    if (!cfg.auth_key_material_id.empty()) {
        std::string material_error;
        auto path = sm::material_path(cfg.auth_key_material_id, &material_error);
        if (!path) {
            if (err) *err = material_error.empty()
                ? "selected auth key material is unavailable"
                : material_error;
            return false;
        }
        cfg.identity = path->string();
    }

    if (!cfg.anonym_pubkey_material_id.empty()) {
        std::string e;
        auto path = sm::material_path(cfg.anonym_pubkey_material_id, &e);
        if (!path) {
            if (err) *err = e.empty() ? "legacy proof key material unavailable" : e;
            return false;
        }
        cfg.anonym_pubkey = path->string();
    }

    if (!cfg.tls_ca_material_id.empty()) {
        std::string e;
        auto path = sm::material_path(cfg.tls_ca_material_id, &e);
        if (!path) {
            if (err) *err = e.empty() ? "TLS CA material unavailable" : e;
            return false;
        }
        cfg.tls_ca_cert = path->string();
    }
    return true;
}

void push_client_log(LogLevel level, std::string message) noexcept {
    try {
        LogSink::instance().push(
            level, "facade.client", std::move(message));
    } catch (...) {
        // Diagnostic subscribers are consumer code. They must not unwind a
        // lifecycle worker or suppress its terminal state notification.
    }
}

void apply_config_status(ClientStatus& status,
                         client::ClientConfig const& cfg) {
    status.profile = cfg.tls_stealth_profile;
    status.security_mode = std::string(
        ratchet::SecurityModeName(cfg.security_profile.mode));
    status.effective_protection =
        "composite-auth + ML-KEM-1024/X25519/PSK directional ratchet";
    status.tls_backend = cfg.tls_backend;
    status.rekey_window = cfg.rekey_window;
    status.server_endpoint = endpoint_for(cfg);
}

void notify_client_status(ClientSession::StatusCallback const& callback,
                          ClientStatus const& status) noexcept {
    if (!callback) return;
    try {
        callback(status);
    } catch (std::exception const& ex) {
        try {
            push_client_log(
                LogLevel::Error,
                std::string("client status callback threw: ") + ex.what());
        } catch (...) {
        }
    } catch (...) {
        push_client_log(
            LogLevel::Error,
            "client status callback threw an unknown exception");
    }
}

}  // namespace

struct ClientSession::Impl {
    mutable std::mutex mtx;
    client::ClientConfig cfg;
    ClientStatus status;
    TrafficMeter traffic;
    InProcClient runtime;

    StatusCallback status_cb;
    std::unordered_map<std::string, std::string> chat_peers;

    std::thread worker;
    std::atomic<bool> worker_busy{false};
    std::thread stop_worker;
    std::atomic<bool> stop_busy{false};
    std::mutex lifecycle_mtx;
    std::recursive_mutex notification_mtx;
    std::atomic<std::uint64_t> lifecycle_generation{0};

    // Periodic IPC poll task: asks the runtime for bytes_in/bytes_out
    // every ~500 ms, deltas into the TrafficMeter so the dashboard
    // graph has live samples to plot. Stopped via stats_stop.
    std::thread stats_thread;
    std::mutex stats_thread_mtx;
    std::atomic<bool> stats_stop{false};
    bool stats_start_enabled{true};
    std::uint64_t last_bytes_in{0};
    std::uint64_t last_bytes_out{0};

    StatusCallback status_callback() const { return status_cb; }

    bool current_start(std::uint64_t generation) const noexcept {
        return lifecycle_generation.load(std::memory_order_acquire) == generation &&
               !stop_busy.load(std::memory_order_acquire);
    }

    void start_stats_thread() {
        std::lock_guard<std::mutex> lock(stats_thread_mtx);
        if (!stats_start_enabled) return;
        if (stats_thread.joinable()) return;
        stats_stop.store(false);
        stats_thread = std::thread([this]() {
            while (!stats_stop.load()) {
                std::string ipc_err;
                auto resp = runtime.request("runtime.status",
                    nlohmann::json::object(), &ipc_err, 1500);
                if (resp.is_object() && resp.value("ok", false)) {
                    auto const& r = resp["result"];
                    const std::uint64_t in  = r.value("bytes_in",  0ULL);
                    const std::uint64_t out = r.value("bytes_out", 0ULL);
                    const std::uint64_t d_in = in > last_bytes_in
                        ? in - last_bytes_in : 0ULL;
                    const std::uint64_t d_out = out > last_bytes_out
                        ? out - last_bytes_out : 0ULL;
                    last_bytes_in = in;
                    last_bytes_out = out;
                    if (d_in) traffic.record_rx(d_in);
                    if (d_out) traffic.record_tx(d_out);
                }
                traffic.tick();
                for (int i = 0; i < 5 && !stats_stop.load(); ++i) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            }
        });
    }

    void request_stats_stop(bool disable_future_starts = false) {
        if (disable_future_starts) {
            std::lock_guard<std::mutex> lock(stats_thread_mtx);
            stats_start_enabled = false;
        }
        stats_stop.store(true, std::memory_order_release);
    }

    void join_stats_thread(bool disable_future_starts = false) {
        // Creation, joinability checks, move/assignment, and join all share one
        // lock. The worker never takes this lock, so joining while holding it
        // cannot deadlock with the polling loop.
        std::lock_guard<std::mutex> lock(stats_thread_mtx);
        if (disable_future_starts) {
            stats_start_enabled = false;
        }
        stats_stop.store(true);
        if (stats_thread.joinable()) stats_thread.join();
        last_bytes_in = 0;
        last_bytes_out = 0;
    }

    bool has_stats_thread() {
        std::lock_guard<std::mutex> lock(stats_thread_mtx);
        return stats_thread.joinable();
    }
};

ClientSession::ClientSession(client::ClientConfig cfg)
    : impl_(std::make_unique<Impl>()) {
    impl_->cfg = std::move(cfg);
    apply_config_status(impl_->status, impl_->cfg);
}

ClientSession::~ClientSession() {
    // Consumer callbacks are not part of teardown. Clear them before asking
    // worker threads to stop so destruction cannot re-enter a partially
    // destroyed facade object.
    {
        std::lock_guard<std::recursive_mutex> notification_lock(
            impl_->notification_mtx);
        std::lock_guard<std::mutex> lock(impl_->mtx);
        impl_->status_cb = {};
    }
    stop();
    impl_->request_stats_stop(true);
    impl_->runtime.request_stop("client session destroyed");

    std::thread stop_worker;
    {
        std::lock_guard<std::mutex> lock(impl_->lifecycle_mtx);
        if (impl_->stop_worker.joinable()) {
            stop_worker = std::move(impl_->stop_worker);
        }
    }
    if (stop_worker.joinable()) stop_worker.join();

    impl_->runtime.stop(nullptr, "client session destroyed");
    std::thread start_worker;
    {
        std::lock_guard<std::mutex> lock(impl_->lifecycle_mtx);
        if (impl_->worker.joinable()) {
            start_worker = std::move(impl_->worker);
        }
    }
    if (start_worker.joinable()) start_worker.join();
    impl_->join_stats_thread(true);
}

bool ClientSession::start(std::string* err) {
    client::ClientConfig cfg;
    StatusCallback cb;
    ClientStatus snapshot;
    std::uint64_t generation = 0;
    {
        std::lock_guard<std::mutex> lifecycle_lock(impl_->lifecycle_mtx);
        const bool has_stats_thread = impl_->has_stats_thread();
        if (impl_->runtime.running() || impl_->worker_busy.load() ||
            impl_->stop_busy.load(std::memory_order_acquire) ||
            has_stats_thread) {
            if (err) *err = impl_->stop_busy.load(std::memory_order_relaxed)
                ? "client runtime is still stopping"
                : (has_stats_thread
                       ? "previous client runtime still needs stop cleanup"
                       : "client runtime is already running");
            return false;
        }
        // A false busy flag is published only after the corresponding worker
        // has completed all state access, so these joins cannot block.
        if (impl_->stop_worker.joinable()) impl_->stop_worker.join();
        if (impl_->worker.joinable()) impl_->worker.join();
        generation = impl_->lifecycle_generation.fetch_add(
            1, std::memory_order_acq_rel) + 1;
        impl_->worker_busy.store(true, std::memory_order_release);
    }
    {
        std::lock_guard<std::recursive_mutex> notification_lock(
            impl_->notification_mtx);
        if (!impl_->current_start(generation)) {
            impl_->worker_busy.store(false, std::memory_order_release);
            if (err) err->clear();
            return true;
        }
        {
            std::lock_guard<std::mutex> lock(impl_->mtx);
            cfg = impl_->cfg;
            impl_->status.state = ConnectionState::Connecting;
            impl_->status.message = "starting yume client runtime";
            snapshot = impl_->status;
            cb = impl_->status_callback();
        }
        // Fire the status callback BEFORE spawning the worker so the GUI sees
        // an immediate "Connecting" state on the same frame the user clicked.
        // notification_mtx serializes this with terminal stop/failure events.
        notify_client_status(cb, snapshot);
    }

    // Hand the blocking material-resolve + config-save + runtime.start
    // (which polls the IPC socket for up to ~1.5s) off to a worker thread
    // so the GUI thread never stalls on click.
    try {
        std::lock_guard<std::mutex> lifecycle_lock(impl_->lifecycle_mtx);
        if (!impl_->current_start(generation)) {
            impl_->worker_busy.store(false, std::memory_order_release);
            return true;
        }
        impl_->worker = std::thread(
            [this, cfg = std::move(cfg), generation]() mutable {
        auto fail = [this, generation](std::string msg) {
            std::lock_guard<std::recursive_mutex> notification_lock(
                impl_->notification_mtx);
            if (!impl_->current_start(generation)) {
                return;
            }
            StatusCallback fcb;
            ClientStatus fsnap;
            {
                std::lock_guard<std::mutex> lock(impl_->mtx);
                impl_->status.state = ConnectionState::Failed;
                impl_->status.message = msg;
                fsnap = impl_->status;
                fcb = impl_->status_callback();
            }
            push_client_log(LogLevel::Error, msg);
            notify_client_status(fcb, fsnap);
        };

        try {
            std::string mat_err;
            if (!resolve_secure_materials(cfg, &mat_err)) {
                fail(mat_err.empty() ? "secure materials not ready" : mat_err);
                impl_->worker_busy.store(false, std::memory_order_release);
                return;
            }

            if (!impl_->current_start(generation)) {
                impl_->worker_busy.store(false, std::memory_order_release);
                return;
            }

            std::string save_err;
            if (!config_io::save_client(cfg, config_io::default_client_config_path(), &save_err)) {
                fail("client config save before start failed: " + save_err);
                impl_->worker_busy.store(false, std::memory_order_release);
                return;
            }

            if (!impl_->current_start(generation)) {
                impl_->worker_busy.store(false, std::memory_order_release);
                return;
            }

            std::string start_err;
            // 30 s wait is the same connect/auth budget the IPC-spawn route
            // used; we inherit it for the in-process route so the GUI's
            // "Connecting..." spinner doesn't time out before a slow TLS
            // handshake completes.
            if (!impl_->runtime.start(std::move(cfg), &start_err,
                                      std::chrono::seconds(30))) {
                fail(start_err.empty() ? "client start failed" : start_err);
                impl_->worker_busy.store(false, std::memory_order_release);
                return;
            }

            if (!impl_->current_start(generation)) {
                impl_->runtime.request_stop("stale client startup");
                impl_->worker_busy.store(false, std::memory_order_release);
                return;
            }

            {
                std::lock_guard<std::recursive_mutex> notification_lock(
                    impl_->notification_mtx);
                if (!impl_->current_start(generation)) {
                    impl_->runtime.request_stop("stale client startup");
                    impl_->worker_busy.store(false, std::memory_order_release);
                    return;
                }
                auto runtime_status = impl_->runtime.status();
                StatusCallback ok_cb;
                ClientStatus ok_snap;
                {
                    std::lock_guard<std::mutex> lock(impl_->mtx);
                    impl_->status.state = runtime_status.ipc_available
                                              ? ConnectionState::Connected
                                              : ConnectionState::Authenticating;
                    impl_->status.message = runtime_status.message;
                    if (runtime_status.ipc_available &&
                        impl_->status.connected_since.time_since_epoch().count() == 0) {
                        impl_->status.connected_since =
                            std::chrono::system_clock::now();
                    }
                    ok_snap = impl_->status;
                    ok_cb = impl_->status_callback();
                }
                push_client_log(
                    LogLevel::Info, "client runtime started");
                notify_client_status(ok_cb, ok_snap);
            }

            // Spin up the stats-poll thread now that IPC is up. It loops
            // until stats_stop flips; each pass asks the runtime for
            // bytes_in/bytes_out and feeds the delta into the meter.
            if (impl_->current_start(generation)) {
                impl_->start_stats_thread();
            }
        } catch (std::exception const& ex) {
            fail(std::string("client startup exception: ") + ex.what());
        } catch (...) {
            fail("client startup exception: unknown error");
        }

        impl_->worker_busy.store(false, std::memory_order_release);
    });
    } catch (std::exception const& ex) {
        impl_->worker_busy.store(false, std::memory_order_release);
        const std::string failure =
            std::string("failed to start client lifecycle worker: ") + ex.what();
        if (err) *err = failure;
        if (impl_->current_start(generation)) {
            std::lock_guard<std::recursive_mutex> notification_lock(
                impl_->notification_mtx);
            if (!impl_->current_start(generation)) return false;
            StatusCallback fail_cb;
            ClientStatus fail_snapshot;
            {
                std::lock_guard<std::mutex> lock(impl_->mtx);
                impl_->status.state = ConnectionState::Failed;
                impl_->status.message = failure;
                fail_snapshot = impl_->status;
                fail_cb = impl_->status_callback();
            }
            notify_client_status(fail_cb, fail_snapshot);
        }
        return false;
    } catch (...) {
        impl_->worker_busy.store(false, std::memory_order_release);
        if (err) *err = "failed to start client lifecycle worker";
        if (impl_->current_start(generation)) {
            std::lock_guard<std::recursive_mutex> notification_lock(
                impl_->notification_mtx);
            if (!impl_->current_start(generation)) return false;
            StatusCallback fail_cb;
            ClientStatus fail_snapshot;
            {
                std::lock_guard<std::mutex> lock(impl_->mtx);
                impl_->status.state = ConnectionState::Failed;
                impl_->status.message = "failed to start client lifecycle worker";
                fail_snapshot = impl_->status;
                fail_cb = impl_->status_callback();
            }
            notify_client_status(fail_cb, fail_snapshot);
        }
        return false;
    }

    if (err) err->clear();
    return true;
}

void ClientSession::stop() {
    std::unique_lock<std::recursive_mutex> notification_lock(
        impl_->notification_mtx);
    {
        std::lock_guard<std::mutex> lifecycle_lock(impl_->lifecycle_mtx);
        if (impl_->stop_busy.load(std::memory_order_acquire)) {
            return;
        }
        if (!impl_->runtime.running() && !impl_->worker_busy.load() &&
            !impl_->worker.joinable() && !impl_->has_stats_thread()) {
            return;
        }
        impl_->lifecycle_generation.fetch_add(1, std::memory_order_acq_rel);
        impl_->stop_busy.store(true, std::memory_order_release);
        if (impl_->stop_worker.joinable()) impl_->stop_worker.join();
    }

    // Mark intent immediately so the UI shows "Disconnecting".
    StatusCallback cb;
    ClientStatus snap;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        impl_->status.state = ConnectionState::Disconnected;
        impl_->status.message = "stopping client";
        snap = impl_->status;
        cb = impl_->status_callback();
    }
    notify_client_status(cb, snap);
    notification_lock.unlock();

    impl_->request_stats_stop();
    impl_->runtime.request_stop("client stopping");

    // Do not join the startup worker here. It may be waiting for the full
    // connect/auth timeout, and ClientSession::stop() is called directly from
    // the GUI action path. The runtime cancellation and its join happen off
    // that thread instead.
    try {
        std::lock_guard<std::mutex> lifecycle_lock(impl_->lifecycle_mtx);
        impl_->stop_worker = std::thread([this]() {
            std::string stop_error;
            impl_->runtime.stop(&stop_error);
            impl_->request_stats_stop();
            impl_->join_stats_thread();

            std::thread start_worker;
            {
                std::lock_guard<std::mutex> lifecycle_lock(
                    impl_->lifecycle_mtx);
                if (impl_->worker.joinable()) {
                    start_worker = std::move(impl_->worker);
                }
            }
            if (start_worker.joinable()) start_worker.join();
            {
                std::lock_guard<std::recursive_mutex> notification_lock(
                    impl_->notification_mtx);
                StatusCallback done_cb;
                ClientStatus done_snap;
                {
                    std::lock_guard<std::mutex> lock(impl_->mtx);
                    impl_->status.state = ConnectionState::Disconnected;
                    impl_->status.message = stop_error.empty()
                        ? "stopped"
                        : stop_error;
                    impl_->status.connected_since = {};
                    done_snap = impl_->status;
                    done_cb = impl_->status_callback();
                }
                impl_->worker_busy.store(false, std::memory_order_release);
                notify_client_status(done_cb, done_snap);
                // Keep new starts excluded until the terminal callback completes
                // so observers cannot see a later Connecting event first.
                impl_->stop_busy.store(false, std::memory_order_release);
            }
        });
    } catch (...) {
        // Thread construction failure must not strand the runtime. This path
        // may block, but it is the only fail-closed fallback available when
        // the system cannot create the asynchronous stop worker.
        impl_->runtime.stop();
        impl_->request_stats_stop();
        impl_->join_stats_thread();
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

bool ClientSession::running() const noexcept {
    return impl_->runtime.running();
}

ClientStatus ClientSession::status() const {
    auto runtime_status = impl_->runtime.status();
    std::lock_guard<std::mutex> lock(impl_->mtx);
    auto s = impl_->status;
    if (runtime_status.running) {
        s.state = runtime_status.ipc_available
                      ? ConnectionState::Connected
                      : ConnectionState::Authenticating;
        s.message = runtime_status.message;
        if (runtime_status.ipc_available && s.connected_since.time_since_epoch().count() == 0) {
            s.connected_since = runtime_status.started;
        }
    } else if (s.state != ConnectionState::Idle &&
               s.state != ConnectionState::Disconnected &&
               s.state != ConnectionState::Failed) {
        s.state = runtime_status.exit_code == 0 ? ConnectionState::Disconnected
                                                : ConnectionState::Failed;
        s.message = runtime_status.message;
    }
    s.server_tls_fingerprint_sha256 =
        runtime_status.server_tls_fingerprint_sha256;
    s.server_capabilities = runtime_status.server_capabilities;
    s.packet_bulk_supported = std::find(
        s.server_capabilities.begin(), s.server_capabilities.end(),
        "packet_bulk_v1") != s.server_capabilities.end();
    s.bytes_sent = impl_->traffic.total_tx();
    s.bytes_received = impl_->traffic.total_rx();
    auto latest = impl_->traffic.latest();
    s.tx_rate_bps = latest.tx_bps;
    s.rx_rate_bps = latest.rx_bps;
    return s;
}

TrafficMeter const& ClientSession::traffic() const noexcept {
    return impl_->traffic;
}

void ClientSession::set_config(client::ClientConfig cfg) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->cfg = std::move(cfg);
    apply_config_status(impl_->status, impl_->cfg);
}

client::ClientConfig ClientSession::config() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->cfg;
}

std::vector<ClientSession::DirectoryEntry> ClientSession::directory(std::string* err) const {
    std::string request_error;
    auto resp = impl_->runtime.request("directory.list", nlohmann::json::object(), &request_error, 10000);
    if (!request_error.empty()) {
        if (err) *err = request_error;
        return {};
    }
    if (!resp.value("ok", false)) {
        if (err) *err = resp.value("error", "directory request failed");
        return {};
    }
    std::vector<DirectoryEntry> out;
    auto items = resp.find("result");
    if (items == resp.end() || !items->is_array()) return out;
    for (auto const& item : *items) {
        DirectoryEntry e;
        e.endpoint_id = item.value("endpoint_id", "");
        e.display_name = item.value("display_name", "");
        e.endpoint_kind = item.value("endpoint_kind", "");
        e.relay_mode = item.value("relay_mode", "");
        e.client_platform = item.value("client_platform", "");
        e.client_variant = item.value("client_variant", "");
        e.allow_chat = item.value("allow_chat", false);
        e.allow_file = item.value("allow_file", false);
        e.allow_bytes = item.value("allow_bytes", false);
        out.push_back(std::move(e));
    }
    return out;
}

std::string ClientSession::open_chat(std::string const& peer_endpoint_id,
                                     std::string* err) {
    client::ClientConfig cfg;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        cfg = impl_->cfg;
    }
    if (cfg.relay_key_file.empty()) {
        if (err) {
            *err = "chat requires a configured relay_key_file";
        }
        return {};
    }
    std::string relay_secret;
    client::RelaySecretWiper relay_secret_wiper(relay_secret);
    if (!client::load_relay_secret_file(
            yume::util::expand_user(cfg.relay_key_file),
            &relay_secret, err)) {
        return {};
    }
    nlohmann::json args{
        {"peer", peer_endpoint_id},
        {"relay_secret", relay_secret},
    };
    std::string request_error;
    auto resp = impl_->runtime.request(
        "chat.open",
        args,
        &request_error,
        10000);
    if (auto secret = args.find("relay_secret");
        secret != args.end() && secret->is_string()) {
        client::wipe_relay_secret(secret->get_ref<std::string&>());
        args.erase(secret);
    }
    if (!request_error.empty()) {
        if (err) *err = request_error;
        return {};
    }
    if (!resp.value("ok", false)) {
        if (err) *err = resp.value("error", "chat open failed");
        return {};
    }
    auto result = resp.find("result");
    if (result == resp.end() || !result->is_object()) {
        if (err) *err = "chat open returned no channel identity";
        return {};
    }
    const std::string channel_id = result->value("channel_id", "");
    const std::string peer_id = result->value("peer_id", "");
    if (channel_id.empty() || peer_id.empty()) {
        if (err) *err = "chat open returned an invalid channel identity";
        return {};
    }
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        impl_->chat_peers[channel_id] = peer_id;
    }
    return channel_id;
}

void ClientSession::close_chat(std::string const& channel_id) {
    std::string request_error;
    auto resp = impl_->runtime.request(
        "chat.close", nlohmann::json{{"channel_id", channel_id}},
        &request_error, 10000);
    if (!request_error.empty() || !resp.value("ok", false)) {
        const std::string message = !request_error.empty()
            ? std::move(request_error)
            : resp.value("error", "chat close failed");
        push_client_log(LogLevel::Warn, message);
        return;
    }
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->chat_peers.erase(channel_id);
}

bool ClientSession::send_chat(std::string const& channel_id,
                              std::string const& text,
                              std::string* err) {
    std::string request_error;
    auto resp = impl_->runtime.request(
        "chat.send",
        nlohmann::json{{"channel_id", channel_id}, {"text", text}},
        &request_error,
        10000);
    if (!request_error.empty()) {
        if (err) *err = request_error;
        return false;
    }
    if (!resp.value("ok", false)) {
        if (err) *err = resp.value("error", "chat send failed");
        return false;
    }
    return true;
}

std::vector<ClientSession::ChatMessage> ClientSession::chat_history(
    std::string const& channel_id, std::size_t max) const {
    nlohmann::json args = nlohmann::json::object();
    if (!channel_id.empty()) {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        auto peer = impl_->chat_peers.find(channel_id);
        if (peer == impl_->chat_peers.end()) return {};
        args["peer_id"] = peer->second;
    }
    std::string request_error;
    auto resp = impl_->runtime.request("history.list", args, &request_error, 10000);
    if (!request_error.empty() || !resp.value("ok", false)) return {};
    auto items = resp.find("result");
    if (items == resp.end() || !items->is_array()) return {};
    std::vector<ChatMessage> out;
    for (auto const& item : *items) {
        ChatMessage msg;
        msg.channel_id = channel_id;
        msg.outgoing = item.value("direction", "") == "out";
        msg.from_endpoint_id = msg.outgoing
            ? "you" : item.value("peer_id", "");
        msg.text = item.value("text", "");
        const auto ts_ms = item.value("ts_ms", std::int64_t{0});
        msg.ts = std::chrono::system_clock::time_point{
            std::chrono::milliseconds(ts_ms)};
        out.push_back(std::move(msg));
    }
    if (out.size() <= max) return out;
    return std::vector<ChatMessage>(out.end() - static_cast<std::ptrdiff_t>(max), out.end());
}

void ClientSession::set_status_callback(StatusCallback cb) {
    std::lock_guard<std::recursive_mutex> notification_lock(
        impl_->notification_mtx);
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->status_cb = std::move(cb);
}

}  // namespace yume::facade
