/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/session/client_session.hpp"

#include <atomic>
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

namespace yume::facade {

namespace {

std::string endpoint_for(client::ClientConfig const& cfg) {
    if (cfg.server.empty()) return {};
    return cfg.server + ":" + std::to_string(cfg.port);
}

std::string strip_ansi(std::string const& in) {
    std::string out;
    out.reserve(in.size());
    std::size_t i = 0;
    while (i < in.size()) {
        if (in[i] == '\x1b' && i + 1 < in.size() && in[i + 1] == '[') {
            i += 2;
            while (i < in.size() && (in[i] < '@' || in[i] > '~')) ++i;
            if (i < in.size()) ++i;  // skip the CSI terminator
            continue;
        }
        out.push_back(in[i]);
        ++i;
    }
    return out;
}

bool resolve_secure_materials(client::ClientConfig& cfg, std::string* err) {
    namespace sm = secure_materials;

    if (cfg.anonym_ca_material_id.empty()) {
        cfg.anonym_ca_material_id = sm::kDefaultAnonymCaId;
    }
    if (!cfg.anonym_ca_material_id.empty()) {
        std::string material_error;
        auto path = sm::material_path(cfg.anonym_ca_material_id, &material_error);
        if (!path) {
            if (err) *err = material_error.empty()
                ? "selected anonym CA material is unavailable"
                : material_error;
            return false;
        }
        cfg.anonym_ca_cert = path->string();
    } else if (cfg.anonym_ca_cert.empty()) {
        std::string material_error;
        auto path = sm::ensure_default_anonym_ca(&material_error);
        if (path.empty()) {
            if (err) *err = material_error.empty()
                ? "embedded anonym CA could not be prepared"
                : material_error;
            return false;
        }
        cfg.anonym_ca_cert = path.string();
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
            if (err) *err = e.empty() ? "anonym public key material unavailable" : e;
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

}  // namespace

struct ClientSession::Impl {
    mutable std::mutex mtx;
    client::ClientConfig cfg;
    ClientStatus status;
    TrafficMeter traffic;
    InProcClient runtime;

    StatusCallback status_cb;
    ChatCallback chat_cb;
    std::unordered_map<std::string, std::vector<ChatMessage>> history;

    std::thread worker;
    std::atomic<bool> worker_busy{false};
    std::thread stop_worker;
    std::atomic<bool> stop_busy{false};

    // Periodic IPC poll task: asks the runtime for bytes_in/bytes_out
    // every ~500 ms, deltas into the TrafficMeter so the dashboard
    // graph has live samples to plot. Stopped via stats_stop.
    std::thread stats_thread;
    std::mutex stats_thread_mtx;
    std::atomic<bool> stats_stop{false};
    std::uint64_t last_bytes_in{0};
    std::uint64_t last_bytes_out{0};

    StatusCallback status_callback() const { return status_cb; }

    void join_previous_worker() {
        if (worker.joinable()) worker.join();
    }

    void join_previous_stop_worker() {
        if (stop_worker.joinable()) stop_worker.join();
    }

    void start_stats_thread() {
        std::lock_guard<std::mutex> lock(stats_thread_mtx);
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

    void stop_stats_thread() {
        // Creation, joinability checks, move/assignment, and join all share one
        // lock. The worker never takes this lock, so joining while holding it
        // cannot deadlock with the polling loop.
        std::lock_guard<std::mutex> lock(stats_thread_mtx);
        stats_stop.store(true);
        if (stats_thread.joinable()) stats_thread.join();
        last_bytes_in = 0;
        last_bytes_out = 0;
    }
};

ClientSession::ClientSession(client::ClientConfig cfg)
    : impl_(std::make_unique<Impl>()) {
    impl_->cfg = std::move(cfg);
    impl_->status.profile = impl_->cfg.tls_stealth_profile;
    impl_->status.inner_mode =
        impl_->cfg.inner_crypto
            ? (impl_->cfg.inner_heavy ? "heavy" : "light")
            : "off";
    impl_->status.server_endpoint = endpoint_for(impl_->cfg);
    impl_->runtime.set_log_callback([](std::string const& line) {
        std::string clean = strip_ansi(line);
        LogLevel level = LogLevel::Info;
        if (clean.find("[ERROR]") != std::string::npos || clean.find("error") != std::string::npos) {
            level = LogLevel::Error;
        } else if (clean.find("[WARN]") != std::string::npos || clean.find("warn") != std::string::npos) {
            level = LogLevel::Warn;
        }
        LogSink::instance().push(level, "client.runtime", std::move(clean));
    });
}

ClientSession::~ClientSession() {
    stop();
    impl_->stop_stats_thread();
    impl_->join_previous_worker();
    impl_->join_previous_stop_worker();
}

bool ClientSession::start(std::string* err) {
    client::ClientConfig cfg;
    StatusCallback cb;
    ClientStatus snapshot;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        if (impl_->runtime.running() || impl_->worker_busy.load() ||
            impl_->stop_busy.load(std::memory_order_acquire)) {
            if (err) *err = impl_->stop_busy.load(std::memory_order_relaxed)
                ? "client runtime is still stopping"
                : "client runtime is already running";
            return false;
        }
        cfg = impl_->cfg;
        impl_->status.state = ConnectionState::Connecting;
        impl_->status.message = "starting yume client runtime";
        snapshot = impl_->status;
        cb = impl_->status_callback();
    }
    // Fire the status callback BEFORE spawning the worker so the GUI sees
    // an immediate "Connecting" state on the same frame the user clicked.
    if (cb) cb(snapshot);

    // Reap any previous worker (start/stop alternation).
    impl_->join_previous_stop_worker();
    impl_->join_previous_worker();
    impl_->worker_busy.store(true);

    // Hand the blocking material-resolve + config-save + runtime.start
    // (which polls the IPC socket for up to ~1.5s) off to a worker thread
    // so the GUI thread never stalls on click.
    impl_->worker = std::thread([this, cfg = std::move(cfg)]() mutable {
        auto fail = [this](std::string msg) {
            if (impl_->stop_busy.load(std::memory_order_acquire)) {
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
            LogSink::instance().push(LogLevel::Error, "facade.client", msg);
            if (fcb) fcb(fsnap);
        };

        std::string mat_err;
        if (!resolve_secure_materials(cfg, &mat_err)) {
            fail(mat_err.empty() ? "secure materials not ready" : mat_err);
            impl_->worker_busy.store(false);
            return;
        }

        std::string save_err;
        if (!config_io::save_client(cfg, config_io::default_client_config_path(), &save_err)) {
            fail("client config save before start failed: " + save_err);
            impl_->worker_busy.store(false);
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
            impl_->worker_busy.store(false);
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
                impl_->status.connected_since = std::chrono::system_clock::now();
            }
            ok_snap = impl_->status;
            ok_cb = impl_->status_callback();
        }
        LogSink::instance().push(LogLevel::Info, "facade.client", "client runtime started");
        if (ok_cb) ok_cb(ok_snap);

        // Spin up the stats-poll thread now that IPC is up. It loops
        // until stats_stop flips; each pass asks the runtime for
        // bytes_in/bytes_out and feeds the delta into the meter.
        if (!impl_->stop_busy.load(std::memory_order_acquire)) {
            impl_->start_stats_thread();
        }

        impl_->worker_busy.store(false);
    });

    return true;
}

void ClientSession::stop() {
    if ((!impl_->runtime.running() && !impl_->worker_busy.load()) ||
        impl_->stop_busy.exchange(true)) return;

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
    if (cb) cb(snap);

    impl_->stop_stats_thread();

    // Do not join the startup worker here. It may be waiting for the full
    // connect/auth timeout, and ClientSession::stop() is called directly from
    // the GUI action path. The runtime cancellation and its join happen off
    // that thread instead.
    impl_->join_previous_stop_worker();
    impl_->stop_worker = std::thread([this]() {
        std::string stop_error;
        impl_->runtime.stop(&stop_error);
        StatusCallback done_cb;
        ClientStatus done_snap;
        {
            std::lock_guard<std::mutex> lock(impl_->mtx);
            impl_->status.state = ConnectionState::Disconnected;
            impl_->status.message = stop_error.empty() ? "stopped" : stop_error;
            impl_->status.connected_since = {};
            done_snap = impl_->status;
            done_cb = impl_->status_callback();
        }
        if (done_cb) done_cb(done_snap);
        impl_->worker_busy.store(false);
        impl_->stop_busy.store(false);
    });
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
    impl_->status.profile = impl_->cfg.tls_stealth_profile;
    impl_->status.inner_mode =
        impl_->cfg.inner_crypto
            ? (impl_->cfg.inner_heavy ? "heavy" : "light")
            : "off";
    impl_->status.server_endpoint = endpoint_for(impl_->cfg);
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
    std::string request_error;
    auto resp = impl_->runtime.request(
        "chat.open",
        nlohmann::json{{"peer", peer_endpoint_id}},
        &request_error,
        10000);
    if (!request_error.empty()) {
        if (err) *err = request_error;
        return {};
    }
    if (!resp.value("ok", false)) {
        if (err) *err = resp.value("error", "chat open failed");
        return {};
    }
    return "active";
}

void ClientSession::close_chat(std::string const& /*channel_id*/) {}

bool ClientSession::send_chat(std::string const& /*channel_id*/,
                              std::string const& text,
                              std::string* err) {
    std::string request_error;
    auto resp = impl_->runtime.request(
        "chat.send",
        nlohmann::json{{"text", text}},
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
    if (!channel_id.empty() && channel_id != "active") {
        args["peer_id"] = channel_id;
    }
    std::string request_error;
    auto resp = impl_->runtime.request("history.list", args, &request_error, 10000);
    if (!request_error.empty() || !resp.value("ok", false)) return {};
    auto items = resp.find("result");
    if (items == resp.end() || !items->is_array()) return {};
    std::vector<ChatMessage> out;
    for (auto const& item : *items) {
        ChatMessage msg;
        msg.channel_id = channel_id.empty() ? "active" : channel_id;
        msg.from_endpoint_id = item.value("peer_id", "");
        msg.text = item.value("text", "");
        out.push_back(std::move(msg));
    }
    if (out.size() <= max) return out;
    return std::vector<ChatMessage>(out.end() - static_cast<std::ptrdiff_t>(max), out.end());
}

void ClientSession::set_status_callback(StatusCallback cb) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->status_cb = std::move(cb);
}

void ClientSession::set_chat_callback(ChatCallback cb) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->chat_cb = std::move(cb);
}

}  // namespace yume::facade
