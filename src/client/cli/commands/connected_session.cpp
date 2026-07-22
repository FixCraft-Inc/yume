/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/commands/connected_session.hpp"

#include "client/cli/commands/bench.hpp"
#include "client/cli/commands/console.hpp"
#include "client/cli/commands/io_runtime.hpp"
#include "client/cli/commands/proxy.hpp"
#include "client/cli/commands/relay_secret.hpp"
#include "client/cli/parse/endpoints.hpp"
#include "client/cli/config/platform.hpp"
#include "client/cli/connect/diagnostics.hpp"
#include "client/cli/connect/auth.hpp"
#include "client/cli/connect/secondary_tunnel.hpp"
#include "client/codec/monero_rpc.hpp"
#include "client/packet/channel.hpp"
#include "client/packet/tun_adapter.hpp"
#include "client/proxy/forward.hpp"
#include "client/proxy/socks.hpp"
#include "client/relay/runtime.hpp"
#include "client/runtime/local_runtime.hpp"
#include "client/transport/tunnel.hpp"
#include "client/transport/tunnel_pool.hpp"
#include "core/protocol/protocol.hpp"
#include "core/protocol/protocol_stream.hpp"
#include "core/security/identity.hpp"
#include "core/stealth/http_profile.hpp"
#include "core/stealth/tls_stealth.hpp"
#include "core/version.hpp"
#include "util.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <utility>

#include <nlohmann/json.hpp>

namespace yume::client {
namespace {

// Must match the server's kHopDecryptWindow (server/session/session.cpp). 120
// hops at 500 ms intervals = +/-60 s tolerance for queued-frame staleness.
constexpr std::uint64_t kHopDecryptWindow = 120;

struct LongRunningWaitState {
    void signal() {
        {
            std::lock_guard<std::mutex> lock(mu);
            done = true;
        }
        cv.notify_all();
    }

    void wait() {
        std::unique_lock<std::mutex> lock(mu);
        cv.wait(lock, [this] { return done; });
    }

    std::mutex mu;
    std::condition_variable cv;
    bool done{false};
};

using LongRunningWaitStatePtr = std::shared_ptr<LongRunningWaitState>;

crypto::Bytes derive_hop_key(const crypto::Bytes& key,
                             bool hop_enabled,
                             std::uint32_t hop_interval_ms,
                             std::int64_t hop_offset_ms) {
    if (!hop_enabled || hop_interval_ms == 0) {
        return key;
    }
    const std::uint64_t hop_id =
        inner::hop_id_from_time_ms(util::now_ms(), hop_interval_ms, hop_offset_ms);
    return inner::derive_hop_key(key, hop_id);
}

crypto::Bytes decrypt_control_payload(const crypto::Bytes& key,
                                      uint8_t frame_type,
                                      uint8_t stream_id,
                                      const crypto::Bytes& blob,
                                      bool hop_enabled,
                                      std::uint32_t hop_interval_ms,
                                      std::int64_t hop_offset_ms) {
    if (!hop_enabled || hop_interval_ms == 0) {
        return inner::decrypt_payload(key, frame_type, stream_id, blob);
    }
    const std::uint64_t hop_id =
        inner::hop_id_from_time_ms(util::now_ms(), hop_interval_ms, hop_offset_ms);
    std::uint64_t candidates[1 + (kHopDecryptWindow * 2)];
    std::size_t candidate_count = 0;
    candidates[candidate_count++] = hop_id;
    for (std::uint64_t delta = 1; delta <= kHopDecryptWindow; ++delta) {
        if (hop_id >= delta) {
            candidates[candidate_count++] = hop_id - delta;
        }
        candidates[candidate_count++] = hop_id + delta;
    }
    for (std::size_t i = 0; i < candidate_count; ++i) {
        crypto::Bytes hop_key = inner::derive_hop_key(key, candidates[i]);
        try {
            return inner::decrypt_payload(hop_key, frame_type, stream_id, blob);
        } catch (...) {
        }
    }
    throw std::runtime_error("control decrypt failed");
}

class ControlFrameClient {
public:
    ControlFrameClient(ClientTlsStream& stream,
                       boost::asio::io_context& io,
                       const std::optional<crypto::Bytes>& inner_key,
                       bool hop_enabled,
                       std::uint32_t hop_interval_ms,
                       std::int64_t hop_offset_ms,
                       obfs::H2Carrier* carrier,
                       crypto::Bytes* prefetched,
                       ratchet::SessionRatchet* ratchet)
        : stream_(stream),
          io_(io),
          inner_key_(inner_key),
          hop_enabled_(hop_enabled),
          hop_interval_ms_(hop_interval_ms),
          hop_offset_ms_(hop_offset_ms),
          carrier_(carrier),
          prefetched_(prefetched),
          ratchet_(ratchet) {}

    void send(const nlohmann::json& req) {
        std::string payload_str = req.dump();
        crypto::Bytes payload(payload_str.begin(), payload_str.end());
        uint16_t flags = 0;
        if (inner_key_.has_value() && !ratchet_) {
            crypto::Bytes key = derive_hop_key(*inner_key_, hop_enabled_, hop_interval_ms_, hop_offset_ms_);
            payload = inner::encrypt_payload(key, protocol::CONTROL, 0, payload);
            flags |= protocol::kFlagInnerEncrypted;
        }
        protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::CONTROL, 0, flags}, payload};
        if (ratchet_) {
            frame = ratchet_->Seal(frame, std::chrono::steady_clock::now());
        }
        if (carrier_) {
            send_frame_over_h2_with_timeout(stream_, io_, *carrier_, frame,
                                            kServerInfoTimeout, "control request");
        } else {
            protocol::send_frame(stream_, frame);
        }
    }

    nlohmann::json request(const nlohmann::json& req) {
        send(req);
        auto resp_frame = carrier_
            ? read_frame_over_h2_with_timeout(
                  stream_, io_, *carrier_, prefetched_, kServerInfoTimeout,
                  "control response", "server", 0)
            : protocol::read_frame(stream_);
        if (ratchet_) {
            auto opened = ratchet_->Open(resp_frame,
                                         std::chrono::steady_clock::now());
            if (opened.control_response.has_value()) {
                if (!carrier_) {
                    throw std::runtime_error("ratchet control response requires H2 carrier");
                }
                send_frame_over_h2_with_timeout(
                    stream_, io_, *carrier_, *opened.control_response,
                    kServerInfoTimeout, "rekey acknowledgement");
                resp_frame = carrier_
                    ? read_frame_over_h2_with_timeout(
                          stream_, io_, *carrier_, prefetched_,
                          kServerInfoTimeout, "control response", "server", 0)
                    : protocol::read_frame(stream_);
                opened = ratchet_->Open(resp_frame,
                                         std::chrono::steady_clock::now());
            }
            if (!opened.application_frame.has_value()) {
                throw std::runtime_error("missing control application response");
            }
            resp_frame = std::move(*opened.application_frame);
        }
        if (resp_frame.header.type != protocol::CONTROL) {
            throw std::runtime_error("unexpected control response");
        }
        crypto::Bytes payload = resp_frame.payload;
        if (inner_key_.has_value() && !ratchet_) {
            if ((resp_frame.header.flags & protocol::kFlagInnerEncrypted) == 0) {
                throw std::runtime_error("control response missing inner encryption");
            }
            payload = decrypt_control_payload(
                *inner_key_,
                protocol::CONTROL,
                resp_frame.header.stream_id,
                resp_frame.payload,
                hop_enabled_,
                hop_interval_ms_,
                hop_offset_ms_);
        }
        return nlohmann::json::parse(std::string(payload.begin(), payload.end()));
    }

private:
    ClientTlsStream& stream_;
    boost::asio::io_context& io_;
    const std::optional<crypto::Bytes>& inner_key_;
    bool hop_enabled_{false};
    std::uint32_t hop_interval_ms_{0};
    std::int64_t hop_offset_ms_{0};
    obfs::H2Carrier* carrier_{nullptr};
    crypto::Bytes* prefetched_{nullptr};
    ratchet::SessionRatchet* ratchet_{nullptr};
};

void register_control_client_if_needed(const ClientConfig& cfg, ControlFrameClient& control_client) {
    if (!cfg.server_in_charge && !cfg.allow_exec) {
        return;
    }
    nlohmann::json reg;
    reg["cmd"] = "register";
    reg["hostname"] = get_system_hostname();
    reg["wan_ip"] = "";
    reg["server_in_charge"] = cfg.server_in_charge;
    reg["allow_exec"] = cfg.allow_exec;
    control_client.send(reg);
}

int list_controlled_clients(ControlFrameClient& control_client) {
    nlohmann::json req;
    req["cmd"] = "list";
    auto resp = control_client.request(req);
    if (resp.contains("error")) {
        util::log_error(resp["error"].get<std::string>());
        return 1;
    }
    if (!resp.contains("clients")) {
        util::log_error("control list missing clients");
        return 1;
    }
    const auto& clients = resp["clients"];
    if (!clients.is_array() || clients.empty()) {
        std::cout << "no controlled clients\n";
        return 0;
    }
    for (const auto& item : clients) {
        std::string perms;
        const bool allow_exec = item.value("allow_exec", false);
        const bool server_in_charge = item.value("server_in_charge", false);
        if (server_in_charge) {
            perms += "server-in-charge";
        }
        if (allow_exec) {
            if (!perms.empty()) {
                perms += ",";
            }
            perms += "exec";
        }
        if (perms.empty()) {
            perms = "none";
        }
        std::cout << "id=" << item.value("id", "")
                  << " host=" << item.value("hostname", "")
                  << " wan=" << item.value("wan_ip", "")
                  << " perms=" << perms << "\n";
    }
    return 0;
}

int attach_control_client(const std::string& control_id, ControlFrameClient& control_client) {
    nlohmann::json req;
    req["cmd"] = "attach";
    req["id"] = control_id;
    auto resp = control_client.request(req);
    if (!resp.value("ok", false)) {
        util::log_error(resp.value("error", "control attach failed"));
        return 1;
    }
    std::string perms;
    if (resp.value("server_in_charge", false)) {
        perms += "server-in-charge";
    }
    if (resp.value("allow_exec", false)) {
        if (!perms.empty()) {
            perms += ",";
        }
        perms += "exec";
    }
    if (perms.empty()) {
        perms = "none";
    }
    util::log_info("attached to id=" + resp.value("id", "") +
                   " host=" + resp.value("hostname", "") +
                   " wan=" + resp.value("wan_ip", "") +
                   " perms=" + perms);
    return 0;
}

RelayRuntime::Options make_relay_options(const ClientConfig& cfg) {
    RelayRuntime::Options relay_opts;
    relay_opts.identity_path = cfg.identity;
    relay_opts.hostname = get_system_hostname();
    relay_opts.preferred_name = cfg.preferred_name;
    relay_opts.preferred_id = cfg.preferred_id;
    relay_opts.instance_name = cfg.instance_name.empty()
        ? yume::identity::derive_instance_key(cfg.server + ":" + cfg.identity)
        : cfg.instance_name;
    relay_opts.client_platform = detect_client_platform();
    relay_opts.client_variant = "cli";
    relay_opts.client_version = yume::kVersion;
    relay_opts.relay_mode = control::relay_mode_from_string(cfg.relay_mode);
    relay_opts.allow_inbound_admin = cfg.allow_inbound_admin;
    relay_opts.allow_outbound_admin = cfg.allow_outbound_admin;
    relay_opts.allow_chat = cfg.allow_chat;
    relay_opts.allow_file = cfg.allow_file;
    relay_opts.allow_bytes = cfg.allow_bytes;
    relay_opts.history_enabled = cfg.history_enabled;
    relay_opts.history_dir = util::expand_user(cfg.history_dir);
    return relay_opts;
}

std::string effective_protection_summary(const ClientConfig& cfg,
                                         bool inner_key_established,
                                         bool have_inner_caps,
                                         bool server_inner_dual,
                                         bool server_inner_active,
                                         bool hop_enabled,
                                         const std::optional<inner::KdfParams>& inner_kdf) {
    if (!inner_key_established && !server_inner_active) {
        return "TLS over 443";
    }
    std::string protection = (have_inner_caps && server_inner_dual)
        ? "Inner dual"
        : (std::string("Inner ") + (cfg.inner_heavy ? "heavy" : "light"));
    if (hop_enabled) {
        protection += " + hop";
    }
    protection += " over 443";
    std::string kdf_name;
    if (inner_kdf.has_value()) {
        kdf_name = inner_kdf->name;
    }
    if (kdf_name.empty()) {
        kdf_name = cfg.inner_heavy ? "argon2" : "hkdf";
    }
    if (!kdf_name.empty()) {
        protection += " (" + kdf_name + ")";
    }
    return protection;
}

bool should_open_secondary_socks_tunnels(const ClientConfig& cfg,
                                         const ParsedArgs& args,
                                         bool use_reverse) {
    return cfg.socks_port > 0 &&
           args.run_cmd.empty() &&
           args.exec_cmd.empty() &&
           args.lport <= 0 &&
           args.rhost.empty() &&
           args.rport <= 0 &&
           !use_reverse &&
           !args.directory_mode &&
           cfg.app_codec.empty() &&
           args.chat_target.empty() &&
           args.file_target.empty() &&
           args.bytes_target.empty() &&
           args.admin_target.empty() &&
           !args.control_mode;
}

std::vector<std::shared_ptr<Tunnel>> open_secondary_socks_tunnels(
    boost::asio::io_context& io,
    boost::asio::ssl::context& ctx,
    const ClientConfig& cfg,
    const outbound_proxy::Config& proxy_cfg,
    const ParsedArgs& args,
    bool use_reverse,
    const std::shared_ptr<TunnelPool>& tunnel_pool,
    const ConnectedSessionOptions& options) {
    std::vector<std::shared_ptr<Tunnel>> secondary_tunnels;
    if (!should_open_secondary_socks_tunnels(cfg, args, use_reverse) || cfg.tunnel_count <= 1) {
        return secondary_tunnels;
    }
    for (int i = 2; i <= cfg.tunnel_count; ++i) {
        try {
            util::log_info("opening SOCKS secondary tunnel " +
                           std::to_string(i) + "/" +
                           std::to_string(cfg.tunnel_count));
            std::optional<tls_fingerprint::BrowserProfile> profile;
            std::string carrier_user_agent = http_profile::active_client_ua();
            if (cfg.tls_stealth_enabled && cfg.tls_stealth_rotate &&
                options.completed_tls_connections &&
                options.base_tls_profile != tls_fingerprint::BrowserProfile::UNKNOWN) {
                profile = tls_stealth::profile_for_connection(
                    options.base_tls_profile,
                    true,
                    cfg.tls_stealth_rotation_interval,
                    *options.completed_tls_connections);
                if (!options.explicit_http_profile) {
                    if (auto http = http_profile::transport_client_for_tls_profile(*profile)) {
                        carrier_user_agent = http->user_agent;
                    }
                }
            }
            auto extra = connect_secondary_tunnel(
                io, ctx, cfg, proxy_cfg, i, profile,
                std::move(carrier_user_agent),
                cfg.tls_stealth_enabled ? options.completed_tls_connections
                                        : nullptr);
            tunnel_pool->add(extra);
            secondary_tunnels.push_back(extra);
        } catch (const std::exception& ex) {
            util::log_warn("SOCKS secondary tunnel " +
                           std::to_string(i) + "/" +
                           std::to_string(cfg.tunnel_count) +
                           " failed: " + ex.what());
        }
    }
    return secondary_tunnels;
}

class HopStatusGuard {
public:
    HopStatusGuard(std::shared_ptr<std::atomic<bool>> stop, std::thread* thread)
        : stop_(std::move(stop)), thread_(thread) {}
    HopStatusGuard(const HopStatusGuard&) = delete;
    HopStatusGuard& operator=(const HopStatusGuard&) = delete;
    ~HopStatusGuard() {
        if (stop_) {
            stop_->store(true);
        }
        if (thread_ && thread_->joinable()) {
            thread_->join();
        }
        util::clear_status_line();
    }

private:
    std::shared_ptr<std::atomic<bool>> stop_;
    std::thread* thread_{nullptr};
};

void start_live_status_if_needed(bool live_status_enabled,
                                 bool hop_enabled,
                                 std::uint32_t hop_interval_ms,
                                 const std::shared_ptr<std::atomic<bool>>& hop_status_stop,
                                 const std::function<std::string()>& status_block_builder,
                                 std::thread* hop_status_thread) {
    if (!live_status_enabled) {
        return;
    }
    if (status_block_builder && hop_enabled) {
        const int refresh_raw = static_cast<int>(hop_interval_ms / 2) + 137;
        const auto refresh_ms = std::chrono::milliseconds(
            std::clamp<int>(refresh_raw, 300, 1200));
        *hop_status_thread = std::thread([hop_status_stop, status_block_builder, refresh_ms]() {
            while (!hop_status_stop->load()) {
                util::set_status_line(status_block_builder());
                std::this_thread::sleep_for(refresh_ms);
            }
            util::clear_status_line();
        });
    } else if (status_block_builder) {
        util::set_status_line(status_block_builder());
    }
}

int wait_for_long_running_mode(IoThreadGroup& io_threads,
                               std::atomic<bool>& stop_requested,
                               const std::function<void()>& announce_stopping,
                               const std::string& close_reason,
                               const std::function<void()>& on_ready = {},
                               const LongRunningWaitStatePtr& wait_state = {}) {
    if (on_ready) {
        on_ready();
    }
    if (wait_state) {
        wait_state->wait();
        io_threads.stop_and_wait();
    } else {
        io_threads.wait();
    }
    if (stop_requested.load()) {
        if (announce_stopping) {
            announce_stopping();
        }
        return 130;
    }
    if (!close_reason.empty()) {
        util::log_error("tunnel closed: " + close_reason);
        return 1;
    }
    return 0;
}

int start_directory_mode(const std::shared_ptr<RelayRuntime>& relay_runtime,
                         std::string* relay_error) {
    auto endpoints = relay_runtime->request_directory(relay_error);
    if (!relay_error->empty()) {
        util::log_error(*relay_error);
        return 1;
    }
    for (const auto& endpoint : endpoints) {
        std::cout << endpoint.endpoint_id
                  << " " << endpoint.display_name
                  << " kind=" << control::to_string(endpoint.endpoint_kind)
                  << " relay=" << control::to_string(endpoint.relay_mode)
                  << " platform=" << endpoint.client_platform
                  << " variant=" << endpoint.client_variant
                  << " chat=" << (endpoint.allow_chat ? "yes" : "no")
                  << " file=" << (endpoint.allow_file ? "yes" : "no")
                  << " bytes=" << (endpoint.allow_bytes ? "yes" : "no")
                  << "\n";
    }
    return 0;
}

int start_relay_one_shots(const ParsedArgs& args,
                          const ClientConfig& cfg,
                          const std::shared_ptr<RelayRuntime>& relay_runtime,
                          std::string* relay_error) {
    if (!args.chat_target.empty()) {
        std::string relay_secret_b64;
        if (!resolve_relay_secret(cfg, "", "chat with " + args.chat_target, &relay_secret_b64, relay_error)) {
            util::log_error("chat open failed: " + *relay_error);
            return 1;
        }
        if (!relay_runtime->open_chat(args.chat_target, relay_secret_b64, relay_error)) {
            util::log_error("chat open failed: " + *relay_error);
            return 1;
        }
    }
    if (!args.file_target.empty()) {
        std::string relay_secret_b64;
        if (!resolve_relay_secret(cfg, "", "file send to " + args.file_target, &relay_secret_b64, relay_error)) {
            util::log_error("file send failed: " + *relay_error);
            return 1;
        }
        if (!relay_runtime->send_file(args.file_target, args.file_path, relay_secret_b64, relay_error)) {
            util::log_error("file send failed: " + *relay_error);
            return 1;
        }
    }
    if (!args.bytes_target.empty()) {
        std::string relay_secret_b64;
        if (!resolve_relay_secret(cfg, "", "bytes send to " + args.bytes_target, &relay_secret_b64, relay_error)) {
            util::log_error("bytes send failed: " + *relay_error);
            return 1;
        }
        if (!relay_runtime->send_bytes_path(args.bytes_target, args.bytes_path, relay_secret_b64, relay_error)) {
            util::log_error("bytes send failed: " + *relay_error);
            return 1;
        }
    }
    if (!args.admin_target.empty() &&
        !relay_runtime->admin_attach(args.admin_target, relay_error)) {
        util::log_error("admin attach failed: " + *relay_error);
        return 1;
    }
    return 0;
}

struct ReverseTarget {
    std::string host;
    int port{0};
};

void install_reverse_handler(const std::shared_ptr<Tunnel>& tunnel,
                             const std::shared_ptr<std::unordered_map<uint8_t, ReverseTarget>>& reverse_targets,
                             const std::shared_ptr<std::unordered_map<uint8_t, std::shared_ptr<ReverseForwardSession>>>& reverse_sessions) {
    tunnel->set_reverse_handler([reverse_targets, reverse_sessions, tunnel](uint8_t listen_id, uint8_t stream_id) {
        auto it = reverse_targets->find(listen_id);
        if (it == reverse_targets->end()) {
            tunnel->send_open_ack(stream_id, false, "unknown reverse listener");
            return;
        }
        auto session = std::make_shared<ReverseForwardSession>(
            tunnel, stream_id, it->second.host, it->second.port);
        (*reverse_sessions)[stream_id] = session;
        session->start();
    });
}

int request_reverse_listener(const ConnectedSessionOptions& options,
                             const std::shared_ptr<Tunnel>& tunnel,
                             const std::shared_ptr<std::unordered_map<uint8_t, ReverseTarget>>& reverse_targets) {
    const uint8_t listen_id = tunnel->reserve_stream_id();
    if (listen_id == 0) {
        util::log_error("no stream ids available for remote forward");
        return 1;
    }
    (*reverse_targets)[listen_id] = ReverseTarget{options.reverse_host, options.reverse_port};
    const bool auto_random =
        options.reverse_server_in_charge_auto && !options.reverse_server_in_charge_manual;
    const bool reclaim = !options.reverse_server_in_charge_auto;
    const int min_port = auto_random ? options.reverse_auto_min_port : 0;
    const int max_port = auto_random ? options.reverse_auto_max_port : 0;
    if (auto_random) {
        util::log_info("requesting server-in-charge reverse SSH on random port " +
                       std::to_string(min_port) + "-" + std::to_string(max_port));
    } else {
        util::log_info("requesting remote listener on " +
                       format_display_bind_endpoint(options.reverse_bind_host, options.reverse_listen_port));
    }
    tunnel->request_remote_listen(
        listen_id,
        options.reverse_bind_host,
        options.reverse_listen_port,
        [listen_port = options.reverse_listen_port,
         bind_host = options.reverse_bind_host,
         auto_mode = options.reverse_server_in_charge_auto](bool ok, const std::string& reason) {
            if (ok) {
                int active_port = listen_port;
                if (!reason.empty()) {
                    try {
                        auto json = nlohmann::json::parse(reason);
                        active_port = json.value("port", active_port);
                    } catch (...) {
                        try {
                            active_port = std::stoi(reason);
                        } catch (...) {
                        }
                    }
                }
                util::log_info("remote listener active on " +
                               format_display_bind_endpoint(bind_host, active_port));
                if (auto_mode) {
                    util::log_info("server-in-charge ready: server can reach client SSH via 127.0.0.1:" +
                                   std::to_string(active_port) + " -> 127.0.0.1:22");
                }
            } else {
                util::log_error("remote listener failed: " + reason);
            }
        },
        reclaim,
        min_port,
        max_port);
    return 0;
}

int run_exec_mode(const ParsedArgs& args,
                  boost::asio::io_context& io,
                  const std::shared_ptr<Tunnel>& tunnel,
                  IoThreadGroup& io_threads,
                  const std::string& close_reason) {
    const uint8_t stream_id = tunnel->reserve_stream_id();
    if (stream_id == 0) {
        util::log_error("no stream ids available for exec");
        return 1;
    }
    auto done = std::make_shared<std::atomic<bool>>(false);
    tunnel->register_stream(stream_id,
                            [stream_id](const Tunnel::Bytes& data) {
                                (void)stream_id;
                                std::cout.write(reinterpret_cast<const char*>(data.data()), data.size());
                                std::cout.flush();
                            },
                            [done, &io](const std::string&) {
                                done->store(true);
                                io.stop();
                            });
    tunnel->send_exec(stream_id, args.exec_cmd);
    io_threads.wait();
    if (!close_reason.empty()) {
        util::log_error("tunnel closed: " + close_reason);
        return 1;
    }
    return 0;
}

int run_local_command_mode(const ParsedArgs& args,
                           const ClientConfig& cfg,
                           boost::asio::io_context& io,
                           const std::shared_ptr<Tunnel>& tunnel,
                           IoThreadGroup& io_threads,
                           const std::string& argv0) {
    const int port = cfg.socks_port > 0 ? cfg.socks_port : 0;
    auto socks = std::make_shared<SocksServer>(io, std::string("127.0.0.1"), port, tunnel, cfg.allow_udp);
    socks->start();
    const int actual_port = socks->port();
    if (actual_port <= 0) {
        util::log_error("failed to start local SOCKS5 proxy for --run");
        return 1;
    }
    util::log_info("running local command via SOCKS5 127.0.0.1:" + std::to_string(actual_port));
    auto work = boost::asio::make_work_guard(io);
    std::string cmd = maybe_force_ipv4(args.run_cmd, true);
    if (cmd == args.run_cmd) {
        util::log_warn("IPv4-only enforced; if your command supports IPv4 forcing, add it explicitly.");
    }
    std::string self_path;
    try {
        self_path = std::filesystem::absolute(argv0).string();
    } catch (...) {
        self_path.clear();
    }
    cmd = wrap_ssh_with_proxy(cmd, actual_port, self_path);
    const int code = run_local_command_with_proxy(cmd, actual_port, true);
    work.reset();
    io.stop();
    io_threads.wait();
    return code == 0 ? 0 : 1;
}

int run_local_forward_mode(const ParsedArgs& args,
                           const ClientConfig& cfg,
                           boost::asio::io_context& io,
                           const std::shared_ptr<Tunnel>& tunnel,
                           IoThreadGroup& io_threads,
                           std::atomic<bool>& stop_requested,
                           const std::function<void()>& announce_stopping,
                           const std::string& close_reason,
                           const std::function<void()>& on_ready,
                           const LongRunningWaitStatePtr& wait_state) {
    if (args.lport <= 0 || args.rhost.empty() || args.rport <= 0) {
        util::log_error("--lport, --rhost, and --rport must be set together");
        return 1;
    }

    if (cfg.allow_udp) {
        auto forward = std::make_shared<UdpForwardServer>(
            io, args.lbind_host, args.lport, args.rhost, args.rport, tunnel, cfg.allow_local_ip);
        forward->start();
        util::log_info("udp forwarding " + format_display_bind_endpoint(args.lbind_host, args.lport) + " -> " +
                       args.rhost + ":" + std::to_string(args.rport));
        return wait_for_long_running_mode(
            io_threads, stop_requested, announce_stopping, close_reason, on_ready, wait_state);
    }

    auto forward = std::make_shared<ForwardServer>(
        io, args.lbind_host, args.lport, args.rhost, args.rport, tunnel, cfg.allow_local_ip);
    forward->start();
    util::log_info("forwarding " + format_display_bind_endpoint(args.lbind_host, args.lport) + " -> " +
                   args.rhost + ":" + std::to_string(args.rport));
    return wait_for_long_running_mode(
        io_threads, stop_requested, announce_stopping, close_reason, on_ready, wait_state);
}

int run_socks_mode(const ClientConfig& cfg,
                   boost::asio::io_context& io,
                   const std::shared_ptr<TunnelPool>& tunnel_pool,
                   IoThreadGroup& io_threads,
                   std::atomic<bool>& stop_requested,
                   const std::function<void()>& announce_stopping,
                   const std::string& close_reason,
                   const std::function<void()>& on_ready,
                   const LongRunningWaitStatePtr& wait_state) {
    auto socks = std::make_shared<SocksServer>(
        io, cfg.socks_bind_host, cfg.socks_port, tunnel_pool, cfg.allow_udp);
    socks->start();
    util::log_info("SOCKS5 listening on " + format_display_bind_endpoint(cfg.socks_bind_host, cfg.socks_port) +
                   " over " + std::to_string(tunnel_pool->size()) + " tunnel(s)");
    // SOCKS5 only covers what the browser/app actually routes through it.
    util::log_warn(
        "SOCKS5-mode leak notice: WebRTC / QUIC / system DNS "
        "BYPASS this proxy by design. A 'what's my IP' page that uses "
        "WebRTC (whoer.net, browserleaks.com) will show your real IP "
        "even though HTTP traffic is tunneled. To close: see "
        "docs/LEAK_TIGHT.md (browser flags + an iptables route-tight "
        "option), or use the Android client which runs at the VPN TUN "
        "layer and covers everything.");
    if (!cfg.allow_udp) {
        util::log_info(
            "  (UDP ASSOCIATE is off; pass --udp to allow apps that "
            "negotiate UDP through SOCKS5 - note: most browsers don't.)");
    }
    return wait_for_long_running_mode(
        io_threads, stop_requested, announce_stopping, close_reason, on_ready, wait_state);
}

int run_app_codec_mode(const ClientConfig& cfg,
                       boost::asio::io_context& io,
                       const std::shared_ptr<Tunnel>& tunnel,
                       IoThreadGroup& io_threads,
                       std::atomic<bool>& stop_requested,
                       const std::function<void()>& announce_stopping,
                       const std::string& close_reason,
                       const std::function<void()>& on_ready,
                       const LongRunningWaitStatePtr& wait_state) {
    if (cfg.app_codec != std::string(app_codec::builtin::kMoneroRpcCodecId)) {
        util::log_error("unsupported application codec: " + cfg.app_codec);
        return 1;
    }
    app_codec::Endpoint listen{cfg.app_codec_listen_host, cfg.app_codec_listen_port};
    auto server = std::make_shared<codec::MoneroRpcCodecServer>(io, listen, tunnel);
    server->start();
    util::log_info("Monero wallets can use --daemon-address " +
                   listen.host + ":" + std::to_string(listen.port));
    return wait_for_long_running_mode(
        io_threads, stop_requested, announce_stopping, close_reason, on_ready, wait_state);
}

}  // namespace

int run_connected_session(boost::asio::io_context& io,
                          boost::asio::ssl::context& ctx,
                          ClientTlsStream&& stream,
                          const outbound_proxy::Config& proxy_cfg,
                          ConnectedSessionOptions options,
                          std::atomic<bool>& stop_requested) {
    if (!options.args || !options.cfg) {
        throw std::runtime_error("connected session missing options");
    }
    const ParsedArgs& args = *options.args;
    const ClientConfig& cfg = *options.cfg;

    ControlFrameClient control_client(
        stream,
        io,
        options.inner_key,
        options.hop_enabled,
        options.hop_interval_ms,
        options.hop_offset_ms,
        options.h2_carrier.get(),
        &options.prefetched_carrier_bytes,
        options.ratchet.get());
    register_control_client_if_needed(cfg, control_client);

    if (args.list_controlled) {
        return list_controlled_clients(control_client);
    }

    if (args.control_mode) {
        const int attach_code = attach_control_client(args.control_id, control_client);
        if (attach_code != 0) {
            return attach_code;
        }
    }

    auto tunnel = std::make_shared<Tunnel>(
        std::move(stream), std::move(options.h2_carrier),
        std::move(options.prefetched_carrier_bytes),
        std::move(options.ratchet));
    struct ActiveRuntimeReset {
        ConnectedSessionOptions::SetActiveRuntimeCallback* callback;
        ~ActiveRuntimeReset() {
            if (callback && *callback) {
                (*callback)(nullptr, nullptr, nullptr, {});
            }
        }
    } active_runtime_reset{&options.set_active_runtime};
    if (options.set_active_runtime) {
        options.set_active_runtime(&io, tunnel, nullptr, {});
    }
    if (cfg.allow_embedded_master) {
        util::log_warn(
            "embedded master PQ keypair enabled; connection security depends on basefwx-bundled keys "
            "(disable with --no-embedded-master)");
    }
    if (options.inner_key.has_value()) {
        tunnel->set_inner_key(*options.inner_key);
    }
    tunnel->set_hop(options.hop_enabled, options.hop_interval_ms, options.hop_offset_ms);
    tunnel->set_obfs_shape(cfg.obfs_pad_multiple, cfg.obfs_jitter_ms);
    tunnel->set_server_in_charge(cfg.server_in_charge);
    tunnel->set_allow_exec(cfg.allow_exec);

    std::string close_reason;
    auto hop_status_stop = std::make_shared<std::atomic<bool>>(false);
    auto wait_state = std::make_shared<LongRunningWaitState>();
    tunnel->set_close_handler([&close_reason, &io, hop_status_stop, wait_state](const std::string& reason) {
        close_reason = reason;
        hop_status_stop->store(true);
        wait_state->signal();
        io.stop();
    });

    auto relay_runtime = std::make_shared<RelayRuntime>(tunnel, cfg, make_relay_options(cfg));
    bool runtime_ready_signalled = false;
    auto signal_runtime_ready = [&]() {
        if (runtime_ready_signalled) {
            return;
        }
        runtime_ready_signalled = true;
        if (options.take_runtime_ready_callback) {
            auto cb = options.take_runtime_ready_callback();
            if (!cb) {
                return;
            }
            RuntimeReadyInfo ready_info;
            ready_info.server_tls_fingerprint_sha256 =
                options.server_tls_fingerprint_sha256;
            ready_info.server_capabilities = options.server_capabilities;
            cb(tunnel, relay_runtime, std::move(ready_info));
        }
    };

    const std::string protection_summary = effective_protection_summary(
        cfg,
        options.inner_key.has_value(),
        options.have_inner_caps,
        options.server_inner_dual,
        options.server_inner_active,
        options.hop_enabled,
        options.inner_kdf);

    auto tunnel_pool = std::make_shared<TunnelPool>(TunnelPool::Policy::LeastLoaded);
    tunnel_pool->add(tunnel);
    auto secondary_tunnels = open_secondary_socks_tunnels(
        io, ctx, cfg, proxy_cfg, args, options.use_reverse, tunnel_pool,
        options);

    auto disconnect_once = std::make_shared<std::atomic<bool>>(false);
    auto request_disconnect = [disconnect_once,
                               relay_runtime,
                               tunnel_pool,
                               &io,
                               &stop_requested,
                               wait_state,
                               announce_stopping = options.announce_stopping](const std::string& reason,
                                                                              const std::string& lifecycle_message,
                                                                              bool mark_stop_requested) {
        if (disconnect_once->exchange(true)) {
            return;
        }
        if (mark_stop_requested) {
            stop_requested.store(true);
        }
        if (announce_stopping) {
            announce_stopping();
        }
        wait_state->signal();
        std::string lifecycle_error;
        relay_runtime->notify_disconnecting(lifecycle_message, &lifecycle_error);
        tunnel_pool->stop_all(reason);
        io.stop();
    };

    relay_runtime->set_stop_callback([request_disconnect]() {
        std::thread([request_disconnect]() {
            request_disconnect("runtime stop", "im disconnecting", true);
        }).detach();
    });

    std::string relay_error;
    std::shared_ptr<yume::client::LocalRuntime> local_runtime;
    if (!args.service_streams_only && cfg.packet_tun_name.empty()) {
        local_runtime = std::make_shared<yume::client::LocalRuntime>(
            options.local_runtime_path, relay_runtime);
        if (!local_runtime->start(&relay_error)) {
            util::log_warn("local attach disabled: " + relay_error);
            relay_error.clear();
        }
    }

    tunnel->set_control_handler([relay_runtime](const nlohmann::json& json) {
        relay_runtime->on_control_message(json);
    });
    tunnel->set_inbound_open_handler([relay_runtime](uint8_t stream_id, const nlohmann::json& json) {
        relay_runtime->on_inbound_open(stream_id, json);
    });
    auto traffic_lifecycle_started = std::make_shared<std::atomic<bool>>(false);
    tunnel->set_activity_handler([relay_runtime, protection_summary, traffic_lifecycle_started]() {
        if (traffic_lifecycle_started->exchange(true)) {
            return;
        }
        std::thread([relay_runtime, protection_summary]() {
            std::string ignored_error;
            relay_runtime->notify_traffic_flow(protection_summary, &ignored_error);
        }).detach();
    });

    if (options.set_active_runtime) {
        options.set_active_runtime(&io, tunnel, relay_runtime, [request_disconnect](const std::string& reason) {
            request_disconnect(reason, "im disconnecting", true);
        });
    }
    tunnel->start();
    for (auto& secondary : secondary_tunnels) {
        secondary->start();
    }

    IoThreadGroup io_threads(io, start_io_threads(io, cfg.io_threads));
    if (args.bench) {
        const EndpointBenchOptions bench_options{
            args.bench_mib,
            args.bench_chunk_kib,
            args.bench_streams,
            args.bench_direction,
            args.bench_full,
        };
        const int bench_code = run_endpoint_benchmark(tunnel, cfg, bench_options);
        tunnel_pool->stop_all("benchmark complete");
        // stop_all posts onto each tunnel strand. Let the primary close
        // handler begin (and emit its H2/WebSocket graceful close) before
        // stopping the io_context; otherwise the posted close can be discarded
        // and the peer observes a truncated TLS stream.
        const auto stop_deadline = std::chrono::steady_clock::now() +
                                   std::chrono::seconds(1);
        while (tunnel->is_alive() &&
               std::chrono::steady_clock::now() < stop_deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        io.stop();
        io_threads.wait();
        return bench_code;
    }

    if (!cfg.packet_tun_name.empty()) {
        std::string packet_error;
        auto packet_channel = packet::PacketChannel::open(
            tunnel, options.server_capabilities,
            std::chrono::seconds(30), &packet_error);
        if (!packet_channel) {
            util::log_error("packet channel failed: " + packet_error);
            tunnel_pool->stop_all("packet channel failed");
            io.stop();
            io_threads.wait();
            return 1;
        }
        const auto& assignment = packet_channel->assignment();
        std::cout << "Packet TUN " << cfg.packet_tun_name
                  << "  IPv4=" << assignment.ipv4
                  << "  MTU=" << assignment.mtu;
        if (!assignment.dns_servers.empty()) {
            std::cout << "  DNS=" << assignment.dns_servers.front();
        }
        std::cout << "\nConfigure interface addresses, routes, DNS, firewall, and NAT externally.\n";
        signal_runtime_ready();
        const int packet_code = packet::run_packet_tun_adapter(
            cfg.packet_tun_name, packet_channel, stop_requested, &packet_error);
        if (packet_code != 0 && !packet_error.empty()) {
            util::log_error(packet_error);
        }
        tunnel_pool->stop_all("packet TUN stopped");
        io.stop();
        io_threads.wait();
        return packet_code;
    }

    if (!relay_runtime->announce_presence(&relay_error)) {
        util::log_warn("relay presence unavailable: " + relay_error);
    } else {
        std::string lifecycle_error;
        relay_runtime->notify_authenticated(protection_summary, &lifecycle_error);
    }

    if (args.directory_mode) {
        return start_directory_mode(relay_runtime, &relay_error);
    }

    const int relay_start_code = start_relay_one_shots(args, cfg, relay_runtime, &relay_error);
    if (relay_start_code != 0) {
        return relay_start_code;
    }

    std::thread hop_status_thread;
    start_live_status_if_needed(
        options.live_status_enabled,
        options.hop_enabled,
        options.hop_interval_ms,
        hop_status_stop,
        options.status_block_builder,
        &hop_status_thread);
    HopStatusGuard hop_guard{hop_status_stop, &hop_status_thread};

    InteractiveConsoleSession console_guard;
    if (should_enable_interactive_console(cfg, args, options.use_reverse)) {
        console_guard = start_interactive_console(
            stop_requested,
            cfg,
            tunnel,
            relay_runtime,
            options.status_block_builder,
            request_disconnect);
    }

    auto reverse_targets = std::make_shared<std::unordered_map<uint8_t, ReverseTarget>>();
    auto reverse_sessions =
        std::make_shared<std::unordered_map<uint8_t, std::shared_ptr<ReverseForwardSession>>>();
    install_reverse_handler(tunnel, reverse_targets, reverse_sessions);

    if (options.use_reverse) {
        const int reverse_code = request_reverse_listener(options, tunnel, reverse_targets);
        if (reverse_code != 0) {
            return reverse_code;
        }
    }

    if (!args.exec_cmd.empty()) {
        return run_exec_mode(args, io, tunnel, io_threads, close_reason);
    }

    if (!args.run_cmd.empty()) {
        return run_local_command_mode(args, cfg, io, tunnel, io_threads, options.argv0);
    }

    if (args.lport > 0 || !args.rhost.empty() || args.rport > 0) {
        return run_local_forward_mode(
            args, cfg, io, tunnel, io_threads, stop_requested, options.announce_stopping,
            close_reason, signal_runtime_ready, wait_state);
    }

    if (!cfg.app_codec.empty()) {
        return run_app_codec_mode(
            cfg, io, tunnel, io_threads, stop_requested, options.announce_stopping,
            close_reason, signal_runtime_ready, wait_state);
    }

    if (cfg.socks_port > 0) {
        return run_socks_mode(
            cfg, io, tunnel_pool, io_threads, stop_requested, options.announce_stopping,
            close_reason, signal_runtime_ready, wait_state);
    }

    if (options.use_reverse) {
        return wait_for_long_running_mode(
            io_threads, stop_requested, options.announce_stopping, close_reason,
            signal_runtime_ready, wait_state);
    }

    if (args.service_streams_only) {
        return wait_for_long_running_mode(
            io_threads, stop_requested, options.announce_stopping, close_reason,
            signal_runtime_ready, wait_state);
    }

    if (!args.chat_target.empty() || !args.file_target.empty() ||
        !args.bytes_target.empty() || !args.admin_target.empty()) {
        return wait_for_long_running_mode(
            io_threads, stop_requested, options.announce_stopping, close_reason,
            signal_runtime_ready, wait_state);
    }

    util::log_warn("no mode selected");
    return 1;
}

}  // namespace yume::client
