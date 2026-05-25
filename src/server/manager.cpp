/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "server/manager.hpp"

#include <algorithm>
#include "server/federation_manager.hpp"
#include "server/auth.hpp"
#include "server/session.hpp"
#include "util.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace yume::server {

Manager::Manager(boost::asio::io_context& io, const ServerConfig& cfg)
    : io_(io)
    , cfg_(cfg)
    , acceptor_(io)
    , ssl_ctx_(obfs::create_server_context(cfg.tls_cert, cfg.tls_key, !(cfg.real_http || cfg.obfuscation)))
    , authorized_keys_(std::make_shared<std::vector<crypto::Bytes>>())
    , server_id_(cfg.server_id.empty() ? yume::identity::generate_endpoint_id() : cfg.server_id)
    , server_name_(cfg.server_name.empty() ? std::string("yumed") : cfg.server_name) {
    cfg_.server_id = server_id_;
    cfg_.server_name = server_name_;
}

Manager::~Manager() = default;

void Manager::start() {
    if (cfg_.auth_keys.empty()) {
        throw std::runtime_error("auth_keys must be set");
    }

    try {
        *authorized_keys_ = load_authorized_keys(cfg_.auth_keys);
    } catch (const std::exception& ex) {
        throw std::runtime_error(std::string("authorized_keys load failed: ") + ex.what());
    }

    if (authorized_keys_->empty()) {
        util::log_warn("authorized_keys is empty");
    }
    if (cfg_.federation_enable) {
        if (cfg_.federation_auth_key.empty() || cfg_.federation_anonym_ca.empty() || cfg_.federation_peers.empty()) {
            util::log_warn("federation disabled: federation_auth_key, federation_anonym_ca, and peers are required");
            cfg_.federation_enable = false;
        } else {
            federation_ = std::make_unique<FederationManager>(io_, cfg_, this);
        }
    }

    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), cfg_.listen_port);
    acceptor_.open(ep.protocol());
    acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    acceptor_.bind(ep);
    acceptor_.listen();

    if (util::is_logging_enabled()) {
        util::log_info("yumed listening on port " + std::to_string(cfg_.listen_port));
    } else {
        std::cerr << "\033[1;33myumed listening on port " << cfg_.listen_port << "\033[0m\n";
    }
    if (!cfg_.upstream_response_dir.empty()) {
        const std::size_t loaded = reload_upstream_responses();
        util::log_info("--upstream-response-dir " + cfg_.upstream_response_dir +
                       ": loaded " + std::to_string(loaded) +
                       " capture(s) for per-probe rotation");
        if (cfg_.upstream_response_ttl_s > 0) {
            upstream_reload_timer_ = std::make_unique<boost::asio::steady_timer>(io_);
            schedule_upstream_reload();
            util::log_info("--upstream-response-ttl " + std::to_string(cfg_.upstream_response_ttl_s) +
                           "s: directory will reload on every tick (drop new captures in without restarting)");
        }
    }

    do_accept();
    if (federation_) {
        federation_->start();
    }
}

void Manager::stop() {
    if (federation_) {
        federation_->stop();
    }
    if (upstream_reload_timer_) {
        boost::system::error_code tec;
        upstream_reload_timer_->cancel(tec);
        upstream_reload_stopped_ = true;
    }
    boost::system::error_code ec;
    acceptor_.close(ec);

    std::vector<std::shared_ptr<Session>> sessions;
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (auto it = live_sessions_.begin(); it != live_sessions_.end();) {
            auto session = it->second.lock();
            if (!session) {
                it = live_sessions_.erase(it);
                continue;
            }
            sessions.push_back(std::move(session));
            ++it;
        }
    }
    for (const auto& session : sessions) {
        session->notify_server_shutdown("server closed, kicked");
    }
}

std::size_t Manager::reload_upstream_responses() {
    if (cfg_.upstream_response_dir.empty()) {
        return 0;
    }
    namespace fs = std::filesystem;
    std::vector<std::string> loaded;
    std::error_code ec;
    if (!fs::is_directory(cfg_.upstream_response_dir, ec)) {
        util::log_warn("--upstream-response-dir: " + cfg_.upstream_response_dir +
                       " is not a directory");
        return 0;
    }
    // Stable order across reloads so deterministic captures (e.g.
    // numbered files) don't get reshuffled into a different mix that
    // confuses operators reading logs side-by-side with the dir
    // contents.
    std::vector<fs::path> files;
    for (const auto& entry : fs::directory_iterator(cfg_.upstream_response_dir, ec)) {
        if (!entry.is_regular_file()) continue;
        const auto ext = entry.path().extension().string();
        if (ext == ".http" || ext == ".response") {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());
    for (const auto& path : files) {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            util::log_warn("--upstream-response-dir: cannot open " + path.string());
            continue;
        }
        std::stringstream ss; ss << in.rdbuf();
        std::string raw = ss.str();
        std::string normalized;
        normalized.reserve(raw.size() + raw.size() / 16);
        for (std::size_t i = 0; i < raw.size(); ++i) {
            char c = raw[i];
            if (c == '\n' && (i == 0 || raw[i - 1] != '\r')) {
                normalized += '\r';
            }
            normalized += c;
        }
        if (normalized.rfind("HTTP/1.", 0) != 0) {
            util::log_warn("--upstream-response-dir: " + path.string() +
                           " does not start with 'HTTP/1.' (skipped)");
            continue;
        }
        loaded.push_back(std::move(normalized));
    }
    const std::size_t count = loaded.size();
    auto snapshot = std::make_shared<const std::vector<std::string>>(std::move(loaded));
    {
        std::lock_guard<std::mutex> lock(upstream_cache_mu_);
        upstream_cache_ = std::move(snapshot);
    }
    return count;
}

namespace {
std::size_t pick_index(std::size_t bound) {
    if (bound <= 1) return 0;
    thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<std::size_t> dist(0, bound - 1);
    return dist(rng);
}
}  // namespace

std::string Manager::upstream_response_pick() const {
    std::shared_ptr<const std::vector<std::string>> snap;
    {
        std::lock_guard<std::mutex> lock(upstream_cache_mu_);
        snap = upstream_cache_;
    }
    if (!snap || snap->empty()) {
        return {};
    }
    return (*snap)[pick_index(snap->size())];
}

void Manager::schedule_upstream_reload() {
    if (!upstream_reload_timer_ || upstream_reload_stopped_) {
        return;
    }
    upstream_reload_timer_->expires_after(std::chrono::seconds(cfg_.upstream_response_ttl_s));
    upstream_reload_timer_->async_wait([this](const boost::system::error_code& ec) {
        if (ec || upstream_reload_stopped_) return;
        const std::size_t n = reload_upstream_responses();
        util::log_info("--upstream-response-dir: reloaded " + std::to_string(n) +
                       " capture(s) from " + cfg_.upstream_response_dir);
        schedule_upstream_reload();
    });
}

void Manager::register_session(const std::shared_ptr<Session>& session) {
    if (!session) {
        return;
    }
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    live_sessions_[session.get()] = session;
}

void Manager::unregister_session(Session* session) {
    if (!session) {
        return;
    }
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    live_sessions_.erase(session);
}

void Manager::update_anonym_proof(const std::string& hash,
                                  const std::string& sig,
                                  const std::string& ts,
                                  const std::string& nonce,
                                  const std::string& certfp,
                                  const std::string& proof_policy,
                                  const std::vector<std::string>& proof_sources,
                                  const std::string& ca_sig,
                                  const std::string& ca_alg,
                                  const std::string& sub_sig,
                                  const std::string& sub_alg,
                                  const std::string& sub_cert_b64,
                                  const std::string& pq_pub_b64,
                                  const std::string& pq_sig,
                                  const std::string& pq_alg) {
    std::lock_guard<std::mutex> lock(cfg_mutex_);
    cfg_.anonym_hash = hash;
    cfg_.anonym_sig = sig;
    cfg_.anonym_ts = ts;
    cfg_.anonym_nonce = nonce;
    cfg_.anonym_certfp = certfp;
    cfg_.anonym_proof_mode = proof_policy;
    cfg_.anonym_proof_sources = proof_sources;
    cfg_.anonym_ca_sig = ca_sig;
    cfg_.anonym_ca_alg = ca_alg;
    cfg_.anonym_sub_sig = sub_sig;
    cfg_.anonym_sub_alg = sub_alg;
    cfg_.anonym_sub_cert_b64 = sub_cert_b64;
    cfg_.pq_pub_b64 = pq_pub_b64;
    cfg_.pq_sig = pq_sig;
    cfg_.pq_alg = pq_alg;
}

void Manager::register_reverse_listener(int port, const std::shared_ptr<Session>& session) {
    std::lock_guard<std::mutex> lock(reverse_mutex_);
    reverse_port_sessions_[port] = session;
}

void Manager::unregister_reverse_listener(int port, Session* session) {
    std::lock_guard<std::mutex> lock(reverse_mutex_);
    auto it = reverse_port_sessions_.find(port);
    if (it == reverse_port_sessions_.end()) {
        return;
    }
    auto current = it->second.lock();
    if (!current || current.get() == session) {
        reverse_port_sessions_.erase(it);
    }
}

bool Manager::reclaim_reverse_listener(int port) {
    std::shared_ptr<Session> session;
    {
        std::lock_guard<std::mutex> lock(reverse_mutex_);
        auto it = reverse_port_sessions_.find(port);
        if (it == reverse_port_sessions_.end()) {
            return false;
        }
        session = it->second.lock();
        if (!session) {
            reverse_port_sessions_.erase(it);
            return true;
        }
    }

    if (!session->is_stale()) {
        return false;
    }

    session->force_close_reverse_port(port);
    {
        std::lock_guard<std::mutex> lock(reverse_mutex_);
        auto it = reverse_port_sessions_.find(port);
        if (it != reverse_port_sessions_.end()) {
            auto current = it->second.lock();
            if (!current || current.get() == session.get()) {
                reverse_port_sessions_.erase(it);
            }
        }
    }
    return true;
}

void Manager::register_controlled_client(const std::shared_ptr<Session>& session, const ControlledClientInfo& info) {
    if (!session || info.id.empty()) {
        return;
    }
    ControlledClientEntry entry;
    entry.info = info;
    entry.session = session;
    std::lock_guard<std::mutex> lock(control_mutex_);
    controlled_clients_[info.id] = std::move(entry);
}

void Manager::unregister_controlled_client(Session* session) {
    if (!session) {
        return;
    }
    std::lock_guard<std::mutex> lock(control_mutex_);
    for (auto it = controlled_clients_.begin(); it != controlled_clients_.end();) {
        auto current = it->second.session.lock();
        if (!current || current.get() == session) {
            it = controlled_clients_.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<ControlledClientInfo> Manager::list_controlled_clients(bool anonym_only) {
    std::vector<ControlledClientInfo> out;
    std::lock_guard<std::mutex> lock(control_mutex_);
    for (auto it = controlled_clients_.begin(); it != controlled_clients_.end();) {
        auto current = it->second.session.lock();
        if (!current) {
            it = controlled_clients_.erase(it);
            continue;
        }
        if (anonym_only && !(it->second.info.allow_exec || it->second.info.server_in_charge)) {
            ++it;
            continue;
        }
        out.push_back(it->second.info);
        ++it;
    }
    return out;
}

std::shared_ptr<Session> Manager::find_controlled_session(const std::string& id, ControlledClientInfo* info) {
    if (id.empty()) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(control_mutex_);
    auto it = controlled_clients_.find(id);
    if (it == controlled_clients_.end()) {
        return nullptr;
    }
    auto session = it->second.session.lock();
    if (!session) {
        controlled_clients_.erase(it);
        return nullptr;
    }
    if (info) {
        *info = it->second.info;
    }
    return session;
}

EndpointRegistrationResult Manager::register_endpoint(const std::shared_ptr<Session>& session,
                                                      const control::PresenceAnnouncement& announce,
                                                      const std::string& auth_pubkey_b64) {
    EndpointRegistrationResult result;
    result.server_id = server_id_;
    result.server_name = server_name_;
    result.endpoint.endpoint_kind = announce.endpoint_kind;
    result.endpoint.hostname = announce.hostname;
    result.endpoint.client_platform = announce.client_platform;
    result.endpoint.client_variant = announce.client_variant;
    result.endpoint.client_version = announce.client_version;
    result.endpoint.server_id = server_id_;
    result.endpoint.server_name = server_name_;
    result.endpoint.relay_mode = announce.relay_mode;
    result.endpoint.allow_chat = announce.allow_chat;
    result.endpoint.allow_file = announce.allow_file;
    result.endpoint.allow_bytes = announce.allow_bytes;
    result.endpoint.allow_inbound_admin = announce.allow_inbound_admin;
    result.endpoint.allow_outbound_admin = announce.allow_outbound_admin;
    result.endpoint.online = true;
    result.endpoint.auth_pubkey_b64 = auth_pubkey_b64;

    std::lock_guard<std::mutex> lock(endpoint_mutex_);

    auto allocate_id = [&]() {
        std::string candidate = announce.preferred_id;
        if (!candidate.empty() && yume::identity::is_valid_hex_id(candidate) && endpoints_.find(candidate) == endpoints_.end()) {
            result.preferred_id_accepted = true;
            return candidate;
        }
        do {
            candidate = yume::identity::generate_endpoint_id();
        } while (endpoints_.find(candidate) != endpoints_.end());
        return candidate;
    };

    auto allocate_name = [&]() {
        std::string candidate = yume::identity::sanitize_display_name(announce.preferred_name);
        if (!announce.preferred_name.empty()) {
            auto it = endpoint_names_.find(candidate);
            if (!candidate.empty() && (it == endpoint_names_.end() || it->second == result.endpoint.endpoint_id)) {
                result.preferred_name_accepted = true;
                return candidate;
            }
        }
        do {
            candidate = yume::identity::generate_display_name();
        } while (endpoint_names_.find(candidate) != endpoint_names_.end());
        return candidate;
    };

    auto it_existing = session_endpoints_.find(session.get());
    if (it_existing != session_endpoints_.end()) {
        auto it_endpoint = endpoints_.find(it_existing->second);
        if (it_endpoint != endpoints_.end()) {
            endpoint_names_.erase(it_endpoint->second.info.display_name);
            endpoints_.erase(it_endpoint);
        }
        session_endpoints_.erase(it_existing);
    }

    result.endpoint.endpoint_id = allocate_id();
    result.endpoint.display_name = allocate_name();
    result.server_id = server_id_;
    result.server_name = server_name_;

    EndpointEntry entry;
    entry.info = result.endpoint;
    entry.session = session;
    endpoints_[result.endpoint.endpoint_id] = std::move(entry);
    endpoint_names_[result.endpoint.display_name] = result.endpoint.endpoint_id;
    session_endpoints_[session.get()] = result.endpoint.endpoint_id;
    return result;
}

bool Manager::update_endpoint_lifecycle(Session* session,
                                        control::ClientLifecycleEvent event,
                                        control::ClientLifecycleEvent* stored_event) {
    if (!session) {
        return false;
    }
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    auto it_session = session_endpoints_.find(session);
    if (it_session == session_endpoints_.end()) {
        return false;
    }
    auto it = endpoints_.find(it_session->second);
    if (it == endpoints_.end()) {
        return false;
    }
    event.endpoint_id = it->second.info.endpoint_id;
    event.display_name = it->second.info.display_name;
    if (event.client_platform.empty() || event.client_platform == "unknown") {
        event.client_platform = it->second.info.client_platform;
    }
    if (event.client_variant.empty() || event.client_variant == "unknown") {
        event.client_variant = it->second.info.client_variant;
    }
    if (event.client_version.empty()) {
        event.client_version = it->second.info.client_version;
    }
    event.server_time_ms = yume::util::now_ms();
    it->second.latest_lifecycle = event;
    append_lifecycle_event_locked(event);
    if (stored_event) {
        *stored_event = event;
    }
    return true;
}

void Manager::unregister_endpoint(Session* session) {
    if (!session) {
        return;
    }
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    auto it_session = session_endpoints_.find(session);
    if (it_session == session_endpoints_.end()) {
        return;
    }
    auto it = endpoints_.find(it_session->second);
    if (it != endpoints_.end()) {
        const auto latest_state = it->second.latest_lifecycle.has_value()
            ? it->second.latest_lifecycle->state
            : std::string();
        if (latest_state != "disconnecting") {
            control::ClientLifecycleEvent event;
            event.endpoint_id = it->second.info.endpoint_id;
            event.display_name = it->second.info.display_name;
            event.state = "disconnecting";
            event.message = "disconnecting";
            event.detail = "session ended without graceful disconnect";
            event.client_platform = it->second.info.client_platform;
            event.client_variant = it->second.info.client_variant;
            event.client_version = it->second.info.client_version;
            event.server_time_ms = yume::util::now_ms();
            append_lifecycle_event_locked(event);
        }
        endpoint_names_.erase(it->second.info.display_name);
        const std::string removed_id = it->second.info.endpoint_id;
        endpoints_.erase(it);
        for (auto invite_it = invites_.begin(); invite_it != invites_.end();) {
            if (invite_it->second.invite.from_endpoint_id == removed_id ||
                invite_it->second.invite.to_endpoint_id == removed_id) {
                invite_it = invites_.erase(invite_it);
            } else {
                ++invite_it;
            }
        }
        for (auto channel_it = active_channels_.begin(); channel_it != active_channels_.end();) {
            if (channel_it->second.left_endpoint_id == removed_id ||
                channel_it->second.right_endpoint_id == removed_id) {
                channel_it = active_channels_.erase(channel_it);
            } else {
                ++channel_it;
            }
        }
    }
    session_endpoints_.erase(it_session);
}

std::vector<control::EndpointInfo> Manager::list_endpoints() const {
    auto out = list_local_endpoints();
    if (federation_) {
        auto remote = federation_->remote_endpoints();
        out.insert(out.end(), remote.begin(), remote.end());
    }
    std::sort(out.begin(), out.end(), [](const control::EndpointInfo& a, const control::EndpointInfo& b) {
        return a.display_name < b.display_name;
    });
    return out;
}

std::vector<control::EndpointInfo> Manager::list_local_endpoints() const {
    std::vector<control::EndpointInfo> out;
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    out.reserve(endpoints_.size());
    for (const auto& entry : endpoints_) {
        if (entry.second.session.expired()) {
            continue;
        }
        out.push_back(entry.second.info);
    }
    std::sort(out.begin(), out.end(), [](const control::EndpointInfo& a, const control::EndpointInfo& b) {
        return a.display_name < b.display_name;
    });
    return out;
}

std::vector<control::EndpointRuntimeStatus> Manager::list_endpoint_statuses() const {
    std::vector<control::EndpointRuntimeStatus> out;
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    out.reserve(endpoints_.size());
    for (const auto& entry : endpoints_) {
        if (entry.second.session.expired()) {
            continue;
        }
        control::EndpointRuntimeStatus status;
        status.endpoint = entry.second.info;
        status.latest_lifecycle = entry.second.latest_lifecycle;
        out.push_back(std::move(status));
    }
    std::sort(out.begin(), out.end(), [](const control::EndpointRuntimeStatus& a,
                                         const control::EndpointRuntimeStatus& b) {
        return a.endpoint.display_name < b.endpoint.display_name;
    });
    return out;
}

std::vector<control::ClientLifecycleEvent> Manager::list_recent_lifecycle_events(std::size_t limit) const {
    std::vector<control::ClientLifecycleEvent> out;
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    const std::size_t count = std::min<std::size_t>(limit, lifecycle_events_.size());
    out.reserve(count);
    auto begin = lifecycle_events_.end();
    std::advance(begin, -static_cast<std::ptrdiff_t>(count));
    for (auto it = begin; it != lifecycle_events_.end(); ++it) {
        out.push_back(*it);
    }
    return out;
}

std::shared_ptr<Session> Manager::find_endpoint_session(const std::string& query, control::EndpointInfo* info) {
    if (query.empty()) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    std::string endpoint_id = query;
    auto it_name = endpoint_names_.find(query);
    if (it_name != endpoint_names_.end()) {
        endpoint_id = it_name->second;
    }
    auto it = endpoints_.find(endpoint_id);
    if (it == endpoints_.end()) {
        return nullptr;
    }
    auto session = it->second.session.lock();
    if (!session) {
        endpoint_names_.erase(it->second.info.display_name);
        endpoints_.erase(it);
        return nullptr;
    }
    if (info) {
        *info = it->second.info;
    }
    return session;
}

bool Manager::route_invite(const std::shared_ptr<Session>& from_session,
                           const control::PendingInvite& invite,
                           std::string* error,
                           std::shared_ptr<Session>* local_target_session,
                           bool* federated) {
    if (local_target_session) {
        local_target_session->reset();
    }
    if (federated) {
        *federated = false;
    }
    control::EndpointInfo target_info;
    auto target = find_endpoint_session(invite.to_endpoint_id, &target_info);
    if (target) {
        std::lock_guard<std::mutex> lock(endpoint_mutex_);
        InviteEntry entry;
        entry.invite = invite;
        entry.from_session = from_session;
        entry.to_session = target;
        invites_[invite.invite_id] = std::move(entry);
        if (local_target_session) {
            *local_target_session = target;
        }
        return true;
    }

    if (federation_) {
        std::string peer_id;
        std::string remote_id;
        if (federation_->resolve_remote_endpoint(invite.to_endpoint_id, &peer_id, &remote_id, nullptr)) {
            {
                std::lock_guard<std::mutex> lock(endpoint_mutex_);
                InviteEntry entry;
                entry.invite = invite;
                entry.from_session = from_session;
                entry.outbound_federated = true;
                entry.federation_peer_id = peer_id;
                entry.federation_remote_id = remote_id;
                invites_[invite.invite_id] = std::move(entry);
            }
            if (!federation_->send_invite_request(invite, peer_id, remote_id, error)) {
                std::lock_guard<std::mutex> lock(endpoint_mutex_);
                invites_.erase(invite.invite_id);
                return false;
            }
            if (federated) {
                *federated = true;
            }
            return true;
        }
    }
    if (error) {
        *error = "target not found";
    }
    return false;
}

bool Manager::route_federated_invite(const std::shared_ptr<Session>& from_session,
                                     const control::PendingInvite& invite,
                                     const std::string& raw_target_id,
                                     std::string* error,
                                     std::shared_ptr<Session>* local_target_session) {
    if (local_target_session) {
        local_target_session->reset();
    }
    control::EndpointInfo target_info;
    auto target = find_endpoint_session(raw_target_id.empty() ? invite.to_endpoint_id : raw_target_id, &target_info);
    if (!target) {
        if (error) {
            *error = "target not found";
        }
        return false;
    }
    const std::string peer_id = from_session ? from_session->federation_peer_id() : std::string{};
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    InviteEntry entry;
    entry.invite = invite;
    entry.from_session = from_session;
    entry.to_session = target;
    entry.inbound_federated = true;
    entry.federation_peer_id = peer_id;
    invites_[invite.invite_id] = std::move(entry);
    if (local_target_session) {
        *local_target_session = target;
    }
    return true;
}

bool Manager::respond_invite(const std::shared_ptr<Session>& from_session,
                             const control::PendingInvite& response,
                             std::shared_ptr<Session>* initiator_session,
                             control::PendingInvite* invite_out,
                             std::string* error) {
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    auto it = invites_.find(response.invite_id);
    if (it == invites_.end()) {
        if (error) {
            *error = "invite not found";
        }
        return false;
    }
    if (it->second.invite.to_endpoint_id != response.from_endpoint_id &&
        it->second.invite.to_endpoint_id != response.to_endpoint_id) {
        if (error) {
            *error = "invite responder mismatch";
        }
        return false;
    }
    it->second.invite.accepted = response.accepted;
    it->second.invite.response_reason = response.response_reason;
    it->second.invite.response_ephemeral_pubkey_b64 = response.response_ephemeral_pubkey_b64;
    it->second.invite.response_ephemeral_signature_b64 = response.response_ephemeral_signature_b64;
    auto initiator = it->second.from_session.lock();
    if (!initiator) {
        if (error) {
            *error = "invite initiator unavailable";
        }
        invites_.erase(it);
        return false;
    }
    if (initiator_session) {
        *initiator_session = initiator;
    }
    if (invite_out) {
        *invite_out = it->second.invite;
    }
    if (!it->second.invite.accepted) {
        invites_.erase(it);
    }
    return true;
}

bool Manager::respond_federated_invite(const std::string& peer_id,
                                       const control::PendingInvite& response,
                                       std::shared_ptr<Session>* initiator_session,
                                       control::PendingInvite* invite_out,
                                       std::string* error) {
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    auto it = invites_.find(response.invite_id);
    if (it == invites_.end()) {
        if (error) {
            *error = "invite not found";
        }
        return false;
    }
    if (!it->second.outbound_federated || it->second.federation_peer_id != peer_id) {
        if (error) {
            *error = "invite federation peer mismatch";
        }
        return false;
    }
    it->second.invite.accepted = response.accepted;
    it->second.invite.response_reason = response.response_reason;
    it->second.invite.response_ephemeral_pubkey_b64 = response.response_ephemeral_pubkey_b64;
    it->second.invite.response_ephemeral_signature_b64 = response.response_ephemeral_signature_b64;
    auto initiator = it->second.from_session.lock();
    if (!initiator) {
        if (error) {
            *error = "invite initiator unavailable";
        }
        invites_.erase(it);
        return false;
    }
    if (initiator_session) {
        *initiator_session = initiator;
    }
    if (invite_out) {
        *invite_out = it->second.invite;
    }
    if (!it->second.invite.accepted) {
        invites_.erase(it);
    }
    return true;
}

bool Manager::can_open_channel(const std::string& channel_id,
                               const std::string& from_id,
                               const std::string& to_id,
                               control::ChannelKind channel_kind,
                               std::shared_ptr<Session>* target_session,
                               control::PendingInvite* invite_out,
                               std::string* error) {
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    auto it = invites_.find(channel_id);
    if (it == invites_.end()) {
        if (error) {
            *error = "invite not found";
        }
        return false;
    }
    const auto& invite = it->second.invite;
    if (!invite.accepted) {
        if (error) {
            *error = "invite not accepted";
        }
        return false;
    }
    if (invite.from_endpoint_id != from_id || invite.to_endpoint_id != to_id || invite.channel_kind != channel_kind) {
        if (error) {
            *error = "invite/channel mismatch";
        }
        return false;
    }
    auto target = it->second.to_session.lock();
    if (!target) {
        if (error) {
            *error = "target unavailable";
        }
        invites_.erase(it);
        return false;
    }
    if (target_session) {
        *target_session = target;
    }
    if (invite_out) {
        *invite_out = invite;
    }
    return true;
}

bool Manager::open_federated_channel(const std::shared_ptr<Session>& origin,
                                     std::uint8_t origin_stream_id,
                                     const nlohmann::json& open_json,
                                     std::string* error) {
    if (!federation_ || !origin) {
        return false;
    }
    const std::string target_id = open_json.value("target_id", "");
    const std::string from_id = open_json.value("from_id", origin->endpoint_id());
    const std::string channel_id = open_json.value("channel_id", "");
    const auto channel_kind = control::channel_kind_from_string(open_json.value("channel_kind", "chat"));
    std::string peer_id;
    std::string remote_id;
    if (!federation_->resolve_remote_endpoint(target_id, &peer_id, &remote_id, nullptr)) {
        return false;
    }
    control::PendingInvite invite;
    {
        std::lock_guard<std::mutex> lock(endpoint_mutex_);
        auto it = invites_.find(channel_id);
        if (it == invites_.end()) {
            if (error) {
                *error = "invite not found";
            }
            return true;
        }
        invite = it->second.invite;
        if (!it->second.outbound_federated || it->second.federation_peer_id != peer_id) {
            if (error) {
                *error = "invite federation peer mismatch";
            }
            return true;
        }
        if (!invite.accepted) {
            if (error) {
                *error = "invite not accepted";
            }
            return true;
        }
        if (invite.from_endpoint_id != from_id || invite.to_endpoint_id != target_id || invite.channel_kind != channel_kind) {
            if (error) {
                *error = "invite/channel mismatch";
            }
            return true;
        }
    }
    control::ActiveRelayChannel channel;
    channel.channel_id = invite.invite_id;
    channel.channel_kind = invite.channel_kind;
    channel.left_endpoint_id = invite.from_endpoint_id;
    channel.right_endpoint_id = invite.to_endpoint_id;
    channel.left_stream_id = origin_stream_id;
    channel.right_stream_id = 0;
    channel.pending = true;
    channel.federated = true;
    channel.route_hops = 1;
    register_active_channel(channel);
    if (!federation_->open_channel(origin, origin_stream_id, invite, open_json, error)) {
        unregister_active_channel(invite.invite_id);
        return true;
    }
    return true;
}

void Manager::register_active_channel(const control::ActiveRelayChannel& channel) {
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    active_channels_[channel.channel_id] = channel;
}

void Manager::unregister_active_channel(const std::string& channel_id) {
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    active_channels_.erase(channel_id);
    invites_.erase(channel_id);
}

std::vector<control::ActiveRelayChannel> Manager::list_active_channels() const {
    std::vector<control::ActiveRelayChannel> out;
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    out.reserve(active_channels_.size());
    for (const auto& entry : active_channels_) {
        out.push_back(entry.second);
    }
    return out;
}

std::vector<FederationPeerStatus> Manager::federation_statuses() const {
    if (!federation_) {
        return {};
    }
    return federation_->statuses();
}

bool Manager::disconnect_endpoint(const std::string& query, std::string* error) {
    auto session = find_endpoint_session(query, nullptr);
    if (!session) {
        if (error) {
            *error = "endpoint not found";
        }
        return false;
    }
    session->stop();
    return true;
}

void Manager::add_admin_relationship(const std::string& controller_id, const std::string& target_id) {
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    auto add_unique = [](std::vector<std::string>* values, const std::string& value) {
        if (!values || value.empty()) {
            return;
        }
        if (std::find(values->begin(), values->end(), value) == values->end()) {
            values->push_back(value);
        }
    };
    auto it_controller = endpoints_.find(controller_id);
    auto it_target = endpoints_.find(target_id);
    if (it_controller != endpoints_.end() && it_target != endpoints_.end()) {
        add_unique(&it_controller->second.info.controlled_target_ids, target_id);
        add_unique(&it_target->second.info.controller_ids, controller_id);
    }
}

void Manager::remove_admin_relationship(const std::string& controller_id, const std::string& target_id) {
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    auto remove_value = [](std::vector<std::string>* values, const std::string& value) {
        if (!values) {
            return;
        }
        values->erase(std::remove(values->begin(), values->end(), value), values->end());
    };
    auto it_controller = endpoints_.find(controller_id);
    auto it_target = endpoints_.find(target_id);
    if (it_controller != endpoints_.end()) {
        remove_value(&it_controller->second.info.controlled_target_ids, target_id);
    }
    if (it_target != endpoints_.end()) {
        remove_value(&it_target->second.info.controller_ids, controller_id);
    }
}

const ServerConfig& Manager::config_snapshot() const {
    return cfg_;
}

void Manager::append_lifecycle_event_locked(const control::ClientLifecycleEvent& event) {
    lifecycle_events_.push_back(event);
    while (lifecycle_events_.size() > kMaxLifecycleEvents) {
        lifecycle_events_.pop_front();
    }
}

bool Manager::admit_accept() {
    // Hard session cap first — cheap to check, and it's the absolute
    // ceiling regardless of any rate concerns.
    if (cfg_.max_sessions > 0) {
        std::size_t live = 0;
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            live = live_sessions_.size();
        }
        if (live >= cfg_.max_sessions) {
            ++accept_refused_cap_;
            // Throttle the warn line to once per 64 refusals so a
            // sustained DoS doesn't fill the log faster than it
            // exhausts memory.
            if ((accept_refused_cap_ & 0x3F) == 1) {
                util::log_warn("accept refused: max_sessions cap " +
                              std::to_string(cfg_.max_sessions) +
                              " reached (live=" + std::to_string(live) +
                              ", refused-total=" + std::to_string(accept_refused_cap_) + ")");
            }
            return false;
        }
    }

    // Token bucket over a 1 s rolling window.
    if (cfg_.accept_rate_limit > 0) {
        const auto now = std::chrono::steady_clock::now();
        if (accept_window_start_.time_since_epoch().count() == 0 ||
            now - accept_window_start_ >= std::chrono::seconds(1)) {
            // Window expired — open a fresh one. Snap to now instead
            // of rolling forward by 1 s steps to keep the math simple;
            // worst-case effect of snapping is one extra refused
            // connection per window vs strict sliding semantics.
            accept_window_start_ = now;
            accept_window_count_ = 0;
        }
        if (accept_window_count_ >= cfg_.accept_rate_limit) {
            ++accept_refused_rate_;
            if ((accept_refused_rate_ & 0x3F) == 1) {
                util::log_warn("accept refused: rate-limit " +
                              std::to_string(cfg_.accept_rate_limit) +
                              "/s exceeded (refused-total=" +
                              std::to_string(accept_refused_rate_) + ")");
            }
            return false;
        }
        ++accept_window_count_;
    }
    return true;
}

void Manager::do_accept() {
    if (!acceptor_.is_open()) {
        return;
    }
    acceptor_.async_accept([this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
        if (!ec) {
            if (!admit_accept()) {
                // Close on the spot. Reading nothing then closing
                // mirrors what a load-balancer would do under
                // backpressure — the disguise stays consistent
                // since a real busy nginx also accepts then closes.
                boost::system::error_code close_ec;
                socket.close(close_ec);
            } else {
                uint64_t session_id = next_session_id_.fetch_add(1);
                ServerConfig cfg_copy;
                {
                    std::lock_guard<std::mutex> lock(cfg_mutex_);
                    cfg_copy = cfg_;
                }
                auto session = std::make_shared<Session>(std::move(socket), ssl_ctx_, cfg_copy, authorized_keys_, session_id, this);
                register_session(session);
                session->start();
            }
        } else if (ec != boost::asio::error::operation_aborted && acceptor_.is_open()) {
            util::log_warn(std::string("accept failed: ") + ec.message());
        }
        if (acceptor_.is_open()) {
            do_accept();
        }
    });
}

}  // namespace yume::server
