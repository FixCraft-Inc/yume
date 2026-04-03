/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "server/manager.hpp"

#include <algorithm>
#include "server/auth.hpp"
#include "server/session.hpp"
#include "util.hpp"

#include <iostream>
#include <stdexcept>

namespace yume::server {

Manager::Manager(boost::asio::io_context& io, const ServerConfig& cfg)
    : io_(io)
    , cfg_(cfg)
    , acceptor_(io)
    , ssl_ctx_(obfs::create_server_context(cfg.tls_cert, cfg.tls_key, !cfg.real_http))
    , authorized_keys_(std::make_shared<std::vector<crypto::Bytes>>())
    , server_id_(cfg.server_id.empty() ? yume::identity::generate_endpoint_id() : cfg.server_id)
    , server_name_(cfg.server_name.empty() ? std::string("yumed") : cfg.server_name) {
    cfg_.server_id = server_id_;
    cfg_.server_name = server_name_;
}

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
    do_accept();
}

void Manager::stop() {
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
                           std::string* error) {
    control::EndpointInfo target_info;
    auto target = find_endpoint_session(invite.to_endpoint_id, &target_info);
    if (!target) {
        if (error) {
            *error = "target not found";
        }
        return false;
    }
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    InviteEntry entry;
    entry.invite = invite;
    entry.from_session = from_session;
    entry.to_session = target;
    invites_[invite.invite_id] = std::move(entry);
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

void Manager::do_accept() {
    if (!acceptor_.is_open()) {
        return;
    }
    acceptor_.async_accept([this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
        if (!ec) {
            uint64_t session_id = next_session_id_.fetch_add(1);
            ServerConfig cfg_copy;
            {
                std::lock_guard<std::mutex> lock(cfg_mutex_);
                cfg_copy = cfg_;
            }
            auto session = std::make_shared<Session>(std::move(socket), ssl_ctx_, cfg_copy, authorized_keys_, session_id, this);
            register_session(session);
            session->start();
        } else if (ec != boost::asio::error::operation_aborted && acceptor_.is_open()) {
            util::log_warn(std::string("accept failed: ") + ec.message());
        }
        if (acceptor_.is_open()) {
            do_accept();
        }
    });
}

}  // namespace yume::server
