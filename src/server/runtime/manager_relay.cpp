/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * ----------------------------------------------------------------
 * Manager relay-mesh methods, extracted verbatim from manager.cpp:
 * the endpoint registry (register/update/unregister/list endpoints,
 * find_endpoint_session), invite routing (route/respond_invite and
 * their federated variants), relay channels (can_open_channel,
 * open_federated_channel, active-channel tracking), federation status,
 * and admin relationships.
 *
 * Same yume::server::Manager class, same behavior; different translation
 * unit so neither file stays oversized. No logic change.
 * ---------------------------------------------------------------- */

#include "server/runtime/manager.hpp"

#include <algorithm>
#include "server/federation/manager.hpp"
#include "server/auth/auth.hpp"
#include "server/filter/ip_filter.hpp"
#include "server/packet/tun_egress.hpp"
#include "server/session/authorization.hpp"
#include "server/session/session.hpp"
#include "util.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace yume::server {

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
        if (invite.channel_kind == control::ChannelKind::admin &&
            (!from_session ||
             !authorization::admin_attach_allowed(
                 from_session->is_trusted_relay_endpoint(),
                 from_session->allows_outbound_admin(),
                 target_info.allow_inbound_admin))) {
            if (error) {
                *error = "admin invite requires caller outbound-admin and target inbound-admin permission in trusted relay mode";
            }
            return false;
        }
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
        control::EndpointInfo remote_info;
        if (federation_->resolve_remote_endpoint(
                invite.to_endpoint_id, &peer_id, &remote_id, &remote_info)) {
            if (invite.channel_kind == control::ChannelKind::admin &&
                (!from_session ||
                 !authorization::admin_attach_allowed(
                     from_session->is_trusted_relay_endpoint(),
                     from_session->allows_outbound_admin(),
                     remote_info.allow_inbound_admin))) {
                if (error) {
                    *error = "admin invite requires caller outbound-admin and target inbound-admin permission in trusted relay mode";
                }
                return false;
            }
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
    if (invite.channel_kind == control::ChannelKind::admin &&
        !target_info.allow_inbound_admin) {
        if (error) {
            *error = "admin invite target does not allow inbound admin";
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
    if (channel_kind == control::ChannelKind::admin) {
        bool allowed = false;
        auto target_it = endpoints_.find(to_id);
        if (target_it != endpoints_.end() && target_it->second.info.allow_inbound_admin) {
            if (it->second.inbound_federated) {
                // The originating federation peer enforces its local caller's
                // trusted/outbound half; this server rechecks its local target.
                allowed = true;
            } else {
                auto caller_it = endpoints_.find(from_id);
                if (caller_it != endpoints_.end()) {
                    allowed = authorization::admin_attach_allowed(
                        caller_it->second.info.relay_mode == control::RelayMode::trusted,
                        caller_it->second.info.allow_outbound_admin,
                        target_it->second.info.allow_inbound_admin);
                }
            }
        }
        if (!allowed) {
            if (error) {
                *error = "admin channel no longer satisfies caller outbound-admin and target inbound-admin policy";
            }
            return false;
        }
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
    control::EndpointInfo remote_info;
    if (!federation_->resolve_remote_endpoint(
            target_id, &peer_id, &remote_id, &remote_info)) {
        return false;
    }
    if (channel_kind == control::ChannelKind::admin &&
        !authorization::admin_attach_allowed(
            origin->is_trusted_relay_endpoint(),
            origin->allows_outbound_admin(),
            remote_info.allow_inbound_admin)) {
        if (error) {
            *error = "admin channel no longer satisfies caller outbound-admin and target inbound-admin policy";
        }
        return true;
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

}  // namespace yume::server
