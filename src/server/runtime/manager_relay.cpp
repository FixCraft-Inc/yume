/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Manager relay-mesh methods:
 * the endpoint registry (register/update/unregister/list endpoints,
 * find_endpoint_session), invite routing (route/respond_invite and
 * their federated variants), relay channels (can_open_channel,
 * open_federated_channel, active-channel tracking), federation status,
 * and admin relationships.
 */

#include "server/runtime/manager.hpp"

#include <algorithm>
#include "core/protocol/relay_limits.hpp"
#include "core/protocol/relay_policy.hpp"
#include "server/federation/manager.hpp"
#include "server/auth/auth.hpp"
#include "server/filter/ip_filter.hpp"
#include "server/packet/tun_egress.hpp"
#include "server/runtime/admin_relationships.hpp"
#include "server/session/authorization.hpp"
#include "server/session/session.hpp"
#include "util.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <random>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace yume::server {

namespace {

bool ValidateRelayV2Request(const control::PendingInvite& invite,
                            std::string* error) {
    if (control::relay_v2_invite_request_valid(invite)) return true;
    if (error) {
        *error = "invalid relay-v2 request envelope, identity, or password policy";
    }
    return false;
}

bool ValidateRelayV2Response(const control::PendingInvite& invite,
                             std::string* error) {
    if (control::relay_v2_invite_response_valid(invite)) return true;
    if (error) {
        *error = "invalid relay-v2 response envelope, identity, or password policy";
    }
    return false;
}

bool OrdinaryCallerAllows(const std::shared_ptr<Session>& session,
                          control::ChannelKind kind,
                          std::string* error) {
    if (kind == control::ChannelKind::admin) return true;
    if (session && session->allows_relay_kind(kind)) return true;
    if (error) {
        *error = "relay invite origin is not allowed to use the requested channel kind";
    }
    return false;
}

bool TargetAllows(const control::EndpointInfo& target,
                  control::ChannelKind kind,
                  std::string* error) {
    if (control::relay_target_allows(target, kind)) return true;
    if (error) {
        *error = "relay target disabled the requested channel kind";
    }
    return false;
}

}  // namespace

void Manager::prune_expired_relay_invites_locked(
    std::chrono::steady_clock::time_point now) {
    for (auto it = invites_.begin(); it != invites_.end();) {
        if (control::pending_relay_invite_expired(
                it->second.expires_at, now)) {
            it = invites_.erase(it);
        } else {
            ++it;
        }
    }
}

bool Manager::relay_invite_capacity_available_locked(
    const control::PendingInvite& invite,
    std::string* error) {
    prune_expired_relay_invites_locked(std::chrono::steady_clock::now());
    std::size_t from_count = 0;
    std::size_t to_count = 0;
    for (const auto& [id, entry] : invites_) {
        (void)id;
        from_count += static_cast<std::size_t>(
            entry.invite.from_endpoint_id == invite.from_endpoint_id);
        to_count += static_cast<std::size_t>(
            entry.invite.to_endpoint_id == invite.to_endpoint_id);
    }
    switch (control::pending_relay_invite_admission(
            invites_.size(), from_count, to_count)) {
        case control::PendingRelayInviteAdmission::allowed:
            return true;
        case control::PendingRelayInviteAdmission::server_limit:
            if (error) *error = "server pending relay invite limit reached";
            return false;
        case control::PendingRelayInviteAdmission::origin_limit:
            if (error) *error = "relay invite origin pending limit reached";
            return false;
        case control::PendingRelayInviteAdmission::target_limit:
            if (error) *error = "relay invite target pending limit reached";
            return false;
    }
    if (error) *error = "invalid relay invite admission state";
    return false;
}

void Manager::schedule_relay_invite_expiry_locked() {
    if (invite_expiry_stopped_) {
        return;
    }
    if (invites_.empty()) {
        if (invite_expiry_timer_) {
            invite_expiry_timer_->cancel();
        }
        return;
    }
    const auto earliest = std::min_element(
        invites_.begin(), invites_.end(),
        [](const auto& left, const auto& right) {
            return left.second.expires_at < right.second.expires_at;
        })->second.expires_at;
    if (!invite_expiry_timer_) {
        invite_expiry_timer_ =
            std::make_unique<boost::asio::steady_timer>(io_);
    }
    invite_expiry_timer_->expires_at(earliest);
    invite_expiry_timer_->async_wait(
        [this](const boost::system::error_code& error) {
            if (error) return;
            std::lock_guard<std::mutex> lock(endpoint_mutex_);
            if (invite_expiry_stopped_) return;
            prune_expired_relay_invites_locked(
                std::chrono::steady_clock::now());
            schedule_relay_invite_expiry_locked();
        });
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
        unregister_endpoint_locked(session.get(), false);
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
    unregister_endpoint_locked(session, true);
}

void Manager::unregister_endpoint_locked(Session* session,
                                         bool append_disconnect_event) {
    auto it_session = session_endpoints_.find(session);
    if (it_session == session_endpoints_.end()) {
        return;
    }
    auto it = endpoints_.find(it_session->second);
    if (it != endpoints_.end()) {
        const auto latest_state = it->second.latest_lifecycle.has_value()
            ? it->second.latest_lifecycle->state
            : std::string();
        if (append_disconnect_event && latest_state != "disconnecting") {
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
        const std::string removed_id = it->second.info.endpoint_id;
        std::vector<std::pair<std::string, std::string>> relationships;
        relationships.reserve(it->second.info.controlled_target_ids.size() +
                              it->second.info.controller_ids.size());
        for (const auto& target_id : it->second.info.controlled_target_ids) {
            relationships.emplace_back(removed_id, target_id);
        }
        for (const auto& controller_id : it->second.info.controller_ids) {
            relationships.emplace_back(controller_id, removed_id);
        }
        for (auto invite_it = invites_.begin(); invite_it != invites_.end();) {
            const auto invite_from = invite_it->second.from_session.lock();
            const auto invite_to = invite_it->second.to_session.lock();
            if (invite_it->second.invite.from_endpoint_id == removed_id ||
                invite_it->second.invite.to_endpoint_id == removed_id ||
                invite_from.get() == session || invite_to.get() == session) {
                invite_it = invites_.erase(invite_it);
            } else {
                ++invite_it;
            }
        }
        for (auto channel_it = active_channels_.begin(); channel_it != active_channels_.end();) {
            if (channel_it->second.left_endpoint_id == removed_id ||
                channel_it->second.right_endpoint_id == removed_id) {
                if (admin_relationships::is_established_admin_channel(
                        channel_it->second)) {
                    relationships.emplace_back(
                        channel_it->second.left_endpoint_id,
                        channel_it->second.right_endpoint_id);
                }
                channel_it = active_channels_.erase(channel_it);
            } else {
                ++channel_it;
            }
        }
        for (const auto& relationship : relationships) {
            auto controller_it = endpoints_.find(relationship.first);
            auto target_it = endpoints_.find(relationship.second);
            admin_relationships::remove_local_relationship_if_unused(
                active_channels_,
                controller_it == endpoints_.end()
                    ? nullptr : &controller_it->second.info,
                target_it == endpoints_.end()
                    ? nullptr : &target_it->second.info,
                relationship.first,
                relationship.second);
        }
        endpoint_names_.erase(it->second.info.display_name);
        endpoints_.erase(it);
    }
    session_endpoints_.erase(it_session);
}

std::vector<control::EndpointInfo> Manager::list_endpoints(
        std::size_t limit) const {
    limit = std::min(limit, control::kMaxDirectoryEndpoints);
    auto out = list_local_endpoints(limit);
    if (federation_ && out.size() < limit) {
        auto remote = federation_->remote_endpoints(limit - out.size());
        out.insert(out.end(), remote.begin(), remote.end());
    }
    std::sort(out.begin(), out.end(), [](const control::EndpointInfo& a, const control::EndpointInfo& b) {
        return a.display_name < b.display_name;
    });
    return out;
}

std::vector<control::EndpointInfo> Manager::list_local_endpoints(
        std::size_t limit) const {
    limit = std::min(limit, control::kMaxDirectoryEndpoints);
    std::vector<control::EndpointInfo> out;
    if (limit == 0U) return out;
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    out.reserve(std::min(endpoints_.size(), limit));
    for (const auto& entry : endpoints_) {
        if (entry.second.session.expired()) {
            continue;
        }
        out.push_back(entry.second.info);
        if (out.size() == limit) break;
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
        auto stale_session = std::find_if(
            session_endpoints_.begin(), session_endpoints_.end(),
            [&](const auto& entry) { return entry.second == endpoint_id; });
        if (stale_session != session_endpoints_.end()) {
            unregister_endpoint_locked(stale_session->first, true);
        } else {
            // Defensive fallback for an inconsistent registry. A normal
            // registration always has a session_endpoints_ reverse entry.
            endpoint_names_.erase(it->second.info.display_name);
            endpoints_.erase(it);
        }
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
    if (!from_session || !ValidateRelayV2Request(invite, error) ||
        !OrdinaryCallerAllows(from_session, invite.channel_kind, error)) {
        return false;
    }
    if (from_session->endpoint_id().empty() ||
        from_session->endpoint_id() != invite.from_endpoint_id) {
        if (error) *error = "relay invite origin does not match its registered session";
        return false;
    }
    control::EndpointInfo origin_info;
    const auto registered_origin =
        find_endpoint_session(invite.from_endpoint_id, &origin_info);
    if (!registered_origin || registered_origin.get() != from_session.get() ||
        origin_info.auth_pubkey_b64.empty() ||
        origin_info.auth_pubkey_b64 != invite.from_auth_pubkey_b64) {
        if (error) {
            *error = "relay invite origin identity does not match its authenticated session";
        }
        return false;
    }
    control::EndpointInfo target_info;
    auto target = find_endpoint_session(invite.to_endpoint_id, &target_info);
    if (target) {
        if (target_info.endpoint_id != invite.to_endpoint_id) {
            if (error) {
                *error = "relay target must be an exact endpoint id, not an alias";
            }
            return false;
        }
        if (!TargetAllows(target_info, invite.channel_kind, error)) {
            return false;
        }
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
        if (!relay_invite_capacity_available_locked(invite, error)) {
            return false;
        }
        InviteEntry entry;
        entry.invite = invite;
        entry.from_session = from_session;
        entry.to_session = target;
        entry.expires_at = std::chrono::steady_clock::now() +
            control::kPendingRelayInviteLifetime;
        const auto [stored, inserted] =
            invites_.emplace(invite.invite_id, std::move(entry));
        (void)stored;
        if (!inserted) {
            if (error) *error = "relay invite id is already in use";
            return false;
        }
        schedule_relay_invite_expiry_locked();
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
            if (!TargetAllows(remote_info, invite.channel_kind, error)) {
                return false;
            }
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
                if (!relay_invite_capacity_available_locked(invite, error)) {
                    return false;
                }
                InviteEntry entry;
                entry.invite = invite;
                entry.from_session = from_session;
                entry.outbound_federated = true;
                entry.federation_peer_id = peer_id;
                entry.federation_remote_id = remote_id;
                entry.expires_at = std::chrono::steady_clock::now() +
                    control::kPendingRelayInviteLifetime;
                const auto [stored, inserted] =
                    invites_.emplace(invite.invite_id, std::move(entry));
                (void)stored;
                if (!inserted) {
                    if (error) *error = "relay invite id is already in use";
                    return false;
                }
                schedule_relay_invite_expiry_locked();
            }
            if (!federation_->send_invite_request(invite, peer_id, remote_id, error)) {
                std::lock_guard<std::mutex> lock(endpoint_mutex_);
                invites_.erase(invite.invite_id);
                schedule_relay_invite_expiry_locked();
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
    if (!from_session || !from_session->is_federation_authenticated() ||
        !ValidateRelayV2Request(invite, error)) {
        if (error && error->empty()) *error = "authenticated federation invite required";
        return false;
    }
    const std::string exact_local_target =
        raw_target_id.empty() ? invite.to_endpoint_id : raw_target_id;
    control::EndpointInfo target_info;
    auto target = find_endpoint_session(exact_local_target, &target_info);
    if (!target) {
        if (error) {
            *error = "target not found";
        }
        return false;
    }
    if (target_info.endpoint_id != exact_local_target) {
        if (error) {
            *error = "federated relay target must be an exact endpoint id, not an alias";
        }
        return false;
    }
    if (!TargetAllows(target_info, invite.channel_kind, error)) {
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
    if (!relay_invite_capacity_available_locked(invite, error)) {
        return false;
    }
    InviteEntry entry;
    entry.invite = invite;
    entry.from_session = from_session;
    entry.to_session = target;
    entry.inbound_federated = true;
    entry.federation_peer_id = peer_id;
    entry.expires_at = std::chrono::steady_clock::now() +
        control::kPendingRelayInviteLifetime;
    const auto [stored, inserted] =
        invites_.emplace(invite.invite_id, std::move(entry));
    (void)stored;
    if (!inserted) {
        if (error) *error = "relay invite id is already in use";
        return false;
    }
    schedule_relay_invite_expiry_locked();
    if (local_target_session) {
        *local_target_session = target;
    }
    return true;
}

// Bind a reply to the authenticated session stored when the invite was routed;
// peer-provided endpoint fields are corroborating immutable transcript data,
// never the source of responder authorization.
bool Manager::respond_invite(const std::shared_ptr<Session>& from_session,
                             const control::PendingInvite& response,
                             std::shared_ptr<Session>* initiator_session,
                             control::PendingInvite* invite_out,
                             std::string* error) {
    if (!ValidateRelayV2Response(response, error)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    prune_expired_relay_invites_locked(std::chrono::steady_clock::now());
    auto it = invites_.find(response.invite_id);
    if (it == invites_.end()) {
        if (error) {
            *error = "invite not found";
        }
        return false;
    }
    auto expected_responder = it->second.to_session.lock();
    if (!from_session || !expected_responder ||
        expected_responder.get() != from_session.get()) {
        if (error) {
            *error = "invite response did not come from the invited session";
        }
        return false;
    }
    if (it->second.state != InviteEntry::State::awaiting_response) {
        if (error) *error = "relay invite has already been answered";
        return false;
    }
    if (!control::relay_v2_request_fields_match(
            it->second.invite, response)) {
        if (error) *error = "invite response changed immutable request fields";
        return false;
    }
    if (response.accepted) {
        const auto responder_session_it =
            session_endpoints_.find(from_session.get());
        const auto responder_it = responder_session_it == session_endpoints_.end()
            ? endpoints_.end()
            : endpoints_.find(responder_session_it->second);
        if (responder_it == endpoints_.end() ||
            responder_it->second.info.auth_pubkey_b64.empty() ||
            responder_it->second.info.auth_pubkey_b64 !=
                response.responder_auth_pubkey_b64) {
            if (error) {
                *error = "relay invite responder identity does not match its authenticated session";
            }
            return false;
        }
    }
    it->second.invite.response_present = true;
    it->second.invite.accepted = response.accepted;
    it->second.invite.response_reason = response.response_reason;
    it->second.invite.handshake_response_b64 =
        response.handshake_response_b64;
    it->second.invite.responder_auth_pubkey_b64 =
        response.responder_auth_pubkey_b64;
    if (response.accepted) {
        it->second.state = InviteEntry::State::accepted;
    }
    auto initiator = it->second.from_session.lock();
    if (!initiator) {
        if (error) {
            *error = "invite initiator unavailable";
        }
        invites_.erase(it);
        schedule_relay_invite_expiry_locked();
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
        schedule_relay_invite_expiry_locked();
    }
    return true;
}

bool Manager::respond_federated_invite(const std::string& peer_id,
                                       const control::PendingInvite& response,
                                       std::shared_ptr<Session>* initiator_session,
                                       control::PendingInvite* invite_out,
                                       std::string* error) {
    if (!ValidateRelayV2Response(response, error)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    prune_expired_relay_invites_locked(std::chrono::steady_clock::now());
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
    if (it->second.state != InviteEntry::State::awaiting_response) {
        if (error) *error = "relay invite has already been answered";
        return false;
    }
    if (!control::relay_v2_request_fields_match(
            it->second.invite, response)) {
        if (error) *error = "invite response changed immutable request fields";
        return false;
    }
    it->second.invite.response_present = true;
    it->second.invite.accepted = response.accepted;
    it->second.invite.response_reason = response.response_reason;
    it->second.invite.handshake_response_b64 =
        response.handshake_response_b64;
    it->second.invite.responder_auth_pubkey_b64 =
        response.responder_auth_pubkey_b64;
    if (response.accepted) {
        it->second.state = InviteEntry::State::accepted;
    }
    auto initiator = it->second.from_session.lock();
    if (!initiator) {
        if (error) {
            *error = "invite initiator unavailable";
        }
        invites_.erase(it);
        schedule_relay_invite_expiry_locked();
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
        schedule_relay_invite_expiry_locked();
    }
    return true;
}

bool Manager::can_open_channel(const std::shared_ptr<Session>& origin,
                               const std::string& channel_id,
                               const std::string& from_id,
                               const std::string& to_id,
                               control::ChannelKind channel_kind,
                               std::shared_ptr<Session>* target_session,
                               control::PendingInvite* invite_out,
                               std::string* error) {
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    prune_expired_relay_invites_locked(std::chrono::steady_clock::now());
    auto it = invites_.find(channel_id);
    if (it == invites_.end()) {
        if (error) {
            *error = "invite not found";
        }
        return false;
    }
    const auto& invite = it->second.invite;
    if (!invite.accepted || it->second.state != InviteEntry::State::accepted) {
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
    auto expected_origin = it->second.from_session.lock();
    if (!origin || !expected_origin || expected_origin.get() != origin.get()) {
        if (error) *error = "relay OPEN did not come from the inviting session";
        return false;
    }
    if (!ValidateRelayV2Response(invite, error) || !invite.accepted ||
        (!it->second.inbound_federated &&
         !OrdinaryCallerAllows(origin, channel_kind, error))) {
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
    auto target_session_it = session_endpoints_.find(target.get());
    auto target_it = target_session_it == session_endpoints_.end()
        ? endpoints_.end() : endpoints_.find(target_session_it->second);
    if (target_it == endpoints_.end() ||
        !TargetAllows(target_it->second.info, channel_kind, error)) {
        return false;
    }
    if (channel_kind == control::ChannelKind::admin) {
        bool allowed = false;
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
    it->second.state = InviteEntry::State::opening;
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
    if (!open_json.contains("channel_kind") ||
        !open_json["channel_kind"].is_string()) {
        if (error) *error = "invalid relay channel kind";
        return true;
    }
    const auto parsed_kind = control::try_relay_channel_kind(
        open_json["channel_kind"].get_ref<const std::string&>());
    if (!parsed_kind) {
        if (error) *error = "invalid relay channel kind";
        return true;
    }
    const auto channel_kind = *parsed_kind;
    std::string peer_id;
    std::string remote_id;
    control::EndpointInfo remote_info;
    if (!federation_->resolve_remote_endpoint(
            target_id, &peer_id, &remote_id, &remote_info)) {
        return false;
    }
    if (!OrdinaryCallerAllows(origin, channel_kind, error) ||
        !TargetAllows(remote_info, channel_kind, error)) {
        return true;
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
        prune_expired_relay_invites_locked(std::chrono::steady_clock::now());
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
        if (!invite.accepted ||
            it->second.state != InviteEntry::State::accepted) {
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
        auto expected_origin = it->second.from_session.lock();
        if (!expected_origin || expected_origin.get() != origin.get() ||
            !ValidateRelayV2Response(invite, error) || !invite.accepted) {
            if (error && error->empty()) {
                *error = "relay OPEN did not come from the inviting session";
            }
            return true;
        }
        it->second.state = InviteEntry::State::opening;
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
    if (channel.channel_id.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    std::optional<control::ActiveRelayChannel> previous;
    auto previous_it = active_channels_.find(channel.channel_id);
    if (previous_it != active_channels_.end()) {
        previous = previous_it->second;
    }
    active_channels_[channel.channel_id] = channel;

    auto local_endpoint = [&](const std::string& endpoint_id)
        -> control::EndpointInfo* {
        auto it = endpoints_.find(endpoint_id);
        return it == endpoints_.end() ? nullptr : &it->second.info;
    };
    if (previous &&
        admin_relationships::is_established_admin_channel(*previous)) {
        admin_relationships::remove_local_relationship_if_unused(
            active_channels_,
            local_endpoint(previous->left_endpoint_id),
            local_endpoint(previous->right_endpoint_id),
            previous->left_endpoint_id,
            previous->right_endpoint_id);
    }
    if (admin_relationships::is_established_admin_channel(channel)) {
        admin_relationships::add_local_relationship(
            local_endpoint(channel.left_endpoint_id),
            local_endpoint(channel.right_endpoint_id),
            channel.left_endpoint_id,
            channel.right_endpoint_id);
    }
}

void Manager::unregister_active_channel(const std::string& channel_id) {
    std::lock_guard<std::mutex> lock(endpoint_mutex_);
    std::optional<control::ActiveRelayChannel> removed;
    auto it = active_channels_.find(channel_id);
    if (it != active_channels_.end()) {
        removed = it->second;
        active_channels_.erase(it);
    }
    invites_.erase(channel_id);
    if (!removed ||
        !admin_relationships::is_established_admin_channel(*removed)) {
        return;
    }
    auto controller_it = endpoints_.find(removed->left_endpoint_id);
    auto target_it = endpoints_.find(removed->right_endpoint_id);
    admin_relationships::remove_local_relationship_if_unused(
        active_channels_,
        controller_it == endpoints_.end()
            ? nullptr : &controller_it->second.info,
        target_it == endpoints_.end()
            ? nullptr : &target_it->second.info,
        removed->left_endpoint_id,
        removed->right_endpoint_id);
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
    std::vector<FederationPeerStatus> outbound;
    if (federation_) {
        outbound = federation_->statuses();
    }
    std::map<std::string, FederationPeerStatus> merged;
    for (auto& status : outbound) {
        status.outbound_state = status.state;
        status.outbound_ready = status.ready;
        merged[status.id] = std::move(status);
    }

    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (const auto& [_, inbound] : inbound_federation_sessions_) {
            auto& status = merged[inbound.peer_id];
            status.id = inbound.peer_id;
            if (status.inbound_connections <
                std::numeric_limits<std::uint32_t>::max()) {
                ++status.inbound_connections;
            }
            status.ready = true;
            if (!status.outbound_ready) {
                status.state = "inbound-ready";
            }
            status.last_handshake_ms =
                std::max(status.last_handshake_ms, inbound.handshake_ms);
        }
    }

    std::unordered_map<std::string, std::uint32_t> channel_counts;
    std::unordered_set<std::string> known_peers;
    for (const auto& [peer_id, _] : merged) {
        known_peers.insert(peer_id);
    }
    for (const auto& configured :
         FederationManager::configured_peers(cfg_).peers) {
        known_peers.insert(configured.id);
    }
    for (auto& [_, status] : merged) {
        status.channels_active = 0;
    }
    {
        std::lock_guard<std::mutex> lock(endpoint_mutex_);
        for (const auto& [_, channel] : active_channels_) {
            if (!channel.federated) continue;
            std::string peer_id;
            const auto consider = [&](const std::string& endpoint_id) {
                const auto separator = endpoint_id.find(':');
                if (separator == std::string::npos) return;
                const std::string candidate =
                    endpoint_id.substr(0U, separator);
                if (known_peers.find(candidate) != known_peers.end()) {
                    peer_id = candidate;
                }
            };
            consider(channel.left_endpoint_id);
            if (peer_id.empty()) consider(channel.right_endpoint_id);
            if (peer_id.empty()) continue;
            auto& count = channel_counts[peer_id];
            if (count < std::numeric_limits<std::uint32_t>::max()) {
                ++count;
            }
        }
    }
    for (const auto& [peer_id, count] : channel_counts) {
        auto& status = merged[peer_id];
        status.id = peer_id;
        status.channels_active = count;
    }

    std::vector<FederationPeerStatus> result;
    result.reserve(merged.size());
    for (auto& [_, status] : merged) {
        result.push_back(std::move(status));
    }
    return result;
}

ConfiguredFederationPeers Manager::federation_configured_peers() const {
    if (!federation_) {
        return FederationManager::configured_peers(cfg_);
    }
    return federation_->configured_peers();
}

std::vector<control::EndpointInfo> Manager::federation_remote_endpoints(
        std::size_t limit) const {
    if (!federation_) {
        return {};
    }
    return federation_->remote_endpoints(limit);
}

bool Manager::disconnect_endpoint(const std::string& endpoint_id,
                                  std::string* error) {
    if (endpoint_id.empty()) {
        if (error) *error = "endpoint_id is required";
        return false;
    }

    std::shared_ptr<Session> session;
    {
        std::lock_guard<std::mutex> lock(endpoint_mutex_);
        const auto found = endpoints_.find(endpoint_id);
        if (found != endpoints_.end()) {
            session = found->second.session.lock();
            if (!session) {
                const auto stale_session = std::find_if(
                    session_endpoints_.begin(), session_endpoints_.end(),
                    [&](const auto& entry) {
                        return entry.second == endpoint_id;
                    });
                if (stale_session != session_endpoints_.end()) {
                    unregister_endpoint_locked(stale_session->first, true);
                } else {
                    endpoint_names_.erase(found->second.info.display_name);
                    endpoints_.erase(found);
                }
            }
        }
    }
    if (!session) {
        if (error) {
            *error = "exact endpoint_id not found";
        }
        return false;
    }
    session->stop();
    return true;
}

}  // namespace yume::server
