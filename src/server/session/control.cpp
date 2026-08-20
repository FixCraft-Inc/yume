/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * ----------------------------------------------------------------
 * Session control-plane methods.
 *
 * Contains the control-plane methods of yume::server::Session:
 *
 *   handle_control          — entry-point dispatch for inbound
 *                             control-channel frames
 *   handle_control_open_request / open_ack / data / close / exec
 *                           — per-message-type sub-handlers
 *   send_control_frame      — outbound control-frame writer
 *   send_control_close      — control-channel close helper
 *   send_control_json_to_client — federation/relay JSON push
 * ---------------------------------------------------------------- */

#include "server/session/session.hpp"
#include "server/runtime/manager.hpp"
#include "server/session/internal.hpp"

namespace yume::server {

void Session::handle_control(const protocol::Frame& frame) {
    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        crypto::Bytes decrypted;
        if (decrypt_inner_payload(protocol::CONTROL, frame.header.stream_id, frame.payload, &decrypted)) {
            payload = std::move(decrypted);
        } else {
            util::log_warn("session " + std::to_string(session_id_) + ": CONTROL decrypt failed");
            return;
        }
    }

    nlohmann::json json;
    try {
        json = nlohmann::json::parse(std::string(payload.begin(), payload.end()));
    } catch (...) {
        util::log_warn("session " + std::to_string(session_id_) + ": invalid CONTROL payload");
        return;
    }

    const std::string cmd = json.value("cmd", "");
    if (cmd == "register") {
        client_hostname_ = cfg_.anonym ? std::string{} : json.value("hostname", "");
        client_server_in_charge_ = json.value("server_in_charge", false);
        client_allow_exec_ = json.value("allow_exec", false) && session_allow_exec_policy_;
        const std::string reported_ip = json.value("wan_ip", "");
        if (!cfg_.anonym && !reported_ip.empty()) {
            client_wan_ip_ = reported_ip;
        }
        if (manager_) {
            ControlledClientInfo info;
            info.id = client_id_;
            info.hostname = client_hostname_;
            info.wan_ip = client_wan_ip_;
            info.allow_exec = client_allow_exec_;
            info.server_in_charge = client_server_in_charge_;
            manager_->register_controlled_client(shared_from_this(), info);
        }
        return;
    }

    auto send_json = [&](const nlohmann::json& resp) {
        nlohmann::json payload_json = resp;
        if (json.contains("request_id") && !payload_json.contains("request_id")) {
            payload_json["request_id"] = json["request_id"];
        }
        std::string out = payload_json.dump();
        crypto::Bytes bytes(out.begin(), out.end());
        send_control_frame(protocol::CONTROL, frame.header.stream_id, bytes);
    };

    if (cmd == "presence.announce") {
        util::log_info("session " + std::to_string(session_id_) + ": CONTROL cmd=presence.announce");
        if (!manager_) {
            send_json({{"cmd", cmd}, {"ok", false}, {"error", "manager unavailable"}});
            return;
        }
        control::PresenceAnnouncement announce;
        announce.endpoint_kind = control::endpoint_kind_from_string(json.value("endpoint_kind", "client"));
        announce.preferred_id = json.value("preferred_id", "");
        announce.preferred_name = json.value("preferred_name", "");
        announce.hostname = cfg_.anonym ? std::string{} : json.value("hostname", client_hostname_);
        announce.client_platform = json.value("client_platform", "unknown");
        announce.client_variant = json.value("client_variant", "unknown");
        announce.client_version = json.value("client_version", "");
        announce.relay_mode = control::relay_mode_from_string(json.value("relay_mode", "untrusted"));
        announce.allow_chat = json.value("allow_chat", true) && session_allow_chat_policy_;
        announce.allow_file = json.value("allow_file", true) && session_allow_file_policy_;
        announce.allow_bytes = json.value("allow_bytes", true) && session_allow_bytes_policy_;
        announce.allow_inbound_admin = json.value("allow_inbound_admin", false) &&
                                       session_allow_inbound_admin_policy_;
        announce.allow_outbound_admin = json.value("allow_outbound_admin", false) &&
                                        session_allow_outbound_admin_policy_;
        auto result = manager_->register_endpoint(shared_from_this(), announce, client_auth_pubkey_b64_);
        client_id_ = result.endpoint.endpoint_id;
        client_display_name_ = result.endpoint.display_name;
        client_hostname_ = result.endpoint.hostname;
        client_platform_ = result.endpoint.client_platform;
        client_variant_ = result.endpoint.client_variant;
        client_version_ = result.endpoint.client_version;
        client_relay_mode_ = result.endpoint.relay_mode;
        client_allow_chat_ = result.endpoint.allow_chat;
        client_allow_file_ = result.endpoint.allow_file;
        client_allow_bytes_ = result.endpoint.allow_bytes;
        client_allow_inbound_admin_ = result.endpoint.allow_inbound_admin;
        client_allow_outbound_admin_ = result.endpoint.allow_outbound_admin;
        nlohmann::json resp;
        resp["cmd"] = cmd;
        resp["ok"] = true;
        resp["assigned_id"] = result.endpoint.endpoint_id;
        resp["assigned_name"] = result.endpoint.display_name;
        resp["preferred_id_accepted"] = result.preferred_id_accepted;
        resp["preferred_name_accepted"] = result.preferred_name_accepted;
        resp["server_id"] = result.server_id;
        resp["server_name"] = result.server_name;
        resp["endpoint"] = control::endpoint_to_json(result.endpoint, true);
        util::log_info("session " + std::to_string(session_id_) + ": CONTROL presence.announce assigned " +
                       result.endpoint.endpoint_id + " (" + result.endpoint.display_name + ")");
        send_json(resp);
        return;
    }

    if (cmd == "client.lifecycle") {
        util::log_info("session " + std::to_string(session_id_) + ": CONTROL cmd=client.lifecycle state=" +
                       json.value("state", std::string{}));
        nlohmann::json resp;
        resp["cmd"] = cmd;
        if (!manager_) {
            resp["ok"] = false;
            resp["error"] = "manager unavailable";
            send_json(resp);
            return;
        }
        const std::string state = json.value("state", "");
        const std::string message = json.value("message", "");
        if (state.empty() || message.empty()) {
            resp["ok"] = false;
            resp["error"] = "missing state/message";
            send_json(resp);
            return;
        }
        control::ClientLifecycleEvent event;
        event.state = state;
        event.message = message;
        event.detail = json.value("detail", "");
        event.client_platform = json.value("client_platform", client_platform_);
        event.client_variant = json.value("client_variant", client_variant_);
        event.client_version = json.value("client_version", client_version_);
        event.effective_protection = json.value("effective_protection", "");
        event.traffic_verified = json.value("traffic_verified", false);
        event.exit_ip = json.value("exit_ip", "");
        event.error_code = json.value("error_code", "");
        latest_lifecycle_state_ = state;
        control::ClientLifecycleEvent stored_event;
        if (!manager_->update_endpoint_lifecycle(this, event, &stored_event)) {
            resp["ok"] = false;
            resp["error"] = "presence announce required before lifecycle";
            send_json(resp);
            return;
        }
        resp["ok"] = true;
        resp["accepted_state"] = stored_event.state;
        resp["server_time_ms"] = stored_event.server_time_ms;
        send_json(resp);
        return;
    }

    if (cmd == "directory.list" || cmd == "list") {
        nlohmann::json resp;
        resp["cmd"] = cmd;
        resp["ok"] = true;
        resp["server_id"] = manager_ ? manager_->config_snapshot().server_id : "";
        resp["server_name"] = manager_ ? manager_->config_snapshot().server_name : "";
        resp["endpoints"] = nlohmann::json::array();
        if (manager_) {
            auto endpoints = manager_->list_endpoints();
            for (const auto& endpoint : endpoints) {
                resp["endpoints"].push_back(control::endpoint_to_json(endpoint, true));
            }
        } else {
            resp["ok"] = false;
            resp["error"] = "manager unavailable";
        }
        if (cmd == "list") {
            resp["clients"] = nlohmann::json::array();
            if (manager_) {
                auto list = manager_->list_controlled_clients(cfg_.anonym);
                for (const auto& info : list) {
                    nlohmann::json item;
                    item["id"] = info.id;
                    item["hostname"] = info.hostname;
                    item["wan_ip"] = info.wan_ip;
                    item["allow_exec"] = info.allow_exec;
                    item["server_in_charge"] = info.server_in_charge;
                    resp["clients"].push_back(std::move(item));
                }
            }
        }
        send_json(resp);
        return;
    }

    if (cmd == "federation.hello") {
        nlohmann::json resp;
        resp["cmd"] = cmd;
        if (!is_federation_authenticated()) {
            resp["ok"] = false;
            resp["error"] = "federation auth required";
            send_json(resp);
            return;
        }
        resp["ok"] = true;
        resp["peer_id"] = federation_peer_id_;
        resp["your_peer_id"] = federation_peer_id_;
        resp["server_id"] = manager_ ? manager_->server_id() : cfg_.server_id;
        resp["server_name"] = manager_ ? manager_->server_name() : cfg_.server_name;
        send_json(resp);
        return;
    }

    if (cmd == "federation.directory") {
        nlohmann::json resp;
        resp["cmd"] = cmd;
        if (json.contains("request_id")) {
            resp["request_id"] = json["request_id"];
        }
        if (!is_federation_authenticated()) {
            resp["ok"] = false;
            resp["error"] = "federation auth required";
            send_json(resp);
            return;
        }
        const std::int64_t now = epoch_now_ms();
        while (!federation_directory_hits_.empty() && now - federation_directory_hits_.front() > 1000) {
            federation_directory_hits_.pop_front();
        }
        if (federation_directory_hits_.size() >= 10) {
            resp["ok"] = false;
            resp["error"] = "federation.directory throttled";
            send_json(resp);
            return;
        }
        federation_directory_hits_.push_back(now);
        resp["ok"] = true;
        resp["server_id"] = manager_ ? manager_->server_id() : cfg_.server_id;
        resp["server_name"] = manager_ ? manager_->server_name() : cfg_.server_name;
        resp["endpoints"] = nlohmann::json::array();
        if (manager_) {
            for (const auto& endpoint : manager_->list_local_endpoints()) {
                resp["endpoints"].push_back(control::endpoint_to_json(endpoint, true));
            }
        }
        send_json(resp);
        return;
    }

    if (cmd == "directory.lookup") {
        nlohmann::json resp;
        resp["cmd"] = cmd;
        const std::string query = json.value("query", "");
        control::EndpointInfo endpoint;
        auto target = manager_ ? manager_->find_endpoint_session(query, &endpoint) : nullptr;
        if (!target) {
            resp["ok"] = false;
            resp["error"] = "endpoint not found";
        } else {
            resp["ok"] = true;
            resp["endpoint"] = control::endpoint_to_json(endpoint, true);
        }
        send_json(resp);
        return;
    }

    if (cmd == "invite.request") {
        nlohmann::json resp;
        resp["cmd"] = cmd;
        control::PendingInvite invite = control::invite_from_json(json);
        invite.from_endpoint_id = client_id_;
        invite.from_display_name = client_display_name_;
        invite.from_auth_pubkey_b64 = client_auth_pubkey_b64_;
        invite.created_ms = epoch_now_ms();
        std::string error;
        std::shared_ptr<Session> target;
        bool federated = false;
        if (!manager_ || !manager_->route_invite(shared_from_this(), invite, &error, &target, &federated)) {
            resp["ok"] = false;
            resp["error"] = error.empty() ? "invite routing failed" : error;
            send_json(resp);
            return;
        }
        if (federated) {
            resp["ok"] = true;
            resp["queued"] = true;
            resp["federated"] = true;
            send_json(resp);
            return;
        }
        if (!target) {
            resp["ok"] = false;
            resp["error"] = "target unavailable";
            send_json(resp);
            return;
        }
        nlohmann::json notify = control::invite_to_json(invite, false);
        notify["cmd"] = "invite.request";
        std::string out = notify.dump();
        target->send_control_frame(protocol::CONTROL, 0, crypto::Bytes(out.begin(), out.end()));
        resp["ok"] = true;
        resp["queued"] = true;
        send_json(resp);
        return;
    }

    if (cmd == "federation.invite.request") {
        nlohmann::json resp;
        resp["cmd"] = cmd;
        if (!is_federation_authenticated()) {
            resp["ok"] = false;
            resp["error"] = "federation auth required";
            send_json(resp);
            return;
        }
        control::PendingInvite invite = control::invite_from_json(json);
        const std::string raw_target_id = json.value("raw_to_id", "");
        std::shared_ptr<Session> target;
        std::string error;
        if (!manager_ || !manager_->route_federated_invite(shared_from_this(), invite, raw_target_id, &error, &target)) {
            resp["ok"] = false;
            resp["error"] = error.empty() ? "invite routing failed" : error;
            send_json(resp);
            return;
        }
        if (target) {
            nlohmann::json notify = control::invite_to_json(invite, false);
            notify["cmd"] = "invite.request";
            std::string out = notify.dump();
            target->send_control_frame(protocol::CONTROL, 0, crypto::Bytes(out.begin(), out.end()));
        }
        resp["ok"] = true;
        resp["queued"] = true;
        send_json(resp);
        return;
    }

    if (cmd == "invite.reply") {
        nlohmann::json resp;
        resp["cmd"] = cmd;
        control::PendingInvite reply = control::invite_from_json(json);
        reply.from_endpoint_id = client_id_;
        std::shared_ptr<Session> initiator;
        control::PendingInvite resolved_invite;
        std::string error;
        if (!manager_ || !manager_->respond_invite(shared_from_this(), reply, &initiator, &resolved_invite, &error)) {
            resp["ok"] = false;
            resp["error"] = error.empty() ? "invite response failed" : error;
            send_json(resp);
            return;
        }
        if (initiator) {
            nlohmann::json notify = control::invite_to_json(resolved_invite, true);
            notify["cmd"] = initiator->is_federation_authenticated() ? "federation.invite.reply" : "invite.reply";
            std::string out = notify.dump();
            initiator->send_control_frame(protocol::CONTROL, 0, crypto::Bytes(out.begin(), out.end()));
        }
        resp["ok"] = true;
        send_json(resp);
        return;
    }

    if (cmd == "admin.attach") {
        nlohmann::json resp;
        resp["cmd"] = cmd;
        const std::string target_id = json.value("id", "");
        control::EndpointInfo target_info;
        auto target = manager_ ? manager_->find_endpoint_session(target_id, &target_info) : nullptr;
        if (!target) {
            resp["ok"] = false;
            resp["error"] = "endpoint not found";
            send_json(resp);
            return;
        }
        if (!authorization::admin_attach_allowed(
                client_relay_mode_ == control::RelayMode::trusted,
                client_allow_outbound_admin_,
                target_info.allow_inbound_admin)) {
            resp["ok"] = false;
            resp["error"] = "admin attach requires caller outbound-admin and target inbound-admin permission in trusted relay mode";
            send_json(resp);
            return;
        }
        resp["ok"] = true;
        resp["endpoint"] = control::endpoint_to_json(target_info, true);
        send_json(resp);
        return;
    }

    if (cmd == "attach") {
        nlohmann::json resp;
        resp["cmd"] = "attach";
        const std::string id = json.value("id", "");
        if (id.empty()) {
            resp["ok"] = false;
            resp["error"] = "missing id";
            send_json(resp);
            return;
        }
        ControlledClientInfo info;
        std::shared_ptr<Session> target;
        if (manager_) {
            target = manager_->find_controlled_session(id, &info);
        }
        if (!target) {
            resp["ok"] = false;
            resp["error"] = "client not found";
            send_json(resp);
            return;
        }
        if (!info.server_in_charge) {
            resp["ok"] = false;
            resp["error"] = "client did not grant server-in-charge";
            send_json(resp);
            return;
        }
        if (!authorization::admin_attach_allowed(
                client_relay_mode_ == control::RelayMode::trusted,
                client_allow_outbound_admin_,
                target->allows_inbound_admin())) {
            resp["ok"] = false;
            resp["error"] = "legacy attach requires caller outbound-admin and target inbound-admin permission in trusted relay mode";
            send_json(resp);
            return;
        }
        is_controller_ = true;
        control_target_ = target;
        control_target_id_ = id;
        resp["ok"] = true;
        resp["id"] = info.id;
        resp["hostname"] = info.hostname;
        resp["wan_ip"] = info.wan_ip;
        resp["allow_exec"] = info.allow_exec;
        resp["server_in_charge"] = info.server_in_charge;
        send_json(resp);
        return;
    }

    nlohmann::json resp;
    resp["cmd"] = cmd;
    resp["ok"] = false;
    resp["error"] = "unknown control command";
    send_json(resp);
}

bool Session::handle_control_open_request(const protocol::Frame& frame) {
    if (!is_controller_) {
        return false;
    }
    auto target = control_target_.lock();
    if (!target) {
        send_open_reply(frame.header.stream_id, false, "control target unavailable");
        return true;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(protocol::OPEN, frame.header.stream_id, frame.payload, &payload)) {
            send_open_reply(frame.header.stream_id, false, "control open decrypt failed");
            return true;
        }
    }

    uint8_t target_stream = target->reserve_stream_id();
    if (target_stream == 0) {
        send_open_reply(frame.header.stream_id, false, "no stream ids available");
        return true;
    }

    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        control_outbound_[frame.header.stream_id] = ControlLink{target, target_stream, true, false};
    }
    {
        std::lock_guard<std::mutex> lock(target->control_mutex_);
        target->control_inbound_[target_stream] = ControlLink{shared_from_this(), frame.header.stream_id, true, false};
    }

    target->send_control_frame(protocol::SOPEN, target_stream, payload);
    return true;
}

bool Session::handle_control_open_ack(const protocol::Frame& frame) {
    ControlLink link;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = control_inbound_.find(frame.header.stream_id);
        if (it == control_inbound_.end()) {
            return false;
        }
        link = it->second;
    }

    auto peer = link.peer.lock();
    if (!peer) {
        std::lock_guard<std::mutex> lock(control_mutex_);
        control_inbound_.erase(frame.header.stream_id);
        return true;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(protocol::OPEN, frame.header.stream_id, frame.payload, &payload)) {
            if (auto peer = link.peer.lock()) {
                peer->send_control_close(link.peer_stream_id, "control open decrypt failed");
            }
            std::lock_guard<std::mutex> lock(control_mutex_);
            control_inbound_.erase(frame.header.stream_id);
            return true;
        }
    }
    const bool ok = (frame.header.flags & protocol::kFlagOpenOk) != 0;
    const std::string reason(payload.begin(), payload.end());

    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = control_inbound_.find(frame.header.stream_id);
        if (it != control_inbound_.end()) {
            if (!ok) {
                control_inbound_.erase(it);
            } else {
                it->second.pending = false;
            }
        }
    }
    {
        std::lock_guard<std::mutex> lock(peer->control_mutex_);
        auto it = peer->control_outbound_.find(link.peer_stream_id);
        if (it != peer->control_outbound_.end()) {
            if (!ok) {
                peer->control_outbound_.erase(it);
            } else {
                it->second.pending = false;
            }
        }
    }

    if (ok && manager_ && !link.channel_id.empty()) {
        control::ActiveRelayChannel channel;
        channel.channel_id = link.channel_id;
        channel.channel_kind = link.channel_kind;
        channel.left_endpoint_id = link.left_endpoint_id;
        channel.right_endpoint_id = link.right_endpoint_id;
        channel.left_stream_id = link.peer_stream_id;
        channel.right_stream_id = frame.header.stream_id;
        channel.pending = false;
        manager_->register_active_channel(channel);
    }

    peer->send_open_reply(link.peer_stream_id, ok, reason);
    return true;
}

bool Session::handle_control_data(const protocol::Frame& frame) {
    ControlLink link;
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = control_outbound_.find(frame.header.stream_id);
        if (it != control_outbound_.end()) {
            link = it->second;
            found = true;
        } else {
            auto it_in = control_inbound_.find(frame.header.stream_id);
            if (it_in != control_inbound_.end()) {
                link = it_in->second;
                found = true;
            }
        }
    }
    if (!found) {
        return false;
    }

    auto peer = link.peer.lock();
    if (!peer) {
        std::lock_guard<std::mutex> lock(control_mutex_);
        control_outbound_.erase(frame.header.stream_id);
        control_inbound_.erase(frame.header.stream_id);
        return true;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(protocol::DATA, frame.header.stream_id, frame.payload, &payload)) {
            if (auto peer = link.peer.lock()) {
                peer->send_control_close(link.peer_stream_id, "control data decrypt failed");
            }
            std::lock_guard<std::mutex> lock(control_mutex_);
            control_outbound_.erase(frame.header.stream_id);
            control_inbound_.erase(frame.header.stream_id);
            return true;
        }
    }

    peer->send_control_frame(protocol::DATA, link.peer_stream_id, payload);
    return true;
}

bool Session::handle_control_close(const protocol::Frame& frame) {
    ControlLink link;
    bool found = false;
    bool outbound = false;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = control_outbound_.find(frame.header.stream_id);
        if (it != control_outbound_.end()) {
            link = it->second;
            found = true;
            outbound = true;
        } else {
            auto it_in = control_inbound_.find(frame.header.stream_id);
            if (it_in != control_inbound_.end()) {
                link = it_in->second;
                found = true;
            }
        }
    }
    if (!found) {
        return false;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(protocol::CLOSE, frame.header.stream_id, frame.payload, &payload)) {
            payload.clear();
        }
    }
    const std::string reason(payload.begin(), payload.end());

    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        if (outbound) {
            control_outbound_.erase(frame.header.stream_id);
        } else {
            control_inbound_.erase(frame.header.stream_id);
        }
    }
    if (manager_ && !link.channel_id.empty()) {
        if (link.channel_kind == control::ChannelKind::admin) {
            manager_->remove_admin_relationship(link.left_endpoint_id, link.right_endpoint_id);
        }
        manager_->unregister_active_channel(link.channel_id);
    }
    if (auto peer = link.peer.lock()) {
        peer->send_control_close(link.peer_stream_id, reason);
    }
    return true;
}

bool Session::handle_control_exec(const protocol::Frame& frame) {
    if (!is_controller_) {
        return false;
    }
    auto target = control_target_.lock();
    if (!target) {
        send_control_close(frame.header.stream_id, "control target unavailable");
        return true;
    }
    if (!target->client_allow_exec_) {
        const std::string msg = "EXEC not allowed by client";
        crypto::Bytes payload(msg.begin(), msg.end());
        send_control_frame(protocol::DATA, frame.header.stream_id, payload);
        send_control_close(frame.header.stream_id, "exec denied");
        return true;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(protocol::EXEC, frame.header.stream_id, frame.payload, &payload)) {
            send_control_close(frame.header.stream_id, "control exec decrypt failed");
            return true;
        }
    }

    uint8_t target_stream = target->reserve_stream_id();
    if (target_stream == 0) {
        send_control_close(frame.header.stream_id, "no stream ids available");
        return true;
    }

    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        control_outbound_[frame.header.stream_id] = ControlLink{target, target_stream, false, true};
    }
    {
        std::lock_guard<std::mutex> lock(target->control_mutex_);
        target->control_inbound_[target_stream] = ControlLink{shared_from_this(), frame.header.stream_id, false, true};
    }

    target->send_control_frame(protocol::EXEC, target_stream, payload);
    return true;
}

void Session::send_control_frame(
    protocol::FrameType type,
    uint8_t stream_id,
    const crypto::Bytes& payload,
    uint16_t extra_flags,
    std::function<void(const boost::system::error_code&, std::size_t)> handler) {
    crypto::Bytes out = payload;
    uint16_t flags = extra_flags;
    if (inner_key_.has_value()) {
        out = encrypt_inner_payload(type, stream_id, out);
        flags |= protocol::kFlagInnerEncrypted;
    }
    protocol::Frame frame{{static_cast<uint32_t>(out.size()), type, stream_id, flags}, out};
    async_write_frame(frame, std::move(handler));
}

void Session::send_control_close(uint8_t stream_id, const std::string& reason) {
    crypto::Bytes payload(reason.begin(), reason.end());
    send_control_frame(protocol::CLOSE, stream_id, payload);
}

void Session::send_control_fin(uint8_t stream_id, const std::string& reason) {
    crypto::Bytes payload(reason.begin(), reason.end());
    send_control_frame(protocol::CLOSE, stream_id, payload, protocol::kFlagStreamFin);
}

void Session::send_control_json_to_client(const nlohmann::json& json) {
    const std::string out = json.dump();
    send_control_frame(protocol::CONTROL, 0, crypto::Bytes(out.begin(), out.end()));
}

}  // namespace yume::server
