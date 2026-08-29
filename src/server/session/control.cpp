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

#include <algorithm>
#include <exception>
#include <functional>
#include <stdexcept>
#include <string>
#include <utility>

#include "core/protocol/control_command_policy.hpp"
#include "core/protocol/control_fields.hpp"
#include "core/protocol/directory_policy.hpp"
#include "core/protocol/relay_policy.hpp"
#include "server/runtime/manager.hpp"
#include "server/session/internal.hpp"

namespace yume::server {

namespace {

class ControlRequestContext final {
public:
    using Sender = std::function<void(const nlohmann::json&)>;

    ControlRequestContext(const nlohmann::json& request, Sender sender)
        : request_(request), sender_(std::move(sender)) {
        if (request_.contains("request_id") &&
            request_["request_id"].is_string()) {
            const auto& request_id =
                request_["request_id"].get_ref<const std::string&>();
            if (!request_id.empty() &&
                request_id.size() <= control::kMaxDirectoryRequestIdBytes) {
                request_id_ = request_id;
            }
        }
    }

    std::optional<std::string> read_bounded_text(
        const char* key,
        std::size_t max_bytes) const {
        if (!request_.contains(key)) return std::string{};
        if (!request_[key].is_string()) return std::nullopt;
        const auto& value = request_[key].get_ref<const std::string&>();
        if (value.size() > max_bytes ||
            !std::all_of(value.begin(), value.end(), [](unsigned char byte) {
                return byte >= 0x20U && byte != 0x7fU;
            })) {
            return std::nullopt;
        }
        return value;
    }

    void send(nlohmann::json response) const {
        if (request_id_ && !response.contains("request_id")) {
            response["request_id"] = *request_id_;
        }
        sender_(response);
    }

private:
    const nlohmann::json& request_;
    Sender sender_;
    std::optional<std::string> request_id_;
};

}  // namespace

void Session::handle_control(const protocol::Frame& frame) noexcept {
    try {
        handle_control_impl(frame);
    } catch (const std::exception& ex) {
        try {
            util::log_warn("session " + std::to_string(session_id_) +
                           ": CONTROL command processing failed: " +
                           ex.what());
        } catch (...) {
        }
        try {
            close_with_reason("CONTROL command processing failed");
        } catch (...) {
        }
    } catch (...) {
        try {
            util::log_warn("session " + std::to_string(session_id_) +
                           ": CONTROL command processing failed");
        } catch (...) {
        }
        try {
            close_with_reason("CONTROL command processing failed");
        } catch (...) {
        }
    }
}

void Session::handle_control_impl(const protocol::Frame& frame) {
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

    if (!json.is_object() || !json.contains("cmd") ||
        !json["cmd"].is_string()) {
        util::log_warn("session " + std::to_string(session_id_) +
                       ": CONTROL command is missing or has the wrong type");
        return;
    }
    const auto& command = json["cmd"].get_ref<const std::string&>();
    if (!control::is_valid_control_command_name(command)) {
        util::log_warn("session " + std::to_string(session_id_) +
                       ": CONTROL command name is invalid or too long");
        return;
    }
    const std::string cmd = command;
    if (cmd == "register") {
        std::string registration_error;
        auto registration = control::try_legacy_control_registration_from_json(
            json, &registration_error);
        if (!registration) {
            util::log_warn("session " + std::to_string(session_id_) +
                           ": rejected CONTROL register: " +
                           (registration_error.empty()
                                ? "invalid fields"
                                : registration_error));
            return;
        }
        client_hostname_ = cfg_.anonym
            ? std::string{}
            : std::move(registration->hostname);
        client_server_in_charge_ = registration->server_in_charge;
        client_allow_exec_ = registration->allow_exec &&
                             session_allow_exec_policy_;
        if (!cfg_.anonym && !registration->wan_ip.empty()) {
            client_wan_ip_ = std::move(registration->wan_ip);
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

    ControlRequestContext request(
        json, [&](const nlohmann::json& response) {
            std::string out = response.dump();
            crypto::Bytes bytes(out.begin(), out.end());
            send_control_frame(
                protocol::CONTROL, frame.header.stream_id, bytes);
        });
    auto send_json = [&request](nlohmann::json response) {
        request.send(std::move(response));
    };
    auto read_bounded_text = [&request](const char* key,
                                        std::size_t max_bytes) {
        return request.read_bounded_text(key, max_bytes);
    };

    if (cmd == "presence.announce") {
        util::log_info("session " + std::to_string(session_id_) + ": CONTROL cmd=presence.announce");
        if (!manager_) {
            send_json({{"cmd", cmd}, {"ok", false}, {"error", "manager unavailable"}});
            return;
        }
        std::string announce_error;
        auto parsed_announce = control::try_presence_announcement_from_json(
            json, &announce_error);
        if (!parsed_announce) {
            send_json({{"cmd", cmd},
                       {"ok", false},
                       {"error", announce_error.empty()
                           ? "invalid presence announcement"
                           : announce_error}});
            return;
        }
        control::PresenceAnnouncement announce = std::move(*parsed_announce);
        if (cfg_.anonym) announce.hostname.clear();
        announce.allow_chat = announce.allow_chat && session_allow_chat_policy_;
        announce.allow_file = announce.allow_file && session_allow_file_policy_;
        announce.allow_bytes = announce.allow_bytes && session_allow_bytes_policy_;
        announce.allow_inbound_admin = announce.allow_inbound_admin &&
                                       session_allow_inbound_admin_policy_;
        announce.allow_outbound_admin = announce.allow_outbound_admin &&
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
        nlohmann::json resp;
        resp["cmd"] = cmd;
        std::string lifecycle_error;
        auto parsed_event = control::try_lifecycle_command_from_json(
            json, &lifecycle_error);
        if (!parsed_event) {
            resp["ok"] = false;
            resp["error"] = lifecycle_error.empty()
                ? "invalid lifecycle fields"
                : lifecycle_error;
            send_json(resp);
            return;
        }
        util::log_info("session " + std::to_string(session_id_) +
                       ": CONTROL cmd=client.lifecycle state=" +
                       parsed_event->state);
        if (!manager_) {
            resp["ok"] = false;
            resp["error"] = "manager unavailable";
            send_json(resp);
            return;
        }
        control::ClientLifecycleEvent event = std::move(*parsed_event);
        if (event.client_platform.empty() ||
            event.client_platform == "unknown") {
            event.client_platform = client_platform_;
        }
        if (event.client_variant.empty() ||
            event.client_variant == "unknown") {
            event.client_variant = client_variant_;
        }
        if (event.client_version.empty()) {
            event.client_version = client_version_;
        }
        latest_lifecycle_state_ = event.state;
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
            std::size_t accounted = control::kDirectoryEnvelopeOverheadBytes +
                resp["server_id"].get_ref<const std::string&>().size() +
                resp["server_name"].get_ref<const std::string&>().size();
            auto endpoints = manager_->list_endpoints(
                control::kMaxDirectoryEndpoints);
            for (const auto& endpoint : endpoints) {
                const auto endpoint_bytes =
                    control::directory_endpoint_accounted_bytes(
                        endpoint, control::DirectoryNamespace::ClientVisible);
                if (!endpoint_bytes) {
                    util::log_warn(
                        "omitting an invalid endpoint from directory response");
                    continue;
                }
                if (*endpoint_bytes > control::kMaxDirectoryResponseBytes -
                        std::min(control::kMaxDirectoryResponseBytes,
                                 accounted)) {
                    break;
                }
                accounted += *endpoint_bytes;
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
        if (!manager_ || !manager_->federation_enabled() ||
            !is_federation_authenticated()) {
            resp["ok"] = false;
            resp["error"] = "enabled federation auth required";
            send_json(resp);
            return;
        }
        const bool valid_identity =
            !federation_hello_accepted_ && json.size() == 4U &&
            json.contains("peer_id") && json["peer_id"].is_string() &&
            json.contains("server_id") && json["server_id"].is_string() &&
            json.contains("server_name") && json["server_name"].is_string() &&
            json["peer_id"].get_ref<const std::string&>() ==
                json["server_id"].get_ref<const std::string&>() &&
            control::is_valid_directory_server_identity(
                json["server_id"].get_ref<const std::string&>(),
                json["server_name"].get_ref<const std::string&>(), true);
        if (!valid_identity) {
            resp["ok"] = false;
            resp["error"] = "invalid or repeated federation hello";
            send_json(resp);
            return;
        }
        federation_hello_accepted_ = true;
        manager_->register_inbound_federation_session(
            this, federation_peer_id_);
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
        if (json.contains("request_id") && json["request_id"].is_string() &&
            !json["request_id"].get_ref<const std::string&>().empty() &&
            json["request_id"].get_ref<const std::string&>().size() <=
                control::kMaxDirectoryRequestIdBytes) {
            resp["request_id"] = json["request_id"];
        }
        if (!is_federation_authenticated() ||
            !federation_hello_accepted_) {
            resp["ok"] = false;
            resp["error"] = "accepted federation hello required";
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
            std::size_t accounted = control::kDirectoryEnvelopeOverheadBytes +
                resp["server_id"].get_ref<const std::string&>().size() +
                resp["server_name"].get_ref<const std::string&>().size();
            for (auto endpoint : manager_->list_local_endpoints(
                     control::kMaxDirectoryEndpoints)) {
                // Relationship IDs are server-local authorization metadata;
                // a peer cannot safely reinterpret them in its namespace.
                endpoint.controller_ids.clear();
                endpoint.controlled_target_ids.clear();
                const auto endpoint_bytes =
                    control::directory_endpoint_accounted_bytes(
                        endpoint, control::DirectoryNamespace::FederationRaw);
                if (!endpoint_bytes) {
                    util::log_warn(
                        "omitting an invalid endpoint from federation directory response");
                    continue;
                }
                if (*endpoint_bytes > control::kMaxDirectoryResponseBytes -
                        std::min(control::kMaxDirectoryResponseBytes,
                                 accounted)) {
                    break;
                }
                accounted += *endpoint_bytes;
                resp["endpoints"].push_back(control::endpoint_to_json(endpoint, true));
            }
        }
        send_json(resp);
        return;
    }

    if (cmd == "directory.lookup") {
        nlohmann::json resp;
        resp["cmd"] = cmd;
        auto query = read_bounded_text(
            "query", control::kMaxDirectoryDisplayNameBytes);
        if (!query) {
            resp["ok"] = false;
            resp["error"] = "invalid directory query";
            send_json(resp);
            return;
        }
        control::EndpointInfo endpoint;
        auto target = manager_
            ? manager_->find_endpoint_session(*query, &endpoint)
            : nullptr;
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
        if (json.contains(control::fields::source_trust_id)) {
            resp["ok"] = false;
            resp["error"] = "source_trust_id is server-owned";
            send_json(resp);
            return;
        }
        if (!json.contains("channel_kind") ||
            !json["channel_kind"].is_string() ||
            !control::try_relay_channel_kind(
                json["channel_kind"].get_ref<const std::string&>())) {
            resp["ok"] = false;
            resp["error"] = "invalid relay channel kind";
            send_json(resp);
            return;
        }
        auto parsed_invite = control::try_relay_invite_from_json(json);
        if (!parsed_invite) {
            resp["ok"] = false;
            resp["error"] = "invalid relay invite fields";
            send_json(resp);
            return;
        }
        control::PendingInvite invite = std::move(*parsed_invite);
        if (client_id_.empty() || client_auth_pubkey_b64_.empty()) {
            resp["ok"] = false;
            resp["error"] =
                "presence and authenticated relay identity are required";
            send_json(resp);
            return;
        }
        if ((!invite.from_endpoint_id.empty() &&
             invite.from_endpoint_id != client_id_) ||
            (!invite.from_auth_pubkey_b64.empty() &&
             invite.from_auth_pubkey_b64 != client_auth_pubkey_b64_)) {
            resp["ok"] = false;
            resp["error"] =
                "relay invite origin claim does not match authenticated session";
            send_json(resp);
            return;
        }
        // These are corroborated server facts, not caller-controlled routing
        // hints. Empty claims are filled; non-empty mismatches were rejected
        // above so the server never silently rewrites a signed context.
        invite.from_endpoint_id = client_id_;
        invite.from_display_name = client_display_name_;
        invite.from_auth_pubkey_b64 = client_auth_pubkey_b64_;
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
        if (!is_federation_authenticated() ||
            !federation_hello_accepted_) {
            resp["ok"] = false;
            resp["error"] = "accepted federation hello required";
            send_json(resp);
            return;
        }
        if (json.contains(control::fields::source_trust_id)) {
            resp["ok"] = false;
            resp["error"] = "source_trust_id is server-owned";
            send_json(resp);
            return;
        }
        if (!json.contains("channel_kind") ||
            !json["channel_kind"].is_string() ||
            !control::try_relay_channel_kind(
                json["channel_kind"].get_ref<const std::string&>())) {
            resp["ok"] = false;
            resp["error"] = "invalid relay channel kind";
            send_json(resp);
            return;
        }
        auto parsed_invite = control::try_relay_invite_from_json(json);
        if (!parsed_invite) {
            resp["ok"] = false;
            resp["error"] = "invalid relay invite fields";
            send_json(resp);
            return;
        }
        control::PendingInvite invite = std::move(*parsed_invite);
        if (!json.contains("raw_to_id") ||
            !json["raw_to_id"].is_string() ||
            !control::is_valid_directory_endpoint_id(
                json["raw_to_id"].get_ref<const std::string&>(),
                control::DirectoryNamespace::FederationRaw)) {
            resp["ok"] = false;
            resp["error"] = "invalid federation relay target";
            send_json(resp);
            return;
        }
        const auto source_trust_id =
            control::try_make_federated_visible_endpoint_id(
                federation_peer_id_, invite.from_endpoint_id);
        if (!source_trust_id) {
            resp["ok"] = false;
            resp["error"] = "invalid federation relay source";
            send_json(resp);
            return;
        }
        // An authenticated federation peer forwards its already-corroborated
        // raw source endpoint and the source server's visible target id
        // verbatim. Do not rewrite either signed outer field.
        const std::string raw_target_id =
            json["raw_to_id"].get<std::string>();
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
            // The signed invite keeps the source server's visible/namespaced
            // target id. Corroborate which local endpoint this authenticated
            // federation session routed it to without rewriting the signed
            // transcript.
            notify["local_target_id"] = target->endpoint_id();
            // Only the authenticated destination server may add this field.
            // It names the source in the peer trust store without changing the
            // signed invite's raw from_id or any relay-v2 transcript bytes.
            notify[control::fields::source_trust_id] = *source_trust_id;
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
        if (json.contains(control::fields::source_trust_id)) {
            resp["ok"] = false;
            resp["error"] = "source_trust_id is server-owned";
            send_json(resp);
            return;
        }
        if (is_federation_authenticated() &&
            !federation_hello_accepted_) {
            resp["ok"] = false;
            resp["error"] = "accepted federation hello required";
            send_json(resp);
            return;
        }
        if (!json.contains("channel_kind") ||
            !json["channel_kind"].is_string() ||
            !control::try_relay_channel_kind(
                json["channel_kind"].get_ref<const std::string&>())) {
            resp["ok"] = false;
            resp["error"] = "invalid relay channel kind";
            send_json(resp);
            return;
        }
        auto parsed_reply = control::try_relay_invite_from_json(json);
        if (!parsed_reply) {
            resp["ok"] = false;
            resp["error"] = "invalid relay invite response fields";
            send_json(resp);
            return;
        }
        control::PendingInvite reply = std::move(*parsed_reply);
        if (reply.accepted) {
            if (client_auth_pubkey_b64_.empty()) {
                resp["ok"] = false;
                resp["error"] = "authenticated relay identity is required";
                send_json(resp);
                return;
            }
            if (!reply.responder_auth_pubkey_b64.empty() &&
                reply.responder_auth_pubkey_b64 !=
                    client_auth_pubkey_b64_) {
                resp["ok"] = false;
                resp["error"] =
                    "relay responder identity claim does not match authenticated session";
                send_json(resp);
                return;
            }
            // The response signature inside handshake_response_b64 must use
            // this same authenticated composite identity. The relay server
            // does not parse that record, but it does authoritatively bind the
            // outer corroboration field to the invited connection.
            reply.responder_auth_pubkey_b64 = client_auth_pubkey_b64_;
        }
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
        auto target_id = read_bounded_text(
            "id", control::kMaxDirectoryEndpointIdBytes);
        if (!target_id) {
            resp["ok"] = false;
            resp["error"] = "invalid endpoint id";
            send_json(resp);
            return;
        }
        control::EndpointInfo target_info;
        auto target = manager_
            ? manager_->find_endpoint_session(*target_id, &target_info)
            : nullptr;
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
        auto id = read_bounded_text(
            "id", control::kMaxDirectoryEndpointIdBytes);
        if (!id || id->empty()) {
            resp["ok"] = false;
            resp["error"] = id ? "missing id" : "invalid id";
            send_json(resp);
            return;
        }
        ControlledClientInfo info;
        std::shared_ptr<Session> target;
        if (manager_) {
            target = manager_->find_controlled_session(*id, &info);
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
        control_target_id_ = *id;
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

    auto target_reservation = target->reserve_stream_id();
    if (!target_reservation) {
        send_open_reply(frame.header.stream_id, false, "no stream ids available");
        return true;
    }
    const uint8_t target_stream = target_reservation.stream_id();
    if (!open_stream_id_available(frame.header.stream_id)) {
        send_open_reply(frame.header.stream_id, false,
                        "control stream id is already in use");
        return true;
    }

    bool source_inserted = false;
    bool target_inserted = false;
    try {
        {
            std::lock_guard<std::mutex> lock(control_mutex_);
            source_inserted = control_outbound_.try_emplace(
                frame.header.stream_id,
                ControlLink{target, target_stream, true, false}).second;
        }
        if (!source_inserted) {
            throw std::runtime_error("source control stream id is in use");
        }
        {
            std::lock_guard<std::mutex> lock(target->control_mutex_);
            target_inserted = target->control_inbound_.try_emplace(
                target_stream,
                ControlLink{shared_from_this(), frame.header.stream_id,
                            true, false}).second;
        }
        if (!target_inserted) {
            throw std::runtime_error("target control stream id is in use");
        }
        // The reservation remains alive through target map publication, so no
        // other cross-session OPEN can claim target_stream in between.
        target->send_control_frame(protocol::SOPEN, target_stream, payload);
    } catch (...) {
        if (source_inserted) {
            std::lock_guard<std::mutex> lock(control_mutex_);
            control_outbound_.erase(frame.header.stream_id);
        }
        if (target_inserted) {
            std::lock_guard<std::mutex> lock(target->control_mutex_);
            target->control_inbound_.erase(target_stream);
        }
        send_open_reply(frame.header.stream_id, false,
                        "control stream setup failed");
    }
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
        if (manager_ && !link.channel_id.empty()) {
            manager_->unregister_active_channel(link.channel_id);
        }
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
            if (manager_ && !link.channel_id.empty()) {
                manager_->unregister_active_channel(link.channel_id);
            }
            std::lock_guard<std::mutex> lock(control_mutex_);
            control_inbound_.erase(frame.header.stream_id);
            return true;
        }
    }
    const bool wire_ok = (frame.header.flags & protocol::kFlagOpenOk) != 0;
    const std::string reason(payload.begin(), payload.end());

    bool local_link_present = false;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = control_inbound_.find(frame.header.stream_id);
        if (it != control_inbound_.end() &&
            it->second.peer_stream_id == link.peer_stream_id &&
            it->second.channel_id == link.channel_id) {
            if (!wire_ok) {
                control_inbound_.erase(it);
            } else {
                it->second.pending = false;
                local_link_present = true;
            }
        }
    }
    bool peer_link_present = false;
    {
        std::lock_guard<std::mutex> lock(peer->control_mutex_);
        auto it = peer->control_outbound_.find(link.peer_stream_id);
        if (it != peer->control_outbound_.end() &&
            it->second.peer_stream_id == frame.header.stream_id &&
            it->second.channel_id == link.channel_id) {
            if (!wire_ok) {
                peer->control_outbound_.erase(it);
            } else {
                it->second.pending = false;
                peer_link_present = true;
            }
        }
    }

    if (manager_ && !link.channel_id.empty() && !wire_ok) {
        manager_->unregister_active_channel(link.channel_id);
    }
    bool established = wire_ok && local_link_present && peer_link_present;
    if (established && manager_ && !link.channel_id.empty()) {
        control::ActiveRelayChannel channel;
        channel.channel_id = link.channel_id;
        channel.channel_kind = link.channel_kind;
        channel.left_endpoint_id = link.left_endpoint_id;
        channel.right_endpoint_id = link.right_endpoint_id;
        channel.left_stream_id = link.peer_stream_id;
        channel.right_stream_id = frame.header.stream_id;
        channel.pending = false;
        manager_->register_active_channel(channel);

        // A close can race a successful ACK on another session strand. Check
        // both halves after publication so a removed link cannot be
        // resurrected as an active/admin relationship.
        {
            std::lock_guard<std::mutex> lock(control_mutex_);
            auto it = control_inbound_.find(frame.header.stream_id);
            local_link_present = it != control_inbound_.end() &&
                it->second.peer_stream_id == link.peer_stream_id &&
                it->second.channel_id == link.channel_id &&
                !it->second.pending;
        }
        {
            std::lock_guard<std::mutex> lock(peer->control_mutex_);
            auto it = peer->control_outbound_.find(link.peer_stream_id);
            peer_link_present = it != peer->control_outbound_.end() &&
                it->second.peer_stream_id == frame.header.stream_id &&
                it->second.channel_id == link.channel_id &&
                !it->second.pending;
        }
        established = local_link_present && peer_link_present;
        if (!established) {
            manager_->unregister_active_channel(link.channel_id);
        }
    }

    if (wire_ok && !established) {
        {
            std::lock_guard<std::mutex> lock(control_mutex_);
            auto it = control_inbound_.find(frame.header.stream_id);
            if (it != control_inbound_.end() &&
                it->second.peer_stream_id == link.peer_stream_id &&
                it->second.channel_id == link.channel_id) {
                control_inbound_.erase(it);
            }
        }
        {
            std::lock_guard<std::mutex> lock(peer->control_mutex_);
            auto it = peer->control_outbound_.find(link.peer_stream_id);
            if (it != peer->control_outbound_.end() &&
                it->second.peer_stream_id == frame.header.stream_id &&
                it->second.channel_id == link.channel_id) {
                peer->control_outbound_.erase(it);
            }
        }
        send_control_close(frame.header.stream_id,
                           "control channel closed during open");
    }

    peer->send_open_reply(
        link.peer_stream_id,
        established,
        wire_ok && !established
            ? "control channel closed during open" : reason);
    return true;
}

bool Session::handle_control_data(
    const protocol::Frame& frame,
    runtime::InboundCredit&& inbound_credit) {
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
        if (manager_ && !link.channel_id.empty()) {
            manager_->unregister_active_channel(link.channel_id);
        }
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
            if (manager_ && !link.channel_id.empty()) {
                manager_->unregister_active_channel(link.channel_id);
            }
            std::lock_guard<std::mutex> lock(control_mutex_);
            control_outbound_.erase(frame.header.stream_id);
            control_inbound_.erase(frame.header.stream_id);
            return true;
        }
    }

    if (!inbound_credit) {
        peer->send_control_frame(
            protocol::DATA, link.peer_stream_id, payload);
        return true;
    }
    auto retained_credit = std::make_shared<runtime::InboundCredit>(
        std::move(inbound_credit));
    peer->send_control_frame(
        protocol::DATA, link.peer_stream_id, payload, 0,
        [retained_credit = std::move(retained_credit)](
            const boost::system::error_code&, std::size_t) {
            retained_credit->release_now();
        });
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

    auto target_reservation = target->reserve_stream_id();
    if (!target_reservation) {
        send_control_close(frame.header.stream_id, "no stream ids available");
        return true;
    }
    const uint8_t target_stream = target_reservation.stream_id();
    if (!open_stream_id_available(frame.header.stream_id)) {
        send_control_close(frame.header.stream_id,
                           "control stream id is already in use");
        return true;
    }

    bool source_inserted = false;
    bool target_inserted = false;
    try {
        {
            std::lock_guard<std::mutex> lock(control_mutex_);
            source_inserted = control_outbound_.try_emplace(
                frame.header.stream_id,
                ControlLink{target, target_stream, false, true}).second;
        }
        if (!source_inserted) {
            throw std::runtime_error("source EXEC stream id is in use");
        }
        {
            std::lock_guard<std::mutex> lock(target->control_mutex_);
            target_inserted = target->control_inbound_.try_emplace(
                target_stream,
                ControlLink{shared_from_this(), frame.header.stream_id,
                            false, true}).second;
        }
        if (!target_inserted) {
            throw std::runtime_error("target EXEC stream id is in use");
        }
        target->send_control_frame(protocol::EXEC, target_stream, payload);
    } catch (...) {
        if (source_inserted) {
            std::lock_guard<std::mutex> lock(control_mutex_);
            control_outbound_.erase(frame.header.stream_id);
        }
        if (target_inserted) {
            std::lock_guard<std::mutex> lock(target->control_mutex_);
            target->control_inbound_.erase(target_stream);
        }
        send_control_close(frame.header.stream_id,
                           "control EXEC stream setup failed");
    }
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
