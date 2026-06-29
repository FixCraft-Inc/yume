/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/relay/runtime.hpp"

#include <chrono>
#include <mutex>
#include <string>
#include <utility>

#include "core/security/identity.hpp"
#include "util.hpp"

namespace yume::client {
namespace {

std::string now_request_id() {
    return yume::identity::derive_instance_key(std::to_string(yume::util::now_ms()) + ":" + yume::util::random_hex(8));
}

std::string relay_secret_from_args(const nlohmann::json& args) {
    std::string relay_secret_b64 = args.value("relay_secret", "");
    if (relay_secret_b64.empty()) {
        const std::string password = args.value("password", "");
        if (!password.empty()) {
            relay_secret_b64 = derive_relay_secret_b64(password);
        }
    }
    return relay_secret_b64;
}

}  // namespace

nlohmann::json RelayRuntime::status_json() const {
    std::lock_guard<std::mutex> lock(mutex_);
    nlohmann::json json;
    json["self"] = control::endpoint_to_json(self_, true);
    json["server_id"] = server_id_;
    json["server_name"] = server_name_;
    json["directory_size"] = directory_by_id_.size();
    json["pending_invites"] = incoming_invites_.size();
    json["active_channels"] = channels_.size();
    if (active_chat_stream_.has_value()) {
        json["active_chat_stream"] = *active_chat_stream_;
    }
    if (active_admin_stream_.has_value()) {
        json["active_admin_stream"] = *active_admin_stream_;
    }
    if (latest_lifecycle_.has_value()) {
        json["latest_lifecycle"] = control::lifecycle_event_to_json(*latest_lifecycle_);
    }
    if (tunnel_) {
        json["bytes_in"]  = tunnel_->bytes_received();
        json["bytes_out"] = tunnel_->bytes_sent();
    }
    return json;
}

nlohmann::json RelayRuntime::handle_local_request(const nlohmann::json& request) {
    const std::string op = request.value("op", "");
    const nlohmann::json args = request.value("args", nlohmann::json::object());
    if (op == "runtime.info" || op == "runtime.status") {
        return {{"ok", true}, {"result", status_json()}};
    }
    if (op == "directory.list") {
        std::vector<nlohmann::json> items;
        std::string error;
        for (const auto& endpoint : request_directory(&error)) {
            items.push_back(control::endpoint_to_json(endpoint, true));
        }
        if (!error.empty()) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", items}};
    }
    if (op == "history.list") {
        std::optional<std::string> peer_id;
        if (args.contains("peer_id")) {
            peer_id = args["peer_id"].get<std::string>();
        }
        nlohmann::json items = nlohmann::json::array();
        for (const auto& item : history_.list_chat(peer_id)) {
            items.push_back({{"ts_ms", item.ts_ms}, {"peer_id", item.peer_id}, {"peer_name", item.peer_name},
                             {"direction", item.direction}, {"text", item.text}});
        }
        return {{"ok", true}, {"result", items}};
    }
    if (op == "history.delete") {
        if (args.contains("peer_id")) {
            history_.delete_chat(args["peer_id"].get<std::string>());
        } else {
            history_.delete_chat();
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "invite.list") {
        nlohmann::json items = nlohmann::json::array();
        for (const auto& invite : pending_invites()) {
            items.push_back(control::invite_to_json(invite, true));
        }
        return {{"ok", true}, {"result", items}};
    }
    if (op == "invite.accept") {
        std::string error;
        if (!accept_invite(args.value("invite_id", ""), relay_secret_from_args(args), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "invite.reject") {
        std::string error;
        if (!reject_invite(args.value("invite_id", ""), args.value("reason", ""), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "chat.open") {
        std::string error;
        if (!open_chat(args.value("peer", ""), relay_secret_from_args(args), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "chat.send") {
        std::string error;
        if (!send_chat(args.value("text", ""), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "file.send") {
        std::string error;
        if (!send_file(args.value("peer", ""), args.value("path", ""), relay_secret_from_args(args), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "bytes.send") {
        std::string error;
        if (!send_bytes_path(args.value("peer", ""), args.value("path", ""), relay_secret_from_args(args), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "admin.attach") {
        std::string error;
        if (!admin_attach(args.value("peer", ""), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "admin.status" || op == "admin.sessions" || op == "admin.stop") {
        std::string error;
        const std::string remote_op =
            (op == "admin.stop") ? "runtime.stop" :
            ((op == "admin.sessions") ? "runtime.sessions" : "runtime.status");
        auto response = send_admin_request(remote_op, args, &error);
        if (!error.empty()) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", response}};
    }
    if (op == "runtime.stop") {
        if (stop_callback_) {
            stop_callback_();
        }
        return {{"ok", true}, {"result", true}};
    }
    return {{"ok", false}, {"error", "unsupported op"}};
}

void RelayRuntime::set_stop_callback(std::function<void()> callback) {
    stop_callback_ = std::move(callback);
}

bool RelayRuntime::notify_authenticated(const std::string& effective_protection, std::string* error) {
    return notify_lifecycle("authenticated",
                            "authenticated",
                            "authenticated control path is active",
                            effective_protection,
                            false,
                            "",
                            "",
                            error,
                            2000,
                            true);
}

bool RelayRuntime::notify_traffic_flow(const std::string& effective_protection, std::string* error) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (traffic_flow_announced_) {
            return true;
        }
    }
    const bool ok = notify_lifecycle("traffic_flowing",
                                     "success, traffic flowing",
                                     "first usable traffic observed",
                                     effective_protection,
                                     true,
                                     "",
                                     "",
                                     error,
                                     2000,
                                     true);
    if (ok) {
        std::lock_guard<std::mutex> lock(mutex_);
        traffic_flow_announced_ = true;
    }
    return ok;
}

bool RelayRuntime::notify_disconnecting(const std::string& message, std::string* error) {
    return notify_lifecycle("disconnecting",
                            message,
                            "client requested shutdown",
                            "",
                            false,
                            "",
                            "",
                            error,
                            1200,
                            true);
}

bool RelayRuntime::notify_error(const std::string& message, const std::string& error_code, std::string* error) {
    return notify_lifecycle("error",
                            "error, disconnect",
                            message,
                            "",
                            false,
                            "",
                            error_code,
                            error,
                            1200,
                            true);
}

void RelayRuntime::on_control_message(const nlohmann::json& json) {
    const std::string request_id = json.value("request_id", "");
    if (!request_id.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = control_responses_.find(request_id);
        if (it != control_responses_.end()) {
            it->second.ready = true;
            it->second.value = json;
            control_cv_.notify_all();
            return;
        }
    }
    const std::string cmd = json.value("cmd", "");
    if (cmd == "invite.request") {
        const std::string invite_id = json.value("invite_id", "");
        if (invite_id.empty()) {
            return;
        }
        control::PendingInvite invite = control::invite_from_json(json);
        if (!verify_invite_signature(invite, false)) {
            util::log_warn("relay invite signature verification failed for " + invite.invite_id);
            return;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        PendingIncomingInvite pending;
        pending.invite = invite;
        incoming_invites_[invite.invite_id] = std::move(pending);
        util::log_info("invite " + invite.invite_id + " from " +
                       (invite.from_display_name.empty() ? invite.from_endpoint_id : invite.from_display_name) +
                       " [" + control::to_string(invite.channel_kind) + "]");
        return;
    }
    if (cmd == "invite.reply") {
        const std::string invite_id = json.value("invite_id", "");
        if (invite_id.empty()) {
            return;
        }
        control::PendingInvite invite = control::invite_from_json(json);
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = outgoing_invites_.find(invite.invite_id);
        if (it == outgoing_invites_.end()) {
            return;
        }
        if (!invite.accepted) {
            util::log_warn("invite rejected: " + invite.response_reason);
            outgoing_invites_.erase(it);
            return;
        }
        std::string error;
        if (!open_channel_from_reply(it->second, invite, &error)) {
            util::log_warn("relay open failed: " + error);
            outgoing_invites_.erase(it);
        } else {
            outgoing_invites_.erase(it);
        }
        return;
    }
}

bool RelayRuntime::notify_lifecycle(const std::string& state,
                                    const std::string& message,
                                    const std::string& detail,
                                    const std::string& effective_protection,
                                    bool traffic_verified,
                                    const std::string& exit_ip,
                                    const std::string& error_code,
                                    std::string* error,
                                    int timeout_ms,
                                    bool quiet_unsupported) {
    control::ClientLifecycleEvent accepted;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (self_.endpoint_id.empty()) {
            if (error) {
                *error = "presence announce required";
            }
            return false;
        }
        accepted.endpoint_id = self_.endpoint_id;
        accepted.display_name = self_.display_name;
        accepted.client_platform = self_.client_platform;
        accepted.client_variant = self_.client_variant;
        accepted.client_version = self_.client_version;
    }

    nlohmann::json req;
    req["cmd"] = "client.lifecycle";
    req["state"] = state;
    req["message"] = message;
    req["detail"] = detail;
    req["client_platform"] = accepted.client_platform;
    req["client_variant"] = accepted.client_variant;
    req["client_version"] = accepted.client_version;
    req["effective_protection"] = effective_protection;
    req["traffic_verified"] = traffic_verified;
    req["exit_ip"] = exit_ip;
    req["error_code"] = error_code;

    std::string request_error;
    auto resp = send_control_request(std::move(req), &request_error, timeout_ms);
    if (!request_error.empty()) {
        if (!quiet_unsupported) {
            log_lifecycle_unsupported_once(request_error);
        }
        if (error) {
            *error = request_error;
        }
        return false;
    }
    if (!resp.value("ok", false)) {
        const std::string server_error = resp.value("error", "lifecycle update failed");
        if (server_error == "unknown control command") {
            if (!quiet_unsupported) {
                log_lifecycle_unsupported_once(server_error);
            }
        } else if (error) {
            *error = server_error;
        }
        return false;
    }

    accepted.state = resp.value("accepted_state", state);
    accepted.message = message;
    accepted.detail = detail;
    accepted.effective_protection = effective_protection;
    accepted.traffic_verified = traffic_verified;
    accepted.exit_ip = exit_ip;
    accepted.error_code = error_code;
    accepted.server_time_ms = resp.value("server_time_ms", 0LL);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        latest_lifecycle_ = accepted;
    }
    return true;
}

void RelayRuntime::log_lifecycle_unsupported_once(const std::string& reason) {
    bool should_log = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!lifecycle_unsupported_logged_) {
            lifecycle_unsupported_logged_ = true;
            should_log = true;
        }
    }
    if (should_log) {
        util::log_warn("relay lifecycle notifications unavailable: " + reason);
    }
}

void RelayRuntime::on_inbound_open(uint8_t stream_id, const nlohmann::json& json) {
    const std::string channel_id = json.value("channel_id", "");
    const std::string from_id = json.value("from_id", "");
    const auto kind = control::channel_kind_from_string(json.value("channel_kind", "chat"));
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = incoming_invites_.find(channel_id);
    if (it == incoming_invites_.end() || !it->second.invite.accepted || !it->second.ephemeral_key) {
        tunnel_->send_open_ack(stream_id, false, "invite not accepted");
        return;
    }
    const auto peer_it = directory_by_id_.find(from_id);
    if (peer_it == directory_by_id_.end()) {
        if (it->second.invite.from_auth_pubkey_b64.empty()) {
            tunnel_->send_open_ack(stream_id, false, "unknown peer");
            return;
        }
    }
    ChannelState channel;
    channel.channel_id = channel_id;
    channel.channel_kind = kind;
    channel.peer_id = from_id;
    channel.peer_name = peer_it == directory_by_id_.end()
        ? (it->second.invite.from_display_name.empty() ? from_id : it->second.invite.from_display_name)
        : peer_it->second.display_name;
    channel.stream_id = stream_id;
    auto keys = derive_channel_keys(false,
                                    it->second.ephemeral_key.get(),
                                    it->second.invite.ephemeral_pubkey_b64,
                                    it->second.relay_secret_b64,
                                    it->second.invite.nonce_b64);
    channel.send_key = std::move(keys.send_key);
    channel.recv_key = std::move(keys.recv_key);
    channel.send_nonce_prefix = std::move(keys.send_nonce_prefix);
    channel.recv_nonce_prefix = std::move(keys.recv_nonce_prefix);
    register_channel(stream_id, std::move(channel));
    if (kind == control::ChannelKind::chat) {
        active_chat_stream_ = stream_id;
    } else if (kind == control::ChannelKind::admin) {
        active_admin_stream_ = stream_id;
    }
    incoming_invites_.erase(it);
    tunnel_->send_open_ack(stream_id, true, "");
}

std::string RelayRuntime::next_request_id() {
    return now_request_id();
}

std::string RelayRuntime::next_invite_id() {
    return yume::identity::generate_endpoint_id();
}

nlohmann::json RelayRuntime::send_control_request(nlohmann::json request, std::string* error, int timeout_ms) {
    const std::string request_id = next_request_id();
    request["request_id"] = request_id;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        control_responses_[request_id] = PendingControlResponse{};
    }
    tunnel_->send_control_json(request);
    std::unique_lock<std::mutex> lock(mutex_);
    auto ok = control_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&]() {
        auto it = control_responses_.find(request_id);
        return it != control_responses_.end() && it->second.ready;
    });
    if (!ok) {
        control_responses_.erase(request_id);
        if (error) {
            *error = "control request timed out";
        }
        return nlohmann::json::object();
    }
    auto value = control_responses_[request_id].value;
    control_responses_.erase(request_id);
    return value;
}

nlohmann::json RelayRuntime::send_admin_request(const std::string& op,
                                                const nlohmann::json& args,
                                                std::string* error,
                                                int timeout_ms) {
    const std::string request_id = next_request_id();
    uint8_t stream_id = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_admin_stream_.has_value()) {
            if (error) {
                *error = "no active admin channel";
            }
            return nlohmann::json::object();
        }
        stream_id = *active_admin_stream_;
        auto it = channels_.find(stream_id);
        if (it == channels_.end()) {
            if (error) {
                *error = "admin channel is unavailable";
            }
            return nlohmann::json::object();
        }
        admin_responses_[request_id] = PendingAdminResponse{};
        nlohmann::json request{
            {"type", "admin_req"},
            {"request_id", request_id},
            {"op", op},
            {"args", args},
        };
        auto blob = encrypt_channel_payload(it->second, request.dump());
        tunnel_->send_data(stream_id, blob);
    }

    std::unique_lock<std::mutex> lock(mutex_);
    const bool ok = admin_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&]() {
        auto it = admin_responses_.find(request_id);
        return it != admin_responses_.end() && it->second.ready;
    });
    if (!ok) {
        admin_responses_.erase(request_id);
        if (error) {
            *error = "admin request timed out";
        }
        return nlohmann::json::object();
    }
    auto response = admin_responses_[request_id].value;
    admin_responses_.erase(request_id);
    return response;
}

}  // namespace yume::client
