/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/relay/runtime.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include "core/security/identity.hpp"
#include "core/protocol/control_command_policy.hpp"
#include "core/protocol/directory_policy.hpp"
#include "client/transport/tunnel_pool.hpp"
#include "util.hpp"

namespace yume::client {
namespace {

std::string now_request_id() {
    return yume::identity::derive_instance_key(std::to_string(yume::util::now_ms()) + ":" + yume::util::random_hex(8));
}

bool has_exact_relay_protocol_version(const nlohmann::json& json) {
    if (!json.contains("relay_protocol_version")) {
        return false;
    }
    const auto& version = json["relay_protocol_version"];
    if (version.is_number_unsigned()) {
        return version.get<std::uint64_t>() ==
            control::kRelayProtocolVersion;
    }
    if (version.is_number_integer()) {
        return version.get<std::int64_t>() ==
            control::kRelayProtocolVersion;
    }
    return false;
}

bool has_only_argument_keys(
        const nlohmann::json& args,
        std::initializer_list<std::string_view> allowed) {
    for (auto it = args.begin(); it != args.end(); ++it) {
        const std::string_view key = it.key();
        if (std::find(allowed.begin(), allowed.end(), key) ==
            allowed.end()) {
            return false;
        }
    }
    return true;
}

const std::string* string_argument(const nlohmann::json& args,
                                   std::string_view key,
                                   bool require_nonempty = true) {
    const auto found = args.find(std::string(key));
    if (found == args.end() || !found->is_string()) {
        return nullptr;
    }
    const auto& value = found->get_ref<const std::string&>();
    if (require_nonempty && value.empty()) {
        return nullptr;
    }
    return &value;
}

relay_v2::Bytes decode_handshake_request(const std::string& encoded) {
    const std::string raw = yume::util::base64_decode(encoded);
    return relay_v2::Bytes(raw.begin(), raw.end());
}

class RelaySecretArgument {
public:
    explicit RelaySecretArgument(const nlohmann::json& args) {
        const auto relay_secret = args.find("relay_secret");
        const auto password = args.find("password");
        if (relay_secret != args.end() && !relay_secret->is_string()) {
            throw std::invalid_argument("relay_secret must be a string");
        }
        if (password != args.end() && !password->is_string()) {
            throw std::invalid_argument("password must be a string");
        }
        if (relay_secret != args.end() && password != args.end()) {
            throw std::invalid_argument(
                "relay_secret and password are mutually exclusive");
        }

        if (password != args.end() &&
            !password->get_ref<const std::string&>().empty()) {
            std::string derived = derive_relay_secret_b64(
                password->get_ref<const std::string&>());
            RelaySecretWiper derived_wiper(derived);
            value_.swap(derived);
            return;
        }

        std::string selected;
        RelaySecretWiper selected_wiper(selected);
        if (relay_secret != args.end()) {
            selected.assign(relay_secret->get_ref<const std::string&>());
        }
        value_.swap(selected);
    }
    ~RelaySecretArgument() { wipe_relay_secret(value_); }
    RelaySecretArgument(const RelaySecretArgument&) = delete;
    RelaySecretArgument& operator=(const RelaySecretArgument&) = delete;

    const std::string& value() const noexcept { return value_; }

private:
    std::string value_;
};

// One contact: durable local trust policy, overlaid with directory presence
// when the peer is currently advertised. A fingerprint is a public digest, so
// nothing here is secret material; the composite identity bytes behind it are
// deliberately never held by the trust store or echoed to a caller.
nlohmann::json contact_to_json(const relay_v2::PeerTrustEntry& entry,
                               const control::EndpointInfo* presence) {
    nlohmann::json item{
        {"endpoint_id", entry.endpoint_id},
        {"fingerprint", entry.fingerprint},
        {"trust_source", std::string(relay_v2::to_string(entry.source))},
        {"explicit_marker", entry.explicit_marker},
        {"configured_mismatch", entry.configured_mismatch},
        {"in_directory", presence != nullptr},
    };
    if (presence == nullptr) {
        return item;
    }
    item["online"] = presence->online;
    item["display_name"] = presence->display_name;
    item["endpoint_kind"] = control::to_string(presence->endpoint_kind);
    item["relay_mode"] = control::to_string(presence->relay_mode);
    item["allow_chat"] = presence->allow_chat;
    item["allow_file"] = presence->allow_file;
    item["allow_bytes"] = presence->allow_bytes;
    item["remote"] = presence->remote;
    item["federation_peer_id"] = presence->federation_peer_id;
    return item;
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
        auto active = channels_.find(*active_chat_stream_);
        if (active != channels_.end() &&
            active->second.channel_kind == control::ChannelKind::chat) {
            json["active_chat"] = {
                {"channel_id", active->second.channel_id},
                {"peer_id", active->second.peer_id},
                {"peer_name", active->second.peer_name},
            };
        }
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
    json["requested_tunnels"] = requested_tunnels_;
    if (const auto pool = tunnel_pool_.lock()) {
        const auto snapshot = pool->snapshot();
        // A tunnel enters the pool only after TLS and visitor authentication
        // complete. Keep both counts: membership proves authentication, while
        // live_tunnels detects a connection that died after joining.
        json["authenticated_tunnels"] = snapshot.tunnel_count;
        json["live_tunnels"] = snapshot.live_tunnel_count;
        json["tunnel_sessions"] = snapshot.total_sessions;
    } else {
        json["authenticated_tunnels"] = 0;
        json["live_tunnels"] = 0;
        json["tunnel_sessions"] = 0;
    }
    return json;
}

void RelayRuntime::set_tunnel_pool(std::weak_ptr<TunnelPool> tunnel_pool,
                                   std::size_t requested_tunnels) {
    std::lock_guard<std::mutex> lock(mutex_);
    tunnel_pool_ = std::move(tunnel_pool);
    requested_tunnels_ = std::max<std::size_t>(1, requested_tunnels);
}

nlohmann::json RelayRuntime::handle_local_request(
    const nlohmann::json& request) try {
    if (!request.is_object()) {
        return {{"ok", false}, {"error", "request must be a JSON object"}};
    }
    const auto op_it = request.find("op");
    if (op_it == request.end() || !op_it->is_string() ||
        op_it->get_ref<const std::string&>().empty()) {
        return {{"ok", false},
                {"error", "request op must be a non-empty string"}};
    }
    const std::string op = op_it->get<std::string>();
    const nlohmann::json empty_args = nlohmann::json::object();
    const auto args_it = request.find("args");
    if (args_it != request.end()) {
        if (!args_it->is_object()) {
            return {{"ok", false},
                    {"error", "request args must be a JSON object"}};
        }
    }
    // Keep a reference rather than copying the object: relay_secret/password
    // fields are sensitive and must not acquire another ordinary allocation.
    const nlohmann::json& args =
        args_it == request.end() ? empty_args : *args_it;
    if (op == "runtime.info" || op == "runtime.status") {
        if (!args.empty()) {
            return {{"ok", false},
                    {"error", op + " does not accept arguments"}};
        }
        return {{"ok", true}, {"result", status_json()}};
    }
    if (op == "directory.list") {
        if (!args.empty()) {
            return {{"ok", false},
                    {"error", "directory.list does not accept arguments"}};
        }
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
    if (op == "contacts.list") {
        if (!args.empty()) {
            return {{"ok", false},
                    {"error", "contacts.list does not accept arguments"}};
        }
        // Trust is durable local state; directory presence is a live overlay.
        // A contact list must still render every trusted peer when the server
        // is unreachable, so a failed directory refresh degrades to
        // presence-unknown rather than to an error.
        std::string directory_error;
        std::unordered_map<std::string, control::EndpointInfo> presence;
        for (auto& endpoint : request_directory(&directory_error)) {
            presence.emplace(endpoint.endpoint_id, std::move(endpoint));
        }

        nlohmann::json contacts = nlohmann::json::array();
        try {
            for (const auto& entry : peer_trust_store().list()) {
                const auto found = presence.find(entry.endpoint_id);
                contacts.push_back(contact_to_json(
                    entry,
                    found == presence.end() ? nullptr : &found->second));
            }
        } catch (const std::exception& ex) {
            return {{"ok", false}, {"error", ex.what()}};
        }
        return {{"ok", true},
                {"result", {
                    {"schema_version", 1},
                    {"contacts", std::move(contacts)},
                    {"directory_available", directory_error.empty()},
                    {"directory_error", directory_error},
                }}};
    }
    if (op == "contacts.forget") {
        const auto endpoint_id =
            string_argument(args, "endpoint_id");
        if (args.size() != 1U || endpoint_id == nullptr) {
            return {{"ok", false},
                    {"error", "contacts.forget requires exactly one "
                              "non-empty endpoint_id string"}};
        }
        try {
            const bool removed =
                peer_trust_store().forget(*endpoint_id);
            return {{"ok", true}, {"result", {{"removed", removed}}}};
        } catch (const std::exception& ex) {
            return {{"ok", false}, {"error", ex.what()}};
        }
    }
    if (op == "history.list") {
        constexpr std::uint64_t kDefaultHistoryLimit = 200U;
        constexpr std::uint64_t kMaxHistoryLimit = 1000U;
        bool unknown_argument = args.size() > 2U;
        for (auto it = args.begin();
             !unknown_argument && it != args.end(); ++it) {
            unknown_argument =
                it.key() != "peer_id" && it.key() != "limit";
        }
        if (unknown_argument) {
            return {{"ok", false},
                    {"error", "history.list accepts only peer_id and limit"}};
        }
        std::optional<std::string> peer_id;
        if (args.contains("peer_id")) {
            if (!args["peer_id"].is_string() ||
                args["peer_id"].get_ref<const std::string&>().empty()) {
                return {{"ok", false},
                        {"error", "history.list peer_id must be a non-empty string"}};
            }
            peer_id = args["peer_id"].get<std::string>();
        }
        std::uint64_t limit = kDefaultHistoryLimit;
        if (const auto found = args.find("limit"); found != args.end()) {
            if (found->is_number_unsigned()) {
                limit = found->get<std::uint64_t>();
            } else if (found->is_number_integer()) {
                const auto signed_limit = found->get<std::int64_t>();
                if (signed_limit <= 0) {
                    return {{"ok", false},
                            {"error", "history.list limit must be in 1..1000"}};
                }
                limit = static_cast<std::uint64_t>(signed_limit);
            } else {
                return {{"ok", false},
                        {"error", "history.list limit must be an integer"}};
            }
            if (limit == 0U || limit > kMaxHistoryLimit) {
                return {{"ok", false},
                        {"error", "history.list limit must be in 1..1000"}};
            }
        }
        const auto listed = history_.list_chat(
            peer_id, static_cast<std::size_t>(limit));
        nlohmann::json items = nlohmann::json::array();
        for (const auto& item : listed.items) {
            items.push_back({{"ts_ms", item.ts_ms}, {"peer_id", item.peer_id}, {"peer_name", item.peer_name},
                             {"direction", item.direction}, {"text", item.text}});
        }
        return {{"ok", true},
                {"result", {
                    {"schema_version", 1},
                    {"available", listed.available},
                    {"error", listed.error},
                    {"truncated", listed.truncated},
                    {"items", std::move(items)},
                }}};
    }
    if (op == "history.delete") {
        const bool has_peer = args.contains("peer_id");
        const bool has_all = args.contains("all");
        if (args.size() != 1U || has_peer == has_all) {
            return {{"ok", false},
                    {"error", "history.delete requires exactly one of a "
                              "non-empty peer_id or all=true"}};
        }
        std::optional<std::string> peer_id;
        if (has_peer) {
            if (!args["peer_id"].is_string() ||
                args["peer_id"].get_ref<const std::string&>().empty()) {
                return {{"ok", false},
                        {"error", "history.delete peer_id must be a "
                                  "non-empty string"}};
            }
            peer_id = args["peer_id"].get<std::string>();
        } else if (!args["all"].is_boolean() ||
                   !args["all"].get<bool>()) {
            return {{"ok", false},
                    {"error", "history.delete all must be true"}};
        }
        std::string error;
        if (!history_.delete_chat(peer_id, &error)) {
            return {{"ok", false},
                    {"error", error.empty()
                                  ? "history deletion failed" : error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "invite.list") {
        if (!args.empty()) {
            return {{"ok", false},
                    {"error", "invite.list does not accept arguments"}};
        }
        nlohmann::json items = nlohmann::json::array();
        for (const auto& invite : pending_invites()) {
            items.push_back(control::invite_to_json(invite, true));
        }
        return {{"ok", true}, {"result", items}};
    }
    if (op == "invite.accept") {
        const auto selector =
            string_argument(args, "invite_selector");
        if (selector == nullptr ||
            !has_only_argument_keys(
                args, {"invite_selector", "relay_secret", "password"})) {
            return {{"ok", false},
                    {"error", "invite.accept requires invite_selector and "
                              "accepts only one optional relay secret input"}};
        }
        std::string error;
        RelaySecretArgument relay_secret(args);
        if (!accept_invite(*selector,
                           relay_secret.value(), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "invite.reject") {
        const auto selector =
            string_argument(args, "invite_selector");
        const auto reason_it = args.find("reason");
        if (selector == nullptr ||
            !has_only_argument_keys(args, {"invite_selector", "reason"}) ||
            (reason_it != args.end() && !reason_it->is_string())) {
            return {{"ok", false},
                    {"error", "invite.reject requires invite_selector and "
                              "an optional reason string"}};
        }
        std::string error;
        if (!reject_invite(*selector,
                           args.value("reason", ""), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "chat.open") {
        const auto peer = string_argument(args, "peer");
        if (peer == nullptr ||
            !has_only_argument_keys(
                args, {"peer", "relay_secret", "password"})) {
            return {{"ok", false},
                    {"error", "chat.open requires peer and accepts only one "
                              "optional relay secret input"}};
        }
        std::string error;
        std::string channel_id;
        std::string peer_id;
        RelaySecretArgument relay_secret(args);
        if (!open_chat(*peer, relay_secret.value(), &error,
                       &channel_id, &peer_id)) {
            return {{"ok", false}, {"error", error}};
        }
        return {
            {"ok", true},
            {"result", {
                {"channel_id", channel_id},
                {"peer_id", peer_id},
            }},
        };
    }
    if (op == "chat.send") {
        const auto channel_id = args.find("channel_id");
        const auto text = args.find("text");
        if (args.size() != 2U || channel_id == args.end() ||
            !channel_id->is_string() ||
            channel_id->get_ref<const std::string&>().empty() ||
            text == args.end() || !text->is_string()) {
            return {{"ok", false},
                    {"error", "chat.send requires exactly non-empty "
                              "channel_id and string text"}};
        }
        std::string error;
        if (!send_chat(channel_id->get_ref<const std::string&>(),
                       text->get_ref<const std::string&>(), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "chat.close") {
        const auto channel_id =
            string_argument(args, "channel_id");
        if (args.size() != 1U || channel_id == nullptr) {
            return {{"ok", false},
                    {"error", "chat.close requires exactly one non-empty "
                              "channel_id string"}};
        }
        std::string error;
        if (!close_chat(*channel_id, &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "file.send") {
        const auto peer = string_argument(args, "peer");
        const auto path = string_argument(args, "path");
        if (peer == nullptr || path == nullptr ||
            !has_only_argument_keys(
                args, {"peer", "path", "relay_secret", "password"})) {
            return {{"ok", false},
                    {"error", "file.send requires peer and path and accepts "
                              "only one optional relay secret input"}};
        }
        std::string error;
        RelaySecretArgument relay_secret(args);
        if (!send_file(*peer, *path,
                       relay_secret.value(), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "bytes.send") {
        const auto peer = string_argument(args, "peer");
        const auto path = string_argument(args, "path");
        if (peer == nullptr || path == nullptr ||
            !has_only_argument_keys(
                args, {"peer", "path", "relay_secret", "password"})) {
            return {{"ok", false},
                    {"error", "bytes.send requires peer and path and accepts "
                              "only one optional relay secret input"}};
        }
        std::string error;
        RelaySecretArgument relay_secret(args);
        if (!send_bytes_path(*peer, *path,
                             relay_secret.value(), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "admin.attach") {
        const auto peer = args.find("peer");
        if (args.size() != 1U || peer == args.end() ||
            !peer->is_string() ||
            peer->get_ref<const std::string&>().empty()) {
            return {{"ok", false},
                    {"error", "admin.attach requires exactly one non-empty "
                              "peer string"}};
        }
        std::string error;
        if (!admin_attach(peer->get_ref<const std::string&>(), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "admin.status" || op == "admin.sessions" || op == "admin.stop") {
        if (!args.empty()) {
            return {{"ok", false},
                    {"error", op + " does not accept arguments"}};
        }
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
        if (!args.empty()) {
            return {{"ok", false},
                    {"error", "runtime.stop does not accept arguments"}};
        }
        std::string error;
        if (!invoke_stop_callback(&error)) {
            return {{"ok", false},
                    {"error", error.empty()
                                  ? "relay runtime stop callback failed"
                                  : error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    return {{"ok", false}, {"error", "unsupported op"}};
} catch (const nlohmann::json::exception& ex) {
    return {{"ok", false},
            {"error", "invalid operation arguments: " +
                          std::string(ex.what())}};
} catch (const std::invalid_argument& ex) {
    return {{"ok", false},
            {"error", "invalid operation arguments: " +
                          std::string(ex.what())}};
} catch (const std::exception& ex) {
    return {{"ok", false},
            {"error", "operation failed: " + std::string(ex.what())}};
} catch (...) {
    return {{"ok", false}, {"error", "operation failed"}};
}

void RelayRuntime::set_stop_callback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    stop_callback_ = std::move(callback);
}

std::optional<std::string>
RelayRuntime::source_trust_id_from_notification(
        const nlohmann::json& notification,
        const control::PendingInvite& invite,
        std::string* error) {
    if (error) error->clear();
    const bool has_local_target = notification.contains("local_target_id");
    const bool has_source_trust = notification.contains("source_trust_id");
    auto reject = [error](const char* reason)
            -> std::optional<std::string> {
        if (error) *error = reason;
        return std::nullopt;
    };

    if (has_local_target != has_source_trust) {
        return reject(
            "federated relay invite routing claims are incomplete");
    }
    if (!has_local_target) {
        if (!control::is_valid_directory_endpoint_id(
                invite.from_endpoint_id,
                control::DirectoryNamespace::FederationRaw) ||
            !control::is_valid_directory_endpoint_id(
                invite.to_endpoint_id,
                control::DirectoryNamespace::FederationRaw)) {
            return reject(
                "direct relay invite uses an ambiguous endpoint namespace");
        }
        return invite.from_endpoint_id;
    }

    if (!notification["local_target_id"].is_string() ||
        !notification["source_trust_id"].is_string()) {
        return reject("federated relay invite routing claims are invalid");
    }
    const auto& local_target =
        notification["local_target_id"].get_ref<const std::string&>();
    const auto& source_trust =
        notification["source_trust_id"].get_ref<const std::string&>();
    if (!control::is_valid_directory_endpoint_id(
            invite.from_endpoint_id,
            control::DirectoryNamespace::FederationRaw) ||
        !control::is_valid_directory_endpoint_id(
            local_target,
            control::DirectoryNamespace::FederationRaw) ||
        !control::is_valid_directory_endpoint_id(
            source_trust,
            control::DirectoryNamespace::ClientVisible) ||
        !control::is_valid_directory_endpoint_id(
            invite.to_endpoint_id,
            control::DirectoryNamespace::ClientVisible)) {
        return reject(
            "federated relay invite endpoint namespace is invalid");
    }

    const auto source_separator = source_trust.find(':');
    const auto target_separator = invite.to_endpoint_id.find(':');
    if (source_separator == std::string::npos ||
        target_separator == std::string::npos ||
        source_trust.substr(source_separator + 1U) !=
            invite.from_endpoint_id ||
        invite.to_endpoint_id.substr(target_separator + 1U) !=
            local_target) {
        return reject(
            "federated relay invite namespace does not match its signed ids");
    }
    return source_trust;
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
    const std::string request_id =
        json.contains("request_id") && json["request_id"].is_string()
        ? json["request_id"].get<std::string>() : std::string{};
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
    const std::string cmd =
        json.contains("cmd") && json["cmd"].is_string()
        ? json["cmd"].get<std::string>() : std::string{};
    if (cmd == "invite.request") {
        if (!json.contains("invite_id") ||
            !json["invite_id"].is_string() ||
            json["invite_id"].get_ref<const std::string&>().empty()) {
            return;
        }
        auto parsed_invite = control::try_relay_invite_from_json(json);
        if (!parsed_invite) {
            util::log_warn("relay invite has invalid fields");
            return;
        }
        control::PendingInvite invite = std::move(*parsed_invite);
        std::string source_trust_error;
        auto source_trust_id = source_trust_id_from_notification(
            json, invite, &source_trust_error);
        if (!source_trust_id) {
            util::log_warn(
                source_trust_error.empty()
                    ? "relay invite has ambiguous source trust claims"
                    : source_trust_error);
            return;
        }
        std::string local_target_id = invite.to_endpoint_id;
        if (json.contains("local_target_id")) {
            local_target_id = json["local_target_id"].get<std::string>();
        }
        control::EndpointInfo local_endpoint;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            local_endpoint = self_;
        }
        if (!control::relay_v2_invite_request_valid(invite) ||
            invite.from_endpoint_id.empty() ||
            local_target_id != local_endpoint.endpoint_id ||
            !control::relay_target_allows(
                local_endpoint, invite.channel_kind) ||
            (invite.channel_kind == control::ChannelKind::admin &&
             options_.relay_mode != control::RelayMode::trusted)) {
            util::log_warn("relay invite rejected by local channel policy");
            return;
        }
        if (invite.channel_kind == control::ChannelKind::file ||
            invite.channel_kind == control::ChannelKind::bytes) {
            try {
                const auto metadata = nlohmann::json::parse(invite.metadata_json);
                if (!metadata.is_object() || !metadata.contains("name") ||
                    !metadata["name"].is_string() ||
                    !metadata.contains("size") ||
                    !metadata["size"].is_number_unsigned() ||
                    !metadata.contains("sha256") ||
                    !metadata["sha256"].is_string() ||
                    !RelayFileReceiver::IsSafeBasename(
                        metadata["name"].get_ref<const std::string&>()) ||
                    !RelayFileReceiver::IsCanonicalSha256Digest(
                        metadata["sha256"].get_ref<const std::string&>()) ||
                    metadata["size"].get<std::uint64_t>() >
                        options_.receive_limits.max_transfer_bytes) {
                    throw std::runtime_error("invalid metadata");
                }
            } catch (const std::exception&) {
                util::log_warn("relay transfer invite has invalid metadata");
                return;
            }
        }
        try {
            const relay_v2::Bytes initiator_identity =
                decode_relay_identity(invite.from_auth_pubkey_b64);
            // An unsolicited invite may establish that the claimed identity
            // is locally admissible, but only accept_invite() may persist a
            // TOFU decision after the signed transcript verifies.
            (void)peer_trust_store().precheck(
                *source_trust_id, initiator_identity,
                trust_requirement(invite.channel_kind));

            const relay_v2::Bytes request =
                decode_handshake_request(invite.handshake_request_b64);
            const auto inspected =
                relay_v2::InspectInitiatorRequest(request);
            const auto expected =
                make_handshake_context(invite, inspected.nonce);
            if (inspected != expected) {
                throw std::runtime_error(
                    "relay-v2 request context does not match the invite");
            }
        } catch (const std::exception& ex) {
            util::log_warn(
                std::string("relay-v2 invite precheck failed: ") +
                ex.what());
            return;
        }
        PendingIncomingInvite pending;
        pending.invite = invite;
        pending.source_trust_id = std::move(*source_trust_id);
        bool duplicate = false;
        bool saturated = false;
        bool inserted = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            expire_pending_invites_locked(std::chrono::steady_clock::now());
            duplicate = incoming_invites_.find(invite.invite_id) !=
                incoming_invites_.end();
            saturated = incoming_invites_.size() >=
                control::kMaxPendingRelayInvitesPerEndpoint;
            inserted = admit_incoming_invite_locked(std::move(pending));
            if (!inserted) {
                schedule_pending_invite_expiry_locked();
            }
        }
        if (!inserted) {
            if (saturated && !duplicate) {
                invite.response_present = true;
                invite.accepted = false;
                invite.response_reason = "target relay invite queue is full";
                invite.handshake_response_b64.clear();
                invite.responder_auth_pubkey_b64.clear();
                nlohmann::json reply = control::invite_to_json(invite, true);
                reply["cmd"] = "invite.reply";
                try {
                    tunnel_->send_control_json(reply);
                } catch (const std::exception& ex) {
                    util::log_warn(
                        std::string("failed to send saturated relay invite ") +
                        "reply: " + ex.what());
                }
                util::log_warn("relay invite queue is full; invite rejected");
            } else {
                util::log_warn("duplicate relay invite id rejected");
            }
            return;
        }
        util::log_info("invite " + invite.invite_id + " from " +
                       (invite.from_display_name.empty() ? invite.from_endpoint_id : invite.from_display_name) +
                       " [" + control::to_string(invite.channel_kind) + "]");
        return;
    }
    if (cmd == "invite.reply") {
        const std::string invite_id =
            json.contains("invite_id") && json["invite_id"].is_string()
            ? json["invite_id"].get<std::string>() : std::string{};
        // A target receives an acknowledgement for the one-way reply it sent.
        // That acknowledgement is not an initiator-facing signed invite reply
        // and intentionally contains no invite transcript fields.
        if (invite_id.empty() && json.contains("ok") &&
            json["ok"].is_boolean()) {
            if (!json["ok"].get<bool>()) {
                const std::string reason =
                    json.contains("error") && json["error"].is_string()
                    ? json["error"].get<std::string>()
                    : "server rejected reply";
                util::log_warn("relay invite reply failed: " + reason);
            }
            return;
        }
        if (invite_id.empty()) {
            util::log_warn("relay invite reply is missing its invite id");
            return;
        }
        auto parsed_invite = control::try_relay_invite_from_json(json);
        if (!parsed_invite || !parsed_invite->response_present ||
            !control::relay_v2_invite_response_valid(*parsed_invite)) {
            util::log_warn("relay invite reply has invalid fields");
            return;
        }
        control::PendingInvite invite = std::move(*parsed_invite);
        std::optional<PendingOutgoingInvite> outgoing;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            expire_pending_invites_locked(std::chrono::steady_clock::now());
            auto it = outgoing_invites_.find(invite.invite_id);
            if (it == outgoing_invites_.end()) {
                schedule_pending_invite_expiry_locked();
                return;
            }
            if (!control::relay_v2_request_fields_match(
                    it->second.invite, invite)) {
                schedule_pending_invite_expiry_locked();
                util::log_warn(
                    "relay invite reply does not match its request");
                return;
            }
            if (!invite.accepted) {
                util::log_warn("invite rejected: " + invite.response_reason);
                outgoing_invites_.erase(it);
                schedule_pending_invite_expiry_locked();
                return;
            }
            // Signature verification consults the directory under mutex_, and
            // OPEN completion can also re-enter RelayRuntime. Move ownership
            // out before either operation so an accepted reply cannot
            // self-deadlock the client runtime.
            outgoing.emplace(std::move(it->second));
            outgoing_invites_.erase(it);
            schedule_pending_invite_expiry_locked();
        }
        std::string error;
        try {
            if (!open_channel_from_reply(
                    std::move(*outgoing), invite, &error)) {
                util::log_warn("relay open failed: " + error);
            }
        } catch (const std::exception& ex) {
            util::log_warn(
                std::string("relay open failed: ") + ex.what());
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

    accepted.state = state;
    accepted.message = message;
    accepted.detail = detail;
    accepted.effective_protection = effective_protection;
    accepted.traffic_verified = traffic_verified;
    accepted.exit_ip = exit_ip;
    accepted.error_code = error_code;

    std::string serialization_error;
    auto request = control::try_lifecycle_command_to_json(
        accepted, &serialization_error);
    if (!request) {
        if (error) {
            *error = serialization_error.empty()
                ? "invalid lifecycle event"
                : serialization_error;
        }
        return false;
    }

    std::string request_error;
    auto resp = send_control_request(
        std::move(*request), &request_error, timeout_ms);
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

bool RelayRuntime::on_inbound_open(uint8_t stream_id,
                                   const nlohmann::json& json,
                                   std::string* error) {
    const auto fail = [error](const std::string& reason) {
        if (error) {
            *error = reason;
        }
        return false;
    };
    if (!json.contains("channel_id") || !json["channel_id"].is_string() ||
        !json.contains("channel_kind") || !json["channel_kind"].is_string() ||
        !json.contains("from_id") || !json["from_id"].is_string() ||
        !json.contains("to_id") || !json["to_id"].is_string() ||
        !json.contains("target_id") || !json["target_id"].is_string() ||
        !has_exact_relay_protocol_version(json) ||
        !json.contains("e2ee_required") ||
        !json["e2ee_required"].is_boolean() ||
        !json["e2ee_required"].get<bool>()) {
        return fail("invalid relay OPEN claims");
    }
    const std::string channel_id = json["channel_id"].get<std::string>();
    const std::string from_id = json["from_id"].get<std::string>();
    const std::string to_id = json["to_id"].get<std::string>();
    const std::string target_id = json["target_id"].get<std::string>();
    const auto parsed_kind = control::try_relay_channel_kind(
        json["channel_kind"].get_ref<const std::string&>());
    if (!parsed_kind) {
        return fail("invalid relay channel kind");
    }
    const auto kind = *parsed_kind;
    std::lock_guard<std::mutex> lock(mutex_);
    expire_pending_invites_locked(std::chrono::steady_clock::now());
    schedule_pending_invite_expiry_locked();
    auto it = incoming_invites_.find(channel_id);
    if (it == incoming_invites_.end() ||
        !it->second.invite.response_present ||
        !it->second.invite.accepted || !it->second.ratchet) {
        return fail("invite not accepted");
    }
    const auto& accepted = it->second.invite;
    if (channel_id.empty() || from_id != accepted.from_endpoint_id ||
        to_id != accepted.to_endpoint_id || target_id != accepted.to_endpoint_id ||
        kind != accepted.channel_kind ||
        accepted.relay_protocol_version !=
            control::kRelayProtocolVersion ||
        !control::relay_v2_invite_response_valid(accepted) ||
        !control::relay_target_allows(self_, accepted.channel_kind) ||
        (kind == control::ChannelKind::admin &&
         options_.relay_mode != control::RelayMode::trusted)) {
        incoming_invites_.erase(it);
        schedule_pending_invite_expiry_locked();
        return fail("relay OPEN does not match accepted invite");
    }
    const std::string& source_trust_id = it->second.source_trust_id;
    const auto peer_it = directory_by_id_.find(source_trust_id);
    ChannelState channel;
    channel.channel_id = channel_id;
    channel.channel_kind = kind;
    channel.role = control::RelayChannelRole::responder;
    channel.peer_id = source_trust_id;
    channel.peer_name = peer_it == directory_by_id_.end()
        ? (it->second.invite.from_display_name.empty() ? from_id : it->second.invite.from_display_name)
        : peer_it->second.display_name;
    channel.stream_id = stream_id;
    if (kind == control::ChannelKind::file ||
        kind == control::ChannelKind::bytes) {
        try {
            const auto metadata = nlohmann::json::parse(accepted.metadata_json);
            channel.expected_receive_name =
                metadata.at("name").get<std::string>();
            channel.expected_receive_size =
                metadata.at("size").get<std::uint64_t>();
            channel.expected_receive_sha256 =
                metadata.at("sha256").get<std::string>();
            if (!RelayFileReceiver::IsSafeBasename(
                    channel.expected_receive_name) ||
                !RelayFileReceiver::IsCanonicalSha256Digest(
                    channel.expected_receive_sha256) ||
                *channel.expected_receive_size >
                    options_.receive_limits.max_transfer_bytes) {
                throw std::runtime_error("invalid transfer metadata");
            }
        } catch (const std::exception&) {
            incoming_invites_.erase(it);
            schedule_pending_invite_expiry_locked();
            return fail("accepted transfer metadata is invalid");
        }
    }
    if (channels_.find(stream_id) != channels_.end()) {
        incoming_invites_.erase(it);
        schedule_pending_invite_expiry_locked();
        return fail("relay stream id already in use");
    }
    channel.ratchet = std::move(it->second.ratchet);
    try {
        if (!register_channel(stream_id, std::move(channel))) {
            incoming_invites_.erase(it);
            schedule_pending_invite_expiry_locked();
            return fail("relay stream id already in use");
        }
    } catch (const std::exception& ex) {
        channels_.erase(stream_id);
        try {
            tunnel_->unregister_stream(stream_id);
        } catch (...) {
        }
        incoming_invites_.erase(it);
        schedule_pending_invite_expiry_locked();
        util::log_warn(
            std::string("failed to register relay stream: ") + ex.what());
        return fail("failed to register relay stream");
    }
    if (kind == control::ChannelKind::chat) {
        active_chat_stream_ = stream_id;
    }
    incoming_invites_.erase(it);
    schedule_pending_invite_expiry_locked();
    return true;
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
    try {
        tunnel_->send_control_json(request);
    } catch (const std::exception& ex) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            control_responses_.erase(request_id);
        }
        if (error) {
            *error = std::string("failed to send control request: ") +
                ex.what();
        }
        return nlohmann::json::object();
    } catch (...) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            control_responses_.erase(request_id);
        }
        if (error) {
            *error = "failed to send control request: unknown error";
        }
        return nlohmann::json::object();
    }
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
        if (it == channels_.end() ||
            it->second.channel_kind != control::ChannelKind::admin ||
            it->second.role != control::RelayChannelRole::initiator) {
            if (error) {
                *error = "admin channel is unavailable";
            }
            return nlohmann::json::object();
        }
        PendingAdminResponse pending;
        pending.stream_id = stream_id;
        admin_responses_.emplace(request_id, std::move(pending));
        nlohmann::json request{
            {"type", "admin_req"},
            {"request_id", request_id},
            {"op", op},
            {"args", args},
        };
        try {
            std::string send_error;
            if (!send_channel_payload_locked(
                    it->second, request.dump(), {}, &send_error)) {
                const std::string reason = send_error.empty()
                    ? "admin request write queue is full" : send_error;
                close_channel_locked(stream_id, reason);
                admin_responses_.erase(request_id);
                if (error) *error = reason;
                return nlohmann::json::object();
            }
        } catch (const std::exception& ex) {
            try {
                close_channel_locked(
                    stream_id, "admin request encryption failed");
            } catch (...) {
            }
            admin_responses_.erase(request_id);
            if (error) *error = ex.what();
            return nlohmann::json::object();
        }
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
    auto pending = std::move(admin_responses_[request_id]);
    admin_responses_.erase(request_id);
    if (pending.failed) {
        if (error) *error = pending.error;
        return nlohmann::json::object();
    }
    return pending.value;
}

}  // namespace yume::client
