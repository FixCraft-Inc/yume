#include "core/control_protocol.hpp"

#include <algorithm>
#include <stdexcept>

namespace yume::control {

namespace {
std::string lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}
}  // namespace

std::string to_string(EndpointKind value) {
    switch (value) {
        case EndpointKind::client:
            return "client";
        case EndpointKind::server:
            return "server";
    }
    return "client";
}

std::string to_string(RelayMode value) {
    switch (value) {
        case RelayMode::untrusted:
            return "untrusted";
        case RelayMode::trusted:
            return "trusted";
    }
    return "untrusted";
}

std::string to_string(ChannelKind value) {
    switch (value) {
        case ChannelKind::chat:
            return "chat";
        case ChannelKind::file:
            return "file";
        case ChannelKind::bytes:
            return "bytes";
        case ChannelKind::admin:
            return "admin";
    }
    return "chat";
}

EndpointKind endpoint_kind_from_string(const std::string& value) {
    return lower_copy(value) == "server" ? EndpointKind::server : EndpointKind::client;
}

RelayMode relay_mode_from_string(const std::string& value) {
    return lower_copy(value) == "trusted" ? RelayMode::trusted : RelayMode::untrusted;
}

ChannelKind channel_kind_from_string(const std::string& value) {
    const std::string normalized = lower_copy(value);
    if (normalized == "file") {
        return ChannelKind::file;
    }
    if (normalized == "bytes") {
        return ChannelKind::bytes;
    }
    if (normalized == "admin") {
        return ChannelKind::admin;
    }
    return ChannelKind::chat;
}

nlohmann::json endpoint_to_json(const EndpointInfo& endpoint, bool include_auth_pubkey) {
    nlohmann::json json;
    json["endpoint_id"] = endpoint.endpoint_id;
    json["endpoint_kind"] = to_string(endpoint.endpoint_kind);
    json["display_name"] = endpoint.display_name;
    json["hostname"] = endpoint.hostname;
    json["server_id"] = endpoint.server_id;
    json["relay_mode"] = to_string(endpoint.relay_mode);
    json["allow_inbound_admin"] = endpoint.allow_inbound_admin;
    json["allow_outbound_admin"] = endpoint.allow_outbound_admin;
    json["allow_chat"] = endpoint.allow_chat;
    json["allow_file"] = endpoint.allow_file;
    json["allow_bytes"] = endpoint.allow_bytes;
    json["online"] = endpoint.online;
    json["controller_ids"] = endpoint.controller_ids;
    json["controlled_target_ids"] = endpoint.controlled_target_ids;
    if (include_auth_pubkey && !endpoint.auth_pubkey_b64.empty()) {
        json["auth_pubkey_b64"] = endpoint.auth_pubkey_b64;
    }
    return json;
}

EndpointInfo endpoint_from_json(const nlohmann::json& json) {
    EndpointInfo endpoint;
    endpoint.endpoint_id = json.value("endpoint_id", "");
    endpoint.endpoint_kind = endpoint_kind_from_string(json.value("endpoint_kind", "client"));
    endpoint.display_name = json.value("display_name", "");
    endpoint.hostname = json.value("hostname", "");
    endpoint.server_id = json.value("server_id", "");
    endpoint.relay_mode = relay_mode_from_string(json.value("relay_mode", "untrusted"));
    endpoint.allow_inbound_admin = json.value("allow_inbound_admin", false);
    endpoint.allow_outbound_admin = json.value("allow_outbound_admin", true);
    endpoint.allow_chat = json.value("allow_chat", true);
    endpoint.allow_file = json.value("allow_file", true);
    endpoint.allow_bytes = json.value("allow_bytes", true);
    endpoint.online = json.value("online", true);
    endpoint.auth_pubkey_b64 = json.value("auth_pubkey_b64", "");
    if (json.contains("controller_ids") && json["controller_ids"].is_array()) {
        endpoint.controller_ids = json["controller_ids"].get<std::vector<std::string>>();
    }
    if (json.contains("controlled_target_ids") && json["controlled_target_ids"].is_array()) {
        endpoint.controlled_target_ids = json["controlled_target_ids"].get<std::vector<std::string>>();
    }
    return endpoint;
}

nlohmann::json invite_to_json(const PendingInvite& invite, bool include_response) {
    nlohmann::json json;
    json["invite_id"] = invite.invite_id;
    json["from_id"] = invite.from_endpoint_id;
    json["to_id"] = invite.to_endpoint_id;
    json["channel_kind"] = to_string(invite.channel_kind);
    json["created_ms"] = invite.created_ms;
    json["requires_password"] = invite.requires_password;
    if (!invite.metadata_json.empty()) {
        try {
            json["metadata"] = nlohmann::json::parse(invite.metadata_json);
        } catch (...) {
            json["metadata_json"] = invite.metadata_json;
        }
    }
    json["ephemeral_pubkey_b64"] = invite.ephemeral_pubkey_b64;
    json["ephemeral_signature_b64"] = invite.ephemeral_signature_b64;
    json["nonce_b64"] = invite.nonce_b64;
    json["from_display_name"] = invite.from_display_name;
    if (!invite.from_auth_pubkey_b64.empty()) {
        json["from_auth_pubkey_b64"] = invite.from_auth_pubkey_b64;
    }
    if (include_response) {
        json["accepted"] = invite.accepted;
        if (!invite.response_reason.empty()) {
            json["reason"] = invite.response_reason;
        }
        if (!invite.response_ephemeral_pubkey_b64.empty()) {
            json["response_ephemeral_pubkey_b64"] = invite.response_ephemeral_pubkey_b64;
        }
        if (!invite.response_ephemeral_signature_b64.empty()) {
            json["response_ephemeral_signature_b64"] = invite.response_ephemeral_signature_b64;
        }
    }
    return json;
}

PendingInvite invite_from_json(const nlohmann::json& json) {
    PendingInvite invite;
    invite.invite_id = json.value("invite_id", "");
    invite.from_endpoint_id = json.value("from_id", "");
    invite.to_endpoint_id = json.value("to_id", "");
    invite.channel_kind = channel_kind_from_string(json.value("channel_kind", "chat"));
    invite.created_ms = json.value("created_ms", 0LL);
    invite.requires_password = json.value("requires_password", true);
    if (json.contains("metadata")) {
        invite.metadata_json = json["metadata"].dump();
    } else {
        invite.metadata_json = json.value("metadata_json", "");
    }
    invite.ephemeral_pubkey_b64 = json.value("ephemeral_pubkey_b64", "");
    invite.ephemeral_signature_b64 = json.value("ephemeral_signature_b64", "");
    invite.nonce_b64 = json.value("nonce_b64", "");
    invite.from_display_name = json.value("from_display_name", "");
    invite.from_auth_pubkey_b64 = json.value("from_auth_pubkey_b64", "");
    invite.accepted = json.value("accepted", false);
    invite.response_reason = json.value("reason", "");
    invite.response_ephemeral_pubkey_b64 = json.value("response_ephemeral_pubkey_b64", "");
    invite.response_ephemeral_signature_b64 = json.value("response_ephemeral_signature_b64", "");
    return invite;
}

nlohmann::json channel_to_json(const ActiveRelayChannel& channel) {
    nlohmann::json json;
    json["channel_id"] = channel.channel_id;
    json["channel_kind"] = to_string(channel.channel_kind);
    json["left_endpoint_id"] = channel.left_endpoint_id;
    json["right_endpoint_id"] = channel.right_endpoint_id;
    json["left_stream_id"] = channel.left_stream_id;
    json["right_stream_id"] = channel.right_stream_id;
    json["e2ee_required"] = channel.e2ee_required;
    json["pending"] = channel.pending;
    json["federated"] = channel.federated;
    json["route_hops"] = channel.route_hops;
    return json;
}

}  // namespace yume::control
