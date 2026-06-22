#include "core/protocol/control_protocol.hpp"

#include <algorithm>
#include <stdexcept>

#include "core/protocol/control_fields.hpp"

namespace yume::control {

namespace {
std::string lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string normalize_client_platform(const std::string& value) {
    const std::string normalized = lower_copy(value);
    if (normalized == "linux" || normalized == "windows" || normalized == "macos" ||
        normalized == "android") {
        return normalized;
    }
    return "unknown";
}

std::string normalize_client_variant(const std::string& value) {
    const std::string normalized = lower_copy(value);
    if (normalized == "cli" || normalized == "android_vpn") {
        return normalized;
    }
    return "unknown";
}

std::string normalize_lifecycle_state(const std::string& value) {
    const std::string normalized = lower_copy(value);
    if (normalized == "connecting" || normalized == "authenticated" ||
        normalized == "traffic_flowing" || normalized == "disconnecting" ||
        normalized == "error") {
        return normalized;
    }
    return "unknown";
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
    json[fields::endpoint_id] = endpoint.endpoint_id;
    json[fields::endpoint_kind] = to_string(endpoint.endpoint_kind);
    json[fields::display_name] = endpoint.display_name;
    json[fields::hostname] = endpoint.hostname;
    json[fields::client_platform] = normalize_client_platform(endpoint.client_platform);
    json[fields::client_variant] = normalize_client_variant(endpoint.client_variant);
    json[fields::client_version] = endpoint.client_version;
    json[fields::server_id] = endpoint.server_id;
    if (!endpoint.server_name.empty()) {
        json[fields::server_name] = endpoint.server_name;
    }
    json[fields::relay_mode] = to_string(endpoint.relay_mode);
    json[fields::allow_inbound_admin] = endpoint.allow_inbound_admin;
    json[fields::allow_outbound_admin] = endpoint.allow_outbound_admin;
    json[fields::allow_chat] = endpoint.allow_chat;
    json[fields::allow_file] = endpoint.allow_file;
    json[fields::allow_bytes] = endpoint.allow_bytes;
    json[fields::online] = endpoint.online;
    json[fields::controller_ids] = endpoint.controller_ids;
    json[fields::controlled_target_ids] = endpoint.controlled_target_ids;
    if (endpoint.remote) {
        json[fields::remote] = true;
        json[fields::federation_peer_id] = endpoint.federation_peer_id;
        json[fields::remote_endpoint_id] = endpoint.remote_endpoint_id;
    }
    if (include_auth_pubkey && !endpoint.auth_pubkey_b64.empty()) {
        json[fields::auth_pubkey_b64] = endpoint.auth_pubkey_b64;
    }
    return json;
}

EndpointInfo endpoint_from_json(const nlohmann::json& json) {
    EndpointInfo endpoint;
    endpoint.endpoint_id = json.value(fields::endpoint_id, "");
    endpoint.endpoint_kind = endpoint_kind_from_string(json.value(fields::endpoint_kind, "client"));
    endpoint.display_name = json.value(fields::display_name, "");
    endpoint.hostname = json.value(fields::hostname, "");
    endpoint.client_platform = normalize_client_platform(json.value(fields::client_platform, "unknown"));
    endpoint.client_variant = normalize_client_variant(json.value(fields::client_variant, "unknown"));
    endpoint.client_version = json.value(fields::client_version, "");
    endpoint.server_id = json.value(fields::server_id, "");
    endpoint.server_name = json.value(fields::server_name, "");
    endpoint.relay_mode = relay_mode_from_string(json.value(fields::relay_mode, "untrusted"));
    endpoint.allow_inbound_admin = json.value(fields::allow_inbound_admin, false);
    endpoint.allow_outbound_admin = json.value(fields::allow_outbound_admin, false);
    endpoint.allow_chat = json.value(fields::allow_chat, true);
    endpoint.allow_file = json.value(fields::allow_file, true);
    endpoint.allow_bytes = json.value(fields::allow_bytes, true);
    endpoint.online = json.value(fields::online, true);
    endpoint.auth_pubkey_b64 = json.value(fields::auth_pubkey_b64, "");
    endpoint.remote = json.value(fields::remote, false);
    endpoint.federation_peer_id = json.value(fields::federation_peer_id, "");
    endpoint.remote_endpoint_id = json.value(fields::remote_endpoint_id, "");
    if (json.contains(fields::controller_ids) && json[fields::controller_ids].is_array()) {
        endpoint.controller_ids = json[fields::controller_ids].get<std::vector<std::string>>();
    }
    if (json.contains(fields::controlled_target_ids) && json[fields::controlled_target_ids].is_array()) {
        endpoint.controlled_target_ids = json[fields::controlled_target_ids].get<std::vector<std::string>>();
    }
    return endpoint;
}

nlohmann::json lifecycle_event_to_json(const ClientLifecycleEvent& event) {
    nlohmann::json json;
    json[fields::endpoint_id] = event.endpoint_id;
    json[fields::display_name] = event.display_name;
    json[fields::state] = normalize_lifecycle_state(event.state);
    json[fields::message] = event.message;
    json[fields::detail] = event.detail;
    json[fields::client_platform] = normalize_client_platform(event.client_platform);
    json[fields::client_variant] = normalize_client_variant(event.client_variant);
    json[fields::client_version] = event.client_version;
    json[fields::effective_protection] = event.effective_protection;
    json[fields::traffic_verified] = event.traffic_verified;
    json[fields::exit_ip] = event.exit_ip;
    json[fields::error_code] = event.error_code;
    json[fields::server_time_ms] = event.server_time_ms;
    return json;
}

ClientLifecycleEvent lifecycle_event_from_json(const nlohmann::json& json) {
    ClientLifecycleEvent event;
    event.endpoint_id = json.value(fields::endpoint_id, "");
    event.display_name = json.value(fields::display_name, "");
    event.state = normalize_lifecycle_state(json.value(fields::state, "unknown"));
    event.message = json.value(fields::message, "");
    event.detail = json.value(fields::detail, "");
    event.client_platform = normalize_client_platform(json.value(fields::client_platform, "unknown"));
    event.client_variant = normalize_client_variant(json.value(fields::client_variant, "unknown"));
    event.client_version = json.value(fields::client_version, "");
    event.effective_protection = json.value(fields::effective_protection, "");
    event.traffic_verified = json.value(fields::traffic_verified, false);
    event.exit_ip = json.value(fields::exit_ip, "");
    event.error_code = json.value(fields::error_code, "");
    event.server_time_ms = json.value(fields::server_time_ms, 0LL);
    return event;
}

nlohmann::json endpoint_runtime_status_to_json(const EndpointRuntimeStatus& status,
                                               bool include_auth_pubkey) {
    nlohmann::json json;
    json[fields::endpoint] = endpoint_to_json(status.endpoint, include_auth_pubkey);
    if (status.latest_lifecycle.has_value()) {
        json[fields::latest_lifecycle] = lifecycle_event_to_json(*status.latest_lifecycle);
    }
    return json;
}

nlohmann::json invite_to_json(const PendingInvite& invite, bool include_response) {
    nlohmann::json json;
    json[fields::invite_id] = invite.invite_id;
    json[fields::from_id] = invite.from_endpoint_id;
    json[fields::to_id] = invite.to_endpoint_id;
    json[fields::channel_kind] = to_string(invite.channel_kind);
    json[fields::created_ms] = invite.created_ms;
    json[fields::requires_password] = invite.requires_password;
    if (!invite.metadata_json.empty()) {
        try {
            json[fields::metadata] = nlohmann::json::parse(invite.metadata_json);
        } catch (...) {
            json[fields::metadata_json] = invite.metadata_json;
        }
    }
    json[fields::ephemeral_pubkey_b64] = invite.ephemeral_pubkey_b64;
    json[fields::ephemeral_signature_b64] = invite.ephemeral_signature_b64;
    json[fields::nonce_b64] = invite.nonce_b64;
    json[fields::from_display_name] = invite.from_display_name;
    if (!invite.from_auth_pubkey_b64.empty()) {
        json[fields::from_auth_pubkey_b64] = invite.from_auth_pubkey_b64;
    }
    if (include_response) {
        json[fields::accepted] = invite.accepted;
        if (!invite.response_reason.empty()) {
            json[fields::reason] = invite.response_reason;
        }
        if (!invite.response_ephemeral_pubkey_b64.empty()) {
            json[fields::response_ephemeral_pubkey_b64] = invite.response_ephemeral_pubkey_b64;
        }
        if (!invite.response_ephemeral_signature_b64.empty()) {
            json[fields::response_ephemeral_signature_b64] =
                invite.response_ephemeral_signature_b64;
        }
    }
    return json;
}

PendingInvite invite_from_json(const nlohmann::json& json) {
    PendingInvite invite;
    invite.invite_id = json.value(fields::invite_id, "");
    invite.from_endpoint_id = json.value(fields::from_id, "");
    invite.to_endpoint_id = json.value(fields::to_id, "");
    invite.channel_kind = channel_kind_from_string(json.value(fields::channel_kind, "chat"));
    invite.created_ms = json.value(fields::created_ms, 0LL);
    invite.requires_password = json.value(fields::requires_password, true);
    if (json.contains(fields::metadata)) {
        invite.metadata_json = json[fields::metadata].dump();
    } else {
        invite.metadata_json = json.value(fields::metadata_json, "");
    }
    invite.ephemeral_pubkey_b64 = json.value(fields::ephemeral_pubkey_b64, "");
    invite.ephemeral_signature_b64 = json.value(fields::ephemeral_signature_b64, "");
    invite.nonce_b64 = json.value(fields::nonce_b64, "");
    invite.from_display_name = json.value(fields::from_display_name, "");
    invite.from_auth_pubkey_b64 = json.value(fields::from_auth_pubkey_b64, "");
    invite.accepted = json.value(fields::accepted, false);
    invite.response_reason = json.value(fields::reason, "");
    invite.response_ephemeral_pubkey_b64 =
        json.value(fields::response_ephemeral_pubkey_b64, "");
    invite.response_ephemeral_signature_b64 =
        json.value(fields::response_ephemeral_signature_b64, "");
    return invite;
}

nlohmann::json channel_to_json(const ActiveRelayChannel& channel) {
    nlohmann::json json;
    json[fields::channel_id] = channel.channel_id;
    json[fields::channel_kind] = to_string(channel.channel_kind);
    json[fields::left_endpoint_id] = channel.left_endpoint_id;
    json[fields::right_endpoint_id] = channel.right_endpoint_id;
    json[fields::left_stream_id] = channel.left_stream_id;
    json[fields::right_stream_id] = channel.right_stream_id;
    json[fields::e2ee_required] = channel.e2ee_required;
    json[fields::pending] = channel.pending;
    json[fields::federated] = channel.federated;
    json[fields::route_hops] = channel.route_hops;
    return json;
}

}  // namespace yume::control
