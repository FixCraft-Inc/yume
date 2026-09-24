/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "modules/relay/control.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>

#include "modules/relay/control_fields.hpp"

namespace yume::relay {

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

}  // namespace

std::string to_string(EndpointKind value) {
    switch (value) {
        case EndpointKind::Client:
            return "client";
        case EndpointKind::Server:
            return "server";
    }
    return "client";
}

std::string to_string(RelayMode value) {
    switch (value) {
        case RelayMode::Untrusted:
            return "untrusted";
        case RelayMode::Trusted:
            return "trusted";
    }
    return "untrusted";
}

std::string to_string(ChannelKind value) {
    switch (value) {
        case ChannelKind::Chat:
            return "chat";
        case ChannelKind::File:
            return "file";
        case ChannelKind::Bytes:
            return "bytes";
        case ChannelKind::Admin:
            return "admin";
    }
    return "chat";
}

EndpointKind endpoint_kind_from_string(const std::string& value) {
    return lower_copy(value) == "server" ? EndpointKind::Server : EndpointKind::Client;
}

RelayMode relay_mode_from_string(const std::string& value) {
    return lower_copy(value) == "trusted" ? RelayMode::Trusted : RelayMode::Untrusted;
}

ChannelKind channel_kind_from_string(const std::string& value) {
    const std::string normalized = lower_copy(value);
    if (normalized == "file") {
        return ChannelKind::File;
    }
    if (normalized == "bytes") {
        return ChannelKind::Bytes;
    }
    if (normalized == "admin") {
        return ChannelKind::Admin;
    }
    return ChannelKind::Chat;
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

nlohmann::json invite_to_json(const PendingInvite& invite, bool include_response) {
    nlohmann::json json;
    json[fields::relay_protocol_version] = invite.relay_protocol_version;
    json[fields::invite_id] = invite.invite_id;
    json[fields::from_id] = invite.from_endpoint_id;
    json[fields::to_id] = invite.to_endpoint_id;
    json[fields::channel_kind] = to_string(invite.channel_kind);
    json[fields::created_ms] = invite.created_ms;
    json[fields::requires_password] = invite.requires_password;
    // The relay-v2 handshake signs a digest over these exact bytes. Never
    // parse and re-emit this string as a JSON object: doing so would silently
    // change the representation that endpoints bind cryptographically.
    json[fields::metadata_json] = invite.metadata_json;
    json[fields::handshake_request_b64] = invite.handshake_request_b64;
    json[fields::from_display_name] = invite.from_display_name;
    if (!invite.from_auth_pubkey_b64.empty()) {
        json[fields::from_auth_pubkey_b64] = invite.from_auth_pubkey_b64;
    }
    if (include_response) {
        json[fields::accepted] = invite.accepted;
        if (!invite.response_reason.empty()) {
            json[fields::reason] = invite.response_reason;
        }
        if (!invite.handshake_response_b64.empty()) {
            json[fields::handshake_response_b64] =
                invite.handshake_response_b64;
        }
        if (!invite.responder_auth_pubkey_b64.empty()) {
            json[fields::responder_auth_pubkey_b64] =
                invite.responder_auth_pubkey_b64;
        }
    }
    return json;
}

PendingInvite invite_from_json(const nlohmann::json& json) {
    PendingInvite invite;
    // Required keys use at()/get() deliberately. The strict outer parser
    // validates their exact types before calling this function, and a direct
    // caller must not acquire relay-v2 semantics from struct defaults.
    invite.relay_protocol_version =
        json.at(fields::relay_protocol_version).get<std::uint16_t>();
    invite.invite_id = json.at(fields::invite_id).get<std::string>();
    invite.from_endpoint_id = json.at(fields::from_id).get<std::string>();
    invite.to_endpoint_id = json.at(fields::to_id).get<std::string>();
    invite.channel_kind = channel_kind_from_string(
        json.at(fields::channel_kind).get<std::string>());
    invite.created_ms = json.at(fields::created_ms).get<std::int64_t>();
    invite.requires_password =
        json.at(fields::requires_password).get<bool>();
    invite.metadata_json = json.value(fields::metadata_json, "");
    invite.handshake_request_b64 =
        json.at(fields::handshake_request_b64).get<std::string>();
    invite.from_display_name = json.value(fields::from_display_name, "");
    invite.from_auth_pubkey_b64 = json.value(fields::from_auth_pubkey_b64, "");
    invite.response_present = json.contains(fields::accepted);
    invite.accepted = json.value(fields::accepted, false);
    invite.response_reason = json.value(fields::reason, "");
    invite.handshake_response_b64 =
        json.value(fields::handshake_response_b64, "");
    invite.responder_auth_pubkey_b64 =
        json.value(fields::responder_auth_pubkey_b64, "");
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

}  // namespace yume::relay
