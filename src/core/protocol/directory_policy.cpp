/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/protocol/directory_policy.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <limits>
#include <unordered_set>

#include "core/protocol/control_fields.hpp"

namespace yume::control {
namespace {

constexpr std::array<std::string_view, 23> kEndpointFields{
    fields::endpoint_id,
    fields::endpoint_kind,
    fields::display_name,
    fields::hostname,
    fields::client_platform,
    fields::client_variant,
    fields::client_version,
    fields::server_id,
    fields::server_name,
    fields::relay_mode,
    fields::allow_inbound_admin,
    fields::allow_outbound_admin,
    fields::allow_chat,
    fields::allow_file,
    fields::allow_bytes,
    fields::online,
    fields::auth_pubkey_b64,
    fields::controller_ids,
    fields::controlled_target_ids,
    fields::remote,
    fields::federation_peer_id,
    fields::remote_endpoint_id,
    // Reserved for a future explicit endpoint schema. Keeping no aliases here
    // makes an unexpected key fail closed today.
    "endpoint_schema",
};

constexpr std::array<std::string_view, 6> kDirectoryFields{
    "cmd", "ok", "request_id", "server_id", "server_name", "endpoints",
};

constexpr std::array<std::string_view, 16> kPresenceFields{
    "cmd",
    "request_id",
    fields::endpoint_kind,
    "preferred_id",
    "preferred_name",
    fields::hostname,
    fields::client_platform,
    fields::client_variant,
    fields::client_version,
    fields::relay_mode,
    fields::allow_chat,
    fields::allow_file,
    fields::allow_bytes,
    fields::allow_inbound_admin,
    fields::allow_outbound_admin,
    // Reserved for a future explicit presence schema. It is not accepted
    // until the parser gives it fixed semantics.
    "presence_schema",
};

void SetError(std::string* error, std::string_view message) noexcept {
    if (!error) return;
    try {
        error->assign(message);
    } catch (...) {
    }
}

template <std::size_t Size>
bool HasOnlyKnownFields(
    const nlohmann::json& json,
    const std::array<std::string_view, Size>& known) {
    if (!json.is_object() || json.size() > known.size()) return false;
    for (auto it = json.begin(); it != json.end(); ++it) {
        if (std::find(known.begin(), known.end(), it.key()) == known.end()) {
            return false;
        }
    }
    return true;
}

bool IsSafeText(std::string_view value,
                std::size_t max_bytes,
                bool allow_empty) noexcept {
    if (value.size() > max_bytes || (!allow_empty && value.empty())) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](unsigned char byte) {
        return byte >= 0x20U && byte != 0x7fU;
    });
}

bool IsEndpointCharacter(unsigned char byte) noexcept {
    return (byte >= 'a' && byte <= 'z') ||
           (byte >= 'A' && byte <= 'Z') ||
           (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' ||
           byte == '.';
}

bool IsRawEndpointId(std::string_view value) noexcept {
    return !value.empty() && value.size() <= kMaxDirectoryEndpointIdBytes &&
           value != "." && value != ".." &&
           std::all_of(value.begin(), value.end(), [](unsigned char byte) {
               return IsEndpointCharacter(byte);
           });
}

bool IsFederationPeerId(std::string_view value) noexcept {
    return !value.empty() &&
           value.size() <= kMaxDirectoryFederationPeerIdBytes &&
           std::all_of(value.begin(), value.end(), [](unsigned char byte) {
               return IsEndpointCharacter(byte);
           });
}

int Base64Value(unsigned char byte) noexcept {
    if (byte >= 'A' && byte <= 'Z') return byte - 'A';
    if (byte >= 'a' && byte <= 'z') return byte - 'a' + 26;
    if (byte >= '0' && byte <= '9') return byte - '0' + 52;
    if (byte == '+') return 62;
    if (byte == '/') return 63;
    return -1;
}

bool IsBoundedCanonicalBase64(std::string_view encoded,
                              std::size_t max_decoded_bytes) noexcept {
    if (encoded.empty() || encoded.size() > kMaxDirectoryIdentityBase64Bytes ||
        (encoded.size() % 4U) != 0U) {
        return false;
    }
    std::size_t padding = 0;
    if (encoded.back() == '=') {
        padding = 1;
        if (encoded.size() >= 2U && encoded[encoded.size() - 2U] == '=') {
            padding = 2;
        }
    }
    const std::size_t data_size = encoded.size() - padding;
    if ((padding == 0U && (data_size % 4U) != 0U) ||
        (padding == 1U && (data_size % 4U) != 3U) ||
        (padding == 2U && (data_size % 4U) != 2U)) {
        return false;
    }
    for (std::size_t index = 0; index < data_size; ++index) {
        if (Base64Value(static_cast<unsigned char>(encoded[index])) < 0) {
            return false;
        }
    }
    for (std::size_t index = data_size; index < encoded.size(); ++index) {
        if (encoded[index] != '=') return false;
    }
    // Reject alternate encodings whose unused tail bits are non-zero.
    if (padding == 2U &&
        (Base64Value(static_cast<unsigned char>(encoded[data_size - 1U])) &
         0x0f) != 0) {
        return false;
    }
    if (padding == 1U &&
        (Base64Value(static_cast<unsigned char>(encoded[data_size - 1U])) &
         0x03) != 0) {
        return false;
    }
    const std::size_t decoded_size =
        (encoded.size() / 4U) * 3U - padding;
    return decoded_size >= kMinDirectoryIdentityBytes &&
           decoded_size <= max_decoded_bytes;
}

bool RequiredString(const nlohmann::json& json,
                    const char* key,
                    std::size_t max_bytes,
                    bool allow_empty) {
    return json.contains(key) && json[key].is_string() &&
           IsSafeText(json[key].get_ref<const std::string&>(), max_bytes,
                      allow_empty);
}

bool OptionalString(const nlohmann::json& json,
                    const char* key,
                    std::size_t max_bytes,
                    bool allow_empty = true) {
    return !json.contains(key) ||
           (json[key].is_string() &&
            IsSafeText(json[key].get_ref<const std::string&>(), max_bytes,
                       allow_empty));
}

bool RequiredBool(const nlohmann::json& json, const char* key) {
    return json.contains(key) && json[key].is_boolean();
}

bool IsKnownPlatform(std::string_view value) noexcept {
    return value == "linux" || value == "windows" || value == "macos" ||
           value == "android" || value == "unknown";
}

bool IsKnownVariant(std::string_view value) noexcept {
    return value == "cli" || value == "android_vpn" || value == "unknown";
}

bool AddAccounted(std::size_t amount,
                  std::size_t limit,
                  std::size_t* total) noexcept {
    if (!total || amount > limit || *total > limit - amount) return false;
    *total += amount;
    return true;
}

bool ParseRelationships(const nlohmann::json& json,
                        const char* key,
                        std::vector<std::string>* output) {
    if (!output || !json.contains(key) || !json[key].is_array() ||
        json[key].size() > kMaxDirectoryRelationshipsPerList) {
        return false;
    }
    output->clear();
    output->reserve(json[key].size());
    for (const auto& item : json[key]) {
        if (!item.is_string()) return false;
        const auto& id = item.get_ref<const std::string&>();
        if (!is_valid_directory_endpoint_id(
                id, DirectoryNamespace::ClientVisible) ||
            std::find(output->begin(), output->end(), id) != output->end()) {
            return false;
        }
        output->push_back(id);
    }
    return true;
}

bool EndpointFieldsValid(const EndpointInfo& endpoint,
                         DirectoryNamespace namespace_kind,
                         std::size_t* accounted_bytes) noexcept {
    std::string_view relay_mode;
    switch (endpoint.relay_mode) {
        case RelayMode::untrusted:
            relay_mode = "untrusted";
            break;
        case RelayMode::trusted:
            relay_mode = "trusted";
            break;
        default:
            return false;
    }
    switch (endpoint.endpoint_kind) {
        case EndpointKind::client:
        case EndpointKind::server:
            break;
        default:
            return false;
    }
    if (!accounted_bytes ||
        !is_valid_directory_endpoint_id(endpoint.endpoint_id,
                                        namespace_kind) ||
        !IsSafeText(endpoint.display_name, kMaxDirectoryDisplayNameBytes,
                    false) ||
        !IsSafeText(endpoint.hostname, kMaxDirectoryHostnameBytes, true) ||
        !IsKnownPlatform(endpoint.client_platform) ||
        !IsKnownVariant(endpoint.client_variant) ||
        !IsSafeText(endpoint.client_version,
                    kMaxDirectoryClientVersionBytes, true) ||
        !IsSafeText(endpoint.server_id, kMaxDirectoryServerIdBytes, true) ||
        !IsSafeText(endpoint.server_name, kMaxDirectoryServerNameBytes, true) ||
        !IsBoundedCanonicalBase64(endpoint.auth_pubkey_b64,
                                  kMaxDirectoryIdentityBytes) ||
        endpoint.controller_ids.size() >
            kMaxDirectoryRelationshipsPerList ||
        endpoint.controlled_target_ids.size() >
            kMaxDirectoryRelationshipsPerList) {
        return false;
    }

    if (namespace_kind == DirectoryNamespace::FederationRaw) {
        if (endpoint.remote || !endpoint.federation_peer_id.empty() ||
            !endpoint.remote_endpoint_id.empty()) {
            return false;
        }
    } else if (endpoint.remote) {
        const std::size_t visible_size = endpoint.federation_peer_id.size() +
                                         1U +
                                         endpoint.remote_endpoint_id.size();
        if (!IsFederationPeerId(endpoint.federation_peer_id) ||
            !IsRawEndpointId(endpoint.remote_endpoint_id) ||
            visible_size != endpoint.endpoint_id.size() ||
            endpoint.endpoint_id.compare(
                0U, endpoint.federation_peer_id.size(),
                endpoint.federation_peer_id) != 0 ||
            endpoint.endpoint_id[endpoint.federation_peer_id.size()] != ':' ||
            endpoint.endpoint_id.compare(
                endpoint.federation_peer_id.size() + 1U,
                endpoint.remote_endpoint_id.size(),
                endpoint.remote_endpoint_id) != 0) {
            return false;
        }
    } else if (!endpoint.federation_peer_id.empty() ||
               !endpoint.remote_endpoint_id.empty()) {
        return false;
    }

    std::size_t accounted = kDirectoryEndpointOverheadBytes;
    const std::array<std::string_view, 12> strings{
        endpoint.endpoint_id,
        endpoint.display_name,
        endpoint.hostname,
        endpoint.client_platform,
        endpoint.client_variant,
        endpoint.client_version,
        endpoint.server_id,
        endpoint.server_name,
        endpoint.auth_pubkey_b64,
        endpoint.federation_peer_id,
        endpoint.remote_endpoint_id,
        relay_mode,
    };
    for (const auto value : strings) {
        if (!AddAccounted(value.size(), kMaxDirectoryEndpointBytes,
                          &accounted)) {
            return false;
        }
    }
    auto account_relationships = [&](const std::vector<std::string>& ids) {
        for (std::size_t index = 0; index < ids.size(); ++index) {
            const auto& id = ids[index];
            if (!is_valid_directory_endpoint_id(
                    id, DirectoryNamespace::ClientVisible) ||
                std::find(ids.begin(), ids.begin() +
                                      static_cast<std::ptrdiff_t>(index),
                          id) != ids.begin() +
                                 static_cast<std::ptrdiff_t>(index) ||
                !AddAccounted(id.size(), kMaxDirectoryEndpointBytes,
                              &accounted)) {
                return false;
            }
        }
        return true;
    };
    if (!account_relationships(endpoint.controller_ids) ||
        !account_relationships(endpoint.controlled_target_ids)) {
        return false;
    }
    *accounted_bytes = accounted;
    return true;
}

}  // namespace

bool is_valid_directory_endpoint_id(
    std::string_view value,
    DirectoryNamespace namespace_kind) noexcept {
    if (namespace_kind == DirectoryNamespace::FederationRaw) {
        return IsRawEndpointId(value);
    }
    if (IsRawEndpointId(value)) return true;
    const auto separator = value.find(':');
    return separator != std::string_view::npos &&
           value.find(':', separator + 1U) == std::string_view::npos &&
           value.size() <= kMaxDirectoryEndpointIdBytes &&
           IsFederationPeerId(value.substr(0, separator)) &&
           IsRawEndpointId(value.substr(separator + 1U));
}

std::optional<std::string> try_make_federated_visible_endpoint_id(
    std::string_view federation_peer_id,
    std::string_view raw_endpoint_id) noexcept {
    if (!IsFederationPeerId(federation_peer_id) ||
        !IsRawEndpointId(raw_endpoint_id) ||
        federation_peer_id.size() + 1U + raw_endpoint_id.size() >
            kMaxDirectoryEndpointIdBytes) {
        return std::nullopt;
    }
    try {
        std::string visible;
        visible.reserve(federation_peer_id.size() + 1U +
                        raw_endpoint_id.size());
        visible.append(federation_peer_id);
        visible.push_back(':');
        visible.append(raw_endpoint_id);
        if (!is_valid_directory_endpoint_id(
                visible, DirectoryNamespace::ClientVisible)) {
            return std::nullopt;
        }
        return visible;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

bool is_valid_directory_server_identity(
    std::string_view server_id,
    std::string_view server_name,
    bool federation_enabled) noexcept {
    return IsSafeText(server_id, kMaxDirectoryServerIdBytes, false) &&
           IsSafeText(server_name, kMaxDirectoryServerNameBytes, false) &&
           (!federation_enabled || IsFederationPeerId(server_id));
}

std::optional<std::size_t> directory_endpoint_accounted_bytes(
    const EndpointInfo& endpoint,
    DirectoryNamespace namespace_kind) noexcept {
    std::size_t accounted = 0;
    if (!EndpointFieldsValid(endpoint, namespace_kind, &accounted)) {
        return std::nullopt;
    }
    return accounted;
}

std::optional<EndpointInfo> try_directory_endpoint_from_json(
    const nlohmann::json& json,
    DirectoryNamespace namespace_kind,
    std::string* error) noexcept {
    try {
        if (!HasOnlyKnownFields(json, kEndpointFields) ||
            json.contains("endpoint_schema") ||
            !RequiredString(json, fields::endpoint_id,
                            kMaxDirectoryEndpointIdBytes, false) ||
            !RequiredString(json, fields::endpoint_kind, 16U, false) ||
            !RequiredString(json, fields::display_name,
                            kMaxDirectoryDisplayNameBytes, false) ||
            !RequiredString(json, fields::hostname,
                            kMaxDirectoryHostnameBytes, true) ||
            !RequiredString(json, fields::client_platform, 16U, false) ||
            !RequiredString(json, fields::client_variant, 16U, false) ||
            !RequiredString(json, fields::client_version,
                            kMaxDirectoryClientVersionBytes, true) ||
            !RequiredString(json, fields::server_id,
                            kMaxDirectoryServerIdBytes, true) ||
            !OptionalString(json, fields::server_name,
                            kMaxDirectoryServerNameBytes) ||
            !RequiredString(json, fields::relay_mode, 16U, false) ||
            !RequiredBool(json, fields::allow_inbound_admin) ||
            !RequiredBool(json, fields::allow_outbound_admin) ||
            !RequiredBool(json, fields::allow_chat) ||
            !RequiredBool(json, fields::allow_file) ||
            !RequiredBool(json, fields::allow_bytes) ||
            !RequiredBool(json, fields::online) ||
            !RequiredString(json, fields::auth_pubkey_b64,
                            kMaxDirectoryIdentityBase64Bytes, false)) {
            SetError(error, "directory endpoint has missing, unknown, or invalid fields");
            return std::nullopt;
        }
        const auto& endpoint_kind =
            json[fields::endpoint_kind].get_ref<const std::string&>();
        const auto& relay_mode =
            json[fields::relay_mode].get_ref<const std::string&>();
        const auto& platform =
            json[fields::client_platform].get_ref<const std::string&>();
        const auto& variant =
            json[fields::client_variant].get_ref<const std::string&>();
        if ((endpoint_kind != "client" && endpoint_kind != "server") ||
            (relay_mode != "untrusted" && relay_mode != "trusted") ||
            !IsKnownPlatform(platform) || !IsKnownVariant(variant) ||
            !IsBoundedCanonicalBase64(
                json[fields::auth_pubkey_b64]
                    .get_ref<const std::string&>(),
                kMaxDirectoryIdentityBytes)) {
            SetError(error, "directory endpoint enum or relay identity is invalid");
            return std::nullopt;
        }

        EndpointInfo endpoint;
        endpoint.endpoint_id = json[fields::endpoint_id].get<std::string>();
        endpoint.endpoint_kind = endpoint_kind == "server"
            ? EndpointKind::server : EndpointKind::client;
        endpoint.display_name = json[fields::display_name].get<std::string>();
        endpoint.hostname = json[fields::hostname].get<std::string>();
        endpoint.client_platform = platform;
        endpoint.client_variant = variant;
        endpoint.client_version =
            json[fields::client_version].get<std::string>();
        endpoint.server_id = json[fields::server_id].get<std::string>();
        endpoint.server_name = json.value(fields::server_name, "");
        endpoint.relay_mode = relay_mode == "trusted"
            ? RelayMode::trusted : RelayMode::untrusted;
        endpoint.allow_inbound_admin =
            json[fields::allow_inbound_admin].get<bool>();
        endpoint.allow_outbound_admin =
            json[fields::allow_outbound_admin].get<bool>();
        endpoint.allow_chat = json[fields::allow_chat].get<bool>();
        endpoint.allow_file = json[fields::allow_file].get<bool>();
        endpoint.allow_bytes = json[fields::allow_bytes].get<bool>();
        endpoint.online = json[fields::online].get<bool>();
        endpoint.auth_pubkey_b64 =
            json[fields::auth_pubkey_b64].get<std::string>();
        endpoint.remote = json.contains(fields::remote)
            ? json[fields::remote].get<bool>() : false;
        endpoint.federation_peer_id =
            json.value(fields::federation_peer_id, "");
        endpoint.remote_endpoint_id =
            json.value(fields::remote_endpoint_id, "");
        if (!ParseRelationships(json, fields::controller_ids,
                                &endpoint.controller_ids) ||
            !ParseRelationships(json, fields::controlled_target_ids,
                                &endpoint.controlled_target_ids)) {
            SetError(error, "directory endpoint relationships are invalid");
            return std::nullopt;
        }
        const auto accounted =
            directory_endpoint_accounted_bytes(endpoint, namespace_kind);
        if (!accounted) {
            SetError(error, "directory endpoint exceeds its identity or byte policy");
            return std::nullopt;
        }
        return endpoint;
    } catch (const std::exception&) {
        SetError(error, "directory endpoint parsing failed");
        return std::nullopt;
    }
}

std::optional<DirectoryResponse> try_directory_response_from_json(
    const nlohmann::json& json,
    DirectoryNamespace namespace_kind,
    std::string* error) noexcept {
    try {
        if (!HasOnlyKnownFields(json, kDirectoryFields) ||
            !RequiredString(json, "cmd", 32U, false) ||
            !RequiredBool(json, "ok") || !json["ok"].get<bool>() ||
            !OptionalString(json, "request_id",
                            kMaxDirectoryRequestIdBytes, false) ||
            !RequiredString(json, "server_id",
                            kMaxDirectoryServerIdBytes, true) ||
            !RequiredString(json, "server_name",
                            kMaxDirectoryServerNameBytes, true) ||
            !json.contains("endpoints") || !json["endpoints"].is_array() ||
            json["endpoints"].size() > kMaxDirectoryEndpoints) {
            SetError(error, "directory response envelope is invalid or oversized");
            return std::nullopt;
        }
        const std::string_view expected_command =
            namespace_kind == DirectoryNamespace::FederationRaw
            ? "federation.directory" : "directory.list";
        if (json["cmd"].get_ref<const std::string&>() != expected_command) {
            SetError(error, "directory response command does not match the request");
            return std::nullopt;
        }

        DirectoryResponse response;
        response.server_id = json["server_id"].get<std::string>();
        response.server_name = json["server_name"].get<std::string>();
        if (!is_valid_directory_server_identity(
                response.server_id, response.server_name,
                namespace_kind == DirectoryNamespace::FederationRaw)) {
            SetError(error, "directory response server identity is invalid");
            return std::nullopt;
        }
        response.endpoints.reserve(json["endpoints"].size());
        std::unordered_set<std::string> endpoint_ids;
        endpoint_ids.reserve(json["endpoints"].size());
        std::size_t accounted = kDirectoryEnvelopeOverheadBytes;
        if (!AddAccounted(response.server_id.size(),
                          kMaxDirectoryResponseBytes, &accounted) ||
            !AddAccounted(response.server_name.size(),
                          kMaxDirectoryResponseBytes, &accounted)) {
            SetError(error, "directory response envelope exceeds its byte policy");
            return std::nullopt;
        }
        for (const auto& item : json["endpoints"]) {
            std::string endpoint_error;
            auto endpoint = try_directory_endpoint_from_json(
                item, namespace_kind, &endpoint_error);
            if (!endpoint) {
                SetError(error, endpoint_error.empty()
                                    ? "directory endpoint is invalid"
                                    : endpoint_error);
                return std::nullopt;
            }
            if (!endpoint_ids.insert(endpoint->endpoint_id).second) {
                SetError(error, "directory response contains duplicate endpoint ids");
                return std::nullopt;
            }
            if ((!endpoint->remote ||
                 namespace_kind == DirectoryNamespace::FederationRaw) &&
                endpoint->server_id != response.server_id) {
                SetError(error, "directory endpoint server identity is inconsistent");
                return std::nullopt;
            }
            const auto endpoint_bytes =
                directory_endpoint_accounted_bytes(*endpoint, namespace_kind);
            if (!endpoint_bytes ||
                !AddAccounted(*endpoint_bytes, kMaxDirectoryResponseBytes,
                              &accounted)) {
                SetError(error, "directory response exceeds its aggregate byte policy");
                return std::nullopt;
            }
            response.endpoints.push_back(std::move(*endpoint));
        }
        return response;
    } catch (const std::exception&) {
        SetError(error, "directory response parsing failed");
        return std::nullopt;
    }
}

std::optional<PresenceAnnouncement> try_presence_announcement_from_json(
    const nlohmann::json& json,
    std::string* error) noexcept {
    try {
        if (!HasOnlyKnownFields(json, kPresenceFields) ||
            json.contains("presence_schema") ||
            !RequiredString(json, "cmd", 32U, false) ||
            json["cmd"].get_ref<const std::string&>() !=
                "presence.announce" ||
            !OptionalString(json, "request_id",
                            kMaxDirectoryRequestIdBytes, false) ||
            !RequiredString(json, fields::endpoint_kind, 16U, false) ||
            !RequiredString(json, "preferred_id",
                            kMaxDirectoryEndpointIdBytes, true) ||
            !RequiredString(json, "preferred_name",
                            kMaxDirectoryDisplayNameBytes, true) ||
            !RequiredString(json, fields::hostname,
                            kMaxDirectoryHostnameBytes, true) ||
            !RequiredString(json, fields::client_platform, 16U, false) ||
            !RequiredString(json, fields::client_variant, 16U, false) ||
            !RequiredString(json, fields::client_version,
                            kMaxDirectoryClientVersionBytes, true) ||
            !RequiredString(json, fields::relay_mode, 16U, false) ||
            !RequiredBool(json, fields::allow_chat) ||
            !RequiredBool(json, fields::allow_file) ||
            !RequiredBool(json, fields::allow_bytes) ||
            !RequiredBool(json, fields::allow_inbound_admin) ||
            !RequiredBool(json, fields::allow_outbound_admin)) {
            SetError(error, "presence announcement has missing, unknown, or invalid fields");
            return std::nullopt;
        }
        const auto& endpoint_kind =
            json[fields::endpoint_kind].get_ref<const std::string&>();
        const auto& relay_mode =
            json[fields::relay_mode].get_ref<const std::string&>();
        const auto& platform =
            json[fields::client_platform].get_ref<const std::string&>();
        const auto& variant =
            json[fields::client_variant].get_ref<const std::string&>();
        if ((endpoint_kind != "client" && endpoint_kind != "server") ||
            (relay_mode != "untrusted" && relay_mode != "trusted") ||
            !IsKnownPlatform(platform) || !IsKnownVariant(variant)) {
            SetError(error, "presence announcement enums are invalid");
            return std::nullopt;
        }

        PresenceAnnouncement announce;
        announce.endpoint_kind = endpoint_kind == "server"
            ? EndpointKind::server : EndpointKind::client;
        announce.preferred_id = json["preferred_id"].get<std::string>();
        announce.preferred_name = json["preferred_name"].get<std::string>();
        announce.hostname = json[fields::hostname].get<std::string>();
        announce.client_platform = platform;
        announce.client_variant = variant;
        announce.client_version =
            json[fields::client_version].get<std::string>();
        announce.relay_mode = relay_mode == "trusted"
            ? RelayMode::trusted : RelayMode::untrusted;
        announce.allow_chat = json[fields::allow_chat].get<bool>();
        announce.allow_file = json[fields::allow_file].get<bool>();
        announce.allow_bytes = json[fields::allow_bytes].get<bool>();
        announce.allow_inbound_admin =
            json[fields::allow_inbound_admin].get<bool>();
        announce.allow_outbound_admin =
            json[fields::allow_outbound_admin].get<bool>();
        return announce;
    } catch (const std::exception&) {
        SetError(error, "presence announcement parsing failed");
        return std::nullopt;
    }
}

static_assert(kMaxDirectoryEndpointIdBytes == 255U);
static_assert(kMaxDirectoryEndpoints > 0U);
static_assert(kMaxFederatedCachedEndpoints >= kMaxDirectoryEndpoints);
static_assert(kMaxDirectoryResponseBytes < 16U * 1024U * 1024U);

}  // namespace yume::control
