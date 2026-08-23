/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/protocol/relay_policy.hpp"

#include <array>
#include <cstdint>
#include <exception>
#include <limits>

#include "core/protocol/control_fields.hpp"

namespace yume::control {

namespace {

bool IsBase64Character(char value) noexcept {
    return (value >= 'A' && value <= 'Z') ||
        (value >= 'a' && value <= 'z') ||
        (value >= '0' && value <= '9') || value == '+' || value == '/';
}

bool IsBoundedBase64(std::string_view encoded,
                     std::size_t max_decoded_bytes,
                     bool allow_empty = false) noexcept {
    if (encoded.empty()) return allow_empty;
    if ((encoded.size() % 4U) != 0U) return false;

    // The encoded cap prevents arithmetic overflow and cheaply rejects an
    // oversized record before examining every byte. The final decoded-length
    // check is still required because 43,692 unpadded characters represent
    // 32,769 bytes, one byte over relay-v2's record limit.
    const std::size_t max_encoded =
        4U * ((max_decoded_bytes + 2U) / 3U);
    if (encoded.size() > max_encoded) return false;

    std::size_t padding = 0;
    if (encoded.back() == '=') {
        padding = 1;
        if (encoded.size() >= 2U && encoded[encoded.size() - 2U] == '=') {
            padding = 2;
        }
    }
    const std::size_t data_bytes = encoded.size() - padding;
    for (std::size_t index = 0; index < data_bytes; ++index) {
        if (!IsBase64Character(encoded[index])) return false;
    }
    for (std::size_t index = data_bytes; index < encoded.size(); ++index) {
        if (encoded[index] != '=') return false;
    }
    // One non-padding symbol cannot represent a complete final quantum. This
    // also rejects impossible padding spellings such as "A===".
    if ((data_bytes % 4U) == 1U) return false;

    const std::size_t decoded_bytes =
        (encoded.size() / 4U) * 3U - padding;
    return decoded_bytes <= max_decoded_bytes;
}

bool HasRequiredString(const nlohmann::json& json,
                       const char* key,
                       std::size_t max_bytes,
                       bool allow_empty) {
    if (!json.contains(key) || !json[key].is_string()) return false;
    const auto& value = json[key].get_ref<const std::string&>();
    return value.size() <= max_bytes && (allow_empty || !value.empty());
}

bool HasOptionalString(const nlohmann::json& json,
                       const char* key,
                       std::size_t max_bytes) {
    return !json.contains(key) ||
        (json[key].is_string() &&
         json[key].get_ref<const std::string&>().size() <= max_bytes);
}

bool HasExactRelayVersion(const nlohmann::json& json) {
    if (!json.contains(fields::relay_protocol_version)) return false;
    const auto& version = json[fields::relay_protocol_version];
    if (!version.is_number_integer() && !version.is_number_unsigned()) {
        return false;
    }
    if (version.is_number_unsigned()) {
        return version.get<std::uint64_t>() == kRelayProtocolVersion;
    }
    return version.get<std::int64_t>() == kRelayProtocolVersion;
}

bool HasNonNegativeCreatedTime(const nlohmann::json& json) {
    if (!json.contains(fields::created_ms)) return false;
    const auto& created = json[fields::created_ms];
    if (!created.is_number_integer() && !created.is_number_unsigned()) {
        return false;
    }
    if (created.is_number_unsigned()) {
        return created.get<std::uint64_t>() <=
            static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    }
    return created.get<std::int64_t>() >= 0;
}

bool HasOptionalBoundedBase64(const nlohmann::json& json,
                              const char* key,
                              std::size_t max_decoded_bytes) {
    if (!json.contains(key)) return true;
    if (!json[key].is_string()) return false;
    const auto& value = json[key].get_ref<const std::string&>();
    return value.empty() || IsBoundedBase64(value, max_decoded_bytes);
}

bool HasLegacyOrAmbiguousRelayField(const nlohmann::json& json) {
    // Reject even empty legacy/alternate-version fields. Accepting a record
    // that carries both generations would create an ambiguous downgrade
    // surface.
    static constexpr std::array<std::string_view, 7> kLegacyFields{
        "ephemeral_pubkey_b64",
        "ephemeral_signature_b64",
        "nonce_b64",
        "response_ephemeral_pubkey_b64",
        "response_ephemeral_signature_b64",
        "protocol_version",
        "version",
    };
    for (const auto field : kLegacyFields) {
        if (json.contains(field)) return true;
    }
    return false;
}

bool JsonCommandDirectionMatches(const nlohmann::json& json,
                                 bool response_present) {
    if (!json.contains("cmd")) return true;
    if (!json["cmd"].is_string()) return false;
    const auto& command = json["cmd"].get_ref<const std::string&>();
    if (command == "invite.request" ||
        command == "federation.invite.request") {
        return !response_present;
    }
    if (command == "invite.reply" ||
        command == "federation.invite.reply") {
        return response_present;
    }
    return true;
}

bool IsKnownRelayChannelKind(ChannelKind kind) noexcept {
    switch (kind) {
        case ChannelKind::chat:
        case ChannelKind::file:
        case ChannelKind::bytes:
        case ChannelKind::admin:
            return true;
    }
    return false;
}

bool RelayV2CommonFieldsValid(const PendingInvite& invite) noexcept {
    return invite.relay_protocol_version == kRelayProtocolVersion &&
        IsKnownRelayChannelKind(invite.channel_kind) &&
        !invite.invite_id.empty() &&
        invite.invite_id.size() <= kMaxRelayInviteIdBytes &&
        !invite.from_endpoint_id.empty() &&
        invite.from_endpoint_id.size() <= kMaxRelayEndpointIdBytes &&
        !invite.to_endpoint_id.empty() &&
        invite.to_endpoint_id.size() <= kMaxRelayEndpointIdBytes &&
        invite.created_ms >= 0 &&
        invite.from_display_name.size() <= kMaxRelayDisplayNameBytes &&
        invite.metadata_json.size() <= kMaxRelayMetadataBytes &&
        IsBoundedBase64(invite.handshake_request_b64,
                        kMaxRelayHandshakeRecordBytes) &&
        !invite.from_auth_pubkey_b64.empty() &&
        IsBoundedBase64(invite.from_auth_pubkey_b64,
                        kMaxRelayHandshakeRecordBytes) &&
        relay_v2_password_policy_valid(invite.channel_kind,
                                       invite.requires_password);
}

}  // namespace

std::optional<ChannelKind> try_relay_channel_kind(std::string_view value) {
    if (value == "chat") return ChannelKind::chat;
    if (value == "file") return ChannelKind::file;
    if (value == "bytes") return ChannelKind::bytes;
    if (value == "admin") return ChannelKind::admin;
    return std::nullopt;
}

std::optional<RelayMessageType> try_relay_message_type(
    std::string_view value) {
    if (value == "chat") return RelayMessageType::chat;
    if (value == "file_meta") return RelayMessageType::file_meta;
    if (value == "file_chunk") return RelayMessageType::file_chunk;
    if (value == "file_done") return RelayMessageType::file_done;
    if (value == "bytes_meta") return RelayMessageType::bytes_meta;
    if (value == "bytes_chunk") return RelayMessageType::bytes_chunk;
    if (value == "bytes_done") return RelayMessageType::bytes_done;
    if (value == "admin_req") return RelayMessageType::admin_request;
    if (value == "admin_resp") return RelayMessageType::admin_response;
    return std::nullopt;
}

std::optional<PendingInvite> try_relay_invite_from_json(
    const nlohmann::json& json) noexcept {
    try {
        if (!json.is_object() || HasLegacyOrAmbiguousRelayField(json) ||
            json.contains(fields::metadata) || !HasExactRelayVersion(json) ||
            !HasRequiredString(json, fields::invite_id,
                               kMaxRelayInviteIdBytes, false) ||
            !HasRequiredString(json, fields::from_id,
                               kMaxRelayEndpointIdBytes, true) ||
            !HasRequiredString(json, fields::to_id,
                               kMaxRelayEndpointIdBytes, false) ||
            !HasRequiredString(json, fields::channel_kind, 16, false) ||
            !HasNonNegativeCreatedTime(json) ||
            !json.contains(fields::requires_password) ||
            !json[fields::requires_password].is_boolean() ||
            !HasRequiredString(json, fields::metadata_json,
                               kMaxRelayMetadataBytes, true) ||
            !HasRequiredString(json, fields::handshake_request_b64,
                               kMaxRelayHandshakeRecordBase64Bytes, false) ||
            !HasOptionalString(json, fields::from_display_name,
                               kMaxRelayDisplayNameBytes) ||
            !HasOptionalString(json, fields::from_auth_pubkey_b64,
                               kMaxRelayHandshakeRecordBase64Bytes) ||
            !HasOptionalString(json, fields::reason,
                               kMaxRelayResponseReasonBytes) ||
            !HasOptionalString(json, fields::handshake_response_b64,
                               kMaxRelayHandshakeRecordBase64Bytes) ||
            !HasOptionalString(json, fields::responder_auth_pubkey_b64,
                               kMaxRelayHandshakeRecordBase64Bytes)) {
            return std::nullopt;
        }
        const auto kind = try_relay_channel_kind(
            json[fields::channel_kind].get_ref<const std::string&>());
        if (!kind) return std::nullopt;
        if (!IsBoundedBase64(
                json[fields::handshake_request_b64]
                    .get_ref<const std::string&>(),
                kMaxRelayHandshakeRecordBytes) ||
            !HasOptionalBoundedBase64(json, fields::from_auth_pubkey_b64,
                                      kMaxRelayHandshakeRecordBytes)) {
            return std::nullopt;
        }

        const bool response_present = json.contains(fields::accepted);
        if (!JsonCommandDirectionMatches(json, response_present)) {
            return std::nullopt;
        }
        if (!response_present) {
            if (json.contains(fields::reason) ||
                json.contains(fields::handshake_response_b64) ||
                json.contains(fields::responder_auth_pubkey_b64)) {
                return std::nullopt;
            }
        } else {
            if (!json[fields::accepted].is_boolean()) return std::nullopt;
            const bool accepted = json[fields::accepted].get<bool>();
            if (accepted) {
                if (!json.contains(fields::handshake_response_b64) ||
                    !json[fields::handshake_response_b64].is_string() ||
                    !IsBoundedBase64(
                        json[fields::handshake_response_b64]
                            .get_ref<const std::string&>(),
                        kMaxRelayHandshakeRecordBytes) ||
                    !HasOptionalBoundedBase64(
                        json, fields::responder_auth_pubkey_b64,
                        kMaxRelayHandshakeRecordBytes)) {
                    return std::nullopt;
                }
            } else if (json.contains(fields::handshake_response_b64) ||
                       json.contains(fields::responder_auth_pubkey_b64)) {
                return std::nullopt;
            }
        }
        auto invite = invite_from_json(json);
        if (invite.channel_kind != *kind ||
            !relay_v2_password_policy_valid(*kind,
                                            invite.requires_password)) {
            return std::nullopt;
        }
        return invite;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

bool relay_kind_requires_password(ChannelKind kind) noexcept {
    return kind != ChannelKind::admin;
}

bool relay_v2_password_policy_valid(ChannelKind kind,
                                    bool requires_password) noexcept {
    return requires_password == relay_kind_requires_password(kind);
}

bool relay_v2_invite_request_valid(const PendingInvite& invite) noexcept {
    return RelayV2CommonFieldsValid(invite) && !invite.response_present &&
        !invite.accepted && invite.response_reason.empty() &&
        invite.handshake_response_b64.empty() &&
        invite.responder_auth_pubkey_b64.empty();
}

bool relay_v2_invite_response_valid(const PendingInvite& invite) noexcept {
    if (!RelayV2CommonFieldsValid(invite) || !invite.response_present ||
        invite.response_reason.size() > kMaxRelayResponseReasonBytes) {
        return false;
    }
    if (!invite.accepted) {
        return invite.handshake_response_b64.empty() &&
            invite.responder_auth_pubkey_b64.empty();
    }
    return IsBoundedBase64(invite.handshake_response_b64,
                           kMaxRelayHandshakeRecordBytes) &&
        !invite.responder_auth_pubkey_b64.empty() &&
        IsBoundedBase64(invite.responder_auth_pubkey_b64,
                        kMaxRelayHandshakeRecordBytes);
}

bool relay_v2_request_fields_match(const PendingInvite& expected,
                                   const PendingInvite& response) noexcept {
    return response.relay_protocol_version ==
            expected.relay_protocol_version &&
        response.invite_id == expected.invite_id &&
        response.from_endpoint_id == expected.from_endpoint_id &&
        response.to_endpoint_id == expected.to_endpoint_id &&
        response.channel_kind == expected.channel_kind &&
        response.created_ms == expected.created_ms &&
        response.requires_password == expected.requires_password &&
        response.metadata_json == expected.metadata_json &&
        response.handshake_request_b64 == expected.handshake_request_b64 &&
        response.from_display_name == expected.from_display_name &&
        response.from_auth_pubkey_b64 == expected.from_auth_pubkey_b64;
}

bool relay_target_allows(const EndpointInfo& target,
                         ChannelKind kind) noexcept {
    switch (kind) {
        case ChannelKind::chat:
            return target.allow_chat;
        case ChannelKind::file:
            return target.allow_file;
        case ChannelKind::bytes:
            return target.allow_bytes;
        case ChannelKind::admin:
            return target.allow_inbound_admin;
    }
    return false;
}

namespace {

RelayMessagePolicyDecision Reject(std::string_view reason,
                                  RelayTransferPhase phase) noexcept {
    return {false, phase, reason};
}

RelayMessagePolicyDecision Allow(RelayTransferPhase phase) noexcept {
    return {true, phase, {}};
}

RelayMessagePolicyDecision EvaluateTransfer(
    const RelayMessagePolicyInput& input,
    RelayMessageType metadata,
    RelayMessageType chunk,
    RelayMessageType done) noexcept {
    if (input.role != RelayChannelRole::responder) {
        return Reject("transfer initiator must not receive channel DATA",
                      input.transfer_phase);
    }
    switch (input.transfer_phase) {
        case RelayTransferPhase::awaiting_metadata:
            if (input.message_type == metadata) {
                return Allow(RelayTransferPhase::receiving);
            }
            return Reject("transfer metadata must be first",
                          input.transfer_phase);
        case RelayTransferPhase::receiving:
            if (input.message_type == chunk) {
                return Allow(RelayTransferPhase::receiving);
            }
            if (input.message_type == done) {
                return Allow(RelayTransferPhase::complete);
            }
            return Reject("transfer expects a chunk or completion",
                          input.transfer_phase);
        case RelayTransferPhase::complete:
            return Reject("transfer DATA received after completion",
                          input.transfer_phase);
    }
    return Reject("invalid transfer state", input.transfer_phase);
}

}  // namespace

RelayMessagePolicyDecision evaluate_relay_message_policy(
    const RelayMessagePolicyInput& input) noexcept {
    switch (input.channel_kind) {
        case ChannelKind::chat:
            if (input.message_type == RelayMessageType::chat) {
                return Allow(input.transfer_phase);
            }
            return Reject("non-chat message on chat channel",
                          input.transfer_phase);
        case ChannelKind::file:
            return EvaluateTransfer(input,
                                    RelayMessageType::file_meta,
                                    RelayMessageType::file_chunk,
                                    RelayMessageType::file_done);
        case ChannelKind::bytes:
            return EvaluateTransfer(input,
                                    RelayMessageType::bytes_meta,
                                    RelayMessageType::bytes_chunk,
                                    RelayMessageType::bytes_done);
        case ChannelKind::admin:
            if (input.role == RelayChannelRole::responder) {
                if (!input.inbound_admin_allowed) {
                    return Reject("inbound admin is not authorized",
                                  input.transfer_phase);
                }
                if (input.message_type == RelayMessageType::admin_request) {
                    return Allow(input.transfer_phase);
                }
                return Reject("admin responder accepts requests only",
                              input.transfer_phase);
            }
            if (input.message_type != RelayMessageType::admin_response) {
                return Reject("admin initiator accepts responses only",
                              input.transfer_phase);
            }
            if (!input.admin_response_outstanding) {
                return Reject("unsolicited admin response",
                              input.transfer_phase);
            }
            return Allow(input.transfer_phase);
    }
    return Reject("invalid relay channel kind", input.transfer_phase);
}

}  // namespace yume::control
