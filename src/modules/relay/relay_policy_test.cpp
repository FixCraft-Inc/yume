/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "modules/relay/relay_policy.hpp"
#include "modules/relay/relay_limits.hpp"

#include <cassert>
#include <chrono>
#include <cstddef>
#include <string>

namespace {

using yume::relay::ChannelKind;
using yume::relay::RelayChannelRole;
using yume::relay::RelayMessagePolicyInput;
using yume::relay::RelayMessageType;
using yume::relay::RelayTransferPhase;

std::string ZeroBytesBase64(std::size_t bytes) {
    std::string encoded((bytes / 3U) * 4U, 'A');
    switch (bytes % 3U) {
        case 0:
            break;
        case 1:
            encoded += "AA==";
            break;
        case 2:
            encoded += "AAA=";
            break;
    }
    return encoded;
}

nlohmann::json ValidRelayV2Request() {
    return {
        {"cmd", "invite.request"},
        {"relay_protocol_version", 2},
        {"invite_id", "invite"},
        {"from_id", "from"},
        {"to_id", "to"},
        {"channel_kind", "file"},
        {"created_ms", 1234},
        {"requires_password", true},
        {"metadata_json", R"({"name":"exact representation"})"},
        {"handshake_request_b64", "YQ=="},
        {"from_display_name", "From"},
        {"from_auth_pubkey_b64", "Yg=="},
    };
}

bool Allowed(ChannelKind kind,
             RelayChannelRole role,
             RelayTransferPhase phase,
             RelayMessageType type,
             bool inbound_admin = false,
             bool response_outstanding = false) {
    return yume::relay::evaluate_relay_message_policy(
               RelayMessagePolicyInput{kind,
                                       role,
                                       phase,
                                       type,
                                       inbound_admin,
                                       response_outstanding})
        .allowed;
}

}  // namespace

int main() {
    using namespace yume::relay;

    assert(try_relay_channel_kind("chat") == ChannelKind::Chat);
    assert(try_relay_channel_kind("file") == ChannelKind::File);
    assert(!try_relay_channel_kind("Chat"));
    assert(!try_relay_channel_kind("unknown"));
    assert(try_relay_message_type("admin_req") ==
           RelayMessageType::AdminRequest);
    assert(!try_relay_message_type("runtime.stop"));

    const nlohmann::json valid_invite = ValidRelayV2Request();
    const auto parsed_request = try_relay_invite_from_json(valid_invite);
    assert(parsed_request);
    assert(parsed_request->created_ms == 1234);
    assert(!parsed_request->response_present);
    assert(relay_v2_invite_request_valid(*parsed_request));

    const auto encoded_request = invite_to_json(*parsed_request, false);
    assert(encoded_request.at("relay_protocol_version") == 2);
    assert(encoded_request.at("metadata_json") ==
           valid_invite.at("metadata_json"));
    assert(encoded_request.at("created_ms") == valid_invite.at("created_ms"));
    assert(!encoded_request.contains("metadata"));
    assert(!encoded_request.contains("accepted"));
    assert(!encoded_request.contains("nonce_b64"));
    assert(!encoded_request.contains("ephemeral_pubkey_b64"));

    auto bad_invite = valid_invite;
    bad_invite["requires_password"] = "yes";
    assert(!try_relay_invite_from_json(bad_invite));
    bad_invite = valid_invite;
    bad_invite["channel_kind"] = "future-kind";
    assert(!try_relay_invite_from_json(bad_invite));
    bad_invite = valid_invite;
    bad_invite["metadata"] = nlohmann::json::array();
    assert(!try_relay_invite_from_json(bad_invite));
    for (const char* string_field : {
             "invite_id", "from_id", "to_id", "channel_kind",
             "metadata_json", "handshake_request_b64",
             "from_display_name", "from_auth_pubkey_b64",
         }) {
        bad_invite = valid_invite;
        bad_invite[string_field] = 7;
        assert(!try_relay_invite_from_json(bad_invite));
    }
    bad_invite = valid_invite;
    bad_invite["created_ms"] = "1234";
    assert(!try_relay_invite_from_json(bad_invite));
    bad_invite["created_ms"] = 1234.0;
    assert(!try_relay_invite_from_json(bad_invite));
    bad_invite["created_ms"] = -1;
    assert(!try_relay_invite_from_json(bad_invite));
    bad_invite = valid_invite;
    bad_invite.erase("relay_protocol_version");
    assert(!try_relay_invite_from_json(bad_invite));
    bad_invite = valid_invite;
    bad_invite["relay_protocol_version"] = 1;
    assert(!try_relay_invite_from_json(bad_invite));
    bad_invite["relay_protocol_version"] = 3;
    assert(!try_relay_invite_from_json(bad_invite));
    bad_invite["relay_protocol_version"] = 2.0;
    assert(!try_relay_invite_from_json(bad_invite));
    bad_invite["relay_protocol_version"] = "2";
    assert(!try_relay_invite_from_json(bad_invite));
    bad_invite = valid_invite;
    bad_invite.erase("handshake_request_b64");
    assert(!try_relay_invite_from_json(bad_invite));
    bad_invite["handshake_request_b64"] = "";
    assert(!try_relay_invite_from_json(bad_invite));
    bad_invite["handshake_request_b64"] = "!!!!";
    assert(!try_relay_invite_from_json(bad_invite));

    bad_invite = valid_invite;
    bad_invite["handshake_request_b64"] =
        ZeroBytesBase64(kMaxRelayHandshakeRecordBytes);
    assert(try_relay_invite_from_json(bad_invite));
    bad_invite["handshake_request_b64"] =
        ZeroBytesBase64(kMaxRelayHandshakeRecordBytes + 1U);
    assert(!try_relay_invite_from_json(bad_invite));

    for (const char* legacy_field : {
             "ephemeral_pubkey_b64",
             "ephemeral_signature_b64",
             "nonce_b64",
             "response_ephemeral_pubkey_b64",
             "response_ephemeral_signature_b64",
             "protocol_version",
             "version",
         }) {
        bad_invite = valid_invite;
        bad_invite[legacy_field] = "";
        assert(!try_relay_invite_from_json(bad_invite));
    }

    // A request command cannot smuggle response semantics, and a reply
    // command cannot turn a missing `accepted` key into an implicit reject.
    bad_invite = valid_invite;
    bad_invite["accepted"] = false;
    assert(!try_relay_invite_from_json(bad_invite));
    bad_invite = valid_invite;
    bad_invite["cmd"] = "invite.reply";
    assert(!try_relay_invite_from_json(bad_invite));

    auto accepted_json = valid_invite;
    accepted_json["cmd"] = "invite.reply";
    accepted_json["accepted"] = true;
    accepted_json["handshake_response_b64"] = "Yw==";
    accepted_json["responder_auth_pubkey_b64"] = "ZA==";
    const auto parsed_response = try_relay_invite_from_json(accepted_json);
    assert(parsed_response);
    assert(parsed_response->response_present);
    assert(parsed_response->accepted);
    assert(relay_v2_invite_response_valid(*parsed_response));
    assert(relay_v2_request_fields_match(*parsed_request, *parsed_response));
    const auto encoded_response = invite_to_json(*parsed_response, true);
    const auto reparsed_response =
        try_relay_invite_from_json(encoded_response);
    assert(reparsed_response);
    assert(relay_v2_invite_response_valid(*reparsed_response));
    assert(encoded_response.at("metadata_json") ==
           valid_invite.at("metadata_json"));

    bad_invite = accepted_json;
    bad_invite["accepted"] = "true";
    assert(!try_relay_invite_from_json(bad_invite));
    bad_invite = accepted_json;
    bad_invite["reason"] = nlohmann::json::object();
    assert(!try_relay_invite_from_json(bad_invite));
    bad_invite = accepted_json;
    bad_invite["handshake_response_b64"] = 7;
    assert(!try_relay_invite_from_json(bad_invite));
    bad_invite = accepted_json;
    bad_invite["responder_auth_pubkey_b64"] = 7;
    assert(!try_relay_invite_from_json(bad_invite));

    auto missing_responder = accepted_json;
    missing_responder.erase("responder_auth_pubkey_b64");
    const auto parsed_missing_responder =
        try_relay_invite_from_json(missing_responder);
    // A local server may fill an omitted claim from the authenticated session,
    // but the fully corroborated object is not manager-admissible yet.
    assert(parsed_missing_responder);
    assert(!relay_v2_invite_response_valid(*parsed_missing_responder));
    bad_invite = accepted_json;
    bad_invite.erase("handshake_response_b64");
    assert(!try_relay_invite_from_json(bad_invite));
    bad_invite = accepted_json;
    bad_invite["handshake_response_b64"] =
        ZeroBytesBase64(kMaxRelayHandshakeRecordBytes + 1U);
    assert(!try_relay_invite_from_json(bad_invite));

    auto rejected_json = valid_invite;
    rejected_json["cmd"] = "invite.reply";
    rejected_json["accepted"] = false;
    rejected_json["reason"] = "declined";
    const auto parsed_rejection = try_relay_invite_from_json(rejected_json);
    assert(parsed_rejection);
    assert(relay_v2_invite_response_valid(*parsed_rejection));
    rejected_json["handshake_response_b64"] = "Yw==";
    assert(!try_relay_invite_from_json(rejected_json));
    rejected_json.erase("handshake_response_b64");
    rejected_json["responder_auth_pubkey_b64"] = "ZA==";
    assert(!try_relay_invite_from_json(rejected_json));

    auto changed = *parsed_response;
    changed.relay_protocol_version = 1;
    assert(!relay_v2_request_fields_match(*parsed_request, changed));
    changed = *parsed_response;
    changed.invite_id += "-changed";
    assert(!relay_v2_request_fields_match(*parsed_request, changed));
    changed = *parsed_response;
    changed.from_endpoint_id += "-changed";
    assert(!relay_v2_request_fields_match(*parsed_request, changed));
    changed = *parsed_response;
    changed.to_endpoint_id += "-changed";
    assert(!relay_v2_request_fields_match(*parsed_request, changed));
    changed = *parsed_response;
    changed.channel_kind = ChannelKind::Bytes;
    assert(!relay_v2_request_fields_match(*parsed_request, changed));
    changed = *parsed_response;
    ++changed.created_ms;
    assert(!relay_v2_request_fields_match(*parsed_request, changed));
    changed = *parsed_response;
    changed.requires_password = false;
    assert(!relay_v2_request_fields_match(*parsed_request, changed));
    changed = *parsed_response;
    changed.metadata_json += " ";
    assert(!relay_v2_request_fields_match(*parsed_request, changed));
    changed = *parsed_response;
    changed.handshake_request_b64 = "ZQ==";
    assert(!relay_v2_request_fields_match(*parsed_request, changed));
    changed = *parsed_response;
    changed.from_display_name += "-changed";
    assert(!relay_v2_request_fields_match(*parsed_request, changed));
    changed = *parsed_response;
    changed.from_auth_pubkey_b64 = "Zg==";
    assert(!relay_v2_request_fields_match(*parsed_request, changed));

    assert(relay_v2_password_policy_valid(ChannelKind::Chat, true));
    assert(relay_v2_password_policy_valid(ChannelKind::File, true));
    assert(relay_v2_password_policy_valid(ChannelKind::Bytes, true));
    assert(relay_v2_password_policy_valid(ChannelKind::Admin, false));
    assert(!relay_v2_password_policy_valid(ChannelKind::Chat, false));
    assert(!relay_v2_password_policy_valid(ChannelKind::Admin, true));
    auto invalid_kind_request = *parsed_request;
    invalid_kind_request.channel_kind = static_cast<ChannelKind>(255);
    assert(!relay_v2_invite_request_valid(invalid_kind_request));

    using Admission = PendingRelayInviteAdmission;
    assert(pending_relay_invite_admission(0, 0, 0) ==
           Admission::Allowed);
    assert(pending_relay_invite_admission(
               kMaxPendingRelayInvitesPerServer - 1,
               kMaxPendingRelayInvitesPerEndpoint - 1,
               kMaxPendingRelayInvitesPerEndpoint - 1) ==
           Admission::Allowed);
    assert(pending_relay_invite_admission(
               kMaxPendingRelayInvitesPerServer, 0, 0) ==
           Admission::ServerLimit);
    assert(pending_relay_invite_admission(
               0, kMaxPendingRelayInvitesPerEndpoint, 0) ==
           Admission::OriginLimit);
    assert(pending_relay_invite_admission(
               0, 0, kMaxPendingRelayInvitesPerEndpoint) ==
           Admission::TargetLimit);
    const auto now = std::chrono::steady_clock::time_point(
        std::chrono::seconds(10));
    assert(!pending_relay_invite_expired(
        now + std::chrono::nanoseconds(1), now));
    assert(pending_relay_invite_expired(now, now));
    assert(pending_relay_invite_expired(
        now - std::chrono::nanoseconds(1), now));

    EndpointInfo endpoint;
    endpoint.allow_chat = false;
    endpoint.allow_file = true;
    endpoint.allow_bytes = false;
    endpoint.allow_inbound_admin = true;
    assert(!relay_target_allows(endpoint, ChannelKind::Chat));
    assert(relay_target_allows(endpoint, ChannelKind::File));
    assert(!relay_target_allows(endpoint, ChannelKind::Bytes));
    assert(relay_target_allows(endpoint, ChannelKind::Admin));

    for (const auto role : {RelayChannelRole::Initiator,
                            RelayChannelRole::Responder}) {
        assert(Allowed(ChannelKind::Chat,
                       role,
                       RelayTransferPhase::AwaitingMetadata,
                       RelayMessageType::Chat));
        assert(!Allowed(ChannelKind::Chat,
                        role,
                        RelayTransferPhase::AwaitingMetadata,
                        RelayMessageType::AdminRequest,
                        true));
        assert(!Allowed(ChannelKind::Chat,
                        role,
                        RelayTransferPhase::AwaitingMetadata,
                        RelayMessageType::FileMeta));
    }

    assert(!Allowed(ChannelKind::File,
                    RelayChannelRole::Initiator,
                    RelayTransferPhase::AwaitingMetadata,
                    RelayMessageType::FileMeta));
    assert(Allowed(ChannelKind::File,
                   RelayChannelRole::Responder,
                   RelayTransferPhase::AwaitingMetadata,
                   RelayMessageType::FileMeta));
    assert(!Allowed(ChannelKind::File,
                    RelayChannelRole::Responder,
                    RelayTransferPhase::AwaitingMetadata,
                    RelayMessageType::FileChunk));
    assert(Allowed(ChannelKind::File,
                   RelayChannelRole::Responder,
                   RelayTransferPhase::Receiving,
                   RelayMessageType::FileChunk));
    assert(Allowed(ChannelKind::File,
                   RelayChannelRole::Responder,
                   RelayTransferPhase::Receiving,
                   RelayMessageType::FileDone));
    assert(!Allowed(ChannelKind::File,
                    RelayChannelRole::Responder,
                    RelayTransferPhase::Complete,
                    RelayMessageType::FileDone));
    assert(!Allowed(ChannelKind::File,
                    RelayChannelRole::Responder,
                    RelayTransferPhase::Receiving,
                    RelayMessageType::BytesChunk));

    assert(Allowed(ChannelKind::Bytes,
                   RelayChannelRole::Responder,
                   RelayTransferPhase::AwaitingMetadata,
                   RelayMessageType::BytesMeta));
    assert(Allowed(ChannelKind::Bytes,
                   RelayChannelRole::Responder,
                   RelayTransferPhase::Receiving,
                   RelayMessageType::BytesChunk));
    assert(Allowed(ChannelKind::Bytes,
                   RelayChannelRole::Responder,
                   RelayTransferPhase::Receiving,
                   RelayMessageType::BytesDone));
    assert(!Allowed(ChannelKind::Bytes,
                    RelayChannelRole::Responder,
                    RelayTransferPhase::Receiving,
                    RelayMessageType::FileChunk));

    assert(Allowed(ChannelKind::Admin,
                   RelayChannelRole::Responder,
                   RelayTransferPhase::AwaitingMetadata,
                   RelayMessageType::AdminRequest,
                   true));
    assert(!Allowed(ChannelKind::Admin,
                    RelayChannelRole::Responder,
                    RelayTransferPhase::AwaitingMetadata,
                    RelayMessageType::AdminRequest,
                    false));
    assert(!Allowed(ChannelKind::Admin,
                    RelayChannelRole::Responder,
                    RelayTransferPhase::AwaitingMetadata,
                    RelayMessageType::AdminResponse,
                    true,
                    true));
    assert(Allowed(ChannelKind::Admin,
                   RelayChannelRole::Initiator,
                   RelayTransferPhase::AwaitingMetadata,
                   RelayMessageType::AdminResponse,
                   false,
                   true));
    assert(!Allowed(ChannelKind::Admin,
                    RelayChannelRole::Initiator,
                    RelayTransferPhase::AwaitingMetadata,
                    RelayMessageType::AdminResponse));
    assert(!Allowed(ChannelKind::Admin,
                    RelayChannelRole::Initiator,
                    RelayTransferPhase::AwaitingMetadata,
                    RelayMessageType::AdminRequest,
                    true,
                    true));

    return 0;
}
