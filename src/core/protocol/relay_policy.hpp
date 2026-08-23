/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include "core/protocol/control_protocol.hpp"

namespace yume::control {

inline constexpr std::uint16_t kRelayProtocolVersion =
    PendingInvite::kRelayProtocolVersion;
inline constexpr std::size_t kMaxRelayHandshakeRecordBytes = 32U * 1024U;
inline constexpr std::size_t kMaxRelayHandshakeRecordBase64Bytes =
    4U * ((kMaxRelayHandshakeRecordBytes + 2U) / 3U);
inline constexpr std::size_t kMaxRelayInviteIdBytes = 128;
inline constexpr std::size_t kMaxRelayEndpointIdBytes = 255;
inline constexpr std::size_t kMaxRelayDisplayNameBytes = 256;
inline constexpr std::size_t kMaxRelayMetadataBytes = 16U * 1024U;
inline constexpr std::size_t kMaxRelayResponseReasonBytes = 1024;

// The relay record protocol is directional even though chat messages may flow
// both ways. File/byte payloads flow only from the invite initiator to the
// responder, while admin requests flow only from initiator to responder.
enum class RelayChannelRole { initiator, responder };

enum class RelayTransferPhase {
    awaiting_metadata,
    receiving,
    complete,
};

enum class RelayMessageType {
    chat,
    file_meta,
    file_chunk,
    file_done,
    bytes_meta,
    bytes_chunk,
    bytes_done,
    admin_request,
    admin_response,
};

struct RelayMessagePolicyInput {
    ChannelKind channel_kind{ChannelKind::chat};
    RelayChannelRole role{RelayChannelRole::initiator};
    RelayTransferPhase transfer_phase{RelayTransferPhase::awaiting_metadata};
    RelayMessageType message_type{RelayMessageType::chat};
    bool inbound_admin_allowed{false};
    bool admin_response_outstanding{false};
};

struct RelayMessagePolicyDecision {
    bool allowed{false};
    RelayTransferPhase next_transfer_phase{
        RelayTransferPhase::awaiting_metadata};
    std::string_view reason{"relay message rejected"};
};

// Strict wire parsers. Unlike the legacy configuration parser
// channel_kind_from_string(), these reject missing, misspelled, mixed-case, or
// future values instead of silently turning them into a chat channel.
std::optional<ChannelKind> try_relay_channel_kind(std::string_view value);
std::optional<RelayMessageType> try_relay_message_type(std::string_view value);
std::optional<PendingInvite> try_relay_invite_from_json(
    const nlohmann::json& json) noexcept;

// Relay-v2 has one fixed signed password policy: ordinary channels require an
// already-derived 32-byte out-of-band PSK, while admin channels forbid one and
// rely on the separately authorized trusted-relay relationship.
bool relay_kind_requires_password(ChannelKind kind) noexcept;
bool relay_v2_password_policy_valid(ChannelKind kind,
                                    bool requires_password) noexcept;

// Programmatic admission checks used after the server has corroborated local
// endpoint identity claims. These validate only the outer routing envelope;
// the relay server deliberately never parses the opaque handshake record.
bool relay_v2_invite_request_valid(const PendingInvite& invite) noexcept;
bool relay_v2_invite_response_valid(const PendingInvite& invite) noexcept;

// A response must echo every request-side field byte-for-byte. Accepted/reason
// and responder proof fields are intentionally excluded because they are the
// response itself.
bool relay_v2_request_fields_match(const PendingInvite& expected,
                                   const PendingInvite& response) noexcept;

// Target-side feature policy. The server is authoritative and endpoints check
// it again before accepting an inbound OPEN.
bool relay_target_allows(const EndpointInfo& target,
                         ChannelKind kind) noexcept;

// Pure fail-closed transition table evaluated before message dispatch.
RelayMessagePolicyDecision evaluate_relay_message_policy(
    const RelayMessagePolicyInput& input) noexcept;

}  // namespace yume::control
