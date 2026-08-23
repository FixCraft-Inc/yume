/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

namespace yume::control::fields {

inline constexpr char accepted[] = "accepted";
inline constexpr char allow_bytes[] = "allow_bytes";
inline constexpr char allow_chat[] = "allow_chat";
inline constexpr char allow_file[] = "allow_file";
inline constexpr char allow_inbound_admin[] = "allow_inbound_admin";
inline constexpr char allow_outbound_admin[] = "allow_outbound_admin";
inline constexpr char auth_pubkey_b64[] = "auth_pubkey_b64";
inline constexpr char channel_id[] = "channel_id";
inline constexpr char channel_kind[] = "channel_kind";
inline constexpr char client_platform[] = "client_platform";
inline constexpr char client_variant[] = "client_variant";
inline constexpr char client_version[] = "client_version";
inline constexpr char controlled_target_ids[] = "controlled_target_ids";
inline constexpr char controller_ids[] = "controller_ids";
inline constexpr char created_ms[] = "created_ms";
inline constexpr char detail[] = "detail";
inline constexpr char display_name[] = "display_name";
inline constexpr char e2ee_required[] = "e2ee_required";
inline constexpr char effective_protection[] = "effective_protection";
inline constexpr char endpoint[] = "endpoint";
inline constexpr char endpoint_id[] = "endpoint_id";
inline constexpr char endpoint_kind[] = "endpoint_kind";
inline constexpr char error_code[] = "error_code";
inline constexpr char exit_ip[] = "exit_ip";
inline constexpr char federated[] = "federated";
inline constexpr char federation_peer_id[] = "federation_peer_id";
inline constexpr char from_auth_pubkey_b64[] = "from_auth_pubkey_b64";
inline constexpr char from_display_name[] = "from_display_name";
inline constexpr char from_id[] = "from_id";
inline constexpr char handshake_request_b64[] = "handshake_request_b64";
inline constexpr char handshake_response_b64[] = "handshake_response_b64";
inline constexpr char hostname[] = "hostname";
inline constexpr char invite_id[] = "invite_id";
inline constexpr char latest_lifecycle[] = "latest_lifecycle";
inline constexpr char left_endpoint_id[] = "left_endpoint_id";
inline constexpr char left_stream_id[] = "left_stream_id";
inline constexpr char message[] = "message";
inline constexpr char metadata[] = "metadata";
inline constexpr char metadata_json[] = "metadata_json";
inline constexpr char online[] = "online";
inline constexpr char pending[] = "pending";
inline constexpr char reason[] = "reason";
inline constexpr char relay_mode[] = "relay_mode";
inline constexpr char relay_protocol_version[] = "relay_protocol_version";
inline constexpr char remote[] = "remote";
inline constexpr char remote_endpoint_id[] = "remote_endpoint_id";
inline constexpr char requires_password[] = "requires_password";
inline constexpr char responder_auth_pubkey_b64[] = "responder_auth_pubkey_b64";
inline constexpr char right_endpoint_id[] = "right_endpoint_id";
inline constexpr char right_stream_id[] = "right_stream_id";
inline constexpr char route_hops[] = "route_hops";
inline constexpr char server_id[] = "server_id";
inline constexpr char server_name[] = "server_name";
inline constexpr char server_time_ms[] = "server_time_ms";
// Server-corroborated namespace used only on an inbound invite notification.
// It is deliberately not part of PendingInvite or the signed relay-v2
// transcript: a caller must never be able to supply it.
inline constexpr char source_trust_id[] = "source_trust_id";
inline constexpr char state[] = "state";
inline constexpr char to_id[] = "to_id";
inline constexpr char traffic_verified[] = "traffic_verified";

}  // namespace yume::control::fields
