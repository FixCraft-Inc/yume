/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "modules/relay/channel_kind.hpp"

namespace yume::relay {

enum class EndpointKind { Client, Server };
enum class RelayMode { Untrusted, Trusted };

struct EndpointInfo {
    std::string endpoint_id;
    EndpointKind endpoint_kind{EndpointKind::Client};
    std::string display_name;
    std::string hostname;
    std::string client_platform{"unknown"};
    std::string client_variant{"unknown"};
    std::string client_version;
    std::string server_id;
    std::string server_name;
    RelayMode relay_mode{RelayMode::Untrusted};
    bool allow_inbound_admin{false};
    bool allow_chat{true};
    bool allow_file{true};
    bool allow_bytes{true};
    bool allow_outbound_admin{false};
    bool online{true};
    std::string auth_pubkey_b64;
    std::vector<std::string> controller_ids;
    std::vector<std::string> controlled_target_ids;
    bool remote{false};
    std::string federation_peer_id;
    std::string remote_endpoint_id;
};

struct PresenceAnnouncement {
    EndpointKind endpoint_kind{EndpointKind::Client};
    std::string preferred_id;
    std::string preferred_name;
    std::string hostname;
    std::string client_platform{"unknown"};
    std::string client_variant{"unknown"};
    std::string client_version;
    RelayMode relay_mode{RelayMode::Untrusted};
    bool allow_chat{true};
    bool allow_file{true};
    bool allow_bytes{true};
    bool allow_inbound_admin{false};
    bool allow_outbound_admin{false};
};

struct PresenceReply {
    std::string assigned_id;
    std::string assigned_name;
    bool preferred_id_accepted{false};
    bool preferred_name_accepted{false};
    std::string server_id;
    std::string server_name;
};

struct PendingInvite {
    static constexpr std::uint16_t kRelayProtocolVersion = 2;

    std::uint16_t relay_protocol_version{kRelayProtocolVersion};
    std::string invite_id;
    std::string from_endpoint_id;
    std::string to_endpoint_id;
    ChannelKind channel_kind{ChannelKind::Chat};
    std::int64_t created_ms{0};
    bool requires_password{true};
    std::string metadata_json;
    std::string handshake_request_b64;
    std::string from_display_name;
    std::string from_auth_pubkey_b64;
    // Internal parse/state marker. The wire representation is the explicit
    // `accepted` key; this flag prevents a request-shaped object from being
    // accepted as an implicit rejection response.
    bool response_present{false};
    bool accepted{false};
    std::string response_reason;
    std::string handshake_response_b64;
    std::string responder_auth_pubkey_b64;
};

struct ActiveRelayChannel {
    std::string channel_id;
    ChannelKind channel_kind{ChannelKind::Chat};
    std::string left_endpoint_id;
    std::string right_endpoint_id;
    std::uint8_t left_stream_id{0};
    std::uint8_t right_stream_id{0};
    bool e2ee_required{true};
    bool pending{true};
    bool federated{false};
    int route_hops{0};
};

std::string to_string(EndpointKind value);
std::string to_string(RelayMode value);
std::string to_string(ChannelKind value);

EndpointKind endpoint_kind_from_string(const std::string& value);
RelayMode relay_mode_from_string(const std::string& value);
ChannelKind channel_kind_from_string(const std::string& value);

nlohmann::json endpoint_to_json(const EndpointInfo& endpoint, bool include_auth_pubkey = false);
EndpointInfo endpoint_from_json(const nlohmann::json& json);

nlohmann::json invite_to_json(const PendingInvite& invite, bool include_response = true);
PendingInvite invite_from_json(const nlohmann::json& json);

nlohmann::json channel_to_json(const ActiveRelayChannel& channel);

}  // namespace yume::relay
