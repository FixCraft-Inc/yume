#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace yume::control {

enum class EndpointKind { client, server };
enum class RelayMode { untrusted, trusted };
enum class ChannelKind { chat, file, bytes, admin };

struct EndpointInfo {
    std::string endpoint_id;
    EndpointKind endpoint_kind{EndpointKind::client};
    std::string display_name;
    std::string hostname;
    std::string client_platform{"unknown"};
    std::string client_variant{"unknown"};
    std::string client_version;
    std::string server_id;
    RelayMode relay_mode{RelayMode::untrusted};
    bool allow_inbound_admin{false};
    bool allow_chat{true};
    bool allow_file{true};
    bool allow_bytes{true};
    bool allow_outbound_admin{false};
    bool online{true};
    std::string auth_pubkey_b64;
    std::vector<std::string> controller_ids;
    std::vector<std::string> controlled_target_ids;
};

struct PresenceAnnouncement {
    EndpointKind endpoint_kind{EndpointKind::client};
    std::string preferred_id;
    std::string preferred_name;
    std::string hostname;
    std::string client_platform{"unknown"};
    std::string client_variant{"unknown"};
    std::string client_version;
    RelayMode relay_mode{RelayMode::untrusted};
    bool allow_chat{true};
    bool allow_file{true};
    bool allow_bytes{true};
    bool allow_inbound_admin{false};
    bool allow_outbound_admin{false};
};

struct ClientLifecycleEvent {
    std::string endpoint_id;
    std::string display_name;
    std::string state{"unknown"};
    std::string message;
    std::string detail;
    std::string client_platform{"unknown"};
    std::string client_variant{"unknown"};
    std::string client_version;
    std::string effective_protection;
    bool traffic_verified{false};
    std::string exit_ip;
    std::string error_code;
    std::int64_t server_time_ms{0};
};

struct EndpointRuntimeStatus {
    EndpointInfo endpoint;
    std::optional<ClientLifecycleEvent> latest_lifecycle;
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
    std::string invite_id;
    std::string from_endpoint_id;
    std::string to_endpoint_id;
    ChannelKind channel_kind{ChannelKind::chat};
    std::int64_t created_ms{0};
    bool requires_password{true};
    std::string metadata_json;
    std::string ephemeral_pubkey_b64;
    std::string ephemeral_signature_b64;
    std::string nonce_b64;
    std::string from_display_name;
    std::string from_auth_pubkey_b64;
    bool accepted{false};
    std::string response_reason;
    std::string response_ephemeral_pubkey_b64;
    std::string response_ephemeral_signature_b64;
};

struct ActiveRelayChannel {
    std::string channel_id;
    ChannelKind channel_kind{ChannelKind::chat};
    std::string left_endpoint_id;
    std::string right_endpoint_id;
    std::uint8_t left_stream_id{0};
    std::uint8_t right_stream_id{0};
    bool e2ee_required{true};
    bool pending{true};
    bool federated{false};
    int route_hops{0};
};

struct LocalRuntimeRequest {
    std::string op;
    std::string request_id;
    nlohmann::json args{nlohmann::json::object()};
};

struct LocalRuntimeResponse {
    std::string request_id;
    bool ok{false};
    nlohmann::json result{nlohmann::json::object()};
    std::string error;
};

std::string to_string(EndpointKind value);
std::string to_string(RelayMode value);
std::string to_string(ChannelKind value);

EndpointKind endpoint_kind_from_string(const std::string& value);
RelayMode relay_mode_from_string(const std::string& value);
ChannelKind channel_kind_from_string(const std::string& value);

nlohmann::json endpoint_to_json(const EndpointInfo& endpoint, bool include_auth_pubkey = false);
EndpointInfo endpoint_from_json(const nlohmann::json& json);
nlohmann::json lifecycle_event_to_json(const ClientLifecycleEvent& event);
ClientLifecycleEvent lifecycle_event_from_json(const nlohmann::json& json);
nlohmann::json endpoint_runtime_status_to_json(const EndpointRuntimeStatus& status,
                                               bool include_auth_pubkey = false);

nlohmann::json invite_to_json(const PendingInvite& invite, bool include_response = true);
PendingInvite invite_from_json(const nlohmann::json& json);

nlohmann::json channel_to_json(const ActiveRelayChannel& channel);

}  // namespace yume::control
