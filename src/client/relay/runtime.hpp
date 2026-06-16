#pragma once

#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "client/cli/entry.hpp"
#include "client/relay/history.hpp"
#include "client/relay/secret.hpp"
#include "client/transport/tunnel.hpp"
#include "core/control_protocol.hpp"
#include "core/crypto.hpp"

namespace yume::client {

class RelayRuntime {
public:
    struct Options {
        std::string identity_path;
        std::string hostname;
        std::string preferred_name;
        std::string preferred_id;
        std::string instance_name;
        std::string client_platform{"unknown"};
        std::string client_variant{"cli"};
        std::string client_version;
        control::RelayMode relay_mode{control::RelayMode::untrusted};
        bool allow_inbound_admin{false};
        bool allow_outbound_admin{false};
        bool allow_chat{true};
        bool allow_file{true};
        bool allow_bytes{true};
        bool history_enabled{true};
        std::filesystem::path history_dir;
    };

    RelayRuntime(std::shared_ptr<Tunnel> tunnel, ClientConfig cfg, Options options);

    bool announce_presence(std::string* error);
    std::vector<control::EndpointInfo> request_directory(std::string* error);
    control::EndpointInfo self_info() const;
    std::vector<control::PendingInvite> pending_invites() const;
    bool open_chat(const std::string& peer, const std::string& relay_secret_b64, std::string* error);
    bool send_chat(const std::string& text, std::string* error);
    bool send_file(const std::string& peer, const std::filesystem::path& path, const std::string& relay_secret_b64, std::string* error);
    bool send_bytes_path(const std::string& peer, const std::filesystem::path& path, const std::string& relay_secret_b64, std::string* error);
    bool accept_invite(const std::string& invite_id, const std::string& relay_secret_b64, std::string* error);
    bool reject_invite(const std::string& invite_id, const std::string& reason, std::string* error);
    bool admin_attach(const std::string& peer, std::string* error);
    nlohmann::json status_json() const;
    nlohmann::json handle_local_request(const nlohmann::json& request);
    void set_stop_callback(std::function<void()> callback);
    bool notify_authenticated(const std::string& effective_protection, std::string* error = nullptr);
    bool notify_traffic_flow(const std::string& effective_protection = {}, std::string* error = nullptr);
    bool notify_disconnecting(const std::string& message = "im disconnecting", std::string* error = nullptr);
    bool notify_error(const std::string& message, const std::string& error_code = {}, std::string* error = nullptr);
    void on_control_message(const nlohmann::json& json);
    void on_inbound_open(uint8_t stream_id, const nlohmann::json& json);

private:
    struct PendingControlResponse {
        bool ready{false};
        nlohmann::json value;
    };

    struct PendingAdminResponse {
        bool ready{false};
        nlohmann::json value;
    };

    struct PendingOutgoingInvite {
        control::PendingInvite invite;
        std::string relay_secret_b64;
        crypto::EVP_PKEY_ptr ephemeral_key{nullptr, EVP_PKEY_free};
        control::EndpointInfo peer;
        std::filesystem::path payload_path;
        control::ChannelKind channel_kind{control::ChannelKind::chat};
        std::string bytes_label;
    };

    struct PendingIncomingInvite {
        control::PendingInvite invite;
        std::string relay_secret_b64;
        crypto::EVP_PKEY_ptr ephemeral_key{nullptr, EVP_PKEY_free};
    };

    struct ChannelState {
        std::string channel_id;
        control::ChannelKind channel_kind{control::ChannelKind::chat};
        std::string peer_id;
        std::string peer_name;
        uint8_t stream_id{0};
        crypto::Bytes send_key;
        crypto::Bytes recv_key;
        crypto::Bytes send_nonce_prefix;
        crypto::Bytes recv_nonce_prefix;
        std::uint64_t send_counter{0};
        std::uint64_t recv_counter{0};
        std::filesystem::path receive_path;
        std::ofstream receive_stream;
        std::string bytes_label;
    };

    struct DerivedChannelKeys {
        crypto::Bytes send_key;
        crypto::Bytes recv_key;
        crypto::Bytes send_nonce_prefix;
        crypto::Bytes recv_nonce_prefix;
    };

    std::string next_request_id();
    std::string next_invite_id();
    nlohmann::json send_control_request(nlohmann::json request, std::string* error, int timeout_ms = 8000);
    nlohmann::json send_admin_request(const std::string& op, const nlohmann::json& args, std::string* error, int timeout_ms = 8000);
    std::optional<control::EndpointInfo> resolve_peer_locked(const std::string& peer) const;
    void update_directory_locked(const std::vector<control::EndpointInfo>& endpoints);
    static std::string build_invite_signature_message(const control::PendingInvite& invite, bool response);
    crypto::KeyPair load_identity_keypair() const;
    bool verify_invite_signature(const control::PendingInvite& invite, bool response) const;
    DerivedChannelKeys derive_channel_keys(bool initiator,
                                           EVP_PKEY* local_ephemeral,
                                           const std::string& peer_ephemeral_b64,
                                           const std::string& relay_secret_b64,
                                           const std::string& nonce_b64) const;
    bool open_channel_from_reply(const PendingOutgoingInvite& outgoing, const control::PendingInvite& reply, std::string* error);
    void register_channel(uint8_t stream_id, ChannelState channel);
    void handle_channel_data(ChannelState* channel, const Tunnel::Bytes& payload);
    void handle_channel_close(uint8_t stream_id, const std::string& reason);
    Tunnel::Bytes encrypt_channel_payload(ChannelState& channel, const std::string& plaintext);
    std::string decrypt_channel_payload(ChannelState& channel, const Tunnel::Bytes& ciphertext);
    void append_history(const std::string& peer_id, const std::string& peer_name, const std::string& direction, const std::string& text);
    nlohmann::json handle_admin_request(const nlohmann::json& json);
    void send_admin_response(ChannelState& channel, const nlohmann::json& response);
    bool notify_lifecycle(const std::string& state,
                          const std::string& message,
                          const std::string& detail,
                          const std::string& effective_protection,
                          bool traffic_verified,
                          const std::string& exit_ip,
                          const std::string& error_code,
                          std::string* error,
                          int timeout_ms,
                          bool quiet_unsupported);
    void log_lifecycle_unsupported_once(const std::string& reason);

    std::shared_ptr<Tunnel> tunnel_;
    ClientConfig cfg_;
    Options options_;
    HistoryStore history_;
    mutable std::mutex mutex_;
    std::condition_variable control_cv_;
    std::condition_variable admin_cv_;
    std::string server_id_;
    std::string server_name_;
    control::EndpointInfo self_;
    std::unordered_map<std::string, control::EndpointInfo> directory_by_id_;
    std::unordered_map<std::string, std::string> directory_name_to_id_;
    std::unordered_map<std::string, PendingControlResponse> control_responses_;
    std::unordered_map<std::string, PendingAdminResponse> admin_responses_;
    std::unordered_map<std::string, PendingOutgoingInvite> outgoing_invites_;
    std::unordered_map<std::string, PendingIncomingInvite> incoming_invites_;
    std::unordered_map<uint8_t, ChannelState> channels_;
    std::optional<uint8_t> active_chat_stream_;
    std::optional<uint8_t> active_admin_stream_;
    std::function<void()> stop_callback_;
    std::optional<control::ClientLifecycleEvent> latest_lifecycle_;
    bool lifecycle_unsupported_logged_{false};
    bool traffic_flow_announced_{false};
};

}  // namespace yume::client
