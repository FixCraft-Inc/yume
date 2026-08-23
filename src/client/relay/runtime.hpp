/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <condition_variable>
#include <chrono>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/asio/steady_timer.hpp>
#include <nlohmann/json.hpp>

#include "client/cli/entry.hpp"
#include "client/relay/file_receiver.hpp"
#include "client/relay/history.hpp"
#include "client/relay/outbound_source.hpp"
#include "client/relay/peer_trust.hpp"
#include "client/relay/relay_v2_crypto.hpp"
#include "client/relay/relay_v2_record.hpp"
#include "client/relay/secret.hpp"
#include "client/transport/tunnel.hpp"
#include "core/protocol/control_protocol.hpp"
#include "core/protocol/relay_limits.hpp"
#include "core/protocol/relay_policy.hpp"
#include "core/security/crypto.hpp"

namespace yume::client {

class TunnelPool;
struct RelayRuntimeTestPeer;

class RelayRuntime : public std::enable_shared_from_this<RelayRuntime> {
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
        std::filesystem::path receive_dir;
        RelayReceiveLimits receive_limits{};
        relay_v2::PeerTrustConfig peer_trust;
    };

    RelayRuntime(std::shared_ptr<Tunnel> tunnel, ClientConfig cfg, Options options);
    ~RelayRuntime();

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
    void set_tunnel_pool(std::weak_ptr<TunnelPool> tunnel_pool,
                         std::size_t requested_tunnels);
    nlohmann::json handle_local_request(const nlohmann::json& request);
    void set_stop_callback(std::function<void()> callback);
    bool notify_authenticated(const std::string& effective_protection, std::string* error = nullptr);
    bool notify_traffic_flow(const std::string& effective_protection = {}, std::string* error = nullptr);
    bool notify_disconnecting(const std::string& message = "im disconnecting", std::string* error = nullptr);
    bool notify_error(const std::string& message, const std::string& error_code = {}, std::string* error = nullptr);
    void on_control_message(const nlohmann::json& json);
    bool on_inbound_open(uint8_t stream_id,
                         const nlohmann::json& json,
                         std::string* error);

private:
    struct PendingControlResponse {
        bool ready{false};
        nlohmann::json value;
    };

    struct PendingAdminResponse {
        bool ready{false};
        bool failed{false};
        uint8_t stream_id{0};
        std::string error;
        nlohmann::json value;
    };

    struct PendingOutgoingInvite {
        PendingOutgoingInvite() = default;
        PendingOutgoingInvite(const PendingOutgoingInvite&) = delete;
        PendingOutgoingInvite& operator=(const PendingOutgoingInvite&) = delete;
        PendingOutgoingInvite(PendingOutgoingInvite&&) noexcept = default;
        PendingOutgoingInvite& operator=(PendingOutgoingInvite&&) = delete;
        ~PendingOutgoingInvite();

        control::PendingInvite invite;
        relay_v2::InitiatorState handshake_state;
        relay_v2::Bytes expected_peer_identity;
        control::EndpointInfo peer;
        std::shared_ptr<RelayOutboundSource> payload_source;
        control::ChannelKind channel_kind{control::ChannelKind::chat};
        std::string bytes_label;
        std::chrono::steady_clock::time_point expires_at{};
    };

    struct PendingIncomingInvite {
        PendingIncomingInvite() = default;
        PendingIncomingInvite(const PendingIncomingInvite&) = delete;
        PendingIncomingInvite& operator=(const PendingIncomingInvite&) = delete;
        PendingIncomingInvite(PendingIncomingInvite&&) noexcept = default;
        PendingIncomingInvite& operator=(PendingIncomingInvite&&) = delete;
        ~PendingIncomingInvite();

        control::PendingInvite invite;
        // Local trust namespace for the authenticated source. Federated
        // notifications use `peer-id:raw-source-id`; the signed handshake
        // continues to bind invite.from_endpoint_id verbatim.
        std::string source_trust_id;
        std::unique_ptr<ratchet::SessionRatchet> ratchet;
        std::chrono::steady_clock::time_point expires_at{};
    };

    using ChannelWriteCompletion =
        std::function<void(bool, const std::string&)>;

    struct PendingApplication {
        PendingApplication() = default;
        PendingApplication(relay_v2::Bytes value,
                           ChannelWriteCompletion callback);
        PendingApplication(const PendingApplication&) = delete;
        PendingApplication& operator=(const PendingApplication&) = delete;
        PendingApplication(PendingApplication&&) noexcept;
        PendingApplication& operator=(PendingApplication&&) noexcept;
        ~PendingApplication();

        relay_v2::Bytes plaintext;
        ChannelWriteCompletion completion;
    };

    struct ChannelState {
        ChannelState() = default;
        ChannelState(const ChannelState&) = delete;
        ChannelState& operator=(const ChannelState&) = delete;
        ChannelState(ChannelState&&) noexcept = default;
        ChannelState& operator=(ChannelState&&) = delete;
        ~ChannelState();

        std::string channel_id;
        control::ChannelKind channel_kind{control::ChannelKind::chat};
        control::RelayChannelRole role{control::RelayChannelRole::initiator};
        control::RelayTransferPhase transfer_phase{
            control::RelayTransferPhase::awaiting_metadata};
        std::string peer_id;
        std::string peer_name;
        uint8_t stream_id{0};
        std::unique_ptr<ratchet::SessionRatchet> ratchet;
        std::deque<PendingApplication> pending_applications;
        std::size_t pending_application_bytes{0};
        std::shared_ptr<boost::asio::steady_timer> rekey_timer;
        RelayFileReceiver receiver;
        std::shared_ptr<boost::asio::steady_timer> receive_timer;
        std::string expected_receive_name;
        std::optional<std::uint64_t> expected_receive_size;
        std::string expected_receive_sha256;
        std::string bytes_label;
    };

    std::string next_request_id();
    std::string next_invite_id();
    nlohmann::json send_control_request(nlohmann::json request, std::string* error, int timeout_ms = 8000);
    nlohmann::json send_admin_request(const std::string& op, const nlohmann::json& args, std::string* error, int timeout_ms = 8000);
    static std::optional<std::string> source_trust_id_from_notification(
        const nlohmann::json& notification,
        const control::PendingInvite& invite,
        std::string* error);
    std::optional<control::EndpointInfo> resolve_peer_locked(const std::string& peer) const;
    void update_directory_locked(const std::vector<control::EndpointInfo>& endpoints);
    bool admit_outgoing_invite_locked(PendingOutgoingInvite pending,
                                      std::string* error);
    bool send_outgoing_invite_locked(const control::PendingInvite& invite,
                                     std::string* error);
    bool begin_outgoing_invite_locked(
        control::PendingInvite invite,
        const control::EndpointInfo& peer,
        const std::string& relay_secret_b64,
        std::shared_ptr<RelayOutboundSource> payload_source,
        std::string bytes_label,
        std::string* error);
    bool admit_incoming_invite_locked(PendingIncomingInvite pending);
    void expire_pending_invites_locked(
        std::chrono::steady_clock::time_point now);
    void schedule_pending_invite_expiry_locked();
    crypto::CompositeKeyPair load_identity_keypair() const;
    static relay_v2::Bytes decode_relay_identity(
        const std::string& encoded);
    static relay_v2::Bytes decode_relay_psk(
        const std::string& encoded);
    static relay_v2::HandshakeContext make_handshake_context(
        const control::PendingInvite& invite,
        relay_v2::Digest32 nonce);
    static relay_v2::PeerTrustRequirement trust_requirement(
        control::ChannelKind kind) noexcept;
    relay_v2::PeerTrustStore& peer_trust_store();
    bool open_channel_from_reply(PendingOutgoingInvite outgoing,
                                 const control::PendingInvite& reply,
                                 std::string* error);
    bool register_channel(uint8_t stream_id, ChannelState channel);
    void handle_channel_data(ChannelState* channel, const Tunnel::Bytes& payload);
    void handle_channel_close(uint8_t stream_id, const std::string& reason);
    void close_channel_locked(uint8_t stream_id, const std::string& reason);
    void start_receive_deadline_locked(ChannelState& channel);
    struct OutboundTransfer;
    void start_outbound_transfer(uint8_t stream_id,
                                 std::shared_ptr<RelayOutboundSource> source,
                                 control::ChannelKind kind,
                                 std::uint64_t expected_size,
                                 std::string expected_name);
    void pump_outbound_transfer(const std::shared_ptr<OutboundTransfer>& transfer);
    void fail_outbound_transfer(uint8_t stream_id, const std::string& reason);
    bool send_channel_payload_locked(
        ChannelState& channel,
        std::string plaintext,
        ChannelWriteCompletion completion,
        std::string* error);
    bool send_sealed_record_locked(
        ChannelState& channel,
        relay_v2::record::Bytes encoded,
        ChannelWriteCompletion completion,
        std::string* error);
    void flush_pending_applications_locked(ChannelState& channel);
    void schedule_rekey_deadline_locked(ChannelState& channel);
    void append_history(const std::string& peer_id, const std::string& peer_name, const std::string& direction, const std::string& text);
    nlohmann::json handle_admin_request(const nlohmann::json& json,
                                        bool* stop_after_response);
    void send_admin_response(ChannelState& channel,
                             const nlohmann::json& response,
                             bool stop_after_response);
    void invoke_stop_callback();
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
    std::weak_ptr<TunnelPool> tunnel_pool_;
    std::size_t requested_tunnels_{1};
    ClientConfig cfg_;
    Options options_;
    std::unique_ptr<relay_v2::PeerTrustStore> peer_trust_;
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
    std::shared_ptr<boost::asio::steady_timer> pending_invite_timer_;
    std::uint64_t pending_invite_timer_generation_{0};
    std::unordered_map<uint8_t, ChannelState> channels_;
    std::optional<uint8_t> active_chat_stream_;
    std::optional<uint8_t> active_admin_stream_;
    std::function<void()> stop_callback_;
    std::optional<control::ClientLifecycleEvent> latest_lifecycle_;
    bool lifecycle_unsupported_logged_{false};
    bool traffic_flow_announced_{false};

    friend struct RelayRuntimeTestPeer;
};

}  // namespace yume::client
