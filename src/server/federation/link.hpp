/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

#include "client/transport/tunnel.hpp"
#include "core/protocol/control_protocol.hpp"
#include "core/security/secret_file.hpp"
#include "server/config/config.hpp"
#include "server/federation/types.hpp"

namespace yume::server {

class FederationManager;
class Session;
struct FederationLinkLifecycleTestPeer;

// One outbound link to a federating peer. The dial speaks exactly what a
// YUME 2.0 client speaks -- H2-carrier admission, AUTH v2 with composite
// identity and TLS-exporter channel binding, ratchet establishment -- so the
// accepting peer needs no federation-specific inbound code; it is
// distinguished purely by its authorized-key policy (federation_peer_id).
// After establishment the traffic is CONTROL JSON plus relayed OPEN/DATA/CLOSE
// frames, sealed by the same per-epoch ratchet a client session uses.
class FederationLink : public std::enable_shared_from_this<FederationLink> {
public:
    FederationLink(boost::asio::io_context& server_io,
                   const ServerConfig& cfg,
                   const FederationPeer& peer,
                   FederationManager* owner);
    ~FederationLink();

    void start();
    void close();
    bool is_ready() const;
    const std::string& peer_id() const { return peer_.id; }
    std::string remote_namespace_for_local() const;
    FederationPeerStatus status() const;

    bool send_invite_request(const control::PendingInvite& invite,
                             const std::string& raw_remote_id,
                             std::string* error);
    bool open_channel(const std::shared_ptr<Session>& origin,
                      std::uint8_t origin_stream_id,
                      const control::PendingInvite& invite,
                      const nlohmann::json& open_json,
                      std::string* error);
    void close_channel(std::uint8_t remote_stream,
                       const std::string& channel_id,
                       const std::string& reason);
    void send_data(std::uint8_t remote_stream,
                   const std::string& channel_id,
                   const client::Tunnel::Bytes& payload,
                   client::Tunnel::InboundCredit inbound_credit);

private:
    struct LinkChannel {
        std::weak_ptr<Session> origin;
        std::uint8_t origin_stream{0};
        std::uint8_t remote_stream{0};
        std::string channel_id;
        bool open_pending{true};
    };

    void run_loop();
    void set_state(std::string state, std::string error = {});
    void reset_transport();
    // One connection attempt: TLS dial + pin, carrier admission, AUTH v2,
    // AuthOk. Returns a started-ready-to-start Tunnel; throws on failure.
    // The io_context is owned by the caller's attempt scope and must outlive
    // the returned Tunnel.
    std::shared_ptr<client::Tunnel> dial_v2(boost::asio::io_context& io);
    void send_hello();
    void handle_control(
        const nlohmann::json& json,
        const std::shared_ptr<client::Tunnel>& source_tunnel);
    void request_directory();
    void handle_disconnect(const std::string& reason);
    void complete_channel_open(std::uint8_t remote_stream,
                               const std::string& channel_id,
                               bool ok,
                               const std::string& reason);
    void fail_channel(std::uint8_t remote_stream,
                      const std::string& channel_id,
                      const std::string& reason);
    void handle_remote_channel_close(std::uint8_t remote_stream,
                                     const std::string& channel_id,
                                     const std::string& reason);
    bool wait_for_close(std::chrono::milliseconds duration);

    boost::asio::io_context& server_io_;
    ServerConfig cfg_;
    FederationPeer peer_;
    FederationManager* owner_{nullptr};

    // Loaded once in start(); a missing or malformed secret file is a
    // deterministic configuration error and fails the link immediately rather
    // than retrying forever on the worker.
    security::Secret32 psk_{std::array<std::uint8_t, 32>{}};
    security::Secret32 carrier_secret_{std::array<std::uint8_t, 32>{}};

    mutable std::mutex mutex_;
    std::atomic<bool> closing_{false};
    // Wakes reconnect and directory-refresh backoff immediately on close;
    // server shutdown must not wait for an arbitrary sleep interval.
    std::mutex close_wait_mutex_;
    std::condition_variable close_wait_cv_;
    // False while no live connection attempt owns the current io_context;
    // the Tunnel close handler clears it and stops that io_context.
    std::atomic<bool> attempt_alive_{false};
    std::thread worker_;
    std::thread directory_worker_;
    std::string state_{"idle"};
    std::string last_error_;
    std::int64_t last_handshake_ms_{0};
    bool ready_{false};
    std::string remote_namespace_for_local_;
    std::uint32_t channels_active_{0};
    std::unordered_map<std::uint8_t, LinkChannel> channels_;
    // Shared ownership on purpose: senders grab a copy under mutex_ so a
    // concurrent reset_transport can never leave them holding a dangling raw
    // pointer into a destroyed transport.
    std::shared_ptr<client::Tunnel> tunnel_;

    friend struct FederationLinkLifecycleTestPeer;
};

}  // namespace yume::server
