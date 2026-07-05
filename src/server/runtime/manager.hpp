/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "core/protocol/control_protocol.hpp"
#include "core/runtime/service_stream.hpp"
#include "core/security/crypto.hpp"
#include "core/security/identity.hpp"
#include "core/stealth/obfs.hpp"
#include "server/config/config.hpp"
#include "server/federation/types.hpp"
#include "server/filter/ip_filter.hpp"
#include "server/host/exposure_check.hpp"
#include "server/host/extra_listeners.hpp"
#include "server/host/host_routes.hpp"
#include "server/packet/tun_egress.hpp"

namespace yume::server {

class FederationManager;
class FederationLink;
class PacketTunEgress;
class Session;

struct ControlledClientInfo {
    std::string id;
    std::string hostname;
    std::string wan_ip;
    bool allow_exec{false};
    bool server_in_charge{false};
};

struct EndpointRegistrationResult {
    control::EndpointInfo endpoint;
    bool preferred_id_accepted{false};
    bool preferred_name_accepted{false};
    std::string server_id;
    std::string server_name;
};

class Manager {
public:
    Manager(boost::asio::io_context& io, const ServerConfig& cfg);
    ~Manager();

    void start();
    void stop();
    void register_session(const std::shared_ptr<Session>& session);
    void unregister_session(Session* session);
    void update_anonym_proof(const std::string& hash,
                             const std::string& sig,
                             const std::string& ts,
                             const std::string& nonce,
                             const std::string& certfp,
                             const std::string& proof_policy,
                             const std::vector<std::string>& proof_sources,
                             const std::string& ca_sig,
                             const std::string& ca_alg,
                             const std::string& sub_sig,
                             const std::string& sub_alg,
                             const std::string& sub_cert_b64,
                             const std::string& pq_pub_b64,
                             const std::string& pq_sig,
                             const std::string& pq_alg);
    void register_reverse_listener(int port, const std::shared_ptr<Session>& session);
    void unregister_reverse_listener(int port, Session* session);
    bool reclaim_reverse_listener(int port, const Session* requester = nullptr);
    void register_controlled_client(const std::shared_ptr<Session>& session, const ControlledClientInfo& info);
    void unregister_controlled_client(Session* session);
    std::vector<ControlledClientInfo> list_controlled_clients(bool anonym_only);
    std::shared_ptr<Session> find_controlled_session(const std::string& id, ControlledClientInfo* info);
    EndpointRegistrationResult register_endpoint(const std::shared_ptr<Session>& session,
                                                 const control::PresenceAnnouncement& announce,
                                                 const std::string& auth_pubkey_b64);
    bool update_endpoint_lifecycle(Session* session,
                                   control::ClientLifecycleEvent event,
                                   control::ClientLifecycleEvent* stored_event = nullptr);
    void unregister_endpoint(Session* session);
    std::vector<control::EndpointInfo> list_local_endpoints() const;
    std::vector<control::EndpointInfo> list_endpoints() const;
    std::vector<control::EndpointRuntimeStatus> list_endpoint_statuses() const;
    std::vector<control::ClientLifecycleEvent> list_recent_lifecycle_events(std::size_t limit = 200) const;
    std::shared_ptr<Session> find_endpoint_session(const std::string& query, control::EndpointInfo* info);
    bool route_invite(const std::shared_ptr<Session>& from_session,
                      const control::PendingInvite& invite,
                      std::string* error,
                      std::shared_ptr<Session>* local_target_session = nullptr,
                      bool* federated = nullptr);
    bool route_federated_invite(const std::shared_ptr<Session>& from_session,
                                const control::PendingInvite& invite,
                                const std::string& raw_target_id,
                                std::string* error,
                                std::shared_ptr<Session>* local_target_session = nullptr);
    bool respond_invite(const std::shared_ptr<Session>& from_session, const control::PendingInvite& response,
                        std::shared_ptr<Session>* initiator_session, control::PendingInvite* invite_out, std::string* error);
    bool respond_federated_invite(const std::string& peer_id,
                                  const control::PendingInvite& response,
                                  std::shared_ptr<Session>* initiator_session,
                                  control::PendingInvite* invite_out,
                                  std::string* error);
    bool can_open_channel(const std::string& channel_id,
                          const std::string& from_id,
                          const std::string& to_id,
                          control::ChannelKind channel_kind,
                          std::shared_ptr<Session>* target_session,
                          control::PendingInvite* invite_out,
                          std::string* error);
    bool open_federated_channel(const std::shared_ptr<Session>& origin,
                                std::uint8_t origin_stream_id,
                                const nlohmann::json& open_json,
                                std::string* error);
    void register_active_channel(const control::ActiveRelayChannel& channel);
    void unregister_active_channel(const std::string& channel_id);
    std::vector<control::ActiveRelayChannel> list_active_channels() const;
    std::vector<FederationPeerStatus> federation_statuses() const;
    bool disconnect_endpoint(const std::string& query, std::string* error);
    void add_admin_relationship(const std::string& controller_id, const std::string& target_id);
    void remove_admin_relationship(const std::string& controller_id, const std::string& target_id);
    const ServerConfig& config_snapshot() const;
    const std::string& server_id() const { return server_id_; }
    const std::string& server_name() const { return server_name_; }
    bool egress_fairness_enabled() const;
    std::chrono::milliseconds reserve_egress_write(const std::string& client_key,
                                                   std::uint32_t priority,
                                                   std::size_t bytes);
    bool packet_egress_active() const;
    std::optional<PacketTunAssignment> register_packet_client(
        Session* session,
        std::function<void(crypto::Bytes)> handler);
    void unregister_packet_client(Session* session, std::uint32_t ipv4_be);
    void write_packet_to_egress(std::uint32_t client_ipv4_be, crypto::Bytes packet);
    bool egress_allowed(const boost::asio::ip::address& address, std::string* reason = nullptr) const;
    bool admit_plain_client(boost::asio::ip::tcp::socket& socket);
    bool reload_auth(std::string* error);
    bool reload_client_filter(std::string* error);
    bool kill_sessions(const std::string& query, std::string* error);
    nlohmann::json host_runtime_info() const;
    const host::HostRouteTable& host_routes() const { return host_routes_; }
    const host::ExposureResult& exposure_result() const { return exposure_result_; }
    std::uint64_t accept_refused_filter_total() const { return accept_refused_filter_; }

    // Returns one of the loaded upstream-response captures (chosen
    // uniformly), or an empty string if no directory is configured /
    // the directory is empty. Thread-safe — Session calls this from
    // its strand on every probe. The internal cache is reloaded on
    // the --upstream-response-ttl interval; sessions never see a
    // half-loaded cache because we swap a shared_ptr atomically.
    std::string upstream_response_pick() const;

    // Synchronous load of the configured --upstream-response-dir into
    // the cache. Returns the number of files successfully loaded.
    // Called once at startup and (if TTL > 0) by the periodic timer.
    std::size_t reload_upstream_responses();

    bool register_service(const std::string& service, std::string* error = nullptr);
    bool enqueue_service_stream(const std::string& service,
                                std::shared_ptr<runtime::ServiceStream> stream,
                                std::string* error = nullptr);
    std::shared_ptr<runtime::ServiceStream> accept_service_stream(
        const std::string& service,
        std::uint32_t timeout_ms,
        std::string* error = nullptr);

private:
    static constexpr std::size_t kMaxLifecycleEvents = 512;

    class WeightedEgressLimiter;

    void do_accept();
    void refuse_client_socket(boost::asio::ip::tcp::socket& socket);
    void append_lifecycle_event_locked(const control::ClientLifecycleEvent& event);
    void schedule_upstream_reload();
    std::shared_ptr<const std::vector<crypto::Bytes>> authorized_keys_snapshot() const;

    boost::asio::io_context& io_;
    ServerConfig cfg_;
    std::mutex cfg_mutex_;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ssl::context ssl_ctx_;
    mutable std::mutex auth_keys_mutex_;
    std::shared_ptr<const std::vector<crypto::Bytes>> authorized_keys_;

    std::atomic<uint64_t> next_session_id_{1};
    std::mutex sessions_mutex_;
    std::unordered_map<Session*, std::weak_ptr<Session>> live_sessions_;
    std::mutex reverse_mutex_;
    std::unordered_map<int, std::weak_ptr<Session>> reverse_port_sessions_;
    struct ControlledClientEntry {
        ControlledClientInfo info;
        std::weak_ptr<Session> session;
    };
    std::mutex control_mutex_;
    std::unordered_map<std::string, ControlledClientEntry> controlled_clients_;
    struct EndpointEntry {
        control::EndpointInfo info;
        std::optional<control::ClientLifecycleEvent> latest_lifecycle;
        std::weak_ptr<Session> session;
    };
    struct InviteEntry {
        control::PendingInvite invite;
        std::weak_ptr<Session> from_session;
        std::weak_ptr<Session> to_session;
        bool outbound_federated{false};
        bool inbound_federated{false};
        std::string federation_peer_id;
        std::string federation_remote_id;
    };
    mutable std::mutex endpoint_mutex_;
    std::unordered_map<std::string, EndpointEntry> endpoints_;
    std::unordered_map<Session*, std::string> session_endpoints_;
    std::unordered_map<std::string, std::string> endpoint_names_;
    std::unordered_map<std::string, InviteEntry> invites_;
    std::unordered_map<std::string, control::ActiveRelayChannel> active_channels_;
    std::deque<control::ClientLifecycleEvent> lifecycle_events_;
    std::string server_id_;
    std::string server_name_;
    std::unique_ptr<FederationManager> federation_;
    std::unique_ptr<WeightedEgressLimiter> egress_limiter_;
    std::unique_ptr<PacketTunEgress> packet_egress_;
    std::unique_ptr<IpFilter> ip_filter_;
    host::HostRouteTable host_routes_;
    std::unique_ptr<ExtraListeners> extra_listeners_;
    host::ExposureResult exposure_result_;

    // Per-probe upstream-response rotation. cache_ is swapped under the
    // mutex; readers (Session::send_disguise_404) atomically load a
    // shared_ptr snapshot and pick from it lock-free. timer_ fires on
    // the io_context and reloads the directory every
    // cfg_.upstream_response_ttl_s seconds.
    mutable std::mutex upstream_cache_mu_;
    std::shared_ptr<const std::vector<std::string>> upstream_cache_;
    std::unique_ptr<boost::asio::steady_timer> upstream_reload_timer_;
    bool upstream_reload_stopped_{false};

    // --accept-rate-limit token bucket. Single-threaded by do_accept
    // (which always runs on io_'s default executor) so no lock needed.
    // accept_window_start_ is the steady_clock millisecond timestamp
    // when the current 1000 ms window opened; accept_window_count_ is
    // the number of accepts admitted in that window. When the window
    // expires we roll forward by adding 1000 ms (not snapping to now)
    // so a burst doesn't get punished by an idle gap right after.
    std::chrono::steady_clock::time_point accept_window_start_{};
    std::uint32_t accept_window_count_{0};
    // Counters surfaced via the next start-up banner / future status
    // RPC: how many accepts we've refused for each reason since
    // start(). Lock-free because do_accept is single-reader.
    std::uint64_t accept_refused_cap_{0};
    std::uint64_t accept_refused_rate_{0};
    std::uint64_t accept_refused_filter_{0};
    std::mutex service_mutex_;
    std::condition_variable service_cv_;
    bool services_stopping_{false};
    std::unordered_set<std::string> registered_services_;
    std::unordered_map<std::string, std::deque<std::shared_ptr<runtime::ServiceStream>>> pending_service_streams_;
    // Returns true if the new accept may proceed; false if it must
    // be refused (caller closes the socket). Pure function of
    // (current time, cfg_, live_sessions_.size(), bucket state) —
    // safe to call in the accept handler with no extra locks.
    bool admit_accept();
};

}  // namespace yume::server
