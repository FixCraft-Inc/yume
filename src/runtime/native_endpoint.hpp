/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "config/v1/config.hpp"
#include "engine/session_bootstrap.hpp"
#include "engine/route_provider.hpp"
#include "providers/asio_execution_context.hpp"
#include "providers/asio_tcp_byte_channel_provider.hpp"
#include "providers/system_resolver.hpp"
#include "runtime/native_credentials.hpp"
#include "stealth/outer_carrier_observer.hpp"

namespace yume::providers {
struct H2WebListenerShare;
}

namespace yume::runtime {

class NativeEgressPolicy;

// What the endpoints of one server share when it accepts on one context and
// serves on several (endpoint.event_loops): its listeners' bounds, the
// admission replay cache, the credential policy and security factory a
// reload publishes, the egress limiter, and the per-identity session
// registry through which max_sessions ends an identity's oldest session on
// whichever context serves it. Pass one share to each of those endpoints in
// NativeEndpointOptions::served. The first endpoint created with it loads
// the credentials into it and is the one that reloads them. Every member is
// safe to reach from any of the contexts, and none runs a callback under its
// lock.
class NativeServerShare final {
public:
    // One listener share per configured listen address, in order.
    static engine::Result<std::shared_ptr<NativeServerShare>> create(
        std::vector<std::shared_ptr<providers::H2WebListenerShare>> listeners);

    NativeServerShare(const NativeServerShare&) = delete;
    NativeServerShare& operator=(const NativeServerShare&) = delete;
    ~NativeServerShare() noexcept;

    struct Impl;
    Impl& impl() noexcept { return *impl_; }

private:
    explicit NativeServerShare(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
};

struct NativeServiceBinding final {
    std::string name;
    std::shared_ptr<engine::StreamHandler> handler;
};

// A service the daemon provides itself, beside the configured ones, such as
// yume.circuit. Its name is a reserved one (common/service_name.hpp), which
// no configuration may declare, and it streams up to max_concurrent_streams
// at once on each session. max_receive_credit, when not zero, caps each of
// its streams' receive windows (ServiceRequirement).
struct NativeBuiltinService final {
    std::string name;
    std::shared_ptr<engine::StreamHandler> handler;
    std::uint32_t max_concurrent_streams{0U};
    std::uint32_t max_receive_credit{0U};
};

struct NativeEndpointOptions final {
    std::size_t max_sessions{128U};
    std::size_t max_pending_starts{8U};
    // Client: complete dial/TLS/carrier/AUTH startup. Server: starts at carrier
    // promotion, bounding session creation/AUTH without expiring idle accepts.
    // FrontDoor separately bounds pre-promotion connections and pending work.
    std::chrono::milliseconds start_timeout{30'000};
    // Bound for an unanswered outbound rekey, including provider work and
    // carrier queueing. Positive and at most 30 s; this is local resource policy.
    std::chrono::milliseconds rekey_ack_timeout{engine::kMaxRekeyAckTimeout};
    // An explicit dial address may differ from the configured authenticated
    // DNS host. Empty selects the client's configured connect_address, or that
    // host and the system resolver. A different configured connect_address is
    // refused. Numeric dial addresses avoid system resolution and never replace
    // TLS identity.
    std::string connection_address;
    providers::AsioTcpSocketProtector socket_protector;
    // Resolves a client's dial host when it is a name. Without it such a
    // client fails creation. Use this endpoint's context and share it with a
    // route provider that resolves destination names. A successful endpoint
    // closes it on close, which ends its helper process.
    std::shared_ptr<providers::SystemResolver> resolver;
    // Explicitly composed destination routing, required by configured direct
    // adapters. Use this endpoint's execution context. The engine supplies this
    // provider to route handlers. The endpoint cannot see addresses the
    // provider resolves, so build it with egress_policy's authorize_resolved.
    // A successful endpoint owns cancellation of this instance, which must not
    // be shared with another live endpoint.
    std::shared_ptr<engine::RouteProvider> route_provider;
    // The destination policy of this configuration's direct adapters, required
    // with them and refused without them. Build it once with
    // NativeEgressPolicy::create and give the route provider the same
    // instance, so the request and resolved stages see the same egress lists.
    std::shared_ptr<const NativeEgressPolicy> egress_policy;
    // Optional further restriction for configured direct_tcp/direct_udp
    // adapters. Their schema-1 destinations are always enforced first, after
    // credential service authorization and before DNS or socket creation. This
    // callback runs only when they permit the OPEN and can only refuse more.
    // Exceptions fail closed. It is rejected when no direct adapter is configured.
    std::function<engine::Status(const engine::StreamOpenContext&)> route_authorization;
    // The caller runs every configured SOCKS5 adapter over this endpoint's
    // sessions. Without it a SOCKS5 declaration fails creation, and setting it
    // without one is refused.
    bool caller_runs_socks5_adapters{false};
    // Likewise for configured forward and module adapters. Module services
    // also need the caller's handler bindings.
    bool caller_runs_forward_adapters{false};
    bool caller_runs_module_adapters{false};
    // The caller owns every configured packet device and supplies the service
    // bindings. Setting this without a packet adapter is also refused.
    bool caller_runs_packet_adapters{false};
    // Server only: the daemon's own services. The endpoint's authorization
    // policy and egress pacing wrap them as they do configured services. A
    // name that is not reserved, a repeated one, an empty handler or a zero
    // stream bound is refused.
    std::vector<NativeBuiltinService> builtin_services;
    // A successfully delivered session ended. Runs once on the endpoint
    // context after pending engine callbacks settle and the session slot is
    // released, so it may start a replacement. Startup failures use their
    // completion only. Endpoint close also reports ended sessions; callback
    // exceptions are contained. Keep the endpoint alive through close/drain
    // to receive notifications. Capture owners weakly to avoid an owner cycle.
    // Release old engine handles to return their carrier admission reservations;
    // keeping a closed engine alive still consumes that front-door capacity.
    std::function<void(std::shared_ptr<engine::SessionEngine>, engine::Status)> session_ended;
    // Client only. Payload-free observation of the first carrier this
    // endpoint opens, for outer-carrier evidence. A server refuses it.
    std::shared_ptr<obfs::OuterCarrierTrace> outer_carrier_trace;
    // Server only. Listen nowhere and serve the connections serve() hands
    // over, through one front door per configured listener whose bounds the
    // share's listeners keep, sharing the rest of the share with the other
    // endpoints of the server. A cluster is refused.
    std::shared_ptr<NativeServerShare> served;
};

// Automatic server accepts. The total pending across listeners must fit
// NativeEndpointOptions::max_pending_starts, so no listener is left without a
// pending start to fit a smaller budget.
struct NativeAcceptOptions final {
    std::size_t pending_per_listener{1U};
    // Delay before re-arming a listener after a refused start, or after a start
    // that failed sooner than this after being armed.
    std::chrono::milliseconds retry_delay{100};
};

// yumed and the embedding backend size their servers alike, inside the
// process's open-file limit. 512 descriptors stay for listeners, connections
// not yet admitted, the control socket, the resolver, modules and files. Of
// the rest, sessions take at most half, up to 1024, and the direct routes of
// all sessions share what remains, 16 connections a session up to 16384,
// with up to 1024 of them connecting at once. A limit below 1024 sizes as
// 1024. Up to 4 starts may be pending on each listener, fewer when the total
// would pass 32 but never none. Refused and immediately failed starts keep
// the default retry delay. No listeners give no pending starts.
struct NativeServerSizing final {
    std::size_t max_sessions{0U};
    std::size_t max_pending_starts{0U};
    NativeAcceptOptions accept;
    // Outbound TCP connections and UDP sockets that every session's direct
    // routes hold together, and how many of them may be connecting at once.
    std::size_t max_route_connections{0U};
    std::size_t max_pending_route_opens{0U};
};

inline constexpr std::size_t kNativeServerMaxSessions = 1024U;

inline NativeServerSizing native_server_sizing(
    std::size_t listener_count, std::size_t descriptor_limit) noexcept {
    constexpr std::size_t kMaxPendingStarts = 32U;
    constexpr std::size_t kPendingStartsPerListener = 4U;
    constexpr std::size_t kReservedDescriptors = 512U;
    constexpr std::size_t kMinDescriptors = 1024U;
    constexpr std::size_t kRouteConnectionsPerSession = 16U;
    NativeServerSizing sizing;
    const std::size_t shared =
        std::max(descriptor_limit, kMinDescriptors) - kReservedDescriptors;
    sizing.max_sessions = std::min(kNativeServerMaxSessions, shared / 2U);
    sizing.max_route_connections =
        std::min(shared - sizing.max_sessions,
                 kNativeServerMaxSessions * kRouteConnectionsPerSession);
    sizing.max_pending_route_opens =
        std::min(sizing.max_route_connections, kNativeServerMaxSessions);
    sizing.accept.pending_per_listener = std::max<std::size_t>(
        1U, std::min(
                kPendingStartsPerListener,
                kMaxPendingStarts / std::max<std::size_t>(1U, listener_count)));
    sizing.max_pending_starts =
        sizing.accept.pending_per_listener * listener_count;
    return sizing;
}

// The process's open-file limit, at most 1048576. raise_open_file_limit lifts
// the soft limit to the hard one first, as a standalone program does at
// start. A library leaves the process's limits alone.
std::size_t open_file_limit() noexcept;
std::size_t raise_open_file_limit() noexcept;

// The admission replay cache every listener of a server shares. A proof binds
// the exporter of the TLS connection it arrives on, so it cannot pass on
// another connection, and a connection promotes once. A nonce therefore only
// needs to stay reserved while its own connection may still present a proof,
// which the front door's absolute connection deadline bounds, and twice that
// deadline leaves margin. 65536 entries over that lifetime hold about a
// thousand admissions a second, so reconnecting clients do not fill the cache,
// and a client holding the shared admission key that fills it on purpose locks
// the others out for one lifetime instead of hours.
struct NativeAdmissionReplaySizing final {
    std::size_t max_entries{0U};
    std::uint64_t ttl_seconds{0U};
};

inline NativeAdmissionReplaySizing native_admission_replay_sizing(
    std::chrono::milliseconds connection_deadline) noexcept {
    const auto deadline = std::chrono::ceil<std::chrono::seconds>(connection_deadline);
    return {65536U, 2U * static_cast<std::uint64_t>(std::max<std::int64_t>(
                             1, static_cast<std::int64_t>(deadline.count())))};
}

// One immutable native YTP endpoint composition, shared by application layers.
// Config and protected credentials are loaded before publishing any listener.
// Every configured service needs a concrete handler; per-identity capability
// authorization wraps that handler and is applied independently to every OPEN.
// direct_tcp/direct_udp declarations create DirectRouteHandlers that enforce
// their configured destinations through NativeEgressPolicy and use the route
// provider above. Supply bindings only for the other services. Duplicate
// binding/declaration ownership is refused. SOCKS5 and packet/TUN declarations
// require explicit caller ownership through the options above.
//
// create(), async_start_session(), start_accepting(), listener_endpoint() and
// session operations require the supplied single-runner context. The caller
// owns its runner and contains run() exceptions, resumes cleanup, then closes
// this endpoint, calls finish() and drains before releasing the context.
// close() and destruction may cross threads and use reserved control dispatch.
// No thread is detached or joined here. Name lookups run in the resolver's
// helper process, so a stalled system lookup does not hold the final drain.
// The share of a session's byte budget one circuit stream's receive window
// may reach, on a link and on yume.circuit, so a stalled circuit holds at
// most this part of a link's connection window (CLUSTER_DESIGN 6b).
inline constexpr std::uint32_t kLinkStreamShare = 8U;

struct NativePeerSession final {
    std::string identity;
    std::chrono::steady_clock::time_point admitted_at;
};

class NativeEndpoint final {
public:
    using Completion = engine::SessionBootstrap::Completion;
    using AcceptFailure = std::function<void(engine::Status)>;

    static engine::Result<std::shared_ptr<NativeEndpoint>> create(
        std::shared_ptr<providers::AsioExecutionContext> context,
        const config::v1::Config& config,
        const std::filesystem::path& config_base_directory,
        std::vector<NativeServiceBinding> services,
        NativeEndpointOptions options = {});

    // A cluster link: a client endpoint for this node's outbound session to
    // one peer. It takes its suite and limits from the node's own server
    // configuration, and its transport and credentials from the verified
    // cluster membership. Every stream it opens carries a circuit, so each
    // stream's receive window is capped at kLinkStreamShare of the byte
    // budget. It offers no service and accepts no stream the peer
    // opens. options.connection_address, a SOCKS5 proxy and outer-carrier
    // evidence do not apply and are refused. options.resolver stays the
    // caller's to close, so several links can share one.
    static engine::Result<std::shared_ptr<NativeEndpoint>> create_link(
        std::shared_ptr<providers::AsioExecutionContext> context,
        const config::v1::Config& node_config,
        const NativeLinkCredentials& link, NativeEndpointOptions options = {});

    NativeEndpoint(const NativeEndpoint&) = delete;
    NativeEndpoint& operator=(const NativeEndpoint&) = delete;
    ~NativeEndpoint() noexcept;

    // Client: listener_index must be zero and this starts one outbound session.
    // Server: each operation accepts from exactly the indexed configured
    // listener. Once start_accepting() succeeds the endpoint owns every server
    // start, and this returns FailedPrecondition. Server idle accept waiting
    // has no startup deadline; promotion begins its bounded authenticated
    // bootstrap. Client startup has one end-to-end deadline.
    // Synchronous refusal invokes no callback. Accepted completion is exactly
    // once; the endpoint retains successful sessions until their engine teardown
    // notification releases the slot on its context. Returned engines use that
    // context. A slot is unavailable until that notification is delivered.
    engine::Status async_start_session(Completion completion,
                                      std::size_t listener_index = 0U);
    // Server: keeps accept.pending_per_listener starts pending on every listener
    // until close, retaining successful sessions as above. A refused start, or
    // one that fails sooner than retry_delay after being armed, re-arms after
    // that delay, so sustained refusal is retried at that pace. Synchronous
    // refusal invokes nothing. It is InvalidArgument for a client, an empty
    // callback, a delay outside (0, 10 s] or a total above max_pending_starts,
    // FailedPrecondition while a manual start is pending or after an earlier
    // success, and Closed while closing. If a listener stops accepting, or a
    // retry cannot be scheduled while its listener has no pending start, the
    // endpoint closes and on_failure runs once on its context, possibly before
    // this returns. Ordinary close reports nothing.
    engine::Status start_accepting(NativeAcceptOptions accept, AcceptFailure on_failure);
    std::size_t listener_count() const noexcept;
    // A served endpoint's next connection from its listener_index-th
    // listener, an accepted TCP descriptor holding a place in that
    // listener's count. Callable from any thread. The endpoint owns the
    // descriptor from here on. False, with nothing taken, when the endpoint
    // is not served or closing or the index is out of range.
    bool serve(std::size_t listener_index, int descriptor) noexcept;
    // Sessions and connections waiting for promotion, for a dispatcher that
    // hands the next connection to the least busy endpoint. Any thread.
    std::size_t load() const noexcept;
    // Delivered sessions that have not ended. Any thread.
    std::size_t session_count() const noexcept;
    boost::asio::ip::tcp::endpoint listener_endpoint(std::size_t index) const;
    // Server, on the context: read the authorized and admin stores and the
    // server's composite and ML-KEM keys again. Later sessions authenticate
    // against them, established sessions' next OPEN uses the new grants, and
    // sessions of removed identities or beyond a lowered max_sessions end.
    // TLS material stays as loaded, and a changed admission key is refused.
    // A cluster list naming another operator, or with a lower serial than the
    // loaded one, is refused. On failure the previous credentials stay in
    // force. FailedPrecondition for a client, Closed while closing.
    engine::Status reload_credentials();
    // Server, on the context: the verified cluster membership its
    // configuration names, as last loaded, or nullptr. A reload replaces it.
    const NativeClusterCredentials* cluster() const noexcept;
    // Client: the circuits credentials its configuration names, or nullptr.
    const NativeCircuitCredentials* circuits() const noexcept;
    // Server, on the context: the verified identity of each active session
    // and when it was admitted.
    std::vector<NativePeerSession> authenticated_sessions() const;
    // Server, any thread: ends sessions whose identity the current policy no
    // longer recognizes, such as cluster peers after the list expired, and
    // applies lowered per-identity session bounds. Runs inline on this
    // endpoint's context, otherwise through its reserved control task.
    void end_unrecognized_sessions() noexcept;
    void close() noexcept;

private:
    struct State;
    explicit NativeEndpoint(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::runtime
