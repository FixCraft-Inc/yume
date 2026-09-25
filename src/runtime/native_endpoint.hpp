/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
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

namespace yume::runtime {

class NativeEgressPolicy;

struct NativeServiceBinding final {
    std::string name;
    std::shared_ptr<engine::StreamHandler> handler;
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
    // A successfully delivered session ended. Runs once on the endpoint
    // context after pending engine callbacks settle and the session slot is
    // released, so it may start a replacement. Startup failures use their
    // completion only. Endpoint close also reports ended sessions; callback
    // exceptions are contained. Keep the endpoint alive through close/drain
    // to receive notifications. Capture owners weakly to avoid an owner cycle.
    // Release old engine handles to return their carrier admission reservations;
    // keeping a closed engine alive still consumes that front-door capacity.
    std::function<void(std::shared_ptr<engine::SessionEngine>, engine::Status)> session_ended;
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
    boost::asio::ip::tcp::endpoint listener_endpoint(std::size_t index) const;
    // Server, on the context: read the authorized and admin stores and the
    // server's composite and ML-KEM keys again. Later sessions authenticate
    // against them, established sessions' next OPEN uses the new grants, and
    // sessions of removed identities or beyond a lowered max_sessions end.
    // TLS material stays as loaded, and a changed admission key is refused.
    // On failure the previous credentials stay in force. FailedPrecondition
    // for a client, Closed while closing.
    engine::Status reload_credentials();
    void close() noexcept;

private:
    struct State;
    explicit NativeEndpoint(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::runtime
