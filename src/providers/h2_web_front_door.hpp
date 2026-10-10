/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <span>

#include <boost/asio/ip/tcp.hpp>

#include "admission/h2_admission.hpp"
#include "engine/front_door.hpp"
#include "providers/asio_tcp_byte_channel_provider.hpp"
#include "providers/cover_site.hpp"
#include "providers/h2_duplex_carrier.hpp"
#include "providers/tls13_secure_channel.hpp"

namespace yume::providers {

struct H2WebFrontDoorLimits final {
    std::size_t max_connections{128U};
    std::size_t max_promoted_carriers{128U};
    std::size_t max_pending_accepts{32U};
    std::size_t max_cover_streams{64U};
    std::size_t max_requests_per_connection{256U};
    std::size_t max_output_bytes{4U * 1024U * 1024U};
    // One absolute deadline includes TLS handshake, requests and cover drain.
    // Promotion transfers deadline ownership to the session runtime.
    std::chrono::milliseconds connection_timeout{30'000};
};

struct H2WebFrontDoorConfig final {
    // Numeric endpoint only: ingress performs no DNS resolution. Port zero
    // requests an ephemeral port, available through local_endpoint(). IPv6
    // listeners are IPv6-only; an IPv4 listener may use the same port.
    boost::asio::ip::tcp::endpoint listen_endpoint;
    H2WebFrontDoorLimits limits{};
    H2DuplexCarrierLimits carrier_limits{};
};

// A native listening FrontDoor, independent of CLI/configuration and the ABI.
// Creation and async_accept require the supplied execution context. Cancel,
// close and destruction may cross threads and use reserved control dispatch.
// The caller retains/runs that context through close, finish and final drain,
// contains runner exceptions and resumes delivery. Repeated close/cancel and
// destruction of an already closed handle enqueue no further control work.
// This owner resolves no DNS.
//
// Promoted carriers retain this context and use its reserved control mailbox.
// Cover traffic is served even without an accept waiter. Missing/failed proof,
// replay/cache saturation and promotion capacity use the configured site.
// A waiter is consumed only by a successful promotion, never by a probe.
// ReplayCache ticks and TTL must use monotonic seconds; share the cache across
// listeners accepting the same admission credential.
// The dispatch every carrier on an Asio context uses, in either role: posts,
// reserved control delivery and a cancellable timer for graceful close.
H2Dispatch make_asio_h2_dispatch(std::shared_ptr<AsioExecutionContext> context);

// One listening address's bounds, shared by the front doors that serve its
// connections on other contexts: the count of connections not yet promoted,
// which the listener keeps below max_connections, and the promotion budget.
// H2WebListener makes it, and H2WebFrontDoor::create_served takes it.
struct H2WebListenerShare;

class H2WebFrontDoor final : public engine::FrontDoor {
public:
    // Socket setup preserves permission, address conflict, invalid-address and
    // resource-exhaustion outcomes. Failure publishes no listener; any opened
    // socket closes before return, so a corrected configuration can retry.
    static engine::Result<std::shared_ptr<H2WebFrontDoor>> create(
        std::shared_ptr<AsioExecutionContext> context,
        H2WebFrontDoorConfig config,
        std::shared_ptr<Tls13SecureChannelProvider> tls,
        std::shared_ptr<const CoverSite> cover,
        std::shared_ptr<admission::ReplayCache> replay,
        std::span<const std::byte> admission_key);

    // A front door without a listener of its own, for a server that
    // accepts on one context and serves on several. It takes the
    // connections serve() hands it, keeps them within the share's
    // promotion budget and returns each one's place in the share's
    // connection count when it is promoted or ends. config.listen_endpoint
    // and config.limits are ignored: admission uses the share's listening
    // endpoint, and the listener's limits hold for all its front doors.
    static engine::Result<std::shared_ptr<H2WebFrontDoor>> create_served(
        std::shared_ptr<AsioExecutionContext> context,
        H2WebFrontDoorConfig config,
        std::shared_ptr<Tls13SecureChannelProvider> tls,
        std::shared_ptr<const CoverSite> cover,
        std::shared_ptr<admission::ReplayCache> replay,
        std::span<const std::byte> admission_key,
        std::shared_ptr<H2WebListenerShare> share);

    ~H2WebFrontDoor() noexcept override;
    engine::ExecutorAffinity executor_affinity() const noexcept override;
    boost::asio::ip::tcp::endpoint local_endpoint() const noexcept;
    // True once closing has begun. Descriptor or memory exhaustion pauses
    // accepting for a second. Any other accept failure, or a pause that cannot
    // be scheduled, closes the listener, and a closed listener never accepts
    // again.
    bool closed() const noexcept;
    void async_accept(engine::CancellationToken cancellation,
                      AcceptCompletion completion) override;
    // Cancels current accept waiters; the listener and ordinary cover remain
    // available. close also closes unpromoted connections. Published carriers
    // retain their TCP owner and remain independent of FrontDoor destruction.
    void cancel() noexcept override;
    void close() noexcept override;
    // A served front door's next connection, an accepted TCP descriptor that
    // already holds a place in its share's connection count. Callable from
    // any thread. The front door owns the descriptor from here on and closes
    // it, returning its place, when it cannot serve it.
    void serve(int descriptor) noexcept;
    // A served front door's connections that wait for promotion. Callable
    // from any thread, for a dispatcher choosing the least busy door.
    std::size_t waiting_connections() const noexcept;

private:
    class State;
    explicit H2WebFrontDoor(std::shared_ptr<State> state) noexcept;
    static engine::Result<std::shared_ptr<H2WebFrontDoor>> build(
        std::shared_ptr<AsioExecutionContext> context,
        H2WebFrontDoorConfig config,
        std::shared_ptr<Tls13SecureChannelProvider> tls,
        std::shared_ptr<const CoverSite> cover,
        std::shared_ptr<admission::ReplayCache> replay,
        std::span<const std::byte> admission_key,
        std::shared_ptr<H2WebListenerShare> share);
    std::shared_ptr<State> state_;
};

// The listening half of a server that serves on several contexts. On its
// own context it accepts TCP connections while fewer than max_connections
// of them wait for promotion anywhere, and hands each one's descriptor to
// `dispatch`, which passes it to a served front door's serve() or returns
// false, and the listener then closes it. Descriptor or memory exhaustion
// pauses accepting for a second. Any other accept failure closes the
// listener and calls `stopped` once on its context. A served front door
// that releases a place in a full count resumes accepting. Creation and
// dispatch run on the context, close() and destruction on any thread.
class H2WebListener final {
public:
    using Dispatch = std::function<bool(int descriptor)>;
    using Stopped = std::function<void()>;

    // Socket setup reports permission, address conflict, invalid address
    // and resource exhaustion as H2WebFrontDoor::create does.
    static engine::Result<std::shared_ptr<H2WebListener>> create(
        std::shared_ptr<AsioExecutionContext> context,
        boost::asio::ip::tcp::endpoint listen_endpoint,
        H2WebFrontDoorLimits limits, Dispatch dispatch, Stopped stopped);

    H2WebListener(const H2WebListener&) = delete;
    H2WebListener& operator=(const H2WebListener&) = delete;
    ~H2WebListener() noexcept;

    boost::asio::ip::tcp::endpoint local_endpoint() const noexcept;
    std::shared_ptr<H2WebListenerShare> share() const noexcept;
    void close() noexcept;

private:
    class State;
    explicit H2WebListener(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::providers
