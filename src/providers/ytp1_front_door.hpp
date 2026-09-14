/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <memory>
#include <span>

#include <boost/asio/ip/tcp.hpp>

#include "admission/h2_admission.hpp"
#include "engine/front_door.hpp"
#include "providers/asio_tcp_byte_channel_provider.hpp"
#include "providers/ytp1_cover_site.hpp"
#include "providers/ytp1_h2_carrier.hpp"
#include "providers/ytp1_tls13_secure_channel.hpp"

namespace yume::providers {

struct Ytp1FrontDoorLimits final {
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

struct Ytp1FrontDoorConfig final {
    // Numeric endpoint only: ingress performs no DNS resolution. Port zero
    // requests an ephemeral port, available through local_endpoint(). IPv6
    // listeners are IPv6-only; an IPv4 listener may use the same port.
    boost::asio::ip::tcp::endpoint listen_endpoint;
    Ytp1FrontDoorLimits limits{};
    Ytp1H2CarrierLimits carrier_limits{};
};

// A native listening FrontDoor, independent of CLI/configuration and the ABI.
// Creation and async_accept require the supplied execution context. Cancel,
// close and destruction may cross threads and use reserved control dispatch.
// The caller retains/runs that context through close, finish and final drain,
// contains runner exceptions and resumes delivery. Repeated close/cancel and
// destruction of an already closed handle enqueue no further control work.
// This owner resolves no DNS;
// a runtime adding outbound resolution must separately account for system
// getaddrinfo outliving its user-facing deadline at final shutdown.
//
// Promoted carriers retain this context and use its reserved control mailbox.
// Cover traffic is served even without an accept waiter. Missing/failed proof,
// replay/cache saturation and promotion capacity use the configured site.
// A waiter is consumed only by a successful promotion, never by a probe.
// ReplayCache ticks and TTL must use monotonic seconds; share the cache across
// listeners accepting the same admission credential.
class Ytp1FrontDoor final : public engine::FrontDoor {
public:
    // Socket setup preserves permission, address conflict, invalid-address and
    // resource-exhaustion outcomes. Failure publishes no listener; any opened
    // socket closes before return, so a corrected configuration can retry.
    static engine::Result<std::shared_ptr<Ytp1FrontDoor>> create(
        std::shared_ptr<AsioExecutionContext> context,
        Ytp1FrontDoorConfig config,
        std::shared_ptr<Ytp1Tls13SecureChannelProvider> tls,
        std::shared_ptr<const Ytp1CoverSite> cover,
        std::shared_ptr<admission::ReplayCache> replay,
        std::span<const std::byte> admission_key);

    ~Ytp1FrontDoor() noexcept override;
    engine::ExecutorAffinity executor_affinity() const noexcept override;
    boost::asio::ip::tcp::endpoint local_endpoint() const noexcept;
    void async_accept(engine::CancellationToken cancellation,
                      AcceptCompletion completion) override;
    // Cancels current accept waiters; the listener and ordinary cover remain
    // available. close also closes unpromoted connections. Published carriers
    // retain their TCP owner and remain independent of FrontDoor destruction.
    void cancel() noexcept override;
    void close() noexcept override;

private:
    class State;
    explicit Ytp1FrontDoor(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::providers
