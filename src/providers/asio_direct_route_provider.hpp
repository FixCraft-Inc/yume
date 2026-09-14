/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>

#include "engine/route_provider.hpp"
#include "providers/asio_execution_context.hpp"

namespace yume::providers {

inline constexpr std::string_view kAsioDirectRouteProviderId =
    "boost-asio.direct-route";
inline constexpr std::uint32_t kAsioDirectRouteProviderApiVersion = 1U;

// These are provider-local limits, independent of the session limits. They
// keep a misconfigured or independently embedded provider bounded even when it
// is used outside the included daemon graph.
struct AsioDirectRouteLimits final {
    std::size_t max_pending_opens{64U};
    std::size_t max_active_connections{1024U};
    std::size_t max_resolved_endpoints{32U};
    std::size_t max_tcp_read_bytes{64U * 1024U};
    std::size_t max_tcp_write_bytes{64U * 1024U};
    std::size_t max_udp_packet_bytes{65'507U};
    std::chrono::milliseconds resolve_timeout{10'000};
    std::chrono::milliseconds connect_timeout{10'000};
};

struct NativeSocket final {
    engine::NetworkProtocol protocol{engine::NetworkProtocol::Tcp};
    std::uintptr_t handle{0U};
};

// Called after opening a socket and before connect. The callback must not
// retain the borrowed native handle. It runs on the supplied context. This is
// an instance-local
// seam for VPN loop avoidance or platform policy. It deliberately has no C ABI
// dependency; an eventual endpoint adapter may translate its public callback
// into this source-level provider contract.
using SocketProtector = std::function<engine::Status(NativeSocket)>;

// Required destination policy, in addition to the dispatcher's authorization
// of the original service/name. Called on the context for every selected
// numeric destination before any socket is opened. The original authenticated
// request is borrowed for identity/service/name policy. IPv4-mapped IPv6 is
// presented as IPv4; scoped IPv6 is refused because RouteDestination has no
// scope field. A refusal fails the whole OPEN, including a mixed DNS answer;
// exceptions fail closed. Callbacks must not retain either borrowed argument.
using ResolvedRoutePolicy = std::function<engine::Status(
    const engine::AuthorizedRouteRequest&, const engine::RouteDestination&)>;

// Async initiation requires this caller-owned single-runner context; invalid
// affinity throws before acceptance. Refusals may complete inline on it.
// TCP shutdown_write() returns FailedPrecondition for wrong affinity.
// cancel()/channel close remain cross-thread and use reserved control dispatch.
// Close all channels, finish the context, and drain before releasing its owner.
// System resolution may outlive its application deadline during final drain.
class AsioDirectRouteProvider final : public engine::RouteProvider {
public:
    static engine::Result<std::shared_ptr<AsioDirectRouteProvider>> create(
        std::shared_ptr<AsioExecutionContext> context,
        ResolvedRoutePolicy resolved_policy,
        AsioDirectRouteLimits limits = {},
        SocketProtector socket_protector = {});

    AsioDirectRouteProvider(const AsioDirectRouteProvider&) = delete;
    AsioDirectRouteProvider& operator=(const AsioDirectRouteProvider&) = delete;
    ~AsioDirectRouteProvider() noexcept override;

    const engine::ProviderDescriptor& descriptor() const noexcept override;
    void async_open(const engine::AuthorizedRouteRequest& request,
                    engine::CancellationToken cancellation,
                    Completion completion) override;
    void cancel() noexcept override;

    engine::ExecutorAffinity executor_affinity() const noexcept;
    const AsioDirectRouteLimits& limits() const noexcept;

private:
    class Impl;
    explicit AsioDirectRouteProvider(std::shared_ptr<Impl> impl) noexcept;

    std::shared_ptr<Impl> impl_;
};

}  // namespace yume::providers
