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

namespace yume::runtime {

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
    // An explicit dial address may differ from the configured authenticated
    // DNS host. Empty selects that host and the system resolver. Numeric dial
    // addresses avoid system resolution; they never replace TLS identity.
    std::string connection_address;
    providers::AsioTcpSocketProtector socket_protector;
    // Optional, explicitly composed destination routing. Use this endpoint's
    // execution context. The engine supplies this provider to route handlers.
    // Each handler must authorize destination access; the Asio route provider
    // also requires explicit policy for every selected numeric address. No default egress
    // authority is granted here. A successful endpoint owns cancellation of
    // this instance, which must not be shared with another live endpoint.
    std::shared_ptr<engine::RouteProvider> route_provider;
    // Required for configured direct_tcp/direct_udp adapters. Called after
    // credential service authorization and before DNS or socket creation.
    // Must authorize the authenticated identity, service and destination;
    // exceptions fail closed. It grants no resolved-address authority and is
    // rejected when there are no configured direct adapters to consume it.
    std::function<engine::Status(const engine::StreamOpenContext&)> route_authorization;
};

// One immutable native YTP endpoint composition, shared by application layers.
// Config and protected credentials are loaded before publishing any listener.
// Every configured service needs a concrete handler; per-identity capability
// authorization wraps that handler and is applied independently to every OPEN.
// direct_tcp/direct_udp declarations create DirectRouteHandlers using the
// explicit route provider and policy above. Supply bindings only for the other
// services; duplicate binding/declaration ownership is refused. SOCKS5 and
// packet/TUN declarations remain unsupported and fail creation.
//
// create(), async_start_session(), listener_endpoint() and session operations
// require the supplied single-runner context. The caller owns its runner and
// contains run() exceptions, resumes cleanup, then closes this endpoint, calls
// finish() and drains before releasing the context. close() and destruction
// may cross threads and use reserved control dispatch. No thread is detached
// or joined here. System DNS may outlive its application deadline at drain.
class NativeEndpoint final {
public:
    using Completion = engine::SessionBootstrap::Completion;

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
    // listener. The runtime caller owns the bounded accept loop. Server idle
    // accept waiting has no startup deadline; promotion begins its bounded
    // authenticated bootstrap. Client startup has one end-to-end deadline.
    // Synchronous refusal invokes no callback. Accepted completion is exactly
    // once; the endpoint retains successful sessions through close or until a
    // later start recycles their terminal slot. Returned engines use its context.
    engine::Status async_start_session(Completion completion,
                                      std::size_t listener_index = 0U);
    std::size_t listener_count() const noexcept;
    boost::asio::ip::tcp::endpoint listener_endpoint(std::size_t index) const;
    void close() noexcept;

private:
    struct State;
    explicit NativeEndpoint(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::runtime
