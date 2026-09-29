/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "engine/route_provider.hpp"
#include "engine/stream_handler.hpp"
#include "runtime/circuit_node.hpp"

namespace yume::runtime {
class NativeEgressPolicy;
}  // namespace yume::runtime

// What yumed puts around the circuit service: the routes view that clients
// fetch on yume.routes, and the exit connector that carries a circuit's
// streams to their destinations.
namespace yume::runtime::circuit {

// The routes view as the operator signed it.
struct RoutesView final {
    std::vector<std::byte> view;
    std::vector<std::byte> signature;
};

// yume.routes: writes the current view's signature, then the view's exact
// bytes, then ends its write direction. It reads nothing and closes the
// stream when the client ends or sends anything. current runs on the context
// for every stream, so a reloaded view is served at once, and nothing
// refuses the stream with FailedPrecondition.
class RoutesService final : public engine::StreamHandler {
public:
    using Current = std::function<std::shared_ptr<const RoutesView>()>;

    static engine::Result<std::shared_ptr<RoutesService>> create(
        Current current);

    const engine::ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    engine::ServiceKind service_kind() const noexcept override {
        return engine::ServiceKind::ByteStream;
    }
    engine::Status authorize(const engine::StreamOpenContext&) override {
        // The endpoint's authorization policy grants it with yume.circuit.
        return engine::Status::success();
    }
    void on_open(engine::StreamOpenContext context,
                 std::shared_ptr<engine::StreamResponder> stream) override;

private:
    RoutesService(engine::ProviderDescriptor descriptor,
                  Current current) noexcept;

    engine::ProviderDescriptor descriptor_;
    Current current_;
};

// An exit's NodeEnvironment::open_exit. A circuit's stream takes the path an
// OPEN to the direct_tcp service would take: that service's destination
// policy, then the route provider, which checks every resolved address. The
// route request carries the carrying stream's id and the previous hop's
// evidence, never the client's. All of it runs on the provider's context.
std::function<void(const engine::StreamOpenContext& carried_by,
                   const ytp1::Destination& destination,
                   engine::CancellationToken cancellation, ChannelOpened done)>
exit_connector(std::string service,
               std::shared_ptr<const NativeEgressPolicy> egress,
               std::shared_ptr<engine::RouteProvider> provider);

}  // namespace yume::runtime::circuit
