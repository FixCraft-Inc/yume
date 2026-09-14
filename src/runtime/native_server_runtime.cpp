/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_server_runtime.hpp"

#include <algorithm>
#include <new>
#include <string>
#include <utility>
#include <variant>

#include "engine/route_provider.hpp"
#include "providers/asio_direct_route_provider.hpp"
#include "runtime/native_egress_policy.hpp"
#include "runtime/native_endpoint.hpp"

namespace yume::runtime {
namespace {
using engine::Status;
using engine::StatusCode;

// Matches the embedding backend's server sizing.
constexpr std::size_t kServerSessions = 128U;
constexpr std::size_t kMaxPendingStarts = 32U;
constexpr std::size_t kPendingStartsPerListener = 4U;

bool has_direct_adapter(const config::v1::Config& config, const config::v1::Service& service) {
    return std::any_of(config.adapters().begin(), config.adapters().end(), [&](const auto& adapter) {
        if (const auto* tcp = std::get_if<config::v1::DirectTcpAdapter>(&adapter)) {
            return service.kind() == config::v1::ServiceKind::Stream && tcp->service() == service.name();
        }
        if (const auto* udp = std::get_if<config::v1::DirectUdpAdapter>(&adapter)) {
            return service.kind() == config::v1::ServiceKind::Packet && udp->service() == service.name();
        }
        return false;
    });
}

}  // namespace

struct NativeServerRuntime::State final {
    std::shared_ptr<providers::AsioExecutionContext> context;
    std::shared_ptr<NativeEndpoint> endpoint;
    Stopped on_stopped;
    NativeAcceptOptions accept;
    bool started{false};
};

engine::Result<std::shared_ptr<NativeServerRuntime>> NativeServerRuntime::create(
    std::shared_ptr<providers::AsioExecutionContext> context,
    const config::v1::Config& config,
    const std::filesystem::path& config_base_directory,
    Stopped on_stopped) {
    using Created = engine::Result<std::shared_ptr<NativeServerRuntime>>;
    if (!context || !on_stopped || config.role() != config::v1::Role::Server) {
        return Created(Status(StatusCode::InvalidArgument, "a server configuration is required"));
    }
    context->require_context();
    try {
        for (const auto& service : config.services()) {
            if (!has_direct_adapter(config, service)) {
                return Created(Status(StatusCode::FailedPrecondition,
                    "service '" + service.name() +
                    "' needs a direct adapter, or an application embedding it through the C ABI"));
            }
        }
        auto state = std::make_shared<State>();
        state->context = context;
        state->on_stopped = std::move(on_stopped);

        const auto& endpoint = std::get<config::v1::ServerEndpoint>(config.endpoint());
        const std::size_t listeners = endpoint.listen_addresses().size();
        state->accept.pending_per_listener = std::max<std::size_t>(
            1U, std::min(kPendingStartsPerListener, kMaxPendingStarts / listeners));

        NativeEndpointOptions options;
        options.max_sessions = kServerSessions;
        options.max_pending_starts = state->accept.pending_per_listener * listeners;
        if (!config.adapters().empty()) {
            auto egress = NativeEgressPolicy::create(config.adapters());
            if (!egress.ok()) return Created(egress.status());
            auto provider = providers::AsioDirectRouteProvider::create(
                context,
                [policy = std::move(egress).take_value()](
                    const engine::AuthorizedRouteRequest& request,
                    const engine::RouteDestination& resolved) {
                    return policy->authorize_resolved(request, resolved);
                });
            if (!provider.ok()) return Created(provider.status());
            options.route_provider = std::move(provider).take_value();
        }
        auto created = NativeEndpoint::create(context, config, config_base_directory, {},
                                              std::move(options));
        if (!created.ok()) return Created(created.status());
        state->endpoint = std::move(created).take_value();
        return Created(std::shared_ptr<NativeServerRuntime>(new NativeServerRuntime(std::move(state))));
    } catch (const std::bad_alloc&) {
        return Created(Status(StatusCode::ResourceExhausted));
    }
}

NativeServerRuntime::NativeServerRuntime(std::shared_ptr<State> state) noexcept
    : state_(std::move(state)) {}

NativeServerRuntime::~NativeServerRuntime() noexcept { close(); }

engine::Status NativeServerRuntime::start() {
    state_->context->require_context();
    if (state_->started) return Status(StatusCode::FailedPrecondition);
    state_->started = true;
    return state_->endpoint->start_accepting(
        state_->accept, [weak = std::weak_ptr<State>(state_)](Status status) {
            if (const auto self = weak.lock(); self && self->on_stopped) self->on_stopped(std::move(status));
        });
}

std::vector<boost::asio::ip::tcp::endpoint> NativeServerRuntime::listener_endpoints() const {
    std::vector<boost::asio::ip::tcp::endpoint> endpoints;
    for (std::size_t index = 0U; index < state_->endpoint->listener_count(); ++index) {
        endpoints.push_back(state_->endpoint->listener_endpoint(index));
    }
    return endpoints;
}

void NativeServerRuntime::close() noexcept {
    if (state_->endpoint) state_->endpoint->close();
}

}  // namespace yume::runtime
