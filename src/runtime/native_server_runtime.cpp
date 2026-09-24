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
#ifdef __linux__
#include "runtime/linux_tun_network.hpp"
#endif
#include "runtime/module_supervisor.hpp"
#include "runtime/native_packet_adapter.hpp"

namespace yume::runtime {
namespace {
using engine::Status;
using engine::StatusCode;

// Matches the embedding backend's server sizing.
constexpr std::size_t kServerSessions = 128U;
constexpr std::size_t kMaxPendingStarts = 32U;
constexpr std::size_t kPendingStartsPerListener = 4U;

bool has_runtime_adapter(const config::v1::Config& config, const config::v1::Service& service) {
    return std::any_of(config.adapters().begin(), config.adapters().end(), [&](const auto& adapter) {
        if (const auto* tcp = std::get_if<config::v1::DirectTcpAdapter>(&adapter)) {
            return service.kind() == config::v1::ServiceKind::Stream && tcp->service() == service.name();
        }
        if (const auto* udp = std::get_if<config::v1::DirectUdpAdapter>(&adapter)) {
            return service.kind() == config::v1::ServiceKind::Packet && udp->service() == service.name();
        }
        if (const auto* packet = std::get_if<config::v1::PacketAdapter>(&adapter)) {
            return service.kind() == config::v1::ServiceKind::Packet && packet->service() == service.name();
        }
        if (const auto* module = std::get_if<config::v1::ModuleAdapter>(&adapter)) {
            return service.kind() == config::v1::ServiceKind::Stream && module->service() == service.name();
        }
        return false;
    });
}

#ifdef __linux__
Status validate_packet_routes(const config::v1::PacketAdapter& adapter,
                              const config::v1::ServerEndpoint& endpoint) {
    for (const auto& route : adapter.network().routes) {
        if (route.prefix_length == 0U)
            return Status(StatusCode::InvalidArgument,
                "server packet adapters cannot install a default route without a transport exclusion");
        const std::span<const std::uint8_t> bytes(route.address.data(),
            route.family == common::IpFamily::V4 ? 4U : 16U);
        if (std::none_of(adapter.network().peer_networks.begin(), adapter.network().peer_networks.end(),
                [&](const auto& peer) {
                    return peer.prefix_length <= route.prefix_length &&
                        common::ip_network_contains(peer, route.family, bytes);
                }))
            return Status(StatusCode::InvalidArgument,
                "server managed routes must be within packet peer_networks");
        for (const auto& listener : endpoint.listen_addresses()) {
            const auto address = common::parse_canonical_ip_interface(listener +
                (listener.find(':') == std::string::npos ? "/32" : "/128"));
            if (!address) return Status(StatusCode::InvalidArgument, "invalid numeric listener");
            if (common::ip_network_contains(route, address->family,
                    std::span<const std::uint8_t>(address->address).first(
                        address->family == common::IpFamily::V4 ? 4U : 16U)))
                return Status(StatusCode::InvalidArgument,
                    "server packet routes must not capture listener addresses");
        }
    }
    return Status::success();
}
#endif

}  // namespace

struct NativeServerRuntime::State final {
    std::shared_ptr<providers::AsioExecutionContext> context;
    std::shared_ptr<NativeEndpoint> endpoint;
    std::vector<std::pair<config::v1::PacketAdapter, std::shared_ptr<NativePacketAdapter>>> packets;
    std::vector<std::shared_ptr<ModuleSupervisor>> modules;
    // Shared through managed-network drain, without retaining this runtime.
    std::shared_ptr<Stopped> on_stopped;
    NativeAcceptOptions accept;
    bool started{false};
    bool closing{false};

    void close() noexcept {
        if (closing) return;
        closing = true;
        if (endpoint) endpoint->close();
        for (const auto& packet : packets) packet.second->close();
        for (const auto& module : modules) module->close();
    }
};

engine::Result<std::shared_ptr<NativeServerRuntime>> NativeServerRuntime::create(
    std::shared_ptr<providers::AsioExecutionContext> context,
    const config::v1::Config& config,
    const std::filesystem::path& config_base_directory,
    Stopped on_stopped,
    NativeServerRuntimeOptions runtime_options) {
    using Created = engine::Result<std::shared_ptr<NativeServerRuntime>>;
    if (!context || !on_stopped || config.role() != config::v1::Role::Server) {
        return Created(Status(StatusCode::InvalidArgument, "a server configuration is required"));
    }
    context->require_context();
    try {
        for (const auto& service : config.services()) {
            if (!has_runtime_adapter(config, service)) {
                return Created(Status(StatusCode::FailedPrecondition,
                    "service '" + service.name() +
                    "' needs a direct, module or packet adapter, or an application embedding it through the C ABI"));
            }
        }
        auto state = std::make_shared<State>();
        state->context = context;
        state->on_stopped = std::make_shared<Stopped>(std::move(on_stopped));

        const auto& endpoint = std::get<config::v1::ServerEndpoint>(config.endpoint());
        std::vector<NativeServiceBinding> bindings;
        bool has_direct = false;
        for (const auto& adapter : config.adapters()) {
            if (const auto* packet = std::get_if<config::v1::PacketAdapter>(&adapter)) {
#ifndef __linux__
                (void)packet;
                return Created(Status(StatusCode::FailedPrecondition,
                    "managed packet adapters require Linux"));
#else
                auto status = validate_packet_routes(*packet, endpoint);
                if (!status.ok()) return Created(std::move(status));
                auto created = NativePacketAdapter::create(context, *packet);
                if (!created.ok()) return Created(created.status());
                auto handler = std::move(created).take_value();
                bindings.push_back({packet->service(), handler});
                state->packets.emplace_back(*packet, std::move(handler));
#endif
            } else if (const auto* module = std::get_if<config::v1::ModuleAdapter>(&adapter)) {
                ModuleSupervisorOptions module_options;
                module_options.launcher = runtime_options.module_launcher;
                auto created = ModuleSupervisor::create(context, *module, std::move(module_options),
                                                        runtime_options.report);
                if (!created.ok()) return Created(created.status());
                auto supervisor = std::move(created).take_value();
                bindings.push_back({module->service(), supervisor->handler()});
                state->modules.push_back(std::move(supervisor));
            } else if (std::holds_alternative<config::v1::DirectTcpAdapter>(adapter) ||
                       std::holds_alternative<config::v1::DirectUdpAdapter>(adapter)) {
                has_direct = true;
            }
        }
        const std::size_t listeners = endpoint.listen_addresses().size();
        state->accept.pending_per_listener = std::max<std::size_t>(
            1U, std::min(kPendingStartsPerListener, kMaxPendingStarts / listeners));

        NativeEndpointOptions options;
        options.max_sessions = kServerSessions;
        options.max_pending_starts = state->accept.pending_per_listener * listeners;
        options.caller_runs_packet_adapters = !state->packets.empty();
        options.caller_runs_module_adapters = !state->modules.empty();
        if (has_direct) {
            auto egress = NativeEgressPolicy::create(config.adapters());
            if (!egress.ok()) return Created(egress.status());
            if (!runtime_options.resolver_program.empty()) {
                providers::SystemResolverOptions resolver_options;
                resolver_options.program = std::move(runtime_options.resolver_program);
                auto resolver = providers::SystemResolver::create(context, std::move(resolver_options));
                if (!resolver.ok()) return Created(resolver.status());
                options.resolver = std::move(resolver).take_value();
            }
            auto provider = providers::AsioDirectRouteProvider::create(
                context,
                [policy = std::move(egress).take_value()](
                    const engine::AuthorizedRouteRequest& request,
                    const engine::RouteDestination& resolved) {
                    return policy->authorize_resolved(request, resolved);
                },
                {}, {}, options.resolver);
            if (!provider.ok()) return Created(provider.status());
            options.route_provider = std::move(provider).take_value();
        }
        auto created = NativeEndpoint::create(context, config, config_base_directory, std::move(bindings),
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
    const auto state = state_;
    state->context->require_context();
    if (state->started || state->closing) return Status(StatusCode::FailedPrecondition);
    state->started = true;
    try {
        for (const auto& module : state->modules) {
            const auto status = module->start();
            if (!status.ok()) {
                state->close();
                return status;
            }
        }
#ifdef __linux__
        for (const auto& [config, adapter] : state->packets) {
            auto created = LinuxTunNetwork::create(state->context, config);
            if (!created.ok()) {
                state->close();
                return created.status();
            }
            const auto network = std::move(created).take_value();
            Status status;
            try {
                status = adapter->start(std::shared_ptr<engine::PacketChannel>(network, &network->channel()),
                    [network, stopped = state->on_stopped]() noexcept {
                        auto cleanup = network->close();
                        if (!cleanup.ok()) {
                            auto completion = std::exchange(*stopped, {});
                            if (completion) {
                                try { completion(std::move(cleanup)); } catch (...) {}
                            }
                        }
                    });
            } catch (...) {
                const auto cleanup = network->close();
                if (!cleanup.ok()) {
                    state->close();
                    return cleanup;
                }
                throw;
            }
            if (!status.ok()) {
                const auto cleanup = network->close();
                state->close();
                return cleanup.ok() ? status : cleanup;
            }
        }
#endif
    } catch (const std::bad_alloc&) {
        state->close();
        return Status(StatusCode::ResourceExhausted);
    } catch (...) {
        state->close();
        return Status(StatusCode::Internal);
    }
    auto status = state->endpoint->start_accepting(
        state->accept, [weak = std::weak_ptr<State>(state)](Status status) {
            if (const auto self = weak.lock()) {
                auto completion = std::exchange(*self->on_stopped, {});
                if (completion) completion(std::move(status));
            }
        });
    if (!status.ok()) state->close();
    return status;
}

std::vector<boost::asio::ip::tcp::endpoint> NativeServerRuntime::listener_endpoints() const {
    std::vector<boost::asio::ip::tcp::endpoint> endpoints;
    for (std::size_t index = 0U; index < state_->endpoint->listener_count(); ++index) {
        endpoints.push_back(state_->endpoint->listener_endpoint(index));
    }
    return endpoints;
}

engine::Status NativeServerRuntime::reload() {
    state_->context->require_context();
    if (state_->closing || !state_->endpoint) return Status(StatusCode::Closed);
    return state_->endpoint->reload_credentials();
}

void NativeServerRuntime::close() noexcept {
    state_->close();
}

}  // namespace yume::runtime
