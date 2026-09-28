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

#include <boost/asio/basic_waitable_timer.hpp>

#include "engine/route_provider.hpp"
#include "providers/asio_direct_route_provider.hpp"
#include "runtime/native_egress_policy.hpp"
#include "runtime/native_endpoint.hpp"
#include "runtime/session_keeper.hpp"
#ifdef __linux__
#include "runtime/linux_tun_network.hpp"
#endif
#include "runtime/module_supervisor.hpp"
#include "runtime/native_packet_adapter.hpp"

namespace yume::runtime {
namespace {
using engine::Status;
using engine::StatusCode;
using Timer = boost::asio::basic_waitable_timer<
    std::chrono::steady_clock,
    boost::asio::wait_traits<std::chrono::steady_clock>,
    providers::AsioExecutionContext::Executor>;

// The expiry timer wakes at least this often, so a changed wall clock is
// noticed without waiting out the whole remaining time.
constexpr std::chrono::hours kExpiryRecheck{1};

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

struct NativeServerRuntime::State final : std::enable_shared_from_this<State> {
    // One outbound cluster link and the keeper that holds its session up.
    struct Link final {
        std::string peer_name;
        std::string peer_identity;
        std::shared_ptr<NativeEndpoint> endpoint;
        std::shared_ptr<SessionKeeper> keeper;
    };

    State(std::shared_ptr<providers::AsioExecutionContext> runner,
          const config::v1::Config& node)
        : context(std::move(runner)),
          config(node),
          expiry(context->executor()) {}

    std::shared_ptr<providers::AsioExecutionContext> context;
    config::v1::Config config;
    std::shared_ptr<NativeEndpoint> endpoint;
    std::vector<std::pair<config::v1::PacketAdapter, std::shared_ptr<NativePacketAdapter>>> packets;
    std::vector<std::shared_ptr<ModuleSupervisor>> modules;
    // Shared through managed-network drain, without retaining this runtime.
    std::shared_ptr<Stopped> on_stopped;
    std::function<void(std::string_view)> report;
    NativeAcceptOptions accept;
    // Cluster links share one resolver, which the runtime closes.
    std::shared_ptr<providers::SystemResolver> link_resolver;
    std::vector<Link> links;
    Timer expiry;
    bool cluster_expired{false};
    bool started{false};
    bool closing{false};

    void say(std::string_view text) noexcept {
        if (!report) return;
        try {
            report(text);
        } catch (...) {
        }
    }

    void stop(Status status) noexcept {
        auto completion = std::exchange(*on_stopped, {});
        if (!completion) return;
        try {
            completion(std::move(status));
        } catch (...) {
        }
    }

    // Builds a link endpoint and keeper for every peer of the membership,
    // without starting them.
    std::vector<Link> make_links(const NativeClusterCredentials& cluster) {
        std::vector<Link> made;
        made.reserve(cluster.links.size());
        for (const auto& credentials : cluster.links) {
            SessionKeeperOptions keeper_options;
            keeper_options.report = [weak = weak_from_this(),
                                     prefix = "cluster link to " +
                                              credentials.peer_name +
                                              ": "](std::string_view text) {
                if (const auto self = weak.lock())
                    self->say(prefix + std::string(text));
            };
            auto keeper = std::make_shared<SessionKeeper>(
                context, std::move(keeper_options),
                [weak = weak_from_this()](Status status) {
                    if (const auto self = weak.lock())
                        self->stop(std::move(status));
                });
            NativeEndpointOptions options;
            options.max_sessions = 1U;
            options.max_pending_starts = 1U;
            options.resolver = link_resolver;
            options.session_ended = keeper->session_ended();
            auto endpoint = NativeEndpoint::create_link(
                context, config, credentials, std::move(options));
            if (!endpoint.ok()) {
                close_links(made);
                throw Status(endpoint.status().code(),
                             "cluster link to " + credentials.peer_name + ": " +
                                 endpoint.status().message());
            }
            keeper->attach(endpoint.value());
            made.push_back({credentials.peer_name, credentials.peer_identity,
                            std::move(endpoint).take_value(),
                            std::move(keeper)});
        }
        return made;
    }

    static void close_links(std::vector<Link>& closing_links) noexcept {
        for (const auto& link : closing_links) {
            link.keeper->close();
            link.endpoint->close();
        }
    }

    // Waits for the list's not_after. When it has passed, every link closes
    // and the endpoint ends the peers' sessions, which it no longer
    // recognizes, until a reload loads a newer list.
    void arm_expiry() noexcept {
        const auto* cluster = endpoint ? endpoint->cluster() : nullptr;
        if (closing || !cluster) return;
        const auto left = cluster->not_after - std::chrono::system_clock::now();
        if (left <= std::chrono::system_clock::duration::zero()) {
            expire();
            return;
        }
        try {
            expiry.expires_after(std::min<std::chrono::steady_clock::duration>(
                std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                    left),
                kExpiryRecheck));
            expiry.async_wait([weak = weak_from_this()](
                                  const boost::system::error_code& error) {
                const auto self = weak.lock();
                if (!self || self->closing || error) return;
                self->arm_expiry();
            });
        } catch (const std::bad_alloc&) {
            stop(Status(StatusCode::ResourceExhausted));
        } catch (...) {
            stop(Status(StatusCode::Internal));
        }
    }

    void expire() noexcept {
        if (cluster_expired) return;
        cluster_expired = true;
        close_links(links);
        endpoint->end_unrecognized_sessions();
        say("the cluster list has expired, links stay closed until a newer "
            "list is loaded");
    }

    void close() noexcept {
        if (closing) return;
        closing = true;
        boost::system::error_code ignored;
        expiry.cancel(ignored);
        close_links(links);
        if (link_resolver) link_resolver->close();
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
        auto state = std::make_shared<State>(context, config);
        state->on_stopped = std::make_shared<Stopped>(std::move(on_stopped));
        state->report = runtime_options.report;

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
        const auto sizing =
            native_server_sizing(endpoint.listen_addresses().size());
        state->accept = sizing.accept;

        NativeEndpointOptions options;
        options.max_sessions = sizing.max_sessions;
        options.max_pending_starts = sizing.max_pending_starts;
        options.caller_runs_packet_adapters = !state->packets.empty();
        options.caller_runs_module_adapters = !state->modules.empty();
        if (has_direct) {
            auto egress = NativeEgressPolicy::create(config.adapters(), config_base_directory);
            if (!egress.ok()) return Created(egress.status());
            options.egress_policy = std::move(egress).take_value();
            if (!runtime_options.resolver_program.empty()) {
                providers::SystemResolverOptions resolver_options;
                resolver_options.program = runtime_options.resolver_program;
                auto resolver = providers::SystemResolver::create(context, std::move(resolver_options));
                if (!resolver.ok()) return Created(resolver.status());
                options.resolver = std::move(resolver).take_value();
            }
            auto provider = providers::AsioDirectRouteProvider::create(
                context,
                [policy = options.egress_policy](
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
        if (const auto* cluster = state->endpoint->cluster()) {
            if (!runtime_options.resolver_program.empty()) {
                providers::SystemResolverOptions resolver_options;
                resolver_options.program = runtime_options.resolver_program;
                auto resolver = providers::SystemResolver::create(
                    context, std::move(resolver_options));
                if (!resolver.ok()) {
                    state->close();
                    return Created(resolver.status());
                }
                state->link_resolver = std::move(resolver).take_value();
            }
            try {
                state->links = state->make_links(*cluster);
            } catch (...) {
                state->close();
                throw;
            }
        }
        return Created(std::shared_ptr<NativeServerRuntime>(new NativeServerRuntime(std::move(state))));
    } catch (const Status& status) {
        return Created(Status::diagnostic(status.code(), status.message()));
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
    if (!status.ok()) {
        state->close();
        return status;
    }
    for (const auto& link : state->links) link.keeper->start();
    state->arm_expiry();
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
    const auto state = state_;
    state->context->require_context();
    if (state->closing || !state->endpoint) return Status(StatusCode::Closed);
    auto status = state->endpoint->reload_credentials();
    const auto* cluster = state->endpoint->cluster();
    if (!status.ok() || !cluster) return status;
    // Every link restarts with the reloaded list and peer store. A peer holds
    // up to kMaxPeerSessions sessions, so the new link is admitted while the
    // old session is still ending.
    std::vector<State::Link> links;
    try {
        links = state->make_links(*cluster);
    } catch (const Status& failure) {
        return Status::diagnostic(failure.code(), failure.message());
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted);
    }
    State::close_links(state->links);
    state->links = std::move(links);
    state->cluster_expired = false;
    if (state->started) {
        for (const auto& link : state->links) link.keeper->start();
        boost::system::error_code ignored;
        state->expiry.cancel(ignored);
        state->arm_expiry();
    }
    return status;
}

NativeServerStatus NativeServerRuntime::status() const {
    const auto& state = *state_;
    state.context->require_context();
    NativeServerStatus result;
    if (!state.endpoint) return result;
    result.listeners = listener_endpoints();
    const auto sessions = state.endpoint->authenticated_sessions();
    const auto* cluster = state.endpoint->cluster();
    const auto is_peer = [&](const std::string& identity) {
        return cluster &&
               std::any_of(
                   cluster->inbound.begin(), cluster->inbound.end(),
                   [&](const auto& peer) { return peer.first == identity; });
    };
    result.client_sessions = static_cast<std::size_t>(std::count_if(
        sessions.begin(), sessions.end(),
        [&](const auto& session) { return !is_peer(session.identity); }));
    if (!cluster) return result;
    auto& view = result.cluster.emplace();
    view.cluster = cluster->cluster;
    view.serial = cluster->serial;
    view.not_after = cluster->not_after;
    view.self_name = cluster->self_name;
    view.expired = state.cluster_expired;
    for (const auto& [identity, name] : cluster->inbound) {
        NativeLinkStatus link;
        link.peer_name = name;
        link.peer_identity = identity;
        for (const auto& outbound : state.links) {
            if (outbound.peer_identity == identity)
                link.outbound = outbound.keeper->status();
        }
        for (const auto& session : sessions) {
            if (session.identity != identity) continue;
            if (link.inbound_sessions++ == 0U ||
                session.admitted_at < link.inbound_since)
                link.inbound_since = session.admitted_at;
        }
        view.links.push_back(std::move(link));
    }
    return result;
}

void NativeServerRuntime::close() noexcept {
    state_->close();
}

}  // namespace yume::runtime
