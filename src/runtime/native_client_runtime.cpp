/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_client_runtime.hpp"

#include <algorithm>
#include <new>
#include <string>
#include <utility>
#include <variant>

#include "engine/session_engine.hpp"
#include "engine/stream_handler.hpp"
#include "runtime/circuit_pool.hpp"
#include "runtime/native_endpoint.hpp"
#ifdef __linux__
#include "runtime/linux_tun_network.hpp"
#endif
#include "runtime/native_packet_adapter.hpp"
#include "runtime/session_keeper.hpp"

namespace yume::runtime {
namespace {
using engine::Result;
using engine::ServiceKind;
using engine::Status;
using engine::StatusCode;

// The client offers its configured services for authenticated capability
// exchange but accepts no server-initiated OPEN.
class RefusingHandler final : public engine::StreamHandler {
public:
    RefusingHandler(engine::ProviderDescriptor descriptor, ServiceKind kind) noexcept
        : descriptor_(std::move(descriptor)), kind_(kind) {}

    const engine::ProviderDescriptor& descriptor() const noexcept override { return descriptor_; }
    ServiceKind service_kind() const noexcept override { return kind_; }
    Status authorize(const engine::StreamOpenContext&) override {
        return Status(StatusCode::FailedPrecondition,
                      "this client accepts no server-initiated streams");
    }
    void on_open(engine::StreamOpenContext,
                 std::shared_ptr<engine::StreamResponder> stream) override {
        if (stream) stream->close(Status(StatusCode::FailedPrecondition));
    }

private:
    engine::ProviderDescriptor descriptor_;
    ServiceKind kind_;
};

std::string describe(std::string_view prefix, const Status& status) {
    std::string text(prefix);
    if (!status.message().empty()) {
        text += ": ";
        text += status.message();
    }
    return text;
}

}  // namespace

struct NativeClientRuntime::State final : std::enable_shared_from_this<State> {
    State(std::shared_ptr<providers::AsioExecutionContext> execution,
          Report sink, NativeClientRuntimeOptions bounds, Stopped stopped)
        : context(std::move(execution)),
          report(std::move(sink)),
          on_stopped(std::make_shared<Stopped>(std::move(stopped))),
          options(bounds) {}

    void say(std::string_view text) noexcept {
        if (!report) return;
        try {
            report(text);
        } catch (...) {
        }
    }

    std::shared_ptr<engine::SessionEngine> active_session() const noexcept {
        return keeper ? keeper->active_session() : nullptr;
    }

    // Opens each managed TUN's packet stream once a session authenticates,
    // and hands the session to the circuits.
    void on_authenticated(
        const std::shared_ptr<engine::SessionEngine>& session) noexcept {
        if (pool && !closing) pool->set_session(session);
        try {
            for (const auto& [config, adapter] : packets) {
                if (closing || active_session() != session) break;
                session->async_open(config.service(), ServiceKind::PacketChannel,
                    [weak = weak_from_this(), expected = std::weak_ptr(session), adapter](
                        Result<std::shared_ptr<engine::StreamResponder>> opened) noexcept {
                        const auto self = weak.lock();
                        const auto session = expected.lock();
                        if (!self || self->closing || !session ||
                            self->active_session() != session) {
                            if (opened.ok()) opened.value()->close(Status(StatusCode::Closed));
                            return;
                        }
                        Status status;
                        try {
                            status = opened.ok() ? adapter->attach(opened.value(),
                                [weak, expected]() noexcept {
                                    if (const auto owner = weak.lock(); owner && !owner->closing) {
                                        if (const auto active = expected.lock();
                                            active &&
                                            owner->active_session() == active) {
                                            owner->say("packet stream ended, reconnecting");
                                            active->stop(Status(StatusCode::Closed));
                                        }
                                    }
                                }) : opened.status();
                        } catch (const std::bad_alloc&) {
                            status = Status(StatusCode::ResourceExhausted);
                        } catch (...) {
                            status = Status(StatusCode::Internal);
                        }
                        if (!status.ok()) {
                            try { self->say(describe("packet stream failed", status)); } catch (...) {}
                            if (opened.ok()) opened.value()->close(Status(status.code()));
                            session->stop(std::move(status));
                        }
                    });
            }
        } catch (const std::bad_alloc&) {
            session->stop(Status(StatusCode::ResourceExhausted));
        } catch (...) {
            session->stop(Status(StatusCode::Internal));
        }
    }

    // Opens streams through the circuits, or nothing without them.
    NativeStreamOpener opener() {
        if (!pool) return {};
        return [weak = std::weak_ptr<CircuitPool>(pool)](
                   const engine::RouteDestination& destination,
                   std::string service, engine::CancellationToken cancellation,
                   engine::SessionEngine::OpenCompletion done) {
            const auto circuits = weak.lock();
            if (!circuits) {
                done(Result<std::shared_ptr<engine::StreamResponder>>(
                    Status(StatusCode::Closed)));
                return;
            }
            circuits->open(destination, std::move(service),
                           std::move(cancellation), std::move(done));
        };
    }

    void stop(Status status) noexcept {
        if (closing) return;
        auto stopped = std::exchange(*on_stopped, {});
        if (keeper) keeper->record_failure(status);
        close();
        if (stopped) {
            try { stopped(std::move(status)); } catch (...) {}
        }
    }

    void close() noexcept {
        if (closing) return;
        closing = true;
        if (pool) pool->close();
        if (keeper) keeper->close();
        for (const auto& adapter : adapters) adapter->close();
        for (const auto& forward : forward_adapters) forward->close();
        if (endpoint) endpoint->close();
        for (const auto& packet : packets) packet.second->close();
    }

    std::shared_ptr<providers::AsioExecutionContext> context;
    Report report;
    // Packet cleanup retains this one-shot sink until its I/O drain completes.
    std::shared_ptr<Stopped> on_stopped;
    NativeClientRuntimeOptions options;
    std::shared_ptr<SessionKeeper> keeper;
    std::shared_ptr<NativeEndpoint> endpoint;
    // The client's circuits, when its configuration names them.
    std::shared_ptr<CircuitPool> pool;
    std::vector<config::v1::Socks5Adapter> socks5;
    std::vector<std::shared_ptr<NativeSocks5Adapter>> adapters;
    std::vector<config::v1::ForwardAdapter> forwards;
    std::vector<std::shared_ptr<NativeForwardAdapter>> forward_adapters;
    std::vector<std::pair<config::v1::PacketAdapter, std::shared_ptr<NativePacketAdapter>>> packets;
    std::optional<common::IpInterfaceAddress> transport_address;
    bool started{false};
    bool closing{false};
};

engine::Result<std::shared_ptr<NativeClientRuntime>> NativeClientRuntime::create(
    std::shared_ptr<providers::AsioExecutionContext> context,
    const config::v1::Config& config,
    const std::filesystem::path& config_base_directory,
    Report report,
    NativeClientRuntimeOptions options,
    Stopped on_stopped) {
    using Created = engine::Result<std::shared_ptr<NativeClientRuntime>>;
    if (!context || config.role() != config::v1::Role::Client ||
        options.reconnect_initial <= std::chrono::milliseconds::zero() ||
        options.reconnect_max < options.reconnect_initial) {
        return Created(Status(StatusCode::InvalidArgument, "a client configuration is required"));
    }
    context->require_context();
    try {
        auto state = std::make_shared<State>(context, report, options,
                                             std::move(on_stopped));
        SessionKeeperOptions keeping;
        keeping.reconnect_initial = options.reconnect_initial;
        keeping.reconnect_max = options.reconnect_max;
        keeping.report = std::move(report);
        keeping.on_status = options.on_status;
        keeping.on_authenticated =
            [weak = std::weak_ptr<State>(state)](
                const std::shared_ptr<engine::SessionEngine>&
                    session) noexcept {
                if (const auto self = weak.lock())
                    self->on_authenticated(session);
            };
        state->keeper = std::make_shared<SessionKeeper>(
            context, std::move(keeping),
            [weak = std::weak_ptr<State>(state)](Status status) noexcept {
                if (const auto self = weak.lock())
                    self->stop(std::move(status));
            });
        std::vector<NativeServiceBinding> bindings;
        for (const auto& service : config.services()) {
            const bool packet = service.kind() == config::v1::ServiceKind::Packet;
            auto capabilities = engine::mandatory_capabilities(engine::ProviderKind::StreamHandler);
            if (packet) capabilities = capabilities.with(engine::Capability::PacketChannels);
            auto descriptor = engine::ProviderDescriptor::create(
                "yume.client-refuse", engine::ProviderKind::StreamHandler, 1U, capabilities);
            if (!descriptor.ok()) return Created(descriptor.status());
            bindings.push_back({service.name(), std::make_shared<RefusingHandler>(
                std::move(descriptor).take_value(),
                packet ? ServiceKind::PacketChannel : ServiceKind::ByteStream)});
        }
        for (const auto& adapter : config.adapters()) {
            if (const auto* socks = std::get_if<config::v1::Socks5Adapter>(&adapter)) {
                state->socks5.push_back(*socks);
            } else if (const auto* forward = std::get_if<config::v1::ForwardAdapter>(&adapter)) {
                state->forwards.push_back(*forward);
            } else if (const auto* packet = std::get_if<config::v1::PacketAdapter>(&adapter)) {
#ifndef __linux__
                (void)packet;
                return Created(Status(StatusCode::FailedPrecondition,
                    "managed packet adapters require Linux"));
#else
                auto created = NativePacketAdapter::create(context, *packet);
                if (!created.ok()) return Created(created.status());
                state->packets.emplace_back(*packet, std::move(created).take_value());
#endif
            }
        }
        if (!state->packets.empty()) {
            // The client's own connection must stay outside the tunnel.
            const auto& address = std::get<config::v1::ClientEndpoint>(config.endpoint()).first_hop();
            state->transport_address = common::parse_canonical_ip_interface(
                address + (address.find(':') == std::string::npos ? "/32" : "/128"));
            if (!state->transport_address)
                return Created(Status(StatusCode::InvalidArgument,
                    "packet adapters require a numeric transport host, endpoint.connect_address "
                    "or SOCKS5 proxy"));
        }
        NativeEndpointOptions endpoint_options;
        endpoint_options.max_sessions = 1U;
        endpoint_options.max_pending_starts = 1U;
        endpoint_options.start_timeout = options.start_timeout;
        endpoint_options.caller_runs_socks5_adapters = !state->socks5.empty();
        endpoint_options.caller_runs_forward_adapters = !state->forwards.empty();
        endpoint_options.caller_runs_packet_adapters = !state->packets.empty();
        endpoint_options.outer_carrier_trace = options.outer_carrier_trace;
        if (!options.resolver_program.empty()) {
            providers::SystemResolverOptions resolver_options;
            resolver_options.program = options.resolver_program;
            auto resolver = providers::SystemResolver::create(context, std::move(resolver_options));
            if (!resolver.ok()) return Created(resolver.status());
            endpoint_options.resolver = std::move(resolver).take_value();
        }
        endpoint_options.session_ended = state->keeper->session_ended();
        auto endpoint = NativeEndpoint::create(context, config, config_base_directory,
                                               std::move(bindings), std::move(endpoint_options));
        if (!endpoint.ok()) return Created(endpoint.status());
        state->endpoint = std::move(endpoint).take_value();
        state->keeper->attach(state->endpoint);
        if (const auto& settings = config.circuits()) {
            CircuitPoolOptions pool_options;
            pool_options.hops = settings->hops;
            pool_options.min_hops = settings->min_hops;
            pool_options.plain_http_allowed = settings->plain_http_allowed;
            auto pool = CircuitPool::create(
                context, *state->endpoint->circuits(), pool_options,
                [weak = std::weak_ptr<State>(state)](std::string_view text) {
                    if (const auto self = weak.lock()) self->say(text);
                });
            if (!pool.ok()) {
                state->close();
                return Created(pool.status());
            }
            state->pool = std::move(pool).take_value();
        }
        return Created(std::shared_ptr<NativeClientRuntime>(new NativeClientRuntime(std::move(state))));
    } catch (const std::bad_alloc&) {
        return Created(Status(StatusCode::ResourceExhausted));
    }
}

NativeClientRuntime::NativeClientRuntime(std::shared_ptr<State> state) noexcept
    : state_(std::move(state)) {}

NativeClientRuntime::~NativeClientRuntime() noexcept { close(); }

engine::Status NativeClientRuntime::start() {
    // A stopped callback may release the runtime during the first attempt.
    const auto state = state_;
    state->context->require_context();
    if (state->started || state->closing) return Status(StatusCode::FailedPrecondition);
    state->started = true;
    try {
#ifdef __linux__
        for (const auto& [config, adapter] : state->packets) {
            auto created = LinuxTunNetwork::create(state->context, config, state->transport_address);
            if (!created.ok()) {
                state->close();
                return created.status();
            }
            const auto network = std::move(created).take_value();
            Status status;
            try {
                status = adapter->start(std::shared_ptr<engine::PacketChannel>(network, &network->channel()),
                    [network, report = state->report, stopped = state->on_stopped]() noexcept {
                        auto cleanup = network->close();
                        if (!cleanup.ok() && report) {
                            try { report(describe("TUN cleanup failed", cleanup)); } catch (...) {}
                        }
                        if (!cleanup.ok()) {
                            auto completion = std::exchange(*stopped, {});
                            if (completion) {
                                try { completion(std::move(cleanup)); } catch (...) {}
                            }
                        }
                    });
            } catch (...) {
                const auto cleanup = network->close();
                if (!cleanup.ok()) state->say("TUN cleanup failed");
                throw;
            }
            if (!status.ok()) {
                const auto cleanup = network->close();
                if (!cleanup.ok()) state->say("TUN cleanup failed");
                state->close();
                return status;
            }
        }
#endif
        for (const auto& adapter : state->socks5) {
            auto created = NativeSocks5Adapter::create(
                state->context, adapter,
                [weak = std::weak_ptr<State>(
                     state)]() -> std::shared_ptr<engine::SessionEngine> {
                    const auto self = weak.lock();
                    return self ? self->active_session() : nullptr;
                },
                state->options.socks5,
                [weak = std::weak_ptr<State>(state)](Status status) noexcept {
                    if (const auto self = weak.lock())
                        self->stop(std::move(status));
                },
                state->opener());
            if (!created.ok()) {
                state->close();
                return created.status();
            }
            state->adapters.push_back(std::move(created).take_value());
        }
        for (const auto& adapter : state->forwards) {
            auto created = NativeForwardAdapter::create(
                state->context, adapter,
                [weak = std::weak_ptr<State>(
                     state)]() -> std::shared_ptr<engine::SessionEngine> {
                    const auto self = weak.lock();
                    return self ? self->active_session() : nullptr;
                },
                state->options.forward,
                [weak = std::weak_ptr<State>(state)](Status status) noexcept {
                    if (const auto self = weak.lock())
                        self->stop(std::move(status));
                },
                state->opener());
            if (!created.ok()) {
                state->close();
                return created.status();
            }
            state->forward_adapters.push_back(std::move(created).take_value());
        }
    } catch (const std::bad_alloc&) {
        state->close();
        return Status(StatusCode::ResourceExhausted);
    } catch (...) {
        state->close();
        return Status(StatusCode::Internal);
    }
    state->keeper->start();
    return Status::success();
}

std::vector<boost::asio::ip::tcp::endpoint> NativeClientRuntime::socks5_endpoints() const {
    std::vector<boost::asio::ip::tcp::endpoint> endpoints;
    for (const auto& adapter : state_->adapters) endpoints.push_back(adapter->local_endpoint());
    return endpoints;
}

std::vector<boost::asio::ip::tcp::endpoint> NativeClientRuntime::forward_endpoints() const {
    std::vector<boost::asio::ip::tcp::endpoint> endpoints;
    for (const auto& forward : state_->forward_adapters) {
        const auto endpoint = forward->local_endpoint();
        if (endpoint.port() != 0U) endpoints.push_back(endpoint);
    }
    return endpoints;
}

NativeClientStatus NativeClientRuntime::status() const {
    return state_->keeper->status();
}

std::optional<CircuitPoolStatus> NativeClientRuntime::circuits() const {
    if (!state_->pool) return std::nullopt;
    return state_->pool->status();
}

engine::Status NativeClientRuntime::accept_route(std::string_view id) noexcept {
    if (!state_->pool) return Status(StatusCode::FailedPrecondition);
    return state_->pool->accept(id);
}

void NativeClientRuntime::close() noexcept { state_->close(); }

}  // namespace yume::runtime
