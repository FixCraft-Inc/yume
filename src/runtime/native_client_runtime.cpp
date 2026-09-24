/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_client_runtime.hpp"

#include <algorithm>
#include <mutex>
#include <new>
#include <string>
#include <utility>
#include <variant>

#include <boost/asio/basic_waitable_timer.hpp>

#include "engine/session_engine.hpp"
#include "engine/stream_handler.hpp"
#include "runtime/native_endpoint.hpp"
#ifdef __linux__
#include "runtime/linux_tun_network.hpp"
#endif
#include "runtime/native_packet_adapter.hpp"

namespace yume::runtime {
namespace {
using engine::Result;
using engine::ServiceKind;
using engine::Status;
using engine::StatusCode;
using Clock = std::chrono::steady_clock;
using Timer = boost::asio::basic_waitable_timer<
    Clock, boost::asio::wait_traits<Clock>, providers::AsioExecutionContext::Executor>;

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

engine::SessionTraffic add(engine::SessionTraffic total, const engine::SessionTraffic& more) noexcept {
    total.payload_bytes_sent += more.payload_bytes_sent;
    total.payload_bytes_received += more.payload_bytes_received;
    total.record_bytes_sent += more.record_bytes_sent;
    total.record_bytes_received += more.record_bytes_received;
    return total;
}

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
    State(std::shared_ptr<providers::AsioExecutionContext> execution, Report sink,
          NativeClientRuntimeOptions bounds, Stopped stopped)
        : context(std::move(execution)),
          report(std::move(sink)),
          on_stopped(std::make_shared<Stopped>(std::move(stopped))),
          options(bounds),
          timer(context->executor()),
          backoff(bounds.reconnect_initial) {}

    void say(std::string_view text) noexcept {
        if (!report) return;
        try {
            report(text);
        } catch (...) {
        }
    }

    std::shared_ptr<engine::SessionEngine> active_session() const noexcept {
        return session && session->state() == engine::SessionState::Active ? session : nullptr;
    }

    // Applies one state change to the published status, then reports it.
    // A failed string copy keeps the state change and the older text.
    template <typename Change>
    void transition(Change change) noexcept {
        NativeClientStatus copy;
        bool notify = static_cast<bool>(options.on_status);
        {
            std::lock_guard<std::mutex> lock(status_mutex);
            try {
                change(published);
            } catch (...) {
            }
            if (notify) {
                try {
                    copy = published;
                    copy.traffic = traffic_locked();
                } catch (...) {
                    notify = false;
                }
            }
        }
        if (notify) {
            try {
                options.on_status(copy);
            } catch (...) {
            }
        }
    }

    engine::SessionTraffic traffic_locked() const noexcept {
        return counted_session ? add(finished_traffic, counted_session->traffic())
                               : finished_traffic;
    }

    // Folds a finished session into the totals and stops counting it.
    void retire_counted_session() noexcept {
        std::lock_guard<std::mutex> lock(status_mutex);
        if (!counted_session) return;
        finished_traffic = add(finished_traffic, counted_session->traffic());
        counted_session.reset();
    }

    NativeClientStatus snapshot() const {
        std::lock_guard<std::mutex> lock(status_mutex);
        NativeClientStatus copy = published;
        copy.traffic = traffic_locked();
        return copy;
    }


    void connect() noexcept {
        if (closing) return;
        Status status;
        try {
            status = endpoint->async_start_session(
                [weak = weak_from_this()](Result<std::shared_ptr<engine::SessionEngine>> result) {
                    if (const auto self = weak.lock()) self->on_session(std::move(result));
                });
        } catch (const std::bad_alloc&) {
            status = Status(StatusCode::ResourceExhausted);
        } catch (...) {
            status = Status(StatusCode::Internal);
        }
        if (!status.ok()) {
            try { say(describe("session start refused", status)); } catch (...) {}
            schedule_reconnect(&status);
            return;
        }
        transition([](NativeClientStatus& current) {
            current.state = NativeClientState::Connecting;
            current.retry_delay = std::chrono::milliseconds(0);
        });
    }

    void on_session(Result<std::shared_ptr<engine::SessionEngine>> result) noexcept {
        if (closing) {
            if (result.ok() && result.value()) result.value()->stop(Status(StatusCode::Closed));
            return;
        }
        if (!result.ok()) {
            try { say(describe("session failed", result.status())); } catch (...) {}
            schedule_reconnect(&result.status());
            return;
        }
        session = std::move(result).take_value();
        authenticated_at = Clock::now();
        {
            std::lock_guard<std::mutex> lock(status_mutex);
            counted_session = session;
        }
        const auto peer = session->authenticated_peer();
        transition([&](NativeClientStatus& current) {
            current.state = NativeClientState::Connected;
            current.connected_since = authenticated_at;
            current.retry_delay = std::chrono::milliseconds(0);
            ++current.sessions;
            current.failed_attempts = 0U;
            current.server_identity.clear();
            if (peer.ok()) current.server_identity = peer.value().identity();
        });
        say("session authenticated");
        try {
            for (const auto& [config, adapter] : packets) {
                if (closing || !active_session()) break;
                session->async_open(config.service(), ServiceKind::PacketChannel,
                    [weak = weak_from_this(), expected = std::weak_ptr(session), adapter](
                        Result<std::shared_ptr<engine::StreamResponder>> opened) noexcept {
                        const auto self = weak.lock();
                        const auto session = expected.lock();
                        if (!self || self->closing || !session || self->session != session) {
                            if (opened.ok()) opened.value()->close(Status(StatusCode::Closed));
                            return;
                        }
                        Status status;
                        try {
                            status = opened.ok() ? adapter->attach(opened.value(),
                                [weak, expected]() noexcept {
                                    if (const auto owner = weak.lock(); owner && !owner->closing) {
                                        if (const auto active = expected.lock(); active && owner->session == active) {
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
            if (session) session->stop(Status(StatusCode::ResourceExhausted));
        } catch (...) {
            if (session) session->stop(Status(StatusCode::Internal));
        }
    }

    void on_session_ended(const std::shared_ptr<engine::SessionEngine>& ended,
                          const Status& reason) noexcept {
        if (closing || session != ended) return;
        session.reset();
        retire_counted_session();
        transition([&](NativeClientStatus& current) {
            current.server_identity.clear();
            current.last_failure = reason;
        });
        say("session ended, reconnecting");
        // Reconnect at once only after a session that stayed up for the longest
        // backoff. A path that drops every connection right after AUTH would
        // otherwise redial in a tight loop, which stands out on the wire and
        // uses up entries in the server's admission replay cache, shared by
        // every client.
        if (Clock::now() - authenticated_at >= options.reconnect_max) {
            backoff = options.reconnect_initial;
            connect();
        } else {
            schedule_reconnect();
        }
    }

    // Failed attempts and short sessions wait, doubling up to reconnect_max.
    // The retry timer is armed before the status update, so a status copy
    // never takes the allocation that arming depends on.
    void schedule_reconnect(const Status* failure = nullptr) noexcept {
        if (closing) return;
        const auto delay = backoff;
        backoff = std::min(backoff * 2, options.reconnect_max);
        try {
            timer.expires_after(delay);
            timer.async_wait([weak = weak_from_this()](const boost::system::error_code& error) {
                const auto self = weak.lock();
                if (!self || self->closing) return;
                if (error) {
                    self->stop(Status(StatusCode::Internal));
                    return;
                }
                self->connect();
            });
        } catch (const std::bad_alloc&) {
            stop(Status(StatusCode::ResourceExhausted));
            return;
        } catch (...) {
            stop(Status(StatusCode::Internal));
            return;
        }
        transition([&](NativeClientStatus& current) {
            current.state = NativeClientState::Waiting;
            current.server_identity.clear();
            current.retry_delay = delay;
            if (failure) {
                ++current.failed_attempts;
                current.last_failure = *failure;
            }
        });
    }

    void stop(Status status) noexcept {
        if (closing) return;
        auto stopped = std::exchange(*on_stopped, {});
        transition([&](NativeClientStatus& current) { current.last_failure = status; });
        close();
        if (stopped) {
            try { stopped(std::move(status)); } catch (...) {}
        }
    }

    void close() noexcept {
        if (closing) return;
        closing = true;
        boost::system::error_code ignored;
        timer.cancel(ignored);
        for (const auto& adapter : adapters) adapter->close();
        for (const auto& forward : forward_adapters) forward->close();
        if (endpoint) endpoint->close();
        for (const auto& packet : packets) packet.second->close();
        session.reset();
        retire_counted_session();
        transition([](NativeClientStatus& current) {
            current.state = NativeClientState::Closed;
            current.server_identity.clear();
            current.retry_delay = std::chrono::milliseconds(0);
        });
    }

    std::shared_ptr<providers::AsioExecutionContext> context;
    Report report;
    // Packet cleanup retains this one-shot sink until its I/O drain completes.
    std::shared_ptr<Stopped> on_stopped;
    NativeClientRuntimeOptions options;
    Timer timer;
    std::chrono::milliseconds backoff;
    Clock::time_point authenticated_at{};
    std::shared_ptr<NativeEndpoint> endpoint;
    std::vector<config::v1::Socks5Adapter> socks5;
    std::vector<std::shared_ptr<NativeSocks5Adapter>> adapters;
    std::vector<config::v1::ForwardAdapter> forwards;
    std::vector<std::shared_ptr<NativeForwardAdapter>> forward_adapters;
    std::vector<std::pair<config::v1::PacketAdapter, std::shared_ptr<NativePacketAdapter>>> packets;
    std::optional<common::IpInterfaceAddress> transport_address;
    std::shared_ptr<engine::SessionEngine> session;
    bool started{false};
    bool closing{false};
    // Guards the published status, read from any thread by status().
    mutable std::mutex status_mutex;
    NativeClientStatus published;
    engine::SessionTraffic finished_traffic;
    std::shared_ptr<engine::SessionEngine> counted_session;
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
        auto state = std::make_shared<State>(context, std::move(report), options,
                                              std::move(on_stopped));
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
            const auto& client = std::get<config::v1::ClientEndpoint>(config.endpoint());
            const auto& address = client.connect_address() ? *client.connect_address() : client.host();
            state->transport_address = common::parse_canonical_ip_interface(
                address + (address.find(':') == std::string::npos ? "/32" : "/128"));
            if (!state->transport_address)
                return Created(Status(StatusCode::InvalidArgument,
                    "packet adapters require a numeric transport host or endpoint.connect_address"));
        }
        NativeEndpointOptions endpoint_options;
        endpoint_options.max_sessions = 1U;
        endpoint_options.max_pending_starts = 1U;
        endpoint_options.start_timeout = options.start_timeout;
        endpoint_options.caller_runs_socks5_adapters = !state->socks5.empty();
        endpoint_options.caller_runs_forward_adapters = !state->forwards.empty();
        endpoint_options.caller_runs_packet_adapters = !state->packets.empty();
        if (!options.resolver_program.empty()) {
            providers::SystemResolverOptions resolver_options;
            resolver_options.program = options.resolver_program;
            auto resolver = providers::SystemResolver::create(context, std::move(resolver_options));
            if (!resolver.ok()) return Created(resolver.status());
            endpoint_options.resolver = std::move(resolver).take_value();
        }
        endpoint_options.session_ended = [weak = std::weak_ptr<State>(state)](
            std::shared_ptr<engine::SessionEngine> session, Status reason) noexcept {
            if (const auto self = weak.lock()) self->on_session_ended(session, reason);
        };
        auto endpoint = NativeEndpoint::create(context, config, config_base_directory,
                                               std::move(bindings), std::move(endpoint_options));
        if (!endpoint.ok()) return Created(endpoint.status());
        state->endpoint = std::move(endpoint).take_value();
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
                [weak = std::weak_ptr<State>(state)]() -> std::shared_ptr<engine::SessionEngine> {
                    const auto self = weak.lock();
                    return self ? self->active_session() : nullptr;
                },
                state->options.socks5,
                [weak = std::weak_ptr<State>(state)](Status status) noexcept {
                    if (const auto self = weak.lock()) self->stop(std::move(status));
                });
            if (!created.ok()) {
                state->close();
                return created.status();
            }
            state->adapters.push_back(std::move(created).take_value());
        }
        for (const auto& adapter : state->forwards) {
            auto created = NativeForwardAdapter::create(
                state->context, adapter,
                [weak = std::weak_ptr<State>(state)]() -> std::shared_ptr<engine::SessionEngine> {
                    const auto self = weak.lock();
                    return self ? self->active_session() : nullptr;
                },
                state->options.forward,
                [weak = std::weak_ptr<State>(state)](Status status) noexcept {
                    if (const auto self = weak.lock()) self->stop(std::move(status));
                });
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
    state->connect();
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

NativeClientStatus NativeClientRuntime::status() const { return state_->snapshot(); }

void NativeClientRuntime::close() noexcept { state_->close(); }

}  // namespace yume::runtime
