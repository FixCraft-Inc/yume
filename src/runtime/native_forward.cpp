/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_forward.hpp"

#include <list>
#include <new>
#include <optional>
#include <string>
#include <utility>
#include <variant>

#include <boost/asio/basic_waitable_timer.hpp>

#include "engine/cancellation.hpp"
#include "engine/route_provider.hpp"
#include "providers/asio_tcp_byte_channel_provider.hpp"
#include "providers/direct_route_handler.hpp"
#include "runtime/local_listener.hpp"

namespace yume::runtime {
namespace {
using engine::ByteChannel;
using engine::NetworkProtocol;
using engine::Result;
using engine::RouteDestination;
using engine::ServiceKind;
using engine::Status;
using engine::StatusCode;
using engine::StreamResponder;
using Clock = std::chrono::steady_clock;
using Timer = boost::asio::basic_waitable_timer<
    Clock, boost::asio::wait_traits<Clock>, providers::AsioExecutionContext::Executor>;
using Error = boost::system::error_code;

Result<RouteDestination> route_destination(const config::v1::ForwardDestination& destination) {
    Error error;
    const auto address = boost::asio::ip::make_address(destination.host, error);
    if (!error && address.is_v4())
        return RouteDestination::ipv4(NetworkProtocol::Tcp, address.to_v4().to_bytes(),
                                      destination.port);
    if (!error && address.is_v6())
        return RouteDestination::ipv6(NetworkProtocol::Tcp, address.to_v6().to_bytes(),
                                      destination.port);
    return RouteDestination::dns_name(NetworkProtocol::Tcp, destination.host, destination.port);
}

}  // namespace

struct NativeForwardAdapter::State final : std::enable_shared_from_this<State> {
    class Connection;

    State(std::shared_ptr<providers::AsioExecutionContext> execution, std::string service_name,
          std::optional<RouteDestination> route, NativeSessionSource session_source,
          NativeForwardLimits bounds, std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> owner)
        : context(std::move(execution)),
          service(std::move(service_name)),
          destination(std::move(route)),
          sessions(std::move(session_source)),
          limits(bounds),
          channels(std::move(owner)) {}

    std::shared_ptr<engine::SessionEngine> active_session() const noexcept {
        if (closing || !sessions) return nullptr;
        try {
            return sessions();
        } catch (...) {
            return nullptr;
        }
    }

    void adopt(LocalListener::Connection accepted) noexcept;
    void remove(const Connection* connection) noexcept;
    void stop(Status status) noexcept;
    void close() noexcept;

    std::shared_ptr<providers::AsioExecutionContext> context;
    std::string service;
    std::optional<RouteDestination> destination;
    NativeSessionSource sessions;
    Stopped on_stopped;
    NativeForwardLimits limits;
    std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> channels;
    std::shared_ptr<LocalListener> listener;
    boost::asio::ip::tcp::endpoint endpoint;
    std::list<std::shared_ptr<Connection>> connections;
    bool closing{false};
    StatusCode failure{StatusCode::Ok};
};

// One local connection from accept until its stream is bridged or it closes.
class NativeForwardAdapter::State::Connection final
    : public std::enable_shared_from_this<Connection> {
public:
    Connection(std::weak_ptr<State> owner, std::unique_ptr<ByteChannel> channel,
               providers::AsioExecutionContext::Executor executor)
        : owner_(std::move(owner)), channel_(std::move(channel)), timer_(executor) {}

    // Nothing is read from the socket before the OPEN is accepted, so early
    // application bytes wait in it for the route bridge.
    void start() noexcept {
        const auto owner = owner_.lock();
        const auto session = owner ? owner->active_session() : nullptr;
        if (!session) {
            finish();
            return;
        }
        arm_deadline(owner->limits.open_timeout);
        if (done_) return;
        try {
            session->async_open(owner->service, ServiceKind::ByteStream, owner->destination,
                open_cancellation_.token(),
                [self = shared_from_this()](Result<std::shared_ptr<StreamResponder>> result) noexcept {
                    self->on_open(std::move(result));
                });
        } catch (...) {
            finish();
        }
    }

    void close() noexcept { finish(); }

private:
    void on_open(Result<std::shared_ptr<StreamResponder>> result) noexcept {
        if (done_) {
            if (result.ok() && result.value()) result.value()->close(Status(StatusCode::Cancelled));
            return;
        }
        if (!result.ok() || !result.value()) {
            finish();
            return;
        }
        bridge(std::move(result).take_value());
    }

    void bridge(std::shared_ptr<StreamResponder> stream) noexcept {
        const auto self = shared_from_this();
        done_ = true;
        disarm_deadline();
        auto channel = std::move(channel_);
        if (const auto owner = owner_.lock()) owner->remove(this);
        auto connection = engine::RouteConnection::byte_stream(std::move(channel));
        if (!connection.ok()) {
            stream->close(connection.status());
            return;
        }
        providers::bridge_established_route(std::move(stream), std::move(connection).take_value());
    }

    void arm_deadline(std::chrono::milliseconds duration) noexcept {
        try {
            timer_.expires_after(duration);
            timer_.async_wait([self = shared_from_this()](const Error& error) noexcept {
                // Finishing first makes an acceptance that cancellation
                // delivers inline close its stream instead of bridging it.
                if (!error) self->finish();
            });
        } catch (...) {
            finish();
        }
    }

    void disarm_deadline() noexcept {
        Error ignored;
        timer_.cancel(ignored);
    }

    void finish() noexcept {
        if (done_) return;
        done_ = true;
        const auto self = shared_from_this();
        disarm_deadline();
        open_cancellation_.cancel();
        if (channel_) {
            channel_->cancel();
            channel_->close();
        }
        if (const auto owner = owner_.lock()) owner->remove(this);
    }

    std::weak_ptr<State> owner_;
    std::unique_ptr<ByteChannel> channel_;
    Timer timer_;
    engine::CancellationSource open_cancellation_;
    bool done_{false};
};

void NativeForwardAdapter::State::adopt(LocalListener::Connection accepted) noexcept {
    try {
        auto connection = std::make_shared<Connection>(weak_from_this(),
                                                       std::move(accepted.channel),
                                                       context->executor());
        connections.push_back(connection);
        connection->start();
    } catch (...) {
    }
}

void NativeForwardAdapter::State::remove(const Connection* connection) noexcept {
    connections.remove_if([connection](const auto& value) { return value.get() == connection; });
    if (listener) listener->resume();
}

void NativeForwardAdapter::State::stop(Status status) noexcept {
    if (closing) return;
    failure = status.code();
    auto stopped = std::move(on_stopped);
    close();
    if (stopped) {
        try { stopped(std::move(status)); } catch (...) {}
    }
}

void NativeForwardAdapter::State::close() noexcept {
    if (closing) return;
    closing = true;
    if (listener) listener->close();
    auto current = std::move(connections);
    connections.clear();
    for (const auto& connection : current) connection->close();
    channels->cancel();
    on_stopped = {};
}

engine::Result<std::shared_ptr<NativeForwardAdapter>> NativeForwardAdapter::create(
    std::shared_ptr<providers::AsioExecutionContext> context,
    const config::v1::ForwardAdapter& adapter,
    NativeSessionSource sessions,
    NativeForwardLimits limits,
    Stopped on_stopped) {
    using Created = engine::Result<std::shared_ptr<NativeForwardAdapter>>;
    if (!context || !sessions || limits.max_connections == 0U || limits.max_connections > 4096U ||
        limits.open_timeout <= std::chrono::milliseconds::zero()) {
        return Created(Status(StatusCode::InvalidArgument));
    }
    context->require_context();
    try {
        std::optional<RouteDestination> destination;
        if (adapter.destination()) {
            auto route = route_destination(*adapter.destination());
            if (!route.ok()) return Created(route.status());
            destination = std::move(route).take_value();
        }
        LocalListener::Address address = LocalListener::Unix{};
        if (const auto* loopback = std::get_if<config::v1::LoopbackListener>(&adapter.listener())) {
            Error error;
            const auto ip = boost::asio::ip::make_address(loopback->address, error);
            if (error) return Created(Status(StatusCode::InvalidArgument));
            address = LocalListener::Loopback{ip, loopback->port};
        } else {
            address = LocalListener::Unix{std::get<config::v1::UnixListener>(adapter.listener()).path};
        }
        providers::AsioTcpChannelLimits channel_limits;
        channel_limits.max_active_channels = limits.max_connections;
        auto channels = providers::AsioTcpAcceptedChannelOwner::create(context, channel_limits);
        if (!channels.ok()) return Created(channels.status());
        auto state = std::make_shared<State>(context, adapter.service(), std::move(destination),
                                             std::move(sessions), limits,
                                             std::move(channels).take_value());
        auto listener = LocalListener::open(context, address, state->channels, "forward listener");
        if (!listener.ok()) return Created(listener.status());
        state->listener = std::move(listener).take_value();
        state->endpoint = state->listener->tcp_endpoint();
        // Keep creation failures on the synchronous result path. Publish the
        // callback only once an owner and the first accept or retry exist.
        auto result = std::shared_ptr<NativeForwardAdapter>(new NativeForwardAdapter(state));
        const std::weak_ptr<State> weak = state;
        state->listener->start(
            [weak](LocalListener::Connection connection) {
                if (const auto self = weak.lock()) self->adopt(std::move(connection));
            },
            [weak] {
                const auto self = weak.lock();
                return !self || self->closing ||
                       self->connections.size() >= self->limits.max_connections;
            },
            [weak](Status status) {
                if (const auto self = weak.lock()) self->stop(std::move(status));
            });
        if (state->closing) return Created(Status(state->failure));
        state->on_stopped = std::move(on_stopped);
        return Created(std::move(result));
    } catch (const std::bad_alloc&) {
        return Created(Status(StatusCode::ResourceExhausted));
    } catch (...) {
        return Created(Status(StatusCode::Internal));
    }
}

NativeForwardAdapter::NativeForwardAdapter(std::shared_ptr<State> state) noexcept
    : state_(std::move(state)) {}

NativeForwardAdapter::~NativeForwardAdapter() noexcept { close(); }

boost::asio::ip::tcp::endpoint NativeForwardAdapter::local_endpoint() const noexcept {
    return state_->endpoint;
}

void NativeForwardAdapter::close() noexcept { state_->close(); }

}  // namespace yume::runtime
