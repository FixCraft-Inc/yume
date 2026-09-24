/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_socks5.hpp"

#include <algorithm>
#include <array>
#include <list>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/basic_socket_acceptor.hpp>
#include <boost/asio/basic_waitable_timer.hpp>
#include <boost/asio/ip/v6_only.hpp>

#include "engine/buffer.hpp"
#include "engine/cancellation.hpp"
#include "engine/route_provider.hpp"
#include "providers/asio_tcp_byte_channel_provider.hpp"
#include "providers/direct_route_handler.hpp"
#include "runtime/native_socks5_udp.hpp"
#include "runtime/socks5_request.hpp"

namespace yume::runtime {
namespace {
using engine::Buffer;
using engine::ByteChannel;
using engine::Result;
using engine::RouteDestination;
using engine::ServiceKind;
using engine::Status;
using engine::StatusCode;
using engine::StreamResponder;
using Clock = std::chrono::steady_clock;
using Timer = boost::asio::basic_waitable_timer<
    Clock, boost::asio::wait_traits<Clock>, providers::AsioExecutionContext::Executor>;
using Acceptor = boost::asio::basic_socket_acceptor<
    boost::asio::ip::tcp, providers::AsioExecutionContext::Executor>;
using Error = boost::system::error_code;

constexpr std::chrono::seconds kAcceptRetryDelay{1};

Status diagnostic(StatusCode code, std::string_view message) noexcept {
    try {
        return Status(code, message);
    } catch (...) {
        return Status(code);
    }
}

// The relay socket as the BND field of a UDP ASSOCIATE reply.
Result<RouteDestination> relay_destination(const boost::asio::ip::udp::endpoint& relay) {
    const auto address = relay.address();
    if (address.is_v4()) {
        return RouteDestination::ipv4(engine::NetworkProtocol::Udp, address.to_v4().to_bytes(),
                                      relay.port());
    }
    return RouteDestination::ipv6(engine::NetworkProtocol::Udp, address.to_v6().to_bytes(),
                                  relay.port());
}

}  // namespace

struct NativeSocks5Adapter::State final : std::enable_shared_from_this<State> {
    class Connection;

    State(std::shared_ptr<providers::AsioExecutionContext> execution,
          std::string service_name,
          std::optional<std::string> udp_service_name,
          NativeSessionSource session_source,
          NativeSocks5Limits bounds,
          std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> owner)
        : context(std::move(execution)),
          service(std::move(service_name)),
          udp_service(std::move(udp_service_name)),
          sessions(std::move(session_source)),
          limits(bounds),
          channels(std::move(owner)),
          acceptor(context->executor()),
          retry(context->executor()) {}

    std::shared_ptr<engine::SessionEngine> active_session() const noexcept {
        if (closing || !sessions) return nullptr;
        try {
            return sessions();
        } catch (...) {
            return nullptr;
        }
    }

    void start_accept() noexcept;
    void retry_accept() noexcept;
    void adopt(providers::AsioTcpSocket socket) noexcept;
    void remove(const Connection* connection) noexcept;
    void stop(Status status) noexcept;
    void close() noexcept;

    std::shared_ptr<providers::AsioExecutionContext> context;
    std::string service;
    std::optional<std::string> udp_service;
    NativeSessionSource sessions;
    Stopped on_stopped;
    NativeSocks5Limits limits;
    std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> channels;
    Acceptor acceptor;
    Timer retry;
    boost::asio::ip::tcp::endpoint endpoint;
    std::list<std::shared_ptr<Connection>> connections;
    bool accepting{false};
    bool retry_pending{false};
    bool closing{false};
    StatusCode failure{StatusCode::Ok};
};

// One local client from accept until its stream is bridged, its UDP
// association ends, or it closes.
class NativeSocks5Adapter::State::Connection final
    : public std::enable_shared_from_this<Connection> {
public:
    Connection(std::weak_ptr<State> owner, std::string service,
               std::optional<std::string> udp_service, NativeSocks5Limits limits,
               std::unique_ptr<ByteChannel> channel, boost::asio::ip::address peer,
               providers::AsioExecutionContext::Executor executor)
        : owner_(std::move(owner)),
          service_(std::move(service)),
          udp_service_(std::move(udp_service)),
          limits_(limits),
          channel_(std::move(channel)),
          peer_(std::move(peer)),
          timer_(executor) {}

    void start() noexcept {
        arm_deadline(limits_.handshake_timeout);
        advance();
    }

    void close() noexcept { finish(); }

private:
    enum class Phase : std::uint8_t { Greeting, Request, Opening, Replying, Associated };
    enum class AfterWrite : std::uint8_t { ReadRequest, Close, Bridge, WatchControl };

    void read(std::size_t required_bytes) noexcept {
        if (done_ || reading_) return;
        const std::size_t limit = phase_ == Phase::Greeting
            ? socks5::kMaxGreetingBytes : socks5::kMaxRequestBytes;
        if (required_bytes <= input_.size() || required_bytes > limit) {
            finish();
            return;
        }
        reading_ = true;
        try {
            // Leave early application bytes in the socket for RouteBridge.
            // Reading only the next handshake field also keeps buffering bounded
            // while the remote endpoint decides whether to accept the route.
            channel_->async_read(std::min(required_bytes - input_.size(), channel_->max_read_size()),
                io_cancellation_.token(),
                [self = shared_from_this()](Result<Buffer> result) noexcept {
                    self->on_read(std::move(result));
                });
        } catch (...) {
            reading_ = false;
            finish();
        }
    }

    void on_read(Result<Buffer> result) noexcept {
        reading_ = false;
        if (done_) return;
        if (!result.ok() || result.value().empty()) {
            finish();
            return;
        }
        try {
            for (const std::byte byte : result.value().bytes()) {
                input_.push_back(static_cast<std::uint8_t>(byte));
            }
        } catch (...) {
            finish();
            return;
        }
        advance();
    }

    void advance() noexcept {
        if (done_) return;
        if (phase_ == Phase::Greeting) {
            socks5::Greeting greeting;
            const auto parsed = socks5::parse_greeting(input_, greeting);
            if (parsed == socks5::Parse::NeedMore) {
                read(greeting.required_bytes);
                return;
            }
            if (parsed == socks5::Parse::Invalid) {
                finish();
                return;
            }
            input_.clear();
            if (!greeting.no_authentication) {
                write(socks5::method_reply(false), AfterWrite::Close);
                return;
            }
            phase_ = Phase::Request;
            write(socks5::method_reply(true), AfterWrite::ReadRequest);
            return;
        }
        if (phase_ != Phase::Request) return;
        socks5::Request request;
        const auto parsed = socks5::parse_request(input_, request);
        if (parsed == socks5::Parse::NeedMore) {
            read(request.required_bytes);
            return;
        }
        if (parsed == socks5::Parse::Invalid) {
            finish();
            return;
        }
        input_.clear();
        if (request.reply != socks5::Reply::Succeeded) {
            write(socks5::reply(request.reply), AfterWrite::Close);
            return;
        }
        if (request.command == socks5::Command::UdpAssociate) {
            associate(request.udp_source_port);
            return;
        }
        if (!request.destination) {
            write(socks5::reply(socks5::Reply::GeneralFailure), AfterWrite::Close);
            return;
        }
        open(std::move(*request.destination));
    }

    std::shared_ptr<engine::SessionEngine> current_session() const noexcept {
        const auto owner = owner_.lock();
        return owner ? owner->active_session() : nullptr;
    }

    void open(RouteDestination destination) noexcept {
        const auto session = current_session();
        if (!session) {
            write(socks5::reply(socks5::Reply::GeneralFailure), AfterWrite::Close);
            return;
        }
        phase_ = Phase::Opening;
        arm_deadline(limits_.open_timeout);
        if (done_) return;
        try {
            session->async_open(service_, ServiceKind::ByteStream, std::move(destination),
                open_cancellation_.token(),
                [self = shared_from_this()](Result<std::shared_ptr<StreamResponder>> result) noexcept {
                    self->on_open(std::move(result));
                });
        } catch (...) {
            disarm_deadline();
            phase_ = Phase::Replying;
            write(socks5::reply(socks5::Reply::GeneralFailure), AfterWrite::Close);
        }
    }

    void on_open(Result<std::shared_ptr<StreamResponder>> result) noexcept {
        if (done_ || phase_ != Phase::Opening) {
            if (result.ok() && result.value()) result.value()->close(Status(StatusCode::Cancelled));
            return;
        }
        disarm_deadline();
        phase_ = Phase::Replying;
        if (!result.ok() || !result.value()) {
            write(socks5::reply(result.ok() ? socks5::Reply::GeneralFailure
                                            : socks5::reply_for(result.status())),
                  AfterWrite::Close);
            return;
        }
        stream_ = std::move(result).take_value();
        write(socks5::reply(socks5::Reply::Succeeded), AfterWrite::Bridge);
    }

    // The association relays datagrams from this client's own address only.
    // The server authorizes each destination when its packet stream opens.
    void associate(std::uint16_t client_port) noexcept {
        if (!udp_service_) {
            write(socks5::reply(socks5::Reply::CommandNotSupported), AfterWrite::Close);
            return;
        }
        const auto owner = owner_.lock();
        if (!owner || !owner->active_session()) {
            write(socks5::reply(socks5::Reply::GeneralFailure), AfterWrite::Close);
            return;
        }
        phase_ = Phase::Replying;
        std::vector<std::uint8_t> bound;
        try {
            auto created = NativeSocks5UdpAssociation::create(owner->context, *udp_service_,
                owner->sessions, limits_, owner->endpoint.address(),
                boost::asio::ip::udp::endpoint(peer_, client_port));
            if (created.ok()) {
                association_ = std::move(created).take_value();
                const auto relay = relay_destination(association_->relay_endpoint());
                if (relay.ok()) bound = socks5::associate_reply(relay.value());
            }
        } catch (...) {
            bound.clear();
        }
        if (bound.empty()) {
            write(socks5::reply(socks5::Reply::GeneralFailure), AfterWrite::Close);
            return;
        }
        write(bound, AfterWrite::WatchControl);
    }

    // RFC 1928 ties the association to this TCP connection. Nothing more is
    // expected on it, so its closure or any further byte ends the association.
    void watch_control() noexcept {
        disarm_deadline();
        phase_ = Phase::Associated;
        try {
            channel_->async_read(1U, io_cancellation_.token(),
                [self = shared_from_this()](Result<Buffer>) noexcept { self->finish(); });
        } catch (...) {
            finish();
        }
    }

    void write(std::span<const std::uint8_t> bytes, AfterWrite after) noexcept {
        if (done_) return;
        auto buffer = Buffer::copy_from(std::as_bytes(bytes), bytes.size());
        if (!buffer.ok()) {
            finish();
            return;
        }
        try {
            channel_->async_write(std::move(buffer).take_value(), io_cancellation_.token(),
                [self = shared_from_this(), after, expected = bytes.size()](
                    Status status, std::size_t written) noexcept {
                    self->on_write(std::move(status), written, expected, after);
                });
        } catch (...) {
            finish();
        }
    }

    void on_write(Status status, std::size_t written, std::size_t expected,
                  AfterWrite after) noexcept {
        if (done_) return;
        if (!status.ok() || written != expected || after == AfterWrite::Close) {
            finish();
            return;
        }
        if (after == AfterWrite::ReadRequest) {
            advance();
        } else if (after == AfterWrite::WatchControl) {
            watch_control();
        } else {
            bridge();
        }
    }

    void bridge() noexcept {
        const auto self = shared_from_this();
        done_ = true;
        disarm_deadline();
        auto stream = std::move(stream_);
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
        const std::uint64_t generation = ++deadline_generation_;
        try {
            timer_.expires_after(duration);
            timer_.async_wait([self = shared_from_this(), generation](const Error& error) noexcept {
                if (!error && generation == self->deadline_generation_) self->on_deadline();
            });
        } catch (...) {
            finish();
        }
    }

    void on_deadline() noexcept {
        if (done_) return;
        if (phase_ == Phase::Opening) {
            // Choose the reply before cancellation, which may invoke on_open
            // inline. Any later acceptance must close its stream, not bridge it.
            phase_ = Phase::Replying;
            open_cancellation_.cancel();
            write(socks5::reply(socks5::Reply::TtlExpired), AfterWrite::Close);
        } else {
            finish();
        }
    }

    void disarm_deadline() noexcept {
        // cancel() cannot retract a timer handler already queued for delivery.
        ++deadline_generation_;
        Error ignored;
        timer_.cancel(ignored);
    }

    void finish() noexcept {
        if (done_) return;
        done_ = true;
        const auto self = shared_from_this();
        disarm_deadline();
        io_cancellation_.cancel();
        open_cancellation_.cancel();
        if (stream_) {
            stream_->close(Status(StatusCode::Cancelled));
            stream_.reset();
        }
        if (association_) {
            association_->close();
            association_.reset();
        }
        if (channel_) {
            channel_->cancel();
            channel_->close();
        }
        if (const auto owner = owner_.lock()) owner->remove(this);
    }

    std::weak_ptr<State> owner_;
    const std::string service_;
    const std::optional<std::string> udp_service_;
    const NativeSocks5Limits limits_;
    std::unique_ptr<ByteChannel> channel_;
    const boost::asio::ip::address peer_;
    Timer timer_;
    engine::CancellationSource io_cancellation_;
    engine::CancellationSource open_cancellation_;
    std::vector<std::uint8_t> input_;
    std::shared_ptr<StreamResponder> stream_;
    std::shared_ptr<NativeSocks5UdpAssociation> association_;
    std::uint64_t deadline_generation_{0U};
    Phase phase_{Phase::Greeting};
    bool reading_{false};
    bool done_{false};
};

void NativeSocks5Adapter::State::start_accept() noexcept {
    if (closing || accepting || retry_pending || connections.size() >= limits.max_connections) return;
    try {
        accepting = true;
        acceptor.async_accept(context->executor(),
            [self = shared_from_this()](const Error& error, providers::AsioTcpSocket socket) noexcept {
                self->accepting = false;
                if (self->closing) {
                    Error ignored;
                    socket.close(ignored);
                    return;
                }
                if (error) {
                    // A local listener survives transient failures such as
                    // descriptor exhaustion and tries again after a pause.
                    self->retry_accept();
                    return;
                }
                self->adopt(std::move(socket));
                self->start_accept();
            });
    } catch (...) {
        accepting = false;
        retry_accept();
    }
}

void NativeSocks5Adapter::State::retry_accept() noexcept {
    if (closing || retry_pending) return;
    try {
        retry_pending = true;
        retry.expires_after(kAcceptRetryDelay);
        retry.async_wait([self = shared_from_this()](const Error& error) noexcept {
            self->retry_pending = false;
            if (self->closing) return;
            if (error) {
                self->stop(Status(StatusCode::Internal));
                return;
            }
            self->start_accept();
        });
    } catch (const std::bad_alloc&) {
        retry_pending = false;
        stop(Status(StatusCode::ResourceExhausted));
    } catch (...) {
        // Without a retry nothing would ever accept again, so stop visibly.
        retry_pending = false;
        stop(Status(StatusCode::Internal));
    }
}

void NativeSocks5Adapter::State::adopt(providers::AsioTcpSocket socket) noexcept {
    try {
        // A UDP association accepts datagrams only from this address.
        Error error;
        const auto peer = socket.remote_endpoint(error);
        if (error) return;
        auto channel = channels->adopt(std::move(socket));
        if (!channel.ok()) return;
        auto connection = std::make_shared<Connection>(weak_from_this(), service, udp_service,
                                                       limits, std::move(channel).take_value(),
                                                       peer.address(), context->executor());
        connections.push_back(connection);
        connection->start();
    } catch (...) {
    }
}

void NativeSocks5Adapter::State::remove(const Connection* connection) noexcept {
    connections.remove_if([connection](const auto& value) { return value.get() == connection; });
    start_accept();
}

void NativeSocks5Adapter::State::stop(Status status) noexcept {
    if (closing) return;
    failure = status.code();
    auto stopped = std::move(on_stopped);
    close();
    if (stopped) {
        try { stopped(std::move(status)); } catch (...) {}
    }
}

void NativeSocks5Adapter::State::close() noexcept {
    if (closing) return;
    closing = true;
    Error ignored;
    acceptor.close(ignored);
    retry.cancel(ignored);
    auto current = std::move(connections);
    connections.clear();
    for (const auto& connection : current) connection->close();
    channels->cancel();
    on_stopped = {};
}

engine::Result<std::shared_ptr<NativeSocks5Adapter>> NativeSocks5Adapter::create(
    std::shared_ptr<providers::AsioExecutionContext> context,
    const config::v1::Socks5Adapter& adapter,
    NativeSessionSource sessions,
    NativeSocks5Limits limits,
    Stopped on_stopped) {
    using Created = engine::Result<std::shared_ptr<NativeSocks5Adapter>>;
    if (!context || !sessions || limits.max_connections == 0U || limits.max_connections > 4096U ||
        limits.handshake_timeout <= std::chrono::milliseconds::zero() ||
        limits.open_timeout <= std::chrono::milliseconds::zero() ||
        limits.max_udp_destinations == 0U || limits.max_udp_destinations > 1024U ||
        limits.udp_idle_timeout <= std::chrono::milliseconds::zero() ||
        limits.udp_retry_delay <= std::chrono::milliseconds::zero()) {
        return Created(Status(StatusCode::InvalidArgument));
    }
    context->require_context();
    try {
        Error error;
        const auto address = boost::asio::ip::make_address(adapter.listen_address(), error);
        if (error || !address.is_loopback()) {
            return Created(diagnostic(StatusCode::InvalidArgument,
                                      "SOCKS5 listeners are loopback-only"));
        }
        providers::AsioTcpChannelLimits channel_limits;
        channel_limits.max_active_channels = limits.max_connections;
        auto channels = providers::AsioTcpAcceptedChannelOwner::create(context, channel_limits);
        if (!channels.ok()) return Created(channels.status());
        auto state = std::make_shared<State>(context, adapter.service(), adapter.udp_service(),
                                             std::move(sessions), limits,
                                             std::move(channels).take_value());
        const boost::asio::ip::tcp::endpoint listen{address, adapter.listen_port()};
        state->acceptor.open(listen.protocol(), error);
        if (!error && address.is_v6()) state->acceptor.set_option(boost::asio::ip::v6_only(true), error);
        if (!error) state->acceptor.set_option(boost::asio::socket_base::reuse_address(true), error);
        if (!error) state->acceptor.bind(listen, error);
        if (!error) state->acceptor.listen(boost::asio::socket_base::max_listen_connections, error);
        if (!error) state->endpoint = state->acceptor.local_endpoint(error);
        if (error) {
            const auto code = error == boost::asio::error::address_in_use ? StatusCode::AddressInUse
                : error == boost::asio::error::access_denied ? StatusCode::PermissionDenied
                : StatusCode::Internal;
            return Created(diagnostic(code, "SOCKS5 listener could not open"));
        }
        // Keep creation failures on the synchronous result path. Publish the
        // callback only once an owner and the first accept or retry exist.
        auto result = std::shared_ptr<NativeSocks5Adapter>(new NativeSocks5Adapter(state));
        state->start_accept();
        if (state->closing) return Created(Status(state->failure));
        state->on_stopped = std::move(on_stopped);
        return Created(std::move(result));
    } catch (const std::bad_alloc&) {
        return Created(Status(StatusCode::ResourceExhausted));
    } catch (...) {
        return Created(Status(StatusCode::Internal));
    }
}

NativeSocks5Adapter::NativeSocks5Adapter(std::shared_ptr<State> state) noexcept
    : state_(std::move(state)) {}

NativeSocks5Adapter::~NativeSocks5Adapter() noexcept { close(); }

boost::asio::ip::tcp::endpoint NativeSocks5Adapter::local_endpoint() const noexcept {
    return state_->endpoint;
}

void NativeSocks5Adapter::close() noexcept { state_->close(); }

}  // namespace yume::runtime
