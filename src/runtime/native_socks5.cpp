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
#include "runtime/socks5_request.hpp"

namespace yume::runtime {
namespace {
using engine::Buffer;
using engine::ByteChannel;
using engine::Result;
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

}  // namespace

struct NativeSocks5Adapter::State final : std::enable_shared_from_this<State> {
    class Connection;

    State(std::shared_ptr<providers::AsioExecutionContext> execution,
          std::string service_name,
          NativeSessionSource session_source,
          NativeSocks5Limits bounds,
          std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> owner)
        : context(std::move(execution)),
          service(std::move(service_name)),
          sessions(std::move(session_source)),
          limits(bounds),
          channels(std::move(owner)),
          acceptor(context->executor()),
          retry(context->executor()) {}

    void start_accept() noexcept;
    void retry_accept() noexcept;
    void adopt(providers::AsioTcpSocket socket) noexcept;
    void remove(const Connection* connection) noexcept;
    void close() noexcept;

    std::shared_ptr<providers::AsioExecutionContext> context;
    std::string service;
    NativeSessionSource sessions;
    NativeSocks5Limits limits;
    std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> channels;
    Acceptor acceptor;
    Timer retry;
    boost::asio::ip::tcp::endpoint endpoint;
    std::list<std::shared_ptr<Connection>> connections;
    bool accepting{false};
    bool retry_pending{false};
    bool closing{false};
};

// One local client from accept until its stream is bridged or it closes.
class NativeSocks5Adapter::State::Connection final
    : public std::enable_shared_from_this<Connection> {
public:
    Connection(std::weak_ptr<State> owner, std::string service,
               NativeSocks5Limits limits, std::unique_ptr<ByteChannel> channel,
               providers::AsioExecutionContext::Executor executor)
        : owner_(std::move(owner)),
          service_(std::move(service)),
          limits_(limits),
          channel_(std::move(channel)),
          timer_(executor) {}

    void start() noexcept {
        arm_deadline(limits_.handshake_timeout);
        read();
    }

    void close() noexcept { finish(); }

private:
    enum class Phase : std::uint8_t { Greeting, Request, Opening, Replying };
    enum class AfterWrite : std::uint8_t { ReadRequest, Close, Bridge };

    void read() noexcept {
        if (done_ || reading_) return;
        const std::size_t limit = phase_ == Phase::Greeting
            ? socks5::kMaxGreetingBytes : socks5::kMaxRequestBytes;
        if (input_.size() >= limit) {
            finish();
            return;
        }
        reading_ = true;
        try {
            channel_->async_read(std::min(limit - input_.size(), channel_->max_read_size()),
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
        if (phase_ == Phase::Greeting) {
            socks5::Greeting greeting;
            const auto parsed = socks5::parse_greeting(input_, greeting);
            if (parsed == socks5::Parse::NeedMore) {
                read();
                return;
            }
            if (parsed == socks5::Parse::Invalid) {
                finish();
                return;
            }
            input_.erase(input_.begin(), input_.begin() + static_cast<std::ptrdiff_t>(greeting.consumed));
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
            read();
            return;
        }
        if (parsed == socks5::Parse::Invalid) {
            finish();
            return;
        }
        // A client must wait for the reply before sending stream data.
        if (request.consumed != input_.size()) {
            write(socks5::reply(socks5::Reply::GeneralFailure), AfterWrite::Close);
            return;
        }
        input_.clear();
        if (request.reply != socks5::Reply::Succeeded || !request.destination) {
            write(socks5::reply(request.reply), AfterWrite::Close);
            return;
        }
        open(std::move(*request.destination));
    }

    void open(engine::RouteDestination destination) noexcept {
        std::shared_ptr<engine::SessionEngine> session;
        if (const auto owner = owner_.lock(); owner && !owner->closing && owner->sessions) {
            try {
                session = owner->sessions();
            } catch (...) {
                session.reset();
            }
        }
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
            write(socks5::reply(socks5::Reply::GeneralFailure), AfterWrite::Close);
        }
    }

    void on_open(Result<std::shared_ptr<StreamResponder>> result) noexcept {
        Error ignored;
        timer_.cancel(ignored);
        if (done_) {
            if (result.ok() && result.value()) result.value()->close(Status(StatusCode::Cancelled));
            return;
        }
        if (!result.ok() || !result.value()) {
            write(socks5::reply(result.ok() ? socks5::Reply::GeneralFailure
                                            : socks5::reply_for(result.status())),
                  AfterWrite::Close);
            return;
        }
        stream_ = std::move(result).take_value();
        phase_ = Phase::Replying;
        write(socks5::reply(socks5::Reply::Succeeded), AfterWrite::Bridge);
    }

    template <std::size_t N>
    void write(const std::array<std::uint8_t, N>& bytes, AfterWrite after) noexcept {
        if (done_) return;
        auto buffer = Buffer::copy_from(std::as_bytes(std::span(bytes)), N);
        if (!buffer.ok()) {
            finish();
            return;
        }
        try {
            channel_->async_write(std::move(buffer).take_value(), io_cancellation_.token(),
                [self = shared_from_this(), after](Status status, std::size_t written) noexcept {
                    self->on_write(std::move(status), written, N, after);
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
        } else {
            bridge();
        }
    }

    void bridge() noexcept {
        const auto self = shared_from_this();
        done_ = true;
        Error ignored;
        timer_.cancel(ignored);
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
            // Completion still arrives, as Cancelled, and sends the reply.
            open_cancellation_.cancel();
        } else {
            finish();
        }
    }

    void finish() noexcept {
        if (done_) return;
        done_ = true;
        const auto self = shared_from_this();
        Error ignored;
        timer_.cancel(ignored);
        io_cancellation_.cancel();
        open_cancellation_.cancel();
        if (stream_) {
            stream_->close(Status(StatusCode::Cancelled));
            stream_.reset();
        }
        if (channel_) {
            channel_->cancel();
            channel_->close();
        }
        if (const auto owner = owner_.lock()) owner->remove(this);
    }

    std::weak_ptr<State> owner_;
    const std::string service_;
    const NativeSocks5Limits limits_;
    std::unique_ptr<ByteChannel> channel_;
    Timer timer_;
    engine::CancellationSource io_cancellation_;
    engine::CancellationSource open_cancellation_;
    std::vector<std::uint8_t> input_;
    std::shared_ptr<StreamResponder> stream_;
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
            if (!error) self->start_accept();
        });
    } catch (...) {
        // Without a retry nothing would ever accept again, so stop visibly.
        retry_pending = false;
        close();
    }
}

void NativeSocks5Adapter::State::adopt(providers::AsioTcpSocket socket) noexcept {
    try {
        auto channel = channels->adopt(std::move(socket));
        if (!channel.ok()) return;
        auto connection = std::make_shared<Connection>(weak_from_this(), service, limits,
                                                       std::move(channel).take_value(),
                                                       context->executor());
        connections.push_back(connection);
        connection->start();
    } catch (...) {
    }
}

void NativeSocks5Adapter::State::remove(const Connection* connection) noexcept {
    connections.remove_if([connection](const auto& value) { return value.get() == connection; });
    start_accept();
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
}

engine::Result<std::shared_ptr<NativeSocks5Adapter>> NativeSocks5Adapter::create(
    std::shared_ptr<providers::AsioExecutionContext> context,
    const config::v1::Socks5Adapter& adapter,
    NativeSessionSource sessions,
    NativeSocks5Limits limits) {
    using Created = engine::Result<std::shared_ptr<NativeSocks5Adapter>>;
    if (!context || !sessions || limits.max_connections == 0U || limits.max_connections > 4096U ||
        limits.handshake_timeout <= std::chrono::milliseconds::zero() ||
        limits.open_timeout <= std::chrono::milliseconds::zero()) {
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
        auto state = std::make_shared<State>(context, adapter.service(), std::move(sessions),
                                             limits, std::move(channels).take_value());
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
        state->start_accept();
        return Created(std::shared_ptr<NativeSocks5Adapter>(new NativeSocks5Adapter(std::move(state))));
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
