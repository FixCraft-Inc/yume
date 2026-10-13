/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/module_connector.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <new>
#include <optional>
#include <string>
#include <utility>

#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <boost/asio/basic_waitable_timer.hpp>

#include "engine/buffer.hpp"
#include "engine/cancellation.hpp"
#include "providers/asio_tcp_byte_channel_provider.hpp"
#include "providers/direct_route_handler.hpp"

namespace yume::runtime {
namespace {
using engine::Buffer;
using engine::ByteChannel;
using engine::Result;
using engine::Status;
using engine::StatusCode;
using engine::StreamResponder;
using Clock = std::chrono::steady_clock;
using Executor = providers::AsioExecutionContext::Executor;
using Timer = boost::asio::basic_waitable_timer<Clock, boost::asio::wait_traits<Clock>, Executor>;
using Error = boost::system::error_code;
using Local = boost::asio::local::stream_protocol;

Status diagnostic(StatusCode code, std::string_view first, std::string_view second = {}) noexcept {
    try {
        std::string message(first);
        message += second;
        return Status(code, message);
    } catch (...) {
        return Status(code);
    }
}

// The composite fingerprint is hexadecimal. Anything else would let a
// provider's label change the header's shape.
bool header_safe(std::string_view identity) noexcept {
    return !identity.empty() && identity.size() <= 128U &&
           std::all_of(identity.begin(), identity.end(), [](char ch) {
               return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
           });
}

template <typename Completion, typename... Args>
void complete(Completion& completion, Args&&... args) noexcept {
    auto owned = std::move(completion);
    if (!owned) return;
    try {
        owned(std::forward<Args>(args)...);
    } catch (...) {
    }
}

}  // namespace

engine::Status check_module_socket(const std::filesystem::path& socket) noexcept {
    try {
        if (!socket.is_absolute() || !socket.has_filename())
            return diagnostic(StatusCode::InvalidArgument, "module socket path must be absolute");
        // The directory decides who can replace the socket or plant a link
        // in its place.
        struct stat directory{};
        if (::lstat(socket.parent_path().c_str(), &directory) != 0)
            return diagnostic(StatusCode::FailedPrecondition,
                              errno == ENOENT ? "module socket is missing"
                                              : "module socket directory could not be checked");
        if (!S_ISDIR(directory.st_mode) || (directory.st_uid != 0U && directory.st_uid != ::geteuid()) ||
            (directory.st_mode & (S_IWGRP | S_IWOTH)) != 0U)
            return diagnostic(StatusCode::PermissionDenied,
                "module socket directory must be owned by root or this user and closed to others' writes");
        struct stat info{};
        if (::lstat(socket.c_str(), &info) != 0)
            return diagnostic(StatusCode::FailedPrecondition,
                              errno == ENOENT ? "module socket is missing"
                                              : "module socket could not be checked");
        if (!S_ISSOCK(info.st_mode))
            return diagnostic(StatusCode::FailedPrecondition, "module socket is not a socket");
        if (info.st_uid != ::geteuid() || (info.st_mode & (S_IRWXG | S_IRWXO)) != 0U)
            return diagnostic(StatusCode::PermissionDenied,
                              "module socket must belong to this user and be closed to others");
        return Status::success();
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted);
    } catch (...) {
        return Status(StatusCode::Internal);
    }
}

struct ModuleConnector::State final {
    State(std::shared_ptr<providers::AsioExecutionContext> execution, const config::v1::ModuleAdapter& adapter,
          ModuleConnectorOptions settings, std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> owner)
        : context(std::move(execution)),
          socket_path(adapter.socket()),
          options(settings),
          channels(std::move(owner)) {}

    void close() noexcept {
        open.store(false, std::memory_order_release);
        if (channels) channels->cancel();
    }

    const std::shared_ptr<providers::AsioExecutionContext> context;
    const std::string socket_path;
    const ModuleConnectorOptions options;
    const std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> channels;
    std::shared_ptr<engine::StreamHandler> handler;
    std::optional<engine::ProviderDescriptor> descriptor;
    // What handlers on other contexts read: false once close() ran.
    std::atomic<bool> open{true};
};

namespace {

// Where a handler connects its streams: the context its sessions run on and
// the channel owner there. The connector's own context has one, and so has
// every other context a server serves sessions on.
struct ModuleRoute final {
    std::shared_ptr<providers::AsioExecutionContext> context;
    std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> channels;
};

// One OPEN from the connection attempt until the stream is bridged or refused.
class ModuleOpen final : public std::enable_shared_from_this<ModuleOpen> {
public:
    ModuleOpen(std::shared_ptr<ModuleConnector::State> state,
               ModuleRoute route, std::shared_ptr<StreamResponder> stream,
               engine::StreamHandler::AcceptanceCompletion&& completion,
               std::string header)
        : state_(std::move(state)),
          route_(std::move(route)),
          stream_(std::move(stream)),
          header_(std::move(header)),
          socket_(route_.context->executor()),
          timer_(route_.context->executor()),
          completion_(std::move(completion)) {}

    void start() noexcept {
        try {
            timer_.expires_after(state_->options.connect_timeout);
            timer_.async_wait([self = shared_from_this()](const Error& error) noexcept {
                if (!error) {
                    self->fail(diagnostic(StatusCode::Cancelled,
                                          "the module did not take the stream in time"));
                }
            });
            socket_.async_connect(Local::endpoint(state_->socket_path),
                [self = shared_from_this()](const Error& error) noexcept { self->connected(error); });
        } catch (...) {
            fail(Status(StatusCode::ResourceExhausted));
        }
    }

private:
    void connected(const Error& error) noexcept {
        if (done_) return;
        if (error) {
            fail(diagnostic(StatusCode::FailedPrecondition, "the module refused the stream"));
            return;
        }
        // The listener's creator, which for a socket unit is the service
        // manager. Another user who replaced the socket since start would
        // otherwise receive the stream and its identity.
        ucred listener{};
        socklen_t length = sizeof(listener);
        if (::getsockopt(socket_.native_handle(), SOL_SOCKET, SO_PEERCRED, &listener, &length) != 0 ||
            length != sizeof(listener) || (listener.uid != 0U && listener.uid != ::geteuid())) {
            fail(diagnostic(StatusCode::PermissionDenied, "the module socket belongs to another user"));
            return;
        }
        // Reporting a failure copies its status, which can itself fail.
        try {
            auto channel = route_.channels->adopt(std::move(socket_));
            if (!channel.ok()) {
                fail(channel.status());
                return;
            }
            channel_ = std::move(channel).take_value();
            auto header = Buffer::copy_from(
                {reinterpret_cast<const std::byte*>(header_.data()),
                 header_.size()},
                header_.size());
            if (!header.ok()) {
                fail(header.status());
                return;
            }
            channel_->async_write(std::move(header).take_value(), cancellation_.token(),
                [self = shared_from_this()](Status status, std::size_t written) noexcept {
                    self->written(std::move(status), written);
                });
        } catch (const std::bad_alloc&) {
            fail(Status(StatusCode::ResourceExhausted));
        } catch (...) {
            fail(Status(StatusCode::Internal));
        }
    }

    void written(Status status, std::size_t written) noexcept {
        if (done_) return;
        if (!status.ok() || written != header_.size()) {
            fail(diagnostic(StatusCode::FailedPrecondition, "the module closed the stream"));
            return;
        }
        done_ = true;
        providers::cancel_timer(timer_);
        complete(completion_, Status::success());
        auto connection = engine::RouteConnection::byte_stream(std::move(channel_));
        if (!connection.ok()) {
            stream_->close(connection.status());
            return;
        }
        providers::bridge_established_route(std::move(stream_), std::move(connection).take_value());
    }

    void fail(Status status) noexcept {
        if (done_) return;
        done_ = true;
        Error ignored;
        providers::cancel_timer(timer_);
        socket_.close(ignored);
        cancellation_.cancel();
        if (channel_) {
            channel_->cancel();
            channel_->close();
        }
        const auto code = status.code();
        complete(completion_, std::move(status));
        if (stream_) stream_->close(Status(code));
    }

    std::shared_ptr<ModuleConnector::State> state_;
    ModuleRoute route_;
    std::shared_ptr<StreamResponder> stream_;
    std::string header_;
    providers::AsioUnixSocket socket_;
    Timer timer_;
    engine::CancellationSource cancellation_;
    std::unique_ptr<ByteChannel> channel_;
    bool done_{false};
    // Initialized last, so a constructor that throws leaves the caller's
    // completion intact to refuse the OPEN.
    engine::StreamHandler::AcceptanceCompletion completion_;
};

class ModuleHandler final : public engine::StreamHandler {
public:
    ModuleHandler(std::weak_ptr<ModuleConnector::State> state,
                  ModuleRoute route, engine::ProviderDescriptor descriptor)
        : state_(std::move(state)),
          route_(std::move(route)),
          descriptor_(std::move(descriptor)) {}

    const engine::ProviderDescriptor& descriptor() const noexcept override { return descriptor_; }
    engine::ServiceKind service_kind() const noexcept override { return engine::ServiceKind::ByteStream; }

    Status authorize(const engine::StreamOpenContext& context) override {
        if (context.destination_if())
            return diagnostic(StatusCode::InvalidArgument, "a module stream names no destination");
        const auto state = state_.lock();
        if (!state || !state->open.load(std::memory_order_acquire))
            return diagnostic(StatusCode::FailedPrecondition, "the module service is closed");
        return Status::success();
    }

    void async_open(engine::StreamOpenContext context, std::shared_ptr<StreamResponder> stream,
                    AcceptanceCompletion completion) override {
        if (!stream) return;
        const auto state = state_.lock();
        const auto& identity = context.peer_evidence().identity();
        const bool live = state && state->open.load(std::memory_order_acquire);
        if (!live || !header_safe(identity)) {
            const auto code = !live ? StatusCode::FailedPrecondition
                                    : StatusCode::PermissionDenied;
            complete(completion, Status(code));
            stream->close(Status(code));
            return;
        }
        try {
            std::string header(kModuleHeaderPrefix);
            header += identity;
            header += ' ';
            header += context.service_name();
            header += '\n';
            std::make_shared<ModuleOpen>(
                state, route_, stream, std::move(completion), std::move(header))
                ->start();
        } catch (const std::bad_alloc&) {
            complete(completion, Status(StatusCode::ResourceExhausted));
            stream->close(Status(StatusCode::ResourceExhausted));
        }
    }

    void on_open(engine::StreamOpenContext context, std::shared_ptr<StreamResponder> stream) override {
        async_open(std::move(context), std::move(stream), {});
    }

private:
    std::weak_ptr<ModuleConnector::State> state_;
    const ModuleRoute route_;
    engine::ProviderDescriptor descriptor_;
};

}  // namespace

engine::Result<std::shared_ptr<ModuleConnector>> ModuleConnector::create(
    std::shared_ptr<providers::AsioExecutionContext> context,
    const config::v1::ModuleAdapter& adapter, ModuleConnectorOptions options) {
    using Created = engine::Result<std::shared_ptr<ModuleConnector>>;
    if (!context || options.connect_timeout <= std::chrono::milliseconds::zero() ||
        options.max_streams == 0U || options.max_streams > 65'536U)
        return Created(Status(StatusCode::InvalidArgument));
    context->require_context();
    auto checked = check_module_socket(adapter.socket());
    if (!checked.ok()) return Created(std::move(checked));
    try {
        providers::AsioTcpChannelLimits limits;
        limits.max_active_channels = options.max_streams;
        auto channels = providers::AsioTcpAcceptedChannelOwner::create(context, limits);
        if (!channels.ok()) return Created(channels.status());
        auto descriptor = engine::ProviderDescriptor::create(
            "yume.module", engine::ProviderKind::StreamHandler, 1U,
            engine::mandatory_capabilities(engine::ProviderKind::StreamHandler));
        if (!descriptor.ok()) return Created(descriptor.status());
        auto state = std::make_shared<State>(std::move(context), adapter, options,
                                             std::move(channels).take_value());
        state->descriptor.emplace(descriptor.value());
        state->handler = std::make_shared<ModuleHandler>(
            state, ModuleRoute{state->context, state->channels},
            std::move(descriptor).take_value());
        return Created(std::shared_ptr<ModuleConnector>(new ModuleConnector(std::move(state))));
    } catch (const std::bad_alloc&) {
        return Created(Status(StatusCode::ResourceExhausted));
    }
}

ModuleConnector::ModuleConnector(std::shared_ptr<State> state) noexcept : state_(std::move(state)) {}
ModuleConnector::~ModuleConnector() noexcept { close(); }
std::shared_ptr<engine::StreamHandler> ModuleConnector::handler() const noexcept {
    return state_->handler;
}
engine::Result<std::shared_ptr<engine::StreamHandler>>
ModuleConnector::handler_for(
    std::shared_ptr<providers::AsioExecutionContext> context,
    std::size_t contexts) const {
    using Made = engine::Result<std::shared_ptr<engine::StreamHandler>>;
    if (!context || contexts == 0U)
        return Made(Status(StatusCode::InvalidArgument));
    context->require_context();
    try {
        // Each context's owner holds its share of the module's streams.
        providers::AsioTcpChannelLimits limits;
        limits.max_active_channels =
            std::max<std::size_t>(1U, state_->options.max_streams / contexts);
        auto channels =
            providers::AsioTcpAcceptedChannelOwner::create(context, limits);
        if (!channels.ok()) return Made(channels.status());
        return Made(std::shared_ptr<engine::StreamHandler>(
            std::make_shared<ModuleHandler>(
                state_,
                ModuleRoute{std::move(context),
                            std::move(channels).take_value()},
                *state_->descriptor)));
    } catch (const std::bad_alloc&) {
        return Made(Status(StatusCode::ResourceExhausted));
    }
}
void ModuleConnector::close() noexcept { state_->close(); }

}  // namespace yume::runtime
