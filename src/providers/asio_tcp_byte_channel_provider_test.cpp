/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#define YUME_TEST_ALIGNED_ALLOCATIONS 1
#include "test_support/allocation_failure.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <future>
#include <iostream>
#include <memory>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/local/connect_pair.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/error_code.hpp>

#include "providers/asio_tcp_byte_channel_provider.hpp"
#include "providers/system_resolver.hpp"

#ifndef YUME_TEST_RESOLVER_PROGRAM
#error "YUME_TEST_RESOLVER_PROGRAM names the resolver helper"
#endif

namespace test_allocation_failure {

// One-shot injection targets a selected actor turn. Sustained injection covers
// every thread and both allocation routes used by Boost.Asio.
thread_local std::ptrdiff_t remaining = -1;
std::atomic<bool> sustained{false};

class Scope final {
public:
    explicit Scope(std::ptrdiff_t count) noexcept { remaining = count; }
    ~Scope() { remaining = -1; }
};

class SustainedScope final {
public:
    explicit SustainedScope(bool enabled = true) noexcept {
        sustained.store(enabled, std::memory_order_release);
    }
    ~SustainedScope() { sustained.store(false, std::memory_order_release); }
};

bool consume() noexcept {
    if (sustained.load(std::memory_order_acquire)) return true;
    if (remaining < 0) {
        return false;
    }
    if (remaining == 0) {
        remaining = -1;
        return true;
    }
    --remaining;
    return false;
}

}  // namespace test_allocation_failure

namespace {
void check_test_allocation(std::size_t) {
    if (test_allocation_failure::consume()) throw std::bad_alloc();
}
}


namespace yume::providers {
namespace {

using namespace std::chrono_literals;
using namespace engine;
using Tcp = boost::asio::ip::tcp;

class TestFailure final : public std::runtime_error {
public:
    explicit TestFailure(std::string message)
        : std::runtime_error(std::move(message)) {}
};

#define CHECK(expression)                                                     \
    do {                                                                      \
        if (!(expression)) {                                                  \
            throw TestFailure(std::string("check failed at line ") +        \
                              std::to_string(__LINE__) + ": " + #expression); \
        }                                                                     \
    } while (false)

template <typename T>
T require(Result<T> result) {
    if (!result.ok()) {
        throw TestFailure(result.status().message());
    }
    return std::move(result).take_value();
}

Buffer make_buffer(std::string_view text,
                   std::size_t limit = kAbsoluteMaxBufferBytes) {
    return require(Buffer::copy_from(
        {reinterpret_cast<const std::byte*>(text.data()), text.size()},
        limit));
}

std::string buffer_text(const Buffer& buffer) {
    return std::string(
        reinterpret_cast<const char*>(buffer.bytes().data()), buffer.size());
}

std::shared_ptr<SystemResolver> make_resolver(
    const std::shared_ptr<AsioExecutionContext>& context,
    const char* program = YUME_TEST_RESOLVER_PROGRAM) {
    SystemResolverOptions options;
    options.program = program;
    return require(SystemResolver::create(context, std::move(options)));
}

class IoRuntime final {
public:
    IoRuntime()
        : context_(require(AsioExecutionContext::create(ExecutorAffinity(93U)))),
          resolver_(make_resolver(context_)) {
        std::promise<void> started;
        auto ready = started.get_future();
        thread_ = std::thread([this, &started]() {
            worker_id_ = std::this_thread::get_id();
            started.set_value();
            context_->run();
        });
        ready.get();
    }
    IoRuntime(const IoRuntime&) = delete;
    IoRuntime& operator=(const IoRuntime&) = delete;
    ~IoRuntime() noexcept {
        resolver_->close();
        context_->finish();
        if (thread_.joinable()) thread_.join();
    }

    const std::shared_ptr<AsioExecutionContext>& context() noexcept {
        return context_;
    }
    const std::shared_ptr<SystemResolver>& resolver() noexcept { return resolver_; }
    AsioExecutionContext::Executor executor() noexcept {
        return context_->executor();
    }
    bool is_worker(std::thread::id id) const noexcept { return id == worker_id_; }

    template <typename Function>
    auto sync(Function&& function) -> std::invoke_result_t<Function> {
        if (context_->running_in_this_thread()) return function();
        using Value = std::invoke_result_t<Function>;
        std::promise<Value> promise;
        auto future = promise.get_future();
        boost::asio::post(executor(), [&]() {
            try {
                if constexpr (std::is_void_v<Value>) {
                    function();
                    promise.set_value();
                } else {
                    promise.set_value(function());
                }
            } catch (...) {
                promise.set_exception(std::current_exception());
            }
        });
        CHECK(future.wait_for(3s) == std::future_status::ready);
        return future.get();
    }

private:
    std::shared_ptr<AsioExecutionContext> context_;
    std::shared_ptr<SystemResolver> resolver_;
    std::thread thread_;
    std::thread::id worker_id_;
};

template <typename T>
struct AsyncTicket final {
    std::shared_ptr<std::promise<T>> promise =
        std::make_shared<std::promise<T>>();
    std::future<T> future = promise->get_future();
    std::shared_ptr<std::atomic<unsigned int>> calls =
        std::make_shared<std::atomic<unsigned int>>(0U);
    std::shared_ptr<std::thread::id> callback_thread =
        std::make_shared<std::thread::id>();
};

template <typename T>
T await(AsyncTicket<T>& ticket, std::chrono::milliseconds timeout = 3s) {
    if (ticket.future.wait_for(timeout) != std::future_status::ready) {
        throw TestFailure("asynchronous operation timed out");
    }
    T result = ticket.future.get();
    CHECK(ticket.calls->load(std::memory_order_relaxed) == 1U);
    return result;
}

void run_barrier(IoRuntime& runtime) {
    runtime.sync([]() {});
}

AsyncTicket<Result<std::unique_ptr<ByteChannel>>> start_create(
    IoRuntime& runtime,
    const std::shared_ptr<AsioTcpByteChannelProvider>& provider,
    EndpointRole role = EndpointRole::Client,
    CancellationToken cancellation = {}) {
    AsyncTicket<Result<std::unique_ptr<ByteChannel>>> ticket;
    runtime.sync([&]() { provider->async_create(
        role, std::move(cancellation),
        [promise = ticket.promise, calls = ticket.calls,
         callback_thread = ticket.callback_thread](
            Result<std::unique_ptr<ByteChannel>> result) mutable {
            *callback_thread = std::this_thread::get_id();
            calls->fetch_add(1U, std::memory_order_relaxed);
            promise->set_value(std::move(result));
        });
    });
    return ticket;
}

AsyncTicket<Result<Buffer>> start_read(IoRuntime& runtime, ByteChannel& channel,
                                       std::size_t max_bytes,
                                       CancellationToken cancellation = {}) {
    AsyncTicket<Result<Buffer>> ticket;
    runtime.sync([&]() { channel.async_read(
        max_bytes, std::move(cancellation),
        [promise = ticket.promise, calls = ticket.calls,
         callback_thread = ticket.callback_thread](Result<Buffer> result) mutable {
            *callback_thread = std::this_thread::get_id();
            calls->fetch_add(1U, std::memory_order_relaxed);
            promise->set_value(std::move(result));
        });
    });
    return ticket;
}

struct TransferResult final {
    Status status;
    std::size_t transferred{0U};
};

AsyncTicket<TransferResult> start_write(IoRuntime& runtime, ByteChannel& channel,
                                        Buffer buffer,
                                        CancellationToken cancellation = {}) {
    AsyncTicket<TransferResult> ticket;
    runtime.sync([&]() { channel.async_write(
        std::move(buffer), std::move(cancellation),
        [promise = ticket.promise, calls = ticket.calls,
         callback_thread = ticket.callback_thread](
            Status status, std::size_t transferred) mutable {
            *callback_thread = std::this_thread::get_id();
            calls->fetch_add(1U, std::memory_order_relaxed);
            promise->set_value(
                TransferResult{std::move(status), transferred});
        });
    });
    return ticket;
}

class TcpServer final {
public:
    using Handler = std::function<void(Tcp::socket&)>;

    explicit TcpServer(Handler handler)
        : acceptor_(context_), socket_(context_), handler_(std::move(handler)) {
        boost::system::error_code error;
        acceptor_.open(Tcp::v4(), error);
        if (error) {
            throw TestFailure("TCP acceptor open failed: " + error.message());
        }
        acceptor_.set_option(Tcp::acceptor::reuse_address(true), error);
        CHECK(!error);
        acceptor_.bind(Tcp::endpoint(Tcp::v4(), 0U), error);
        CHECK(!error);
        acceptor_.listen(4, error);
        CHECK(!error);
        port_ = acceptor_.local_endpoint().port();
        future_ = promise_.get_future();
        thread_ = std::thread([this]() noexcept {
            try {
                boost::system::error_code error;
                acceptor_.accept(socket_, error);
                if (error) {
                    throw TestFailure("TCP accept failed: " + error.message());
                }
                handler_(socket_);
                promise_.set_value(nullptr);
            } catch (...) {
                try {
                    promise_.set_value(std::current_exception());
                } catch (...) {
                }
            }
        });
    }

    TcpServer(const TcpServer&) = delete;
    TcpServer& operator=(const TcpServer&) = delete;
    ~TcpServer() noexcept {
        boost::system::error_code ignored;
        acceptor_.cancel(ignored);
        acceptor_.close(ignored);
        socket_.cancel(ignored);
        socket_.shutdown(Tcp::socket::shutdown_both, ignored);
        socket_.close(ignored);
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    std::uint16_t port() const noexcept { return port_; }

    void wait() {
        if (future_.wait_for(3s) != std::future_status::ready) {
            throw TestFailure("TCP server timed out");
        }
        if (std::exception_ptr error = future_.get()) {
            std::rethrow_exception(error);
        }
    }

private:
    boost::asio::io_context context_;
    Tcp::acceptor acceptor_;
    Tcp::socket socket_;
    Handler handler_;
    std::promise<std::exception_ptr> promise_;
    std::future<std::exception_ptr> future_;
    std::thread thread_;
    std::uint16_t port_{0U};
};

std::shared_ptr<AsioTcpByteChannelProvider> make_provider(
    IoRuntime& runtime,
    std::string host,
    std::uint16_t port,
    AsioTcpByteChannelLimits limits = {},
    AsioTcpSocketProtector protector = {}) {
    return require(AsioTcpByteChannelProvider::create(
        runtime.context(),
        std::move(host), port, limits, std::move(protector), runtime.resolver()));
}

std::shared_ptr<AsioTcpAcceptedChannelOwner> make_accepted_owner(
    IoRuntime& runtime,
    AsioTcpChannelLimits limits = {}) {
    return require(AsioTcpAcceptedChannelOwner::create(
        runtime.context(), limits));
}

std::pair<AsioTcpSocket, AsioTcpSocket> connected_pair(
    AsioExecutionContext::Executor executor) {
    Tcp::acceptor acceptor(executor, Tcp::endpoint(Tcp::v4(), 0U));
    AsioTcpSocket peer(executor);
    peer.connect(acceptor.local_endpoint());
    AsioTcpSocket accepted(executor);
    acceptor.accept(accepted);
    return {std::move(accepted), std::move(peer)};
}

std::uint16_t unused_tcp_port() {
    boost::asio::io_context context;
    Tcp::acceptor acceptor(context, Tcp::endpoint(Tcp::v4(), 0U));
    const std::uint16_t port = acceptor.local_endpoint().port();
    boost::system::error_code ignored;
    acceptor.close(ignored);
    return port;
}

void test_descriptor_and_validation() {
    IoRuntime runtime;
    auto provider = make_provider(runtime, "localhost", 443U);
    CHECK(provider->descriptor().provider_id() ==
          kAsioTcpByteChannelProviderId);
    CHECK(provider->descriptor().kind() == ProviderKind::ByteChannel);
    CHECK(provider->descriptor().api_version() ==
          kAsioTcpByteChannelProviderApiVersion);
    CHECK(provider->descriptor().capabilities() ==
          mandatory_capabilities(ProviderKind::ByteChannel));
    CHECK(provider->executor_affinity() == ExecutorAffinity(93U));
    CHECK(provider->remote_host() == "localhost");
    CHECK(provider->remote_port() == 443U);

    auto invalid = [&](AsioTcpByteChannelLimits limits) {
        auto result = AsioTcpByteChannelProvider::create(
            runtime.context(),
            "127.0.0.1", 443U, limits);
        CHECK(!result.ok());
        CHECK(result.status().code() == StatusCode::InvalidArgument);
    };
    AsioTcpByteChannelLimits limits;
    limits.max_pending_creates = 0U;
    invalid(limits);
    limits = {};
    limits.max_active_channels = 0U;
    invalid(limits);
    limits = {};
    limits.max_resolved_endpoints = 0U;
    invalid(limits);
    limits = {};
    limits.max_connect_attempts = 0U;
    invalid(limits);
    limits = {};
    limits.max_read_bytes = 0U;
    invalid(limits);
    limits = {};
    limits.max_queued_read_bytes = limits.max_read_bytes - 1U;
    invalid(limits);
    limits = {};
    limits.max_queued_write_operations = 0U;
    invalid(limits);
    limits = {};
    limits.resolve_timeout = 0ms;
    invalid(limits);
    limits = {};
    limits.connect_timeout = 601s;
    invalid(limits);

    CHECK(!AsioTcpByteChannelProvider::create(
               std::shared_ptr<AsioExecutionContext>{},
               "localhost", 443U).ok());
    CHECK(!AsioTcpByteChannelProvider::create(
               runtime.context(),
               "", 443U).ok());
    CHECK(!AsioTcpByteChannelProvider::create(
               runtime.context(),
               "localhost", 0U).ok());
    // A name needs a resolver on the provider's own context. Numeric hosts
    // never need one.
    CHECK(AsioTcpByteChannelProvider::create(runtime.context(), "localhost", 443U)
              .status().code() == StatusCode::InvalidArgument);
    CHECK(AsioTcpByteChannelProvider::create(runtime.context(), "::1", 443U).ok());
    {
        auto other = require(AsioExecutionContext::create(ExecutorAffinity(94U)));
        auto foreign = make_resolver(other);
        CHECK(AsioTcpByteChannelProvider::create(runtime.context(), "localhost", 443U,
                                                 {}, {}, foreign)
                  .status().code() == StatusCode::InvalidArgument);
        foreign->close();
        other->finish();
        other->run();
    }

    auto server_role = start_create(runtime, provider, EndpointRole::Server);
    auto rejected = await(server_role);
    CHECK(!rejected.ok());
    CHECK(rejected.status().code() == StatusCode::InvalidArgument);
    CHECK(runtime.is_worker(*server_role.callback_thread));
}

void test_accepted_socket_validation_and_capacity_release() {
    IoRuntime runtime;
    AsioTcpChannelLimits limits;
    limits.max_active_channels = 1U;
    auto owner = make_accepted_owner(runtime, limits);
    CHECK(owner->executor_affinity() == ExecutorAffinity(93U));
    CHECK(owner->limits().max_active_channels == 1U);

    CHECK(!AsioTcpAcceptedChannelOwner::create(
               std::shared_ptr<AsioExecutionContext>{}).ok());
    AsioTcpChannelLimits invalid_limits;
    invalid_limits.max_active_channels = 0U;
    CHECK(!AsioTcpAcceptedChannelOwner::create(
               runtime.context(),
               invalid_limits).ok());

    AsioTcpSocket closed(runtime.executor());
    auto closed_result = runtime.sync([&]() { return owner->adopt(std::move(closed)); });
    CHECK(!closed_result.ok());
    CHECK(closed_result.status().code() == StatusCode::InvalidArgument);

    AsioTcpSocket unconnected(runtime.executor());
    unconnected.open(Tcp::v4());
    auto unconnected_result = runtime.sync([&]() { return owner->adopt(std::move(unconnected)); });
    CHECK(!unconnected_result.ok());
    CHECK(unconnected_result.status().code() == StatusCode::InvalidArgument);

    boost::asio::io_context other_context;
    auto wrong_pair = connected_pair(other_context.get_executor());
    auto wrong_executor = runtime.sync([&]() { return owner->adopt(std::move(wrong_pair.first)); });
    CHECK(!wrong_executor.ok());
    CHECK(wrong_executor.status().code() == StatusCode::ProviderMismatch);

    auto first_pair = connected_pair(runtime.executor());
    auto first_result = runtime.sync([&]() { return owner->adopt(std::move(first_pair.first)); });
    CHECK(first_result.ok());
    std::unique_ptr<ByteChannel> first =
        std::move(first_result).take_value();
    CHECK(first->executor_affinity() == ExecutorAffinity(93U));

    auto refused_pair = connected_pair(runtime.executor());
    auto refused = runtime.sync([&]() { return owner->adopt(std::move(refused_pair.first)); });
    CHECK(!refused.ok());
    CHECK(refused.status().code() == StatusCode::ResourceExhausted);

    auto closing_read = start_read(runtime, *first, 1U);
    first->close();
    auto closed_read = await(closing_read);
    CHECK(!closed_read.ok());
    CHECK(closed_read.status().code() == StatusCode::Closed);
    first.reset();
    run_barrier(runtime);

    auto reused_pair = connected_pair(runtime.executor());
    auto reused = runtime.sync([&]() { return owner->adopt(std::move(reused_pair.first)); });
    CHECK(reused.ok());
    std::unique_ptr<ByteChannel> replacement =
        std::move(reused).take_value();
    replacement->close();
    replacement.reset();
}

void test_accepted_socket_traffic_half_close_cancel_and_close() {
    IoRuntime runtime;
    auto owner = make_accepted_owner(runtime);
    auto pair = connected_pair(runtime.executor());
    auto adopted = runtime.sync([&]() { return owner->adopt(std::move(pair.first)); });
    CHECK(adopted.ok());
    std::unique_ptr<ByteChannel> channel =
        std::move(adopted).take_value();
    AsioTcpSocket peer = std::move(pair.second);

    auto first_write = start_write(runtime, *channel, make_buffer("one"));
    auto second_write = start_write(runtime, *channel, make_buffer("two"));
    CHECK(runtime.sync([&]() { return channel->shutdown_write(); }).ok());
    CHECK(runtime.sync([&]() { return channel->shutdown_write(); }).ok());
    TransferResult first = await(first_write);
    TransferResult second = await(second_write);
    CHECK(first.status.ok() && first.transferred == 3U);
    CHECK(second.status.ok() && second.transferred == 3U);
    CHECK(runtime.is_worker(*first_write.callback_thread));
    CHECK(runtime.is_worker(*second_write.callback_thread));

    std::array<char, 6> input{};
    boost::system::error_code error;
    CHECK(boost::asio::read(peer, boost::asio::buffer(input), error) ==
          input.size());
    CHECK(!error);
    CHECK(std::string(input.data(), input.size()) == "onetwo");
    std::array<char, 1> eof_probe{};
    CHECK(peer.read_some(boost::asio::buffer(eof_probe), error) == 0U);
    CHECK(error == boost::asio::error::eof);

    auto cancelled_read = start_read(runtime, *channel, 1U);
    owner->cancel();
    auto cancelled = await(cancelled_read);
    CHECK(!cancelled.ok());
    CHECK(cancelled.status().code() == StatusCode::Cancelled);
    CHECK(runtime.is_worker(*cancelled_read.callback_thread));

    boost::asio::write(peer, boost::asio::buffer("AB", 2U), error);
    CHECK(!error);
    peer.shutdown(Tcp::socket::shutdown_send, error);
    CHECK(!error);
    auto first_read = start_read(runtime, *channel, 1U);
    auto second_read = start_read(runtime, *channel, 1U);
    auto a = await(first_read);
    auto b = await(second_read);
    CHECK(a.ok() && buffer_text(*a.value_if()) == "A");
    CHECK(b.ok() && buffer_text(*b.value_if()) == "B");
    CHECK(runtime.is_worker(*first_read.callback_thread));
    CHECK(runtime.is_worker(*second_read.callback_thread));

    auto eof = start_read(runtime, *channel, 1U);
    auto eof_result = await(eof);
    CHECK(!eof_result.ok());
    CHECK(eof_result.status().code() == StatusCode::Closed);

    auto closed_write = start_write(runtime, *channel, make_buffer("X"));
    channel->close();
    TransferResult closed = await(closed_write);
    CHECK(!closed.status.ok());
    CHECK(closed.status.code() == StatusCode::Closed);
    channel.reset();
}

// UNIX stream sockets share the TCP channel implementation and the owner's
// capacity: traffic, half-close in both directions, cancellation and release.
void test_accepted_unix_socket_traffic_and_capacity() {
    IoRuntime runtime;
    AsioTcpChannelLimits limits;
    limits.max_active_channels = 1U;
    auto owner = make_accepted_owner(runtime, limits);

    AsioUnixSocket closed(runtime.executor());
    auto closed_result = runtime.sync([&]() { return owner->adopt(std::move(closed)); });
    CHECK(closed_result.status().code() == StatusCode::InvalidArgument);
    AsioUnixSocket unconnected(runtime.executor());
    unconnected.open(boost::asio::local::stream_protocol());
    auto unconnected_result =
        runtime.sync([&]() { return owner->adopt(std::move(unconnected)); });
    CHECK(unconnected_result.status().code() == StatusCode::InvalidArgument);

    AsioUnixSocket local(runtime.executor());
    AsioUnixSocket peer(runtime.executor());
    boost::asio::local::connect_pair(local, peer);
    auto channel = require(runtime.sync([&]() { return owner->adopt(std::move(local)); }));
    CHECK(channel->executor_affinity() == ExecutorAffinity(93U));

    AsioUnixSocket extra(runtime.executor());
    AsioUnixSocket extra_peer(runtime.executor());
    boost::asio::local::connect_pair(extra, extra_peer);
    auto refused = runtime.sync([&]() { return owner->adopt(std::move(extra)); });
    CHECK(refused.status().code() == StatusCode::ResourceExhausted);
    auto tcp_pair = connected_pair(runtime.executor());
    auto refused_tcp = runtime.sync([&]() { return owner->adopt(std::move(tcp_pair.first)); });
    CHECK(refused_tcp.status().code() == StatusCode::ResourceExhausted);

    auto written = start_write(runtime, *channel, make_buffer("unix"));
    CHECK(runtime.sync([&]() { return channel->shutdown_write(); }).ok());
    TransferResult sent = await(written);
    CHECK(sent.status.ok() && sent.transferred == 4U);
    std::array<char, 4> input{};
    boost::system::error_code error;
    CHECK(boost::asio::read(peer, boost::asio::buffer(input), error) == input.size());
    CHECK(!error && std::string(input.data(), input.size()) == "unix");
    std::array<char, 1> eof_probe{};
    CHECK(peer.read_some(boost::asio::buffer(eof_probe), error) == 0U);
    CHECK(error == boost::asio::error::eof);

    auto cancelled_read = start_read(runtime, *channel, 1U);
    owner->cancel();
    CHECK(await(cancelled_read).status().code() == StatusCode::Cancelled);

    boost::asio::write(peer, boost::asio::buffer("R", 1U), error);
    CHECK(!error);
    peer.shutdown(AsioUnixSocket::shutdown_send, error);
    CHECK(!error);
    auto received_read = start_read(runtime, *channel, 1U);
    auto received = await(received_read);
    CHECK(received.ok() && buffer_text(*received.value_if()) == "R");
    auto eof_read = start_read(runtime, *channel, 1U);
    auto eof = await(eof_read);
    CHECK(eof.status().code() == StatusCode::Closed);

    channel->close();
    channel.reset();
    run_barrier(runtime);
    AsioUnixSocket reused(runtime.executor());
    AsioUnixSocket reused_peer(runtime.executor());
    boost::asio::local::connect_pair(reused, reused_peer);
    auto replacement = require(runtime.sync([&]() { return owner->adopt(std::move(reused)); }));
    replacement->close();
    replacement.reset();
}

void test_accepted_socket_allocation_rollback() {
    // Exhaust synchronous adoption allocations on its declared context.
    IoRuntime runtime;
    AsioTcpChannelLimits limits;
    limits.max_active_channels = 1U;
    auto owner = require(AsioTcpAcceptedChannelOwner::create(
        runtime.context(), limits));
    std::size_t failed_attempts = 0U;
    bool reached_success = false;
    for (std::ptrdiff_t fail_after = 0; fail_after < 64; ++fail_after) {
        auto pair = connected_pair(runtime.executor());
        auto adopted = runtime.sync([&]() {
            test_allocation_failure::Scope failure(fail_after);
            return owner->adopt(std::move(pair.first));
        });
        if (adopted.ok()) {
            auto channel = std::move(adopted).take_value();
            channel.reset();
            run_barrier(runtime);
            reached_success = true;
            break;
        }
        ++failed_attempts;
        CHECK(adopted.status().code() == StatusCode::ResourceExhausted);

        // Every failed construction must release its reserved channel slot.
        auto retry_pair = connected_pair(runtime.executor());
        auto retry = runtime.sync([&]() { return owner->adopt(std::move(retry_pair.first)); });
        CHECK(retry.ok());
        auto channel = std::move(retry).take_value();
        channel.reset();
        run_barrier(runtime);
    }
    CHECK(failed_attempts > 0U);
    CHECK(reached_success);
}

void test_accepted_socket_owner_lifetime_and_active_close() {
    IoRuntime runtime;
    auto owner = make_accepted_owner(runtime);
    auto pair = connected_pair(runtime.executor());
    auto channel = require(runtime.sync([&]() { return owner->adopt(std::move(pair.first)); }));
    auto pending = start_read(runtime, *channel, 1U);
    run_barrier(runtime);
    owner.reset();
    auto cancelled = await(pending);
    CHECK(!cancelled.ok());
    CHECK(cancelled.status().code() == StatusCode::Cancelled);
    CHECK(runtime.is_worker(*pending.callback_thread));

    auto live = start_read(runtime, *channel, 1U);
    boost::asio::write(pair.second, boost::asio::buffer("R", 1U));
    auto received = await(live);
    CHECK(received.ok() && buffer_text(*received.value_if()) == "R");

    auto active = start_read(runtime, *channel, 1U);
    auto queued = start_read(runtime, *channel, 1U);
    run_barrier(runtime);
    channel->close();
    channel->close();
    channel.reset();
    auto active_closed = await(active);
    auto queued_closed = await(queued);
    CHECK(!active_closed.ok() &&
          active_closed.status().code() == StatusCode::Closed);
    CHECK(!queued_closed.ok() &&
          queued_closed.status().code() == StatusCode::Closed);
    CHECK(runtime.is_worker(*active.callback_thread));
    CHECK(runtime.is_worker(*queued.callback_thread));
    run_barrier(runtime);
    CHECK(active.calls->load(std::memory_order_relaxed) == 1U);
    CHECK(queued.calls->load(std::memory_order_relaxed) == 1U);
}

void test_dns_round_trip_order_and_half_close() {
    std::atomic<unsigned int> protector_calls{0U};
    TcpServer server([&protector_calls](Tcp::socket& socket) {
        CHECK(protector_calls.load(std::memory_order_acquire) >= 1U);
        std::array<char, 6> input{};
        boost::system::error_code error;
        CHECK(boost::asio::read(socket, boost::asio::buffer(input), error) ==
              input.size());
        CHECK(!error);
        CHECK(std::string(input.data(), input.size()) == "onetwo");

        std::array<char, 1> eof_probe{};
        CHECK(socket.read_some(boost::asio::buffer(eof_probe), error) == 0U);
        CHECK(error == boost::asio::error::eof);

        boost::asio::write(socket, boost::asio::buffer("AB", 2U), error);
        CHECK(!error);
        socket.shutdown(Tcp::socket::shutdown_send, error);
    });
    IoRuntime runtime;
    auto provider = make_provider(
        runtime, "localhost", server.port(), {},
        [&protector_calls](std::uintptr_t handle) {
            CHECK(handle != 0U);
            protector_calls.fetch_add(1U, std::memory_order_release);
            return Status::success();
        });
    auto create = start_create(runtime, provider);
    auto created = await(create);
    CHECK(created.ok());
    CHECK(runtime.is_worker(*create.callback_thread));
    std::unique_ptr<ByteChannel> channel = std::move(created).take_value();
    CHECK(channel->executor_affinity() == ExecutorAffinity(93U));
    CHECK(protector_calls.load(std::memory_order_relaxed) >= 1U);

    auto first_write = start_write(runtime, *channel, make_buffer("one"));
    auto second_write = start_write(runtime, *channel, make_buffer("two"));
    CHECK(runtime.sync([&]() { return channel->shutdown_write(); }).ok());
    CHECK(runtime.sync([&]() { return channel->shutdown_write(); }).ok());
    TransferResult first = await(first_write);
    TransferResult second = await(second_write);
    CHECK(first.status.ok() && first.transferred == 3U);
    CHECK(second.status.ok() && second.transferred == 3U);
    CHECK(runtime.is_worker(*first_write.callback_thread));
    CHECK(runtime.is_worker(*second_write.callback_thread));

    auto first_read = start_read(runtime, *channel, 1U);
    auto second_read = start_read(runtime, *channel, 1U);
    auto a = await(first_read);
    auto b = await(second_read);
    CHECK(a.ok() && buffer_text(*a.value_if()) == "A");
    CHECK(b.ok() && buffer_text(*b.value_if()) == "B");
    CHECK(runtime.is_worker(*first_read.callback_thread));
    CHECK(runtime.is_worker(*second_read.callback_thread));
    auto eof = start_read(runtime, *channel, 1U);
    auto eof_result = await(eof);
    CHECK(!eof_result.ok());
    CHECK(eof_result.status().code() == StatusCode::Closed);
    channel->close();
    channel.reset();
    server.wait();
}

void test_protector_fail_throw_and_refused_connect() {
    IoRuntime runtime;
    const std::uint16_t port = unused_tcp_port();
    std::atomic<unsigned int> calls{0U};
    auto rejected_provider = make_provider(
        runtime, "127.0.0.1", port, {},
        [&calls](std::uintptr_t handle) {
            CHECK(handle != 0U);
            calls.fetch_add(1U, std::memory_order_relaxed);
            return Status(StatusCode::FailedPrecondition,
                          "test protector rejection");
        });
    auto rejected_ticket = start_create(runtime, rejected_provider);
    auto rejected = await(rejected_ticket);
    CHECK(!rejected.ok());
    CHECK(rejected.status().code() == StatusCode::FailedPrecondition);
    CHECK(calls.load(std::memory_order_relaxed) == 1U);

    auto throwing_provider = make_provider(
        runtime, "127.0.0.1", port, {},
        [](std::uintptr_t) -> Status {
            throw std::runtime_error("protector test");
        });
    auto throwing_ticket = start_create(runtime, throwing_provider);
    auto thrown = await(throwing_ticket);
    CHECK(!thrown.ok());
    CHECK(thrown.status().code() == StatusCode::Internal);

    auto refused_provider = make_provider(
        runtime, "127.0.0.1", port);
    auto refused_ticket = start_create(runtime, refused_provider);
    auto refused = await(refused_ticket);
    CHECK(!refused.ok());
    CHECK(refused.status().code() == StatusCode::NotFound);
    CHECK(refused_ticket.calls->load(std::memory_order_relaxed) == 1U);
}

void test_connect_deadline_covers_protection_and_attempts() {
    IoRuntime runtime;
    AsioTcpByteChannelLimits limits;
    limits.connect_timeout = 1ms;
    auto provider = make_provider(
        runtime, "127.0.0.1", unused_tcp_port(), limits,
        [](std::uintptr_t) {
            // The deadline is armed before protection and must cover all
            // attempt setup, rather than starting afresh after each endpoint.
            std::this_thread::sleep_for(25ms);
            return Status::success();
        });
    auto ticket = start_create(runtime, provider);
    auto result = await(ticket);
    CHECK(!result.ok());
    CHECK(result.status().code() == StatusCode::Closed);
    CHECK(result.status().message().find("timed out") != std::string::npos);
}

void test_operation_bounds_cancel_and_close() {
    std::promise<void> connected_promise;
    std::shared_future<void> connected = connected_promise.get_future();
    std::promise<void> release_promise;
    std::shared_future<void> release = release_promise.get_future();
    TcpServer server([&](Tcp::socket& socket) {
        connected_promise.set_value();
        release.wait();
        boost::system::error_code error;
        boost::asio::write(socket, boost::asio::buffer("Z", 1U), error);
    });
    IoRuntime runtime;
    AsioTcpByteChannelLimits limits;
    limits.max_queued_read_operations = 2U;
    limits.max_queued_read_bytes = limits.max_read_bytes;
    limits.max_queued_write_operations = 2U;
    limits.max_queued_write_bytes = limits.max_write_bytes;
    auto provider = make_provider(runtime, "127.0.0.1", server.port(), limits);
    auto create = start_create(runtime, provider);
    auto created = await(create);
    CHECK(created.ok());
    std::unique_ptr<ByteChannel> channel = std::move(created).take_value();
    CHECK(connected.wait_for(3s) == std::future_status::ready);

    CancellationSource first_cancel;
    auto first = start_read(runtime, *channel, limits.max_read_bytes,
                            first_cancel.token());
    auto rejected = start_read(runtime, *channel, 1U);
    auto rejected_result = await(rejected);
    CHECK(!rejected_result.ok());
    CHECK(rejected_result.status().code() == StatusCode::ResourceExhausted);
    CHECK(first_cancel.cancel());
    auto cancelled = await(first);
    CHECK(!cancelled.ok());
    CHECK(cancelled.status().code() == StatusCode::Cancelled);

    auto provider_cancelled = start_read(runtime, *channel, 1U);
    std::thread cancel_thread([provider]() { provider->cancel(); });
    cancel_thread.join();
    auto provider_cancel_result = await(provider_cancelled);
    CHECK(!provider_cancel_result.ok());
    CHECK(provider_cancel_result.status().code() == StatusCode::Cancelled);

    auto oversized_write = start_write(runtime,
        *channel, require(Buffer::allocate(
            limits.max_write_bytes + 1U, limits.max_write_bytes + 1U)));
    TransferResult oversized = await(oversized_write);
    CHECK(!oversized.status.ok());
    CHECK(oversized.status.code() == StatusCode::ResourceExhausted);

    auto live_read = start_read(runtime, *channel, 1U);
    release_promise.set_value();
    auto live = await(live_read);
    CHECK(live.ok() && buffer_text(*live.value_if()) == "Z");

    auto closed_read = start_read(runtime, *channel, 1U);
    channel->close();
    auto closed = await(closed_read);
    CHECK(!closed.ok());
    CHECK(closed.status().code() == StatusCode::Closed);
    channel->close();
    channel->cancel();
    channel.reset();
    server.wait();
}

void test_submission_operation_and_byte_bounds() {
    TcpServer server([](Tcp::socket& socket) {
        boost::system::error_code error;
        boost::asio::write(socket, boost::asio::buffer("R", 1U), error);
        CHECK(!error);
        std::array<char, 1> input{};
        CHECK(boost::asio::read(socket, boost::asio::buffer(input), error) ==
              input.size());
        CHECK(!error);
        CHECK(input[0] == 'W');
    });
    IoRuntime runtime;
    AsioTcpByteChannelLimits limits;
    limits.max_read_bytes = 8U;
    limits.max_write_bytes = 8U;
    limits.max_queued_read_operations = 1U;
    limits.max_queued_write_operations = 1U;
    limits.max_queued_read_bytes = 8U;
    limits.max_queued_write_bytes = 8U;
    auto provider = make_provider(runtime, "127.0.0.1", server.port(), limits);
    auto create = start_create(runtime, provider);
    auto created = await(create);
    CHECK(created.ok());
    std::unique_ptr<ByteChannel> channel = std::move(created).take_value();

    AsyncTicket<Result<Buffer>> accepted_read;
    AsyncTicket<Result<Buffer>> rejected_read;
    AsyncTicket<TransferResult> accepted_write;
    AsyncTicket<TransferResult> rejected_write;
    runtime.sync([&]() {
        accepted_read = start_read(runtime, *channel, 8U);
        rejected_read = start_read(runtime, *channel, 1U);
        accepted_write = start_write(runtime, *channel, make_buffer("W"));
        rejected_write = start_write(runtime, *channel, make_buffer("X"));
    });

    auto read_rejection = await(rejected_read);
    CHECK(!read_rejection.ok());
    CHECK(read_rejection.status().code() == StatusCode::ResourceExhausted);
    TransferResult write_rejection = await(rejected_write);
    CHECK(!write_rejection.status.ok());
    CHECK(write_rejection.status.code() == StatusCode::ResourceExhausted);
    auto read = await(accepted_read);
    CHECK(read.ok() && buffer_text(*read.value_if()) == "R");
    TransferResult write = await(accepted_write);
    CHECK(write.status.ok() && write.transferred == 1U);
    channel->close();
    channel.reset();
    server.wait();
}

void test_create_cancellation_capacity_and_reuse() {
    IoRuntime runtime;
    AsioTcpByteChannelLimits limits;
    limits.max_pending_creates = 1U;
    limits.max_active_channels = 1U;

    CancellationSource already_cancelled;
    CHECK(already_cancelled.cancel());
    auto cancelled_provider = make_provider(
        runtime, "localhost", 443U, limits);
    auto cancelled_ticket = start_create(runtime,
        cancelled_provider, EndpointRole::Client,
        already_cancelled.token());
    auto cancelled = await(cancelled_ticket);
    CHECK(!cancelled.ok());
    CHECK(cancelled.status().code() == StatusCode::Cancelled);

    TcpServer server([](Tcp::socket& socket) {
        std::array<char, 1> input{};
        boost::system::error_code error;
        socket.read_some(boost::asio::buffer(input), error);
    });
    auto provider = make_provider(
        runtime, "127.0.0.1", server.port(), limits);
    auto first_ticket = start_create(runtime, provider);
    auto first = await(first_ticket);
    CHECK(first.ok());
    std::unique_ptr<ByteChannel> channel = std::move(first).take_value();

    auto capacity_ticket = start_create(runtime, provider);
    auto capacity = await(capacity_ticket);
    CHECK(!capacity.ok());
    CHECK(capacity.status().code() == StatusCode::ResourceExhausted);

    channel->close();
    channel.reset();
    server.wait();

    CancellationSource external_cancel;
    const std::uint16_t cancelled_port = unused_tcp_port();
    auto external_provider = make_provider(
        runtime, "127.0.0.1", cancelled_port, limits);
    auto external_ticket = runtime.sync([&]() {
        auto ticket = start_create(runtime, external_provider,
                                   EndpointRole::Client, external_cancel.token());
        CHECK(external_cancel.cancel());
        return ticket;
    });
    auto external = await(external_ticket);
    CHECK(!external.ok());
    CHECK(external.status().code() == StatusCode::Cancelled);

    auto provider_ticket = runtime.sync([&]() {
        auto ticket = start_create(runtime, external_provider);
        external_provider->cancel();
        return ticket;
    });
    auto provider_result = await(provider_ticket);
    CHECK(!provider_result.ok());
    CHECK(provider_result.status().code() == StatusCode::Cancelled);

    auto reused_ticket = start_create(runtime, external_provider);
    auto reused = await(reused_ticket);
    CHECK(!reused.ok());
    CHECK(reused.status().code() == StatusCode::NotFound);
}

void test_execution_context_affinity_and_single_runner() {
    auto invalid = AsioExecutionContext::create(ExecutorAffinity{});
    CHECK(!invalid.ok());
    CHECK(invalid.status().code() == StatusCode::InvalidArgument);
    IoRuntime runtime;
    auto context = runtime.context();
    CHECK(context->affinity() == ExecutorAffinity(93U));
    CHECK(!context->running_in_this_thread());
    bool rejected = false;
    try {
        context->require_context();
    } catch (const std::logic_error&) {
        rejected = true;
    }
    CHECK(rejected);
    run_barrier(runtime);
    rejected = false;
    try {
        context->poll();
    } catch (const std::logic_error&) {
        rejected = true;
    }
    CHECK(rejected);
    runtime.sync([&]() {
        context->require_context();
        CHECK(context->running_in_this_thread());
        bool recursive_rejected = false;
        try {
            context->run();
        } catch (const std::logic_error&) {
            recursive_rejected = true;
        }
        CHECK(recursive_rejected);
    });

    auto owner = make_accepted_owner(runtime);
    auto pair = connected_pair(runtime.executor());
    auto channel = runtime.sync([&]() {
        return require(owner->adopt(std::move(pair.first)));
    });
    auto provider = make_provider(runtime, "127.0.0.1", unused_tcp_port());
    unsigned int callbacks = 0U;
    unsigned int rejected_operations = 0U;
    try {
        channel->async_read(1U, {}, [&](Result<Buffer>) { ++callbacks; });
    } catch (const std::logic_error&) {
        ++rejected_operations;
    }
    try {
        channel->async_write(make_buffer("X"), {},
            [&](Status, std::size_t) { ++callbacks; });
    } catch (const std::logic_error&) {
        ++rejected_operations;
    }
    try {
        provider->async_create(EndpointRole::Client, {},
            [&](Result<std::unique_ptr<ByteChannel>>) { ++callbacks; });
    } catch (const std::logic_error&) {
        ++rejected_operations;
    }
    CHECK(channel->shutdown_write().code() == StatusCode::FailedPrecondition);
    CHECK(rejected_operations == 3U);
    run_barrier(runtime);
    CHECK(callbacks == 0U);
    auto read = start_read(runtime, *channel, 1U);
    boost::asio::write(pair.second, boost::asio::buffer("R", 1U));
    auto result = await(read);
    CHECK(result.ok() && buffer_text(*result.value_if()) == "R");
    channel.reset();
}

struct ControlProbe final : public std::enable_shared_from_this<ControlProbe> {
    ControlProbe(AsioExecutionContext& selected_context, std::size_t& call_count,
                 std::size_t& destruction_count, bool& affinity_ok,
                 std::size_t repeat_count)
        : context(selected_context), calls(call_count), destroyed(destruction_count),
          on_context(affinity_ok), repeats(repeat_count), task(&invoke) {}
    ~ControlProbe() { ++destroyed; }

    static void invoke(void* pointer) noexcept {
        auto& self = *static_cast<ControlProbe*>(pointer);
        self.on_context = self.on_context && self.context.running_in_this_thread();
        ++self.calls;
        if (self.calls < self.repeats) {
            self.context.submit(self.task, self.shared_from_this());
        }
    }

    AsioExecutionContext& context;
    std::size_t& calls;
    std::size_t& destroyed;
    bool& on_context;
    std::size_t repeats;
    AsioExecutionContext::ControlTask task;
};

void test_reserved_control_dispatch_under_sustained_allocation_failure() {
    auto context = require(AsioExecutionContext::create(ExecutorAffinity(94U)));
    std::size_t calls = 0U;
    std::size_t destroyed = 0U;
    bool on_context = true;
    std::size_t normal_handler_observed_calls = 0U;
    auto probe = std::make_shared<ControlProbe>(
        *context, calls, destroyed, on_context, 130U);
    std::weak_ptr<ControlProbe> lifetime = probe;
    context->submit(probe->task, probe);
    context->submit(probe->task, probe);
    boost::asio::post(context->executor(), [&]() noexcept {
        normal_handler_observed_calls = calls;
    });
    probe.reset();
    CHECK(!lifetime.expired());
    {
        test_allocation_failure::SustainedScope failure;
        context->poll();
    }
    CHECK(calls == 130U);
    CHECK(destroyed == 1U);
    CHECK(lifetime.expired());
    CHECK(on_context);
    // A self-requeued control task must yield to unrelated I/O handlers.
    CHECK(normal_handler_observed_calls > 0U);
    CHECK(normal_handler_observed_calls < calls);

    calls = 0U;
    probe = std::make_shared<ControlProbe>(
        *context, calls, destroyed, on_context, 1U);
    {
        test_allocation_failure::SustainedScope failure;
        // Test first submission as well as reposting with allocation disabled.
        context->submit(probe->task, probe);
        context->submit(probe->task, probe);
        probe.reset();
        context->finish();
        context->run();
    }
    CHECK(calls == 1U);
    CHECK(destroyed == 2U);
    CHECK(on_context);
}

struct CompletionRecord final {
    unsigned int calls{0U};
    StatusCode code{StatusCode::Internal};
    bool on_context{false};
    std::size_t transferred{0U};

    void record(const AsioExecutionContext& context, const Status& status,
                std::size_t count = 0U) noexcept {
        ++calls;
        code = status.code();
        on_context = context.running_in_this_thread();
        transferred = count;
    }
};

// Fill the sender's bounded kernel queue before adoption so the first async
// write is still active when cancellation/close runs. The peer never reads.
void fill_send_queue(AsioTcpSocket& socket) {
    socket.set_option(Tcp::socket::send_buffer_size(1024));
    socket.non_blocking(true);
    const std::array<char, 16U * 1024U> bytes{};
    boost::system::error_code error;
    std::size_t total = 0U;
    for (; total < 2U * 1024U * 1024U;) {
        total += socket.write_some(boost::asio::buffer(bytes), error);
        if (error) break;
    }
    CHECK(error == boost::asio::error::would_block ||
          error == boost::asio::error::try_again);
    socket.non_blocking(false);
}

enum class CleanupAction { Close, CloseReleaseInCallback, ChannelCancel, OwnerCancel, OwnerDestroy };

void test_pending_cleanup_under_sustained_allocation_failure(CleanupAction action) {
    auto context = require(AsioExecutionContext::create(ExecutorAffinity(95U)));
    auto owner = require(AsioTcpAcceptedChannelOwner::create(context));
    auto pair = connected_pair(context->executor());
    pair.second.set_option(Tcp::socket::receive_buffer_size(1024));
    fill_send_queue(pair.first);
    std::unique_ptr<ByteChannel> channel;
    std::array<CompletionRecord, 4U> records{};
    Buffer first_write = require(Buffer::allocate(64U * 1024U, kAbsoluteMaxBufferBytes));
    Buffer second_write = require(Buffer::allocate(64U * 1024U, kAbsoluteMaxBufferBytes));
    boost::asio::post(context->executor(), [&]() {
        channel = require(owner->adopt(std::move(pair.first)));
        for (std::size_t index = 0U; index < 2U; ++index) {
            channel->async_read(1U, {}, [&, index](Result<Buffer> result) noexcept {
                records[index].record(*context, result.status());
                if (index == 0U && action == CleanupAction::CloseReleaseInCallback) {
                    channel.reset();
                    owner.reset();
                }
            });
        }
        channel->async_write(std::move(first_write), {},
            [&](Status status, std::size_t transferred) noexcept {
                records[2].record(*context, status, transferred);
            });
        channel->async_write(std::move(second_write), {},
            [&](Status status, std::size_t transferred) noexcept {
                records[3].record(*context, status, transferred);
            });
    });
    context->poll();
    for (const auto& record : records) CHECK(record.calls == 0U);
    {
        test_allocation_failure::SustainedScope failure;
        switch (action) {
            case CleanupAction::Close:
                channel->close();
                channel->close();
                channel.reset();
                break;
            case CleanupAction::CloseReleaseInCallback:
                channel->close();
                break;
            case CleanupAction::ChannelCancel:
                channel->cancel();
                channel->cancel();
                break;
            case CleanupAction::OwnerCancel:
                owner->cancel();
                owner->cancel();
                break;
            case CleanupAction::OwnerDestroy:
                owner.reset();
                break;
        }
        context->poll();
    }
    const StatusCode expected = action == CleanupAction::Close ||
                                    action == CleanupAction::CloseReleaseInCallback
                                    ? StatusCode::Closed : StatusCode::Cancelled;
    for (const auto& record : records) {
        CHECK(record.calls == 1U);
        CHECK(record.code == expected);
        CHECK(record.on_context);
    }
    if (channel) {
        // Cancelling or destroying the owner must leave a channel reusable.
        CompletionRecord reused;
        bool correct_byte = false;
        boost::asio::post(context->executor(), [&]() {
            channel->async_read(1U, {}, [&](Result<Buffer> result) noexcept {
                reused.record(*context, result.status());
                correct_byte = result.ok() && result.value_if()->size() == 1U &&
                    result.value_if()->bytes()[0] == std::byte{'R'};
            });
        });
        boost::asio::write(pair.second, boost::asio::buffer("R", 1U));
        context->poll();
        CHECK(reused.calls == 1U);
        CHECK(reused.code == StatusCode::Ok);
        CHECK(reused.on_context);
        CHECK(correct_byte);
        channel.reset();
    }
    owner.reset();
    context->finish();
    context->run();
    for (const auto& record : records) CHECK(record.calls == 1U);
}

void test_pending_create_cancel_under_sustained_allocation_failure() {
    auto context = require(AsioExecutionContext::create(ExecutorAffinity(97U)));
    auto resolver = make_resolver(context);
    auto provider = require(AsioTcpByteChannelProvider::create(
        context, "localhost", unused_tcp_port(), {}, {}, resolver));
    CompletionRecord record;
    boost::asio::post(context->executor(), [&]() {
        provider->async_create(EndpointRole::Client, {},
            [&](Result<std::unique_ptr<ByteChannel>> result) noexcept {
                record.record(*context, result.status());
                provider.reset();
                resolver->close();
            });
        test_allocation_failure::sustained.store(true, std::memory_order_release);
        provider->cancel();
    });
    // Arm only after the lookup is outstanding, then keep allocation disabled
    // through cancellation, callback-driven provider destruction, resolver
    // close and drain. A cancelled lookup's late answer must not escape.
    {
        test_allocation_failure::SustainedScope reset_on_exit(false);
        context->finish();
        context->run();
    }
    CHECK(record.calls == 1U);
    CHECK(record.code == StatusCode::Cancelled);
    CHECK(record.on_context);
    CHECK(!provider);
}

// The resolver's answer arrives while every allocation fails. Its delivery
// cannot build the address list, so the create settles once with
// ResourceExhausted instead of losing its completion or throwing from run().
void test_resolver_delivery_allocation_failure() {
    auto context = require(AsioExecutionContext::create(ExecutorAffinity(98U)));
    auto resolver = make_resolver(context);
    auto provider = require(AsioTcpByteChannelProvider::create(
        context, "localhost", unused_tcp_port(), {}, {}, resolver));
    CompletionRecord record;
    boost::asio::post(context->executor(), [&]() {
        provider->async_create(EndpointRole::Client, {},
            [&](Result<std::unique_ptr<ByteChannel>> result) noexcept {
                record.record(*context, result.status());
                provider.reset();
                resolver->close();
            });
        test_allocation_failure::sustained.store(true, std::memory_order_release);
    });
    {
        test_allocation_failure::SustainedScope reset_on_exit(false);
        context->finish();
        context->run();
    }
    CHECK(record.calls == 1U);
    CHECK(record.code == StatusCode::ResourceExhausted);
    CHECK(record.on_context);
    CHECK(!provider);
}

// A lookup that never returns is cancelled at once. Closing the resolver ends
// its helper, so the final drain does not wait for the stalled system call.
void test_stalled_lookup_cancel_and_drain() {
    auto context = require(AsioExecutionContext::create(ExecutorAffinity(99U)));
    auto resolver = make_resolver(context, YUME_TEST_STALL_RESOLVER_PROGRAM);
    auto provider = require(AsioTcpByteChannelProvider::create(
        context, "resolver-stall.invalid", 443U, {}, {}, resolver));
    CompletionRecord record;
    std::chrono::steady_clock::time_point closed_at{};
    boost::asio::post(context->executor(), [&]() {
        provider->async_create(EndpointRole::Client, {},
            [&](Result<std::unique_ptr<ByteChannel>> result) noexcept {
                record.record(*context, result.status());
            });
        boost::asio::post(context->executor(), [&]() {
            provider->cancel();
            resolver->close();
            closed_at = std::chrono::steady_clock::now();
            context->finish();
        });
    });
    context->run();
    CHECK(std::chrono::steady_clock::now() - closed_at < 2s);
    CHECK(record.calls == 1U);
    CHECK(record.code == StatusCode::Cancelled);
    CHECK(record.on_context);
}

void test_initiation_failure_stays_on_context() {
    auto context = require(AsioExecutionContext::create(ExecutorAffinity(96U)));
    AsioTcpChannelLimits limits;
    limits.max_read_bytes = 1U;
    limits.max_write_bytes = 1U;
    limits.max_queued_read_operations = 1U;
    limits.max_queued_write_operations = 1U;
    limits.max_queued_read_bytes = 1U;
    limits.max_queued_write_bytes = 1U;
    auto owner = require(AsioTcpAcceptedChannelOwner::create(context, limits));
    auto provider = require(AsioTcpByteChannelProvider::create(
        context, "127.0.0.1", unused_tcp_port()));
    auto pair = connected_pair(context->executor());
    std::unique_ptr<ByteChannel> channel;
    std::array<CompletionRecord, 3U> records{};
    Buffer write = make_buffer("W");
    ByteChannel::ReadCompletion read_completion = [&](Result<Buffer> result) noexcept {
        records[0].record(*context, result.status());
    };
    ByteChannel::WriteCompletion write_completion =
        [&](Status status, std::size_t count) noexcept {
            records[1].record(*context, status, count);
        };
    ByteChannelProvider::Completion create_completion =
        [&](Result<std::unique_ptr<ByteChannel>> result) noexcept {
            records[2].record(*context, result.status());
        };
    boost::asio::post(context->executor(), [&]() {
        channel = require(owner->adopt(std::move(pair.first)));
        test_allocation_failure::SustainedScope failure;
        channel->async_read(1U, {}, std::move(read_completion));
        channel->async_write(std::move(write), {}, std::move(write_completion));
        provider->async_create(EndpointRole::Client, {}, std::move(create_completion));
    });
    context->poll();
    CHECK(records[0].calls == 1U);
    CHECK(records[1].calls == 1U);
    CHECK(records[2].calls == 1U);
    for (const auto& record : records) {
        CHECK(record.code == StatusCode::ResourceExhausted);
        CHECK(record.on_context);
    }

    // Each refusal must return its only queue slot and byte reservation. A
    // subsequent read/write uses the same channel after allocation recovers.
    std::array<CompletionRecord, 2U> reused{};
    bool correct_byte = false;
    Buffer retry_write = make_buffer("W");
    boost::asio::write(pair.second, boost::asio::buffer("R", 1U));
    boost::asio::post(context->executor(), [&]() {
        channel->async_read(1U, {}, [&](Result<Buffer> result) noexcept {
            reused[0].record(*context, result.status());
            correct_byte = result.ok() && result.value_if()->size() == 1U &&
                result.value_if()->bytes()[0] == std::byte{'R'};
        });
        channel->async_write(std::move(retry_write), {},
            [&](Status status, std::size_t count) noexcept {
                reused[1].record(*context, status, count);
            });
    });
    context->finish();
    context->run();
    for (const auto& record : reused) {
        CHECK(record.calls == 1U);
        CHECK(record.code == StatusCode::Ok);
        CHECK(record.on_context);
    }
    CHECK(correct_byte);
    CHECK(reused[1].transferred == 1U);
    channel.reset();
    owner.reset();
    provider.reset();
    context->finish();
    context->run();
    for (const auto& record : records) CHECK(record.calls == 1U);
    for (const auto& record : reused) CHECK(record.calls == 1U);
}

}  // namespace
}  // namespace yume::providers

int main() {
    yume::test::before_allocate_on_any_thread.store(check_test_allocation);

    try {
        yume::providers::test_descriptor_and_validation();
        yume::providers::test_accepted_socket_validation_and_capacity_release();
        yume::providers::test_accepted_socket_traffic_half_close_cancel_and_close();
        yume::providers::test_accepted_unix_socket_traffic_and_capacity();
        yume::providers::test_accepted_socket_allocation_rollback();
        yume::providers::test_accepted_socket_owner_lifetime_and_active_close();
        yume::providers::test_dns_round_trip_order_and_half_close();
        yume::providers::test_protector_fail_throw_and_refused_connect();
        yume::providers::test_connect_deadline_covers_protection_and_attempts();
        yume::providers::test_operation_bounds_cancel_and_close();
        yume::providers::test_submission_operation_and_byte_bounds();
        yume::providers::test_create_cancellation_capacity_and_reuse();
        yume::providers::test_execution_context_affinity_and_single_runner();
        yume::providers::test_reserved_control_dispatch_under_sustained_allocation_failure();
        yume::providers::test_pending_cleanup_under_sustained_allocation_failure(
            yume::providers::CleanupAction::Close);
        yume::providers::test_pending_cleanup_under_sustained_allocation_failure(
            yume::providers::CleanupAction::CloseReleaseInCallback);
        yume::providers::test_pending_cleanup_under_sustained_allocation_failure(
            yume::providers::CleanupAction::ChannelCancel);
        yume::providers::test_pending_cleanup_under_sustained_allocation_failure(
            yume::providers::CleanupAction::OwnerCancel);
        yume::providers::test_pending_cleanup_under_sustained_allocation_failure(
            yume::providers::CleanupAction::OwnerDestroy);
        yume::providers::test_pending_create_cancel_under_sustained_allocation_failure();
        yume::providers::test_resolver_delivery_allocation_failure();
        yume::providers::test_stalled_lookup_cancel_and_drain();
        yume::providers::test_initiation_failure_stays_on_context();
        std::cout << "asio TCP ByteChannel provider tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "asio TCP ByteChannel provider test failure: "
                  << error.what() << '\n';
        return 1;
    }
}
