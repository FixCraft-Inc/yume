/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/error_code.hpp>

#include "providers/asio_tcp_byte_channel_provider.hpp"

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

class IoRuntime final {
public:
    explicit IoRuntime(std::size_t thread_count = 2U)
        : guard_(boost::asio::make_work_guard(context_)) {
        CHECK(thread_count > 0U);
        for (std::size_t index = 0U; index < thread_count; ++index) {
            threads_.emplace_back([this]() {
                {
                    std::lock_guard<std::mutex> lock(worker_mutex_);
                    worker_ids_.insert(std::this_thread::get_id());
                }
                context_.run();
            });
        }
    }
    IoRuntime(const IoRuntime&) = delete;
    IoRuntime& operator=(const IoRuntime&) = delete;
    ~IoRuntime() noexcept {
        guard_.reset();
        context_.stop();
        for (std::thread& thread : threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
    }

    boost::asio::io_context& context() noexcept { return context_; }
    bool is_worker(std::thread::id id) const {
        std::lock_guard<std::mutex> lock(worker_mutex_);
        return worker_ids_.contains(id);
    }

private:
    boost::asio::io_context context_;
    boost::asio::executor_work_guard<
        boost::asio::io_context::executor_type> guard_;
    std::vector<std::thread> threads_;
    mutable std::mutex worker_mutex_;
    std::set<std::thread::id> worker_ids_;
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

AsyncTicket<Result<std::unique_ptr<ByteChannel>>> start_create(
    const std::shared_ptr<AsioTcpByteChannelProvider>& provider,
    EndpointRole role = EndpointRole::Client,
    CancellationToken cancellation = {}) {
    AsyncTicket<Result<std::unique_ptr<ByteChannel>>> ticket;
    provider->async_create(
        role, std::move(cancellation),
        [promise = ticket.promise, calls = ticket.calls,
         callback_thread = ticket.callback_thread](
            Result<std::unique_ptr<ByteChannel>> result) mutable {
            *callback_thread = std::this_thread::get_id();
            calls->fetch_add(1U, std::memory_order_relaxed);
            promise->set_value(std::move(result));
        });
    return ticket;
}

AsyncTicket<Result<Buffer>> start_read(ByteChannel& channel,
                                       std::size_t max_bytes,
                                       CancellationToken cancellation = {}) {
    AsyncTicket<Result<Buffer>> ticket;
    channel.async_read(
        max_bytes, std::move(cancellation),
        [promise = ticket.promise, calls = ticket.calls,
         callback_thread = ticket.callback_thread](Result<Buffer> result) mutable {
            *callback_thread = std::this_thread::get_id();
            calls->fetch_add(1U, std::memory_order_relaxed);
            promise->set_value(std::move(result));
        });
    return ticket;
}

struct TransferResult final {
    Status status;
    std::size_t transferred{0U};
};

AsyncTicket<TransferResult> start_write(ByteChannel& channel,
                                        Buffer buffer,
                                        CancellationToken cancellation = {}) {
    AsyncTicket<TransferResult> ticket;
    channel.async_write(
        std::move(buffer), std::move(cancellation),
        [promise = ticket.promise, calls = ticket.calls,
         callback_thread = ticket.callback_thread](
            Status status, std::size_t transferred) mutable {
            *callback_thread = std::this_thread::get_id();
            calls->fetch_add(1U, std::memory_order_relaxed);
            promise->set_value(
                TransferResult{std::move(status), transferred});
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
        runtime.context().get_executor(), ExecutorAffinity(93U),
        std::move(host), port, limits, std::move(protector)));
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
            runtime.context().get_executor(), ExecutorAffinity(1U),
            "localhost", 443U, limits);
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
               boost::asio::any_io_executor{}, ExecutorAffinity(1U),
               "localhost", 443U).ok());
    CHECK(!AsioTcpByteChannelProvider::create(
               runtime.context().get_executor(), ExecutorAffinity{},
               "localhost", 443U).ok());
    CHECK(!AsioTcpByteChannelProvider::create(
               runtime.context().get_executor(), ExecutorAffinity(1U),
               "", 443U).ok());
    CHECK(!AsioTcpByteChannelProvider::create(
               runtime.context().get_executor(), ExecutorAffinity(1U),
               "localhost", 0U).ok());

    auto server_role = start_create(provider, EndpointRole::Server);
    auto rejected = await(server_role);
    CHECK(!rejected.ok());
    CHECK(rejected.status().code() == StatusCode::InvalidArgument);
    CHECK(runtime.is_worker(*server_role.callback_thread));
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
    auto create = start_create(provider);
    auto created = await(create);
    CHECK(created.ok());
    CHECK(runtime.is_worker(*create.callback_thread));
    std::unique_ptr<ByteChannel> channel = std::move(created).take_value();
    CHECK(channel->executor_affinity() == ExecutorAffinity(93U));
    CHECK(protector_calls.load(std::memory_order_relaxed) >= 1U);

    auto first_write = start_write(*channel, make_buffer("one"));
    auto second_write = start_write(*channel, make_buffer("two"));
    CHECK(channel->shutdown_write().ok());
    CHECK(channel->shutdown_write().ok());
    TransferResult first = await(first_write);
    TransferResult second = await(second_write);
    CHECK(first.status.ok() && first.transferred == 3U);
    CHECK(second.status.ok() && second.transferred == 3U);
    CHECK(runtime.is_worker(*first_write.callback_thread));
    CHECK(runtime.is_worker(*second_write.callback_thread));

    auto first_read = start_read(*channel, 1U);
    auto second_read = start_read(*channel, 1U);
    auto a = await(first_read);
    auto b = await(second_read);
    CHECK(a.ok() && buffer_text(*a.value_if()) == "A");
    CHECK(b.ok() && buffer_text(*b.value_if()) == "B");
    CHECK(runtime.is_worker(*first_read.callback_thread));
    CHECK(runtime.is_worker(*second_read.callback_thread));
    auto eof = start_read(*channel, 1U);
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
    auto rejected_ticket = start_create(rejected_provider);
    auto rejected = await(rejected_ticket);
    CHECK(!rejected.ok());
    CHECK(rejected.status().code() == StatusCode::FailedPrecondition);
    CHECK(calls.load(std::memory_order_relaxed) == 1U);

    auto throwing_provider = make_provider(
        runtime, "127.0.0.1", port, {},
        [](std::uintptr_t) -> Status {
            throw std::runtime_error("protector test");
        });
    auto throwing_ticket = start_create(throwing_provider);
    auto thrown = await(throwing_ticket);
    CHECK(!thrown.ok());
    CHECK(thrown.status().code() == StatusCode::Internal);

    auto refused_provider = make_provider(
        runtime, "127.0.0.1", port);
    auto refused_ticket = start_create(refused_provider);
    auto refused = await(refused_ticket);
    CHECK(!refused.ok());
    CHECK(refused.status().code() == StatusCode::NotFound);
    CHECK(refused_ticket.calls->load(std::memory_order_relaxed) == 1U);
}

void test_connect_deadline_covers_protection_and_attempts() {
    IoRuntime runtime(1U);
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
    auto ticket = start_create(provider);
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
    auto create = start_create(provider);
    auto created = await(create);
    CHECK(created.ok());
    std::unique_ptr<ByteChannel> channel = std::move(created).take_value();
    CHECK(connected.wait_for(3s) == std::future_status::ready);

    CancellationSource first_cancel;
    auto first = start_read(*channel, limits.max_read_bytes,
                            first_cancel.token());
    auto rejected = start_read(*channel, 1U);
    auto rejected_result = await(rejected);
    CHECK(!rejected_result.ok());
    CHECK(rejected_result.status().code() == StatusCode::ResourceExhausted);
    CHECK(first_cancel.cancel());
    auto cancelled = await(first);
    CHECK(!cancelled.ok());
    CHECK(cancelled.status().code() == StatusCode::Cancelled);

    auto provider_cancelled = start_read(*channel, 1U);
    std::thread cancel_thread([provider]() { provider->cancel(); });
    cancel_thread.join();
    auto provider_cancel_result = await(provider_cancelled);
    CHECK(!provider_cancel_result.ok());
    CHECK(provider_cancel_result.status().code() == StatusCode::Cancelled);

    auto oversized_write = start_write(
        *channel, require(Buffer::allocate(
            limits.max_write_bytes + 1U, limits.max_write_bytes + 1U)));
    TransferResult oversized = await(oversized_write);
    CHECK(!oversized.status.ok());
    CHECK(oversized.status.code() == StatusCode::ResourceExhausted);

    auto live_read = start_read(*channel, 1U);
    release_promise.set_value();
    auto live = await(live_read);
    CHECK(live.ok() && buffer_text(*live.value_if()) == "Z");

    auto closed_read = start_read(*channel, 1U);
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
    IoRuntime runtime(1U);
    AsioTcpByteChannelLimits limits;
    limits.max_read_bytes = 8U;
    limits.max_write_bytes = 8U;
    limits.max_queued_read_operations = 1U;
    limits.max_queued_write_operations = 1U;
    limits.max_queued_read_bytes = 8U;
    limits.max_queued_write_bytes = 8U;
    auto provider = make_provider(runtime, "127.0.0.1", server.port(), limits);
    auto create = start_create(provider);
    auto created = await(create);
    CHECK(created.ok());
    std::unique_ptr<ByteChannel> channel = std::move(created).take_value();

    std::promise<void> strand_blocked_promise;
    std::future<void> strand_blocked = strand_blocked_promise.get_future();
    std::promise<void> release_strand_promise;
    std::shared_future<void> release_strand =
        release_strand_promise.get_future();
    boost::asio::post(runtime.context(), [&]() {
        strand_blocked_promise.set_value();
        release_strand.wait();
    });
    CHECK(strand_blocked.wait_for(3s) == std::future_status::ready);

    auto accepted_read = start_read(*channel, 8U);
    auto rejected_read = start_read(*channel, 1U);
    auto accepted_write = start_write(*channel, make_buffer("W"));
    auto rejected_write = start_write(*channel, make_buffer("X"));
    release_strand_promise.set_value();

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
    auto cancelled_ticket = start_create(
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
    auto first_ticket = start_create(provider);
    auto first = await(first_ticket);
    CHECK(first.ok());
    std::unique_ptr<ByteChannel> channel = std::move(first).take_value();

    auto capacity_ticket = start_create(provider);
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
    auto external_ticket = start_create(
        external_provider, EndpointRole::Client, external_cancel.token());
    CHECK(external_cancel.cancel());
    auto external = await(external_ticket);
    CHECK(!external.ok());
    CHECK(external.status().code() == StatusCode::Cancelled);

    auto provider_ticket = start_create(
        external_provider, EndpointRole::Client);
    external_provider->cancel();
    auto provider_result = await(provider_ticket);
    CHECK(!provider_result.ok());
    CHECK(provider_result.status().code() == StatusCode::Cancelled);

    auto reused_ticket = start_create(external_provider);
    auto reused = await(reused_ticket);
    CHECK(!reused.ok());
    CHECK(reused.status().code() == StatusCode::NotFound);
}

}  // namespace
}  // namespace yume::providers

int main() {
    try {
        yume::providers::test_descriptor_and_validation();
        yume::providers::test_dns_round_trip_order_and_half_close();
        yume::providers::test_protector_fail_throw_and_refused_connect();
        yume::providers::test_connect_deadline_covers_protection_and_attempts();
        yume::providers::test_operation_bounds_cancel_and_close();
        yume::providers::test_submission_operation_and_byte_bounds();
        yume::providers::test_create_cancellation_capacity_and_reuse();
        std::cout << "asio TCP ByteChannel provider tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "asio TCP ByteChannel provider test failure: "
                  << error.what() << '\n';
        return 1;
    }
}
