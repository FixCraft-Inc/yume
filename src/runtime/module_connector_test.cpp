/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/module_connector.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

#include <sys/stat.h>
#include <unistd.h>

#include <boost/asio/post.hpp>

#include "test_support/allocation_failure.hpp"
#include "test_support/socket_activated_module.hpp"

namespace {
using namespace yume::engine;
using yume::providers::AsioExecutionContext;
using yume::runtime::check_module_socket;
using yume::runtime::ModuleConnector;
using yume::runtime::ModuleConnectorOptions;
using yume::test::SocketActivatedModule;
using Clock = std::chrono::steady_clock;
using std::chrono::milliseconds;

const std::string kIdentity(64U, 'a');

void check(bool condition, const char* description) {
    if (!condition) throw std::runtime_error(description);
}

template <typename T>
T require(Result<T> result) {
    check(result.ok(), "unexpected failure result");
    return std::move(result).take_value();
}

// The application side of one stream: bytes the module sends arrive as writes.
class FakeStream final : public StreamResponder {
public:
    explicit FakeStream(ExecutorAffinity affinity) : affinity_(affinity) {}
    ExecutorAffinity executor_affinity() const noexcept override { return affinity_; }
    ServiceKind service_kind() const noexcept override { return ServiceKind::ByteStream; }
    std::size_t max_write_size() const noexcept override { return 65536U; }
    bool terminated() const noexcept override { return closed.load(); }
    void async_read(CancellationToken, ReadCompletion completion) override {
        if (closed.load()) {
            completion(Result<ReceivedRecord>(Status(StatusCode::Closed)));
            return;
        }
        pending = std::move(completion);
        deliver();
    }
    void async_write(Buffer payload, CancellationToken, WriteCompletion completion) override {
        received.append(reinterpret_cast<const char*>(payload.bytes().data()), payload.size());
        completion(Status::success(), payload.size());
    }
    Status shutdown_write() noexcept override {
        write_shut.store(true);
        return Status::success();
    }
    void close(Status) noexcept override {
        closed.store(true);
        if (auto read = std::exchange(pending, {})) read(Result<ReceivedRecord>(Status(StatusCode::Closed)));
    }
    void push(const std::string& text) {
        queued.push_back(text);
        deliver();
    }
    std::string received;
    std::atomic<bool> closed{false};
    std::atomic<bool> write_shut{false};

private:
    void deliver() {
        if (!pending || queued.empty()) return;
        auto text = std::move(queued.front());
        queued.pop_front();
        auto buffer = require(Buffer::copy_from(
            {reinterpret_cast<const std::byte*>(text.data()), text.size()}, text.size()));
        std::exchange(pending, {})(Result<ReceivedRecord>(ReceivedRecord(std::move(buffer), CarrierCredit())));
    }
    ExecutorAffinity affinity_;
    ReadCompletion pending;
    std::deque<std::string> queued;
};

// A connector for service "chat" whose socket a SocketActivatedModule owns.
class Harness final {
public:
    Harness() : context(require(AsioExecutionContext::create(ExecutorAffinity(9U)))) {}
    template <typename Action>
    auto on_context(Action action) {
        std::optional<std::invoke_result_t<Action>> result;
        boost::asio::post(context->executor(), [&] { result.emplace(action()); });
        while (!result) context->poll();
        return std::move(*result);
    }

    ~Harness() {
        if (connector) on_context([&] { connector->close(); return true; });
        context->finish();
        context->run();
    }

    template <typename Predicate>
    bool wait_for(Predicate predicate, milliseconds limit = milliseconds(5'000)) {
        const auto deadline = Clock::now() + limit;
        while (!predicate()) {
            if (Clock::now() > deadline) return false;
            context->poll();
            std::this_thread::sleep_for(milliseconds(1));
        }
        return true;
    }

    Status create(ModuleConnectorOptions options = {}, std::optional<std::filesystem::path> socket = {}) {
        const yume::config::v1::ModuleAdapter adapter("chat", socket.value_or(module.socket).string());
        return on_context([&] {
            auto created = ModuleConnector::create(context, adapter, options);
            if (!created.ok()) return created.status();
            connector = std::move(created).take_value();
            return Status::success();
        });
    }

    StreamOpenContext open_context(bool destination = false) {
        auto peer = require(PeerEvidence::create(EndpointRole::Client, kIdentity, "test", {std::byte{1}}));
        std::optional<RouteDestination> route;
        if (destination) route.emplace(require(RouteDestination::ipv4(NetworkProtocol::Tcp, {127, 0, 0, 1}, 22U)));
        return require(StreamOpenContext::create(require(StreamId::application(1U, EndpointRole::Client)),
            "chat", ServiceKind::ByteStream, std::move(peer), std::move(route)));
    }

    // Opens one stream through the handler and waits for acceptance.
    std::shared_ptr<FakeStream> open(Status& accepted) {
        auto stream = std::make_shared<FakeStream>(context->affinity());
        std::optional<Status> outcome;
        on_context([&] {
            auto handler = connector->handler();
            auto authorized = handler->authorize(open_context());
            if (!authorized.ok()) {
                outcome = std::move(authorized);
                return true;
            }
            handler->async_open(open_context(), stream, [&](Status status) { outcome = std::move(status); });
            return true;
        });
        check(wait_for([&] { return outcome.has_value(); }), "the OPEN never settled");
        accepted = std::move(*outcome);
        return stream;
    }

    SocketActivatedModule module;
    std::shared_ptr<AsioExecutionContext> context;
    std::shared_ptr<ModuleConnector> connector;
};

void test_streams_reach_the_module_with_the_identity() {
    Harness harness;
    harness.module.run(YUME_TEST_ECHO_MODULE);
    check(harness.create().ok(), "the module socket was refused");
    Status accepted;
    auto stream = harness.open(accepted);
    check(accepted.ok(), "the module refused an OPEN");
    const std::string greeting = "hello " + kIdentity + "\n";
    check(harness.wait_for([&] { return stream->received == greeting; }),
          "the module did not receive the identity header");
    harness.on_context([&] { stream->push("ping"); return true; });
    check(harness.wait_for([&] { return stream->received == greeting + "ping"; }),
          "the stream did not reach the module");
    auto refused = harness.on_context([&] {
        return harness.connector->handler()->authorize(harness.open_context(true));
    });
    check(refused.code() == StatusCode::InvalidArgument, "a destination reached a module");
    harness.on_context([&] { stream->close(Status(StatusCode::Closed)); return true; });
}

// The service manager restarts a module. Streams the old run held end, and
// one opened while the module is down waits in the socket's queue for the
// next run instead of failing.
void test_streams_wait_across_a_restart() {
    Harness harness;
    harness.module.run(YUME_TEST_ECHO_MODULE);
    check(harness.create().ok(), "the module socket was refused");
    Status accepted;
    auto stream = harness.open(accepted);
    check(accepted.ok(), "the first OPEN was refused");
    check(harness.wait_for([&] { return !stream->received.empty(); }),
          "the first module did not answer");
    harness.module.process.kill_and_reap();
    check(harness.wait_for([&] { return stream->write_shut.load(); }),
          "the client was not told the module closed");
    harness.on_context([&] { stream->push("late"); return true; });
    check(harness.wait_for([&] { return stream->closed.load(); }),
          "a stream outlived its module");
    auto waiting = harness.open(accepted);
    check(accepted.ok(), "an OPEN failed while the module restarted");
    check(waiting->received.empty(), "a module that was down answered");
    harness.module.run(YUME_TEST_ECHO_MODULE);
    check(harness.wait_for([&] { return waiting->received == "hello " + kIdentity + "\n"; }),
          "the restarted module did not take the queued stream");
    harness.on_context([&] { waiting->close(Status(StatusCode::Closed)); return true; });
}

// A socket that disappears refuses OPENs, and so does a closed connector.
void test_gone_socket_and_close_refuse() {
    Harness harness;
    harness.module.run(YUME_TEST_ECHO_MODULE);
    check(harness.create().ok(), "the module socket was refused");
    check(::unlink(harness.module.socket.c_str()) == 0, "unlink failed");
    Status accepted;
    auto stream = harness.open(accepted);
    check(accepted.code() == StatusCode::FailedPrecondition, "an OPEN reached a removed socket");
    check(harness.wait_for([&] { return stream->closed.load(); }), "a refused stream stayed open");
    harness.on_context([&] { harness.connector->close(); return true; });
    const auto closed = harness.on_context([&] {
        return harness.connector->handler()->authorize(harness.open_context());
    });
    check(closed.code() == StatusCode::FailedPrecondition, "a closed connector authorized an OPEN");
}

// Only a socket that no other user can reach or replace is accepted, since
// whoever can connect could forge the identity header and whoever can
// replace it could read the streams. A listener of another user is refused
// at each connection, which needs a second user and is not tested here.
void test_sockets_are_checked() {
    SocketActivatedModule module;
    const auto& socket = module.socket;
    check(check_module_socket(socket).ok(), "a private socket below /tmp was refused");
    check(check_module_socket("relative.sock").code() == StatusCode::InvalidArgument,
          "a relative socket path was accepted");
    check(check_module_socket(module.directory / "missing.sock").code() == StatusCode::FailedPrecondition,
          "a missing socket was accepted");
    check(check_module_socket(module.directory / "missing" / "x.sock").code() ==
              StatusCode::FailedPrecondition,
          "a socket in a missing directory was accepted");
    const auto file = module.directory / "file";
    std::ofstream(file) << "x";
    check(check_module_socket(file).code() == StatusCode::FailedPrecondition, "a regular file was accepted");
    const auto link = module.directory / "link.sock";
    std::filesystem::create_symlink(socket, link);
    check(check_module_socket(link).code() == StatusCode::FailedPrecondition, "a linked socket was accepted");
    const auto linked_directory = std::filesystem::path(module.directory.string() + "-link");
    std::filesystem::create_directory_symlink(module.directory, linked_directory);
    const auto through_link = check_module_socket(linked_directory / "module.sock");
    std::filesystem::remove(linked_directory);
    check(through_link.code() == StatusCode::PermissionDenied, "a directory link was followed");
    check(::chmod(socket.c_str(), 0660) == 0, "chmod failed");
    check(check_module_socket(socket).code() == StatusCode::PermissionDenied,
          "a socket open to the group was accepted");
    check(::chmod(socket.c_str(), 0600) == 0 && ::chmod(module.directory.c_str(), 0770) == 0,
          "chmod failed");
    check(check_module_socket(socket).code() == StatusCode::PermissionDenied,
          "a group-writable directory was accepted");
    check(::chmod(module.directory.c_str(), 0700) == 0, "chmod failed");
    Harness harness;
    check(harness.create({}, module.directory / "missing.sock").code() == StatusCode::FailedPrecondition,
          "a connector was created for a missing socket");
}

// One failed allocation while a module OPEN starts still settles its
// acceptance exactly once.
void test_open_allocation_failure_settles_once() {
    Harness harness;
    harness.module.run(YUME_TEST_ECHO_MODULE);
    check(harness.create().ok(), "the module socket was refused");
    bool reached_success = false;
    for (std::size_t failure = 1U; failure <= 256U && !reached_success;
         ++failure) {
        auto stream = std::make_shared<FakeStream>(harness.context->affinity());
        auto context = harness.open_context();
        auto handler = harness.connector->handler();
        unsigned completions = 0U;
        Status outcome;
        StreamHandler::AcceptanceCompletion completion = [&](Status status) {
            ++completions;
            outcome = std::move(status);
        };
        harness.on_context([&] {
            yume::test::arm_allocation_failure(failure);
            handler->async_open(std::move(context), stream,
                                std::move(completion));
            return true;
        });
        check(harness.wait_for(
                  [&] { return completions != 0U || stream->closed.load(); }),
              "a module OPEN never settled");
        const bool fired = yume::test::disarm_allocation_failure();
        check(completions == 1U, "a module OPEN was not settled exactly once");
        reached_success = !fired && outcome.ok();
        harness.on_context([&] {
            stream->close(Status(StatusCode::Closed));
            return true;
        });
    }
    check(reached_success, "no module OPEN succeeded");
}

// A module at its stream limit refuses a further OPEN once, even when copying
// the refusal fails.
void test_refusal_allocation_failure_settles_once() {
    Harness harness;
    harness.module.run(YUME_TEST_ECHO_MODULE);
    ModuleConnectorOptions options;
    options.max_streams = 1U;
    check(harness.create(options).ok(), "the module socket was refused");
    Status accepted;
    auto held = harness.open(accepted);
    check(accepted.ok(), "the module refused its only stream");
    bool reached_end = false;
    for (std::size_t failure = 1U; failure <= 64U && !reached_end; ++failure) {
        auto stream = std::make_shared<FakeStream>(harness.context->affinity());
        auto context = harness.open_context();
        auto handler = harness.connector->handler();
        unsigned completions = 0U;
        Status outcome;
        StreamHandler::AcceptanceCompletion completion = [&](Status status) {
            ++completions;
            outcome = std::move(status);
        };
        // The connection completes at once, so the refusal runs in this poll.
        harness.on_context([&] {
            handler->async_open(std::move(context), stream,
                                std::move(completion));
            yume::test::arm_allocation_failure(failure);
            return true;
        });
        check(harness.wait_for(
                  [&] { return completions != 0U || stream->closed.load(); }),
              "a refused module OPEN never settled");
        const bool fired = yume::test::disarm_allocation_failure();
        check(completions == 1U &&
                  outcome.code() == StatusCode::ResourceExhausted,
              "an OPEN beyond the module stream limit was not refused once");
        reached_end = !fired;
    }
    check(reached_end, "the refusal sweep did not finish");
    harness.on_context([&] {
        held->close(Status(StatusCode::Closed));
        return true;
    });
}

}  // namespace

int main() {
    try {
        test_streams_reach_the_module_with_the_identity();
        test_streams_wait_across_a_restart();
        test_gone_socket_and_close_refuse();
        test_sockets_are_checked();
        test_open_allocation_failure_settles_once();
        test_refusal_allocation_failure_settles_once();
        std::cout << "module connector tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "module connector test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
