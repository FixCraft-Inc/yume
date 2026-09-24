/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/module_supervisor.hpp"

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
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include <boost/asio/post.hpp>

namespace {
using namespace yume::engine;
using yume::providers::AsioExecutionContext;
using yume::runtime::ModuleSupervisor;
using yume::runtime::ModuleSupervisorOptions;
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

class Directory final {
public:
    Directory() {
        std::string pattern = "/tmp/yume-module-test-XXXXXX";
        check(::mkdtemp(pattern.data()) != nullptr, "mkdtemp failed");
        path = pattern;
    }
    ~Directory() {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
    std::filesystem::path script(const std::string& name, const std::string& body, mode_t mode = 0700) {
        const auto file = path / name;
        std::ofstream(file) << "#!/bin/sh\n" << body << "\n";
        check(::chmod(file.c_str(), mode) == 0, "chmod failed");
        return file;
    }
    std::filesystem::path path;
};

class Harness final {
public:
    explicit Harness(std::string program, std::vector<std::string> arguments = {})
        : context(require(AsioExecutionContext::create(ExecutorAffinity(9U)))),
          adapter("chat", std::move(program), std::move(arguments)) {}
    template <typename Action>
    auto on_context(Action action) {
        std::optional<std::invoke_result_t<Action>> result;
        boost::asio::post(context->executor(), [&] { result.emplace(action()); });
        while (!result) context->poll();
        return std::move(*result);
    }

    ~Harness() {
        if (supervisor) on_context([&] { supervisor->close(); return true; });
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

    Status create_and_start(ModuleSupervisorOptions options = {}) {
        if (options.launcher.empty()) options.launcher = YUME_TEST_MODULE_LAUNCHER;
        options.restart_initial = milliseconds(100);
        options.restart_max = milliseconds(400);
        options.stop_grace = milliseconds(300);
        return on_context([&] {
            supervisor = require(ModuleSupervisor::create(context, adapter, options,
                [this](std::string_view text) { reports.emplace_back(text); }));
            return supervisor->start();
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
            auto handler = supervisor->handler();
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

    std::shared_ptr<AsioExecutionContext> context;
    yume::config::v1::ModuleAdapter adapter;
    std::shared_ptr<ModuleSupervisor> supervisor;
    std::vector<std::string> reports;
};

void test_streams_reach_the_module_with_the_identity() {
    Harness harness(YUME_TEST_ECHO_MODULE);
    check(harness.create_and_start().ok(), "the echo module did not start");
    check(harness.on_context([&] { return harness.supervisor->pid(); }) > 0, "no module process");
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
        return harness.supervisor->handler()->authorize(harness.open_context(true));
    });
    check(refused.code() == StatusCode::InvalidArgument, "a destination reached a module");
    harness.on_context([&] { stream->close(Status(StatusCode::Closed)); return true; });
}

void test_crashed_module_restarts() {
    Harness harness(YUME_TEST_ECHO_MODULE);
    check(harness.create_and_start().ok(), "the echo module did not start");
    const pid_t first = harness.on_context([&] { return harness.supervisor->pid(); });
    Status accepted;
    auto stream = harness.open(accepted);
    check(accepted.ok(), "the first OPEN was refused");
    // Once greeted, the stream belongs to this process. A connection still in
    // the listen queue would be served by the restarted module instead.
    check(harness.wait_for([&] { return !stream->received.empty(); }),
          "the first module did not answer");
    check(::kill(first, SIGKILL) == 0, "kill failed");
    check(harness.wait_for([&] { return harness.supervisor->pid() != first; }),
          "the exit was not noticed");
    // Down until the 100 ms restart delay passes.
    const auto down = harness.on_context([&] {
        return harness.supervisor->handler()->authorize(harness.open_context());
    });
    check(down.code() == StatusCode::FailedPrecondition, "an OPEN reached a module that was down");
    // The module's end closed: the client sees end of stream, and its next
    // write ends the stream.
    check(harness.wait_for([&] { return stream->write_shut.load(); }),
          "the client was not told the module closed");
    harness.on_context([&] { stream->push("late"); return true; });
    check(harness.wait_for([&] { return stream->closed.load(); }),
          "a stream outlived its module");
    check(harness.wait_for([&] { return harness.supervisor->pid() > 0; }), "the module did not restart");
    auto again = harness.open(accepted);
    check(accepted.ok(), "the restarted module refused an OPEN");
    check(harness.wait_for([&] { return !again->received.empty(); }), "the restarted module did not answer");
    bool reported_exit = false;
    for (const auto& report : harness.reports) reported_exit = reported_exit || report.find("exited with signal 9") != std::string::npos;
    check(reported_exit, "the exit was not reported");
    harness.on_context([&] { again->close(Status(StatusCode::Closed)); return true; });
}

void test_stalled_module_and_forced_stop() {
    Directory directory;
    const auto stall = directory.script("stall", "trap '' TERM\nexec sleep 60");
    Harness harness(stall.string());
    check(harness.create_and_start().ok(), "the stalling module did not start");
    const pid_t pid = harness.on_context([&] { return harness.supervisor->pid(); });
    // Nothing accepts, but the connection waits in the listen queue, so the
    // OPEN succeeds and the stream simply sees no answer.
    Status accepted;
    auto stream = harness.open(accepted);
    check(accepted.ok(), "a stalled module refused an OPEN");
    check(stream->received.empty(), "a stalled module answered");
    // SIGTERM is ignored only once the script has become sleep.
    const auto command = "/proc/" + std::to_string(pid) + "/comm";
    check(harness.wait_for([&] {
              std::string name;
              std::ifstream(command) >> name;
              return name == "sleep";
          }),
          "the stalling module never started sleeping");
    const auto started = Clock::now();
    harness.on_context([&] { harness.supervisor->close(); return true; });
    check(harness.wait_for([&] { return ::kill(pid, 0) != 0; }), "the module survived close");
    check(Clock::now() - started >= milliseconds(250), "SIGKILL came before the grace period");
    harness.on_context([&] { stream->close(Status(StatusCode::Closed)); return true; });
}

void test_graceful_stop_removes_the_socket() {
    Harness harness(YUME_TEST_ECHO_MODULE);
    check(harness.create_and_start().ok(), "the echo module did not start");
    const pid_t pid = harness.on_context([&] { return harness.supervisor->pid(); });
    const auto directory = harness.supervisor->socket_directory();
    struct stat info {};
    check(::stat(directory.c_str(), &info) == 0 && (info.st_mode & 0777U) == 0700U,
          "the socket directory is not private");
    check(std::filesystem::exists(directory / "module.sock"), "the module socket is missing");
    const auto started = Clock::now();
    harness.on_context([&] { harness.supervisor->close(); return true; });
    check(harness.wait_for([&] { return ::kill(pid, 0) != 0; }), "SIGTERM did not end the module");
    check(Clock::now() - started < milliseconds(250), "a module that obeys SIGTERM waited for SIGKILL");
    check(harness.wait_for([&] { return !std::filesystem::exists(directory); }),
          "the module socket directory was left behind");
}

void test_programs_are_checked() {
    Directory directory;
    Harness missing((directory.path / "missing").string());
    check(missing.create_and_start().code() == StatusCode::FailedPrecondition,
          "a missing module program started");
    const auto shared = directory.script("shared", "exit 0", 0720);
    Harness writable(shared.string());
    check(writable.create_and_start().code() == StatusCode::PermissionDenied,
          "a group-writable module program started");
    Harness launcher(YUME_TEST_ECHO_MODULE);
    ModuleSupervisorOptions options;
    options.launcher = directory.path / "no-launcher";
    check(launcher.create_and_start(options).code() == StatusCode::FailedPrecondition,
          "a missing launcher was accepted");
}

}  // namespace

int main() {
    try {
        test_streams_reach_the_module_with_the_identity();
        test_crashed_module_restarts();
        test_stalled_module_and_forced_stop();
        test_graceful_stop_removes_the_socket();
        test_programs_are_checked();
        std::cout << "module supervisor tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "module supervisor test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
