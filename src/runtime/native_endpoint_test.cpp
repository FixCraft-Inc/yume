/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */
#include "runtime/native_endpoint.hpp"
#include "runtime/native_credentials.hpp"
#include "core/runtime/bounded_file.hpp"
#include "providers/ytp1_h2_carrier.hpp"
#include "providers/ytp1_tls13_secure_channel.hpp"
#include "providers/system_resolver.hpp"

#ifndef YUME_TEST_RESOLVER_PROGRAM
#error "YUME_TEST_RESOLVER_PROGRAM names the resolver helper"
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <optional>
#include <semaphore>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/recycling_allocator.hpp>
#include <boost/asio/ip/tcp.hpp>
#ifdef YUME_NATIVE_TEST_ROUTES
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include "providers/asio_direct_route_provider.hpp"
#include "providers/direct_route_handler.hpp"
#include "runtime/native_client_runtime.hpp"
#include "runtime/native_forward.hpp"
#include "runtime/native_server_runtime.hpp"
#include "runtime/native_socks5.hpp"
#include <boost/asio/local/stream_protocol.hpp>
#define YUME_TEST_ALIGNED_ALLOCATIONS 1
#include "test_support/allocation_failure.hpp"

namespace {
thread_local bool allocation_failure_sustained = false;
thread_local unsigned injected_allocation_failures = 0U;

void fail_runtime_allocation(std::size_t) {
    ++injected_allocation_failures;
    if (!allocation_failure_sustained) yume::test::before_allocate = nullptr;
    throw std::bad_alloc();
}
}
#endif

#ifdef YUME_TEST_WRAP_ACCEPT
#include <cerrno>
#include <sys/socket.h>
namespace {
// Only the runner thread that arms the next accept failure observes it. Every
// other accept, including ordinary listener traffic, calls the OS.
thread_local int injected_accept_error = 0;
#ifdef YUME_NATIVE_TEST_ROUTES
thread_local bool fail_accept_retry_allocation = false;
#endif
}
extern "C" int __real_accept(int, sockaddr*, socklen_t*);
extern "C" int __wrap_accept(int socket, sockaddr* address, socklen_t* length) {
    if (const int failure = std::exchange(injected_accept_error, 0)) {
#ifdef YUME_NATIVE_TEST_ROUTES
        if (std::exchange(fail_accept_retry_allocation, false)) {
            yume::test::before_allocate = fail_runtime_allocation;
        }
#endif
        errno = failure;
        return -1;
    }
    return __real_accept(socket, address, length);
}
#endif

namespace {
using namespace yume::engine;
using namespace yume::runtime;
using namespace std::chrono_literals;

#define CHECK(condition) do { if (!(condition)) throw std::runtime_error( \
    std::string("native endpoint check failed at ") + std::to_string(__LINE__) + ": " #condition); } while (false)

template <typename T> T take(Result<T> result) {
    if (!result.ok()) throw std::runtime_error("native endpoint status " +
        std::to_string(static_cast<int>(result.status().code())) + ": " + result.status().message());
    return std::move(result).take_value();
}

template <typename T> T await(std::future<T>& future) {
    CHECK(future.wait_for(10s) == std::future_status::ready);
    return future.get();
}

class Runner final {
public:
    Runner() : context(take(yume::providers::AsioExecutionContext::create(ExecutorAffinity(311U)))) {
        thread_ = std::thread([this] {
            for (;;) {
                try { context->run(); break; }
                catch (...) { ++exceptions; }
            }
        });
    }
    ~Runner() {
        finish_and_join();
    }
    void finish_and_join() {
        context->finish();
        if (thread_.joinable()) thread_.join();
    }
    template <typename F> auto sync(F fn) {
        using T = std::invoke_result_t<F>;
        auto promise = std::make_shared<std::promise<T>>();
        auto future = promise->get_future();
        boost::asio::post(context->executor(), [fn = std::move(fn), promise]() mutable {
            try {
                if constexpr (std::is_void_v<T>) { fn(); promise->set_value(); }
                else promise->set_value(fn());
            } catch (...) { promise->set_exception(std::current_exception()); }
        });
        return await(future);
    }
    std::shared_ptr<yume::providers::AsioExecutionContext> context;
    std::atomic<unsigned> exceptions{0U};
private:
    std::thread thread_;
};

class Handler final : public StreamHandler {
public:
    explicit Handler(ServiceKind kind = ServiceKind::ByteStream)
        : descriptor_(take(ProviderDescriptor::create("native-test.stream",
            ProviderKind::StreamHandler, 1U,
            mandatory_capabilities(ProviderKind::StreamHandler).with(Capability::PacketChannels)))),
          kind_(kind) {}
    const ProviderDescriptor& descriptor() const noexcept override { return descriptor_; }
    ServiceKind service_kind() const noexcept override { return kind_; }
    Status authorize(const StreamOpenContext&) override { return Status::success(); }
    void on_open(StreamOpenContext context, std::shared_ptr<StreamResponder> stream) override {
        CHECK(context.peer_evidence().credential_evidence().size() == 32U);
        ++opens;
        CHECK(accepted);
        accepted->set_value(std::move(stream));
        accepted.reset();
    }
    void async_open(StreamOpenContext context, std::shared_ptr<StreamResponder> stream,
                    AcceptanceCompletion completion) override {
        on_open(std::move(context), std::move(stream));
        if (hold_acceptance) deferred_acceptance = std::move(completion);
        else completion(Status::success());
    }
    std::shared_ptr<std::promise<std::shared_ptr<StreamResponder>>> accepted;
    bool hold_acceptance{false};
    AcceptanceCompletion deferred_acceptance;
    unsigned opens{0U};
private:
    ProviderDescriptor descriptor_;
    ServiceKind kind_;
};

yume::config::v1::Config load(const std::filesystem::path& file) {
    std::string text;
    CHECK(read_text_file_bounded(file, yume::config::v1::kMaxDocumentBytes, &text));
    return yume::config::v1::ParseJson(text);
}

std::vector<NativeServiceBinding> bindings(const std::shared_ptr<Handler>& handler) {
    return {{"echo", handler}, {"denied", handler}};
}

std::future<Result<std::shared_ptr<SessionEngine>>> start(
    Runner& runner, const std::shared_ptr<NativeEndpoint>& endpoint) {
    auto promise = std::make_shared<std::promise<Result<std::shared_ptr<SessionEngine>>>>();
    auto future = promise->get_future();
    runner.sync([endpoint, promise] {
        CHECK(endpoint->async_start_session([promise](auto result) { promise->set_value(std::move(result)); }).ok());
    });
    return future;
}

Result<std::shared_ptr<StreamResponder>> open_result(Runner& runner,
    const std::shared_ptr<SessionEngine>& session, std::string name) {
    auto promise = std::make_shared<std::promise<Result<std::shared_ptr<StreamResponder>>>>();
    auto future = promise->get_future();
    runner.sync([session, promise, name = std::move(name)] {
        session->async_open(name, ServiceKind::ByteStream,
            [promise](auto result) { promise->set_value(std::move(result)); });
    });
    return await(future);
}

std::shared_ptr<StreamResponder> open(Runner& runner,
    const std::shared_ptr<SessionEngine>& session, std::string name) {
    return take(open_result(runner, session, std::move(name)));
}

void transfer(Runner& runner, const std::shared_ptr<StreamResponder>& sender,
              const std::shared_ptr<StreamResponder>& receiver, std::string text) {
    auto read_promise = std::make_shared<std::promise<Result<ReceivedRecord>>>();
    auto write_promise = std::make_shared<std::promise<Status>>();
    auto read = read_promise->get_future();
    auto write = write_promise->get_future();
    runner.sync([sender, receiver, text, read_promise, write_promise] {
        receiver->async_read({}, [read_promise](auto result) { read_promise->set_value(std::move(result)); });
        sender->async_write(take(Buffer::copy_from(
            {reinterpret_cast<const std::byte*>(text.data()), text.size()}, text.size())), {},
            [write_promise, size = text.size()](Status status, std::size_t written) {
                if (status.ok() && written != size) status = Status(StatusCode::Internal);
                write_promise->set_value(std::move(status));
            });
    });
    CHECK(await(write).ok());
    auto record = take(await(read));
    CHECK(record.payload().size() == text.size());
    CHECK(std::equal(record.payload().bytes().begin(), record.payload().bytes().end(),
        reinterpret_cast<const std::byte*>(text.data())));
}

// Completes genuine TLS and H2 admission without constructing a client
// SessionEngine, so the server receives a promoted carrier but never AUTH.
class AdmissionOnlyClient final {
public:
    AdmissionOnlyClient(Runner& runner, const yume::config::v1::Config& config,
                        const std::filesystem::path& base)
        : runner_(runner),
          endpoint_(std::get<yume::config::v1::ClientEndpoint>(config.endpoint())),
          credentials_(take(load_native_credentials(config, base, endpoint_.host()))),
          tcp_(take(yume::providers::AsioTcpAcceptedChannelOwner::create(runner.context))),
          h2_(take(yume::providers::Ytp1H2CarrierProvider::create(runner.context->affinity(),
              {[context = runner.context](std::function<void()> task) {
                   boost::asio::post(context->executor(), std::move(task));
               },
               [context = runner.context](yume::providers::ControlTask& task,
                                          std::shared_ptr<void> owner) noexcept {
                   context->submit(task, std::move(owner));
               }},
              {endpoint_.host(), endpoint_.port(), {}}, credentials_.admission_key.bytes()))) {}

    std::future<Result<std::unique_ptr<Carrier>>> promote() {
        auto promise = std::make_shared<std::promise<Result<std::unique_ptr<Carrier>>>>();
        auto promoted = promise->get_future();
        runner_.sync([&] {
            yume::providers::AsioTcpSocket socket(runner_.context->executor());
            socket.connect({boost::asio::ip::address_v4::loopback(), endpoint_.port()});
            auto channel = take(tcp_->adopt(std::move(socket)));
            credentials_.tls_provider->async_wrap(std::move(channel), EndpointRole::Client, {},
                [h2 = h2_, promise](Result<std::unique_ptr<SecureChannel>> secure) {
                    if (!secure.ok()) {
                        promise->set_value(Result<std::unique_ptr<Carrier>>(secure.status()));
                        return;
                    }
                    h2->async_create(std::move(secure).take_value(), EndpointRole::Client, {},
                        [promise](auto result) { promise->set_value(std::move(result)); });
                });
        });
        return promoted;
    }

private:
    Runner& runner_;
    yume::config::v1::ClientEndpoint endpoint_;
    LoadedNativeCredentials credentials_;
    std::shared_ptr<yume::providers::AsioTcpAcceptedChannelOwner> tcp_;
    std::shared_ptr<yume::providers::Ytp1H2CarrierProvider> h2_;
};

// With max_sessions 1, a second session of the same identity replaces the
// first instead of being refused, and the replaced one ends with
// ResourceExhausted. The newest session keeps working.
void test_identity_session_replacement(const std::filesystem::path& kit) {
    Runner runner;
    auto handler = std::make_shared<Handler>();
    NativeEndpointOptions server_options;
    server_options.max_sessions = 4U;
    server_options.max_pending_starts = 1U;
    std::promise<Status> first_ended;
    auto first_reason = first_ended.get_future();
    std::shared_ptr<SessionEngine> first;
    server_options.session_ended = [&](std::shared_ptr<SessionEngine> session, Status reason) {
        if (session == first) first_ended.set_value(std::move(reason));
    };
    auto server = runner.sync([&] {
        return take(NativeEndpoint::create(runner.context, load(kit / "server/single-session.json"),
            kit / "server", bindings(handler), server_options));
    });
    std::vector<std::shared_ptr<NativeEndpoint>> clients;
    std::vector<std::shared_ptr<SessionEngine>> client_sessions;
    for (int index = 0; index < 2; ++index) {
        NativeEndpointOptions client_options;
        client_options.max_sessions = client_options.max_pending_starts = 1U;
        client_options.connection_address = "127.0.0.1";
        clients.push_back(runner.sync([&] { return take(NativeEndpoint::create(runner.context,
            load(kit / "client/yume.json"), kit / "client", bindings(handler), client_options)); }));
        auto accepting = start(runner, server);
        auto connecting = start(runner, clients.back());
        auto accepted = take(await(accepting));
        client_sessions.push_back(take(await(connecting)));
        if (index == 0) runner.sync([&] { first = accepted; });
        else CHECK(accepted->state() == SessionState::Active);
    }
    const auto reason = await(first_reason);
    CHECK(reason.code() == StatusCode::ResourceExhausted);
    CHECK(client_sessions[1]->state() == SessionState::Active);
    runner.sync([&] {
        for (const auto& client : clients) client->close();
        server->close();
        first.reset();
    });
    runner.finish_and_join();
    CHECK(runner.exceptions.load() == 0U);
}

// A configured egress rate paces the stream a handler receives, in both
// directions. At one byte per microsecond each 100'000-byte record after the
// first waits about 100 ms, so four records need at least 300 ms each way.
// Unpaced, they cross loopback in a few milliseconds.
void test_egress_pacing(const std::filesystem::path& kit) {
    Runner runner;
    auto handler = std::make_shared<Handler>();
    NativeEndpointOptions server_options;
    server_options.max_sessions = 1U;
    server_options.max_pending_starts = 1U;
    auto server = runner.sync([&] { return take(NativeEndpoint::create(runner.context,
        load(kit / "server/paced.json"), kit / "server", bindings(handler), server_options)); });
    NativeEndpointOptions client_options;
    client_options.max_sessions = client_options.max_pending_starts = 1U;
    client_options.connection_address = "127.0.0.1";
    auto client = runner.sync([&] { return take(NativeEndpoint::create(runner.context,
        load(kit / "client/yume.json"), kit / "client", bindings(handler), client_options)); });
    auto accepting = start(runner, server);
    auto connecting = start(runner, client);
    auto accepted = take(await(accepting));
    auto session = take(await(connecting));
    auto served_promise = std::make_shared<std::promise<std::shared_ptr<StreamResponder>>>();
    auto served_future = served_promise->get_future();
    runner.sync([&] { handler->accepted = served_promise; });
    auto opened = open(runner, session, "echo");
    auto served = await(served_future);
    const std::string record(100'000U, 'y');
    const auto started = std::chrono::steady_clock::now();
    for (int index = 0; index < 4; ++index) transfer(runner, served, opened, record);
    const auto sent = std::chrono::steady_clock::now();
    CHECK(sent - started >= 300ms);
    for (int index = 0; index < 4; ++index) transfer(runner, opened, served, record);
    CHECK(std::chrono::steady_clock::now() - sent >= 300ms);
    runner.sync([&] {
        client->close();
        server->close();
        accepted.reset();
    });
    runner.finish_and_join();
    CHECK(runner.exceptions.load() == 0U);
}

// Reload applies new grants to an established session's next OPEN, refuses a
// malformed store without changing anything, and ends a removed identity's
// session while the endpoint keeps serving.
void test_credential_reload(const std::filesystem::path& kit) {
    const auto store_path = kit / "server/credentials/authorized-keys.json";
    std::string original;
    CHECK(read_text_file_bounded(store_path, yume::config::v1::kMaxDocumentBytes, &original));
    const auto write_store = [&](const std::string& text) {
        std::ofstream output(store_path, std::ios::binary | std::ios::trunc);
        output << text;
        CHECK(static_cast<bool>(output));
    };
    struct Restore final {
        std::function<void()> restore;
        ~Restore() { restore(); }
    } restore{[&] { write_store(original); }};

    // Owned by the callback, which can outlive this frame while a failed
    // check unwinds and the runner drains.
    struct Observed final {
        std::shared_ptr<SessionEngine> accepted;
        std::promise<Status> ended;
        bool reported{false};
    };
    const auto observed = std::make_shared<Observed>();
    auto accepted_reason = observed->ended.get_future();
    Runner runner;
    auto handler = std::make_shared<Handler>();
    NativeEndpointOptions server_options;
    server_options.max_sessions = 2U;
    server_options.max_pending_starts = 1U;
    server_options.session_ended = [observed](std::shared_ptr<SessionEngine> session, Status reason) {
        if (session && session == observed->accepted && !std::exchange(observed->reported, true))
            observed->ended.set_value(std::move(reason));
    };
    auto server = runner.sync([&] { return take(NativeEndpoint::create(runner.context,
        load(kit / "server/yumed.json"), kit / "server", bindings(handler), server_options)); });
    NativeEndpointOptions client_options;
    client_options.max_sessions = client_options.max_pending_starts = 1U;
    client_options.connection_address = "127.0.0.1";
    auto client = runner.sync([&] { return take(NativeEndpoint::create(runner.context,
        load(kit / "client/yume.json"), kit / "client", bindings(handler), client_options)); });
    auto accepting = start(runner, server);
    auto connecting = start(runner, client);
    auto established = take(await(accepting));
    auto session = take(await(connecting));
    runner.sync([&] { observed->accepted = established; });
    // The test handler accepts one armed open at a time.
    const auto opens = [&](std::string name) {
        runner.sync([&] {
            handler->accepted = std::make_shared<std::promise<std::shared_ptr<StreamResponder>>>();
        });
        return open_result(runner, session, std::move(name)).ok();
    };
    CHECK(opens("echo"));
    CHECK(!opens("denied"));

    // Grants move from echo to denied for the established session.
    auto store = nlohmann::json::parse(original);
    CHECK(store["keys"].size() == 2U && store["keys"][0]["name"] == "client1");
    store["keys"][0]["capabilities"] = nlohmann::json::array(
        {{{"service", "denied"}, {"kind", "stream"}}});
    write_store(store.dump());
    CHECK(runner.sync([&] { return server->reload_credentials(); }).ok());
    CHECK(!opens("echo"));
    CHECK(opens("denied"));
    CHECK(session->state() == SessionState::Active);

    // A malformed store changes nothing.
    write_store("{");
    CHECK(!runner.sync([&] { return server->reload_credentials(); }).ok());
    CHECK(opens("denied"));

    // Removing the identity ends its session. The endpoint keeps serving.
    store["keys"].erase(0U);
    write_store(store.dump());
    CHECK(runner.sync([&] { return server->reload_credentials(); }).ok());
    CHECK(await(accepted_reason).code() == StatusCode::PermissionDenied);
    CHECK(runner.sync([&] { return client->reload_credentials(); }).code() ==
          StatusCode::FailedPrecondition);
    runner.sync([&] {
        client->close();
        server->close();
        observed->accepted.reset();
    });
    runner.finish_and_join();
    CHECK(runner.exceptions.load() == 0U);
}

// A client whose system lookup never returns. Endpoint close ends the lookup
// by ending its helper process, so the start settles and the final drain does
// not wait for the stalled system call.
void test_stalled_lookup_close(const std::filesystem::path& kit) {
    Runner runner;
    auto handler = std::make_shared<Handler>();
    NativeEndpointOptions options;
    options.max_sessions = options.max_pending_starts = 1U;
    options.connection_address = "resolver-stall.invalid";
    yume::providers::SystemResolverOptions resolver;
    resolver.program = YUME_TEST_STALL_RESOLVER_PROGRAM;
    auto endpoint = runner.sync([&] {
        options.resolver = take(yume::providers::SystemResolver::create(runner.context, resolver));
        return take(NativeEndpoint::create(runner.context, load(kit / "client/yume.json"),
            kit / "client", bindings(handler), options));
    });
    auto starting = start(runner, endpoint);
    CHECK(starting.wait_for(200ms) == std::future_status::timeout);
    const auto closed_at = std::chrono::steady_clock::now();
    endpoint->close();
    auto settled = await(starting);
    CHECK(!settled.ok());
    runner.finish_and_join();
    CHECK(std::chrono::steady_clock::now() - closed_at < 2s);
    CHECK(runner.exceptions.load() == 0U);
}

void test_start_deadline_and_final_drain(const std::filesystem::path& kit) {
    Runner runner;
    const auto config = load(kit / "server/yumed.json");
    auto handler = std::make_shared<Handler>();
    NativeEndpointOptions options;
    options.max_sessions = 1U;
    options.max_pending_starts = 1U;
    options.start_timeout = 40ms;
    const auto invalid_queue = load(kit / "server/invalid-queue.json");
    runner.sync([&] {
        const auto invalid = NativeEndpoint::create(runner.context, invalid_queue,
            kit / "server", bindings(handler), options);
        CHECK(!invalid.ok() && invalid.status().code() == StatusCode::InvalidArgument);
    });
    const auto dual_config = load(kit / "client/dual-kind.json");
    auto packet_handler = std::make_shared<Handler>(ServiceKind::PacketChannel);
    // The kit's client dials its server by name, which needs a resolver.
    auto dual = runner.sync([&] {
        CHECK(NativeEndpoint::create(runner.context, dual_config, kit / "client",
            {{"echo", handler}, {"echo", packet_handler}}, options).status().code() ==
              StatusCode::InvalidArgument);
        auto named = options;
        yume::providers::SystemResolverOptions resolver;
        resolver.program = YUME_TEST_RESOLVER_PROGRAM;
        named.resolver = take(yume::providers::SystemResolver::create(runner.context, resolver));
        return take(NativeEndpoint::create(runner.context, dual_config, kit / "client",
            {{"echo", handler}, {"echo", packet_handler}}, named));
    });
    dual->close();
    auto endpoint = runner.sync([&] { return take(NativeEndpoint::create(
        runner.context, config, kit / "server", bindings(handler), options)); });
    auto first = start(runner, endpoint);
    CHECK(first.wait_for(120ms) == std::future_status::timeout);
    runner.sync([&] {
        CHECK(endpoint->async_start_session([](auto) {}).code() == StatusCode::ResourceExhausted);
    });
    endpoint->close();
    auto cancelled = await(first);
    CHECK(!cancelled.ok() && cancelled.status().code() == StatusCode::Closed);
    runner.sync([] {}); // Drain the listener close before rebinding below.

    // An inert loopback TCP listener accepts a dial in the kernel but sends no
    // TLS. Client startup still has one absolute deadline, and a completed
    // timeout releases capacity for a later start.
    const auto client_config = load(kit / "client/yume.json");
    const auto port = std::get<yume::config::v1::ClientEndpoint>(client_config.endpoint()).port();
    boost::asio::ip::tcp::acceptor inert(runner.context->executor());
    runner.sync([&] {
        inert.open(boost::asio::ip::tcp::v4());
        inert.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
        inert.bind({boost::asio::ip::address_v4::loopback(), port});
        inert.listen();
    });
    options.connection_address = "127.0.0.1";
    auto client = runner.sync([&] { return take(NativeEndpoint::create(
        runner.context, client_config, kit / "client", bindings(handler), options)); });
    auto connecting = start(runner, client);
    const auto timed_out = await(connecting);
    CHECK(!timed_out.ok() && timed_out.status().code() == StatusCode::Cancelled);
    CHECK(timed_out.status().message() == "native session start deadline expired");
    auto second = start(runner, client);
    client->close();
    CHECK(!await(second).ok());
    runner.sync([&] { inert.close(); });
    runner.finish_and_join();
    client.reset();
    endpoint.reset();
    dual.reset();
    CHECK(runner.context->poll() == 0U);
    CHECK(runner.exceptions.load() == 0U);
}

void test_promoted_server_auth_deadline(const std::filesystem::path& kit) {
    Runner runner;
    const auto server_config = load(kit / "server/yumed.json");
    const auto client_config = load(kit / "client/yume.json");
    auto handler = std::make_shared<Handler>();
    NativeEndpointOptions options;
    options.max_sessions = 1U;
    options.max_pending_starts = 1U;
    options.start_timeout = 300ms;
    unsigned ended = 0U;
    options.session_ended = [&](auto, Status) { ++ended; };
    auto server = runner.sync([&] { return take(NativeEndpoint::create(
        runner.context, server_config, kit / "server", bindings(handler), options)); });
    auto accepting = start(runner, server);
    CHECK(accepting.wait_for(400ms) == std::future_status::timeout);

    // Complete genuine TLS and H2 admission, but deliberately never construct
    // a client SessionEngine or send AUTH. Promotion must start the server's
    // deadline even after an idle accept outlived that same budget.
    AdmissionOnlyClient admission(runner, client_config, kit / "client");
    auto promoted = admission.promote();
    auto carrier = take(await(promoted));
    auto expired = await(accepting);
    CHECK(!expired.ok() && expired.status().code() == StatusCode::Cancelled);
    CHECK(expired.status().message() == "native session start deadline expired");
    auto replacement = start(runner, server);
    CHECK(replacement.wait_for(400ms) == std::future_status::timeout);
    carrier->close();
    server->close();
    auto closed = await(replacement);
    CHECK(!closed.ok() && closed.status().code() == StatusCode::Closed);
    runner.finish_and_join();
    CHECK(ended == 0U); // Failed starts have no published session to end.
    carrier.reset();
    server.reset();
    CHECK(runner.context->poll() == 0U);
    CHECK(runner.exceptions.load() == 0U);
}

void test_unanswered_rekey_watchdog(const std::filesystem::path& kit) {
    Runner server_runner;
    Runner client_runner;
    NativeEndpointOptions options;
    options.max_sessions = 1U;
    options.max_pending_starts = 1U;
    options.start_timeout = 5s;
    auto server = server_runner.sync([&] {
        return take(NativeEndpoint::create(server_runner.context,
            load(kit / "server/yumed.json"), kit / "server",
            bindings(std::make_shared<Handler>()), options));
    });
    struct EndEvidence final {
        std::promise<std::chrono::steady_clock::time_point> completion;
        std::atomic<unsigned> count{0U};
        std::atomic<StatusCode> code{StatusCode::Internal};
    };
    auto ended = std::make_shared<EndEvidence>();
    auto ended_future = ended->completion.get_future();
    options.connection_address = "127.0.0.1";
    options.rekey_ack_timeout = 200ms;
    options.session_ended = [ended](auto, Status reason) {
        ended->code = reason.code();
        if (ended->count.fetch_add(1U) == 0U)
            ended->completion.set_value(std::chrono::steady_clock::now());
    };
    auto client = client_runner.sync([&] {
        return take(NativeEndpoint::create(client_runner.context,
            load(kit / "client/yume.json"), kit / "client",
            bindings(std::make_shared<Handler>()), options));
    });
    auto accepting = start(server_runner, server);
    auto connecting = start(client_runner, client);
    auto client_session = take(await(connecting));
    auto server_session = take(await(accepting));

    std::binary_semaphore paused{0};
    std::binary_semaphore resume{0};
    auto resumed = std::make_shared<std::promise<void>>();
    auto resumed_future = resumed->get_future();
    boost::asio::post(server_runner.context->executor(), [&paused, &resume, resumed] {
        paused.release();
        resume.acquire();
        resumed->set_value();
    });
    struct ResumePeer final {
        std::binary_semaphore& resume;
        std::future<void> finished;
        bool released{false};
        void release() noexcept {
            if (!released) { released = true; resume.release(); }
            finished.wait();
        }
        ~ResumePeer() noexcept { release(); }
    } resume_peer{resume, std::move(resumed_future)};
    CHECK(paused.try_acquire_for(2s));
    // Start between idle watchdog polls. The timer must move to the pending
    // deadline at the next poll, without granting a second timeout interval.
    std::this_thread::sleep_for(220ms);
    const auto deadline = client_runner.sync([&] {
        CHECK(client_session->initiate_rekey().ok());
        const auto value = client_session->rekey_deadline();
        CHECK(value);
        return *value;
    });
    const auto closed_at = await(ended_future);
    CHECK(closed_at >= deadline);
    CHECK(closed_at - deadline < 500ms);
    CHECK(ended->code.load() == StatusCode::FailedPrecondition);
    CHECK(client_session->state() == SessionState::Failed);
    CHECK(!client_session->rekey_deadline());
    resume_peer.release();
    server_runner.sync([&] { server_session->stop(); server->close(); });
    client_runner.sync([&] { client->close(); });
    server_runner.finish_and_join();
    client_runner.finish_and_join();
    CHECK(ended->count.load() == 1U);
    CHECK(server_runner.context->poll() == 0U);
    CHECK(client_runner.context->poll() == 0U);
    CHECK(server_runner.exceptions.load() == 0U);
    CHECK(client_runner.exceptions.load() == 0U);
}

std::shared_ptr<SessionEngine> connect_eventually(Runner& runner,
    const std::shared_ptr<NativeEndpoint>& client);

void test_session_ended_notifications(const std::filesystem::path& kit) {
    Runner runner;
    auto server_handler = std::make_shared<Handler>();
    auto client_handler = std::make_shared<Handler>();
    using Session = std::shared_ptr<SessionEngine>;
    std::array<std::shared_ptr<NativeEndpoint>, 2> endpoints;
    std::array<Session, 2> sessions;
    std::array<std::weak_ptr<SessionEngine>, 2> retired;
    std::array<unsigned, 2> notices{};
    std::array<bool, 2> on_context{};
    std::array<StatusCode, 2> reasons{};
    std::array<StatusCode, 2> start_status{};
    std::array<std::promise<Result<Session>>, 2> replacement;
    auto next_server = replacement[0].get_future();
    auto next_client = replacement[1].get_future();
    std::array<std::promise<void>, 2> closed;
    auto server_closed = closed[0].get_future();
    auto client_closed = closed[1].get_future();
    unsigned reads = 0U;
    bool read_settled_first = false;
    struct Drain final {
        Runner& runner;
        std::array<std::shared_ptr<NativeEndpoint>, 2>& endpoints;
        ~Drain() {
            for (const auto& endpoint : endpoints) if (endpoint) endpoint->close();
            runner.finish_and_join();
        }
    } drain{runner, endpoints};

    runner.sync([&] {
        for (std::size_t index = 0; index < endpoints.size(); ++index) {
            NativeEndpointOptions options;
            options.max_sessions = options.max_pending_starts = 1U;
            options.connection_address = index == 1U ? "127.0.0.1" : "";
            options.session_ended = [&, index](Session session, Status reason) {
                on_context[index] = runner.context->running_in_this_thread();
                reasons[index] = reason.code();
                CHECK(session == sessions[index]);
                ++notices[index];
                if (notices[index] == 1U) {
                    if (index == 1U) read_settled_first = reads == 1U;
                    // A retained engine also retains its carrier's admission
                    // reservation. Drop the old owner before replacement I/O.
                    retired[index] = sessions[index];
                    sessions[index].reset();
                    // Capacity must be released before calling the observer.
                    auto status = endpoints[index]->async_start_session([&, index](auto result) {
                        replacement[index].set_value(std::move(result));
                    });
                    start_status[index] = status.code();
                    if (!status.ok()) replacement[index].set_value(Result<Session>(std::move(status)));
                    throw std::runtime_error("session-ended callback exception");
                }
                closed[index].set_value();
            };
            const auto role = index == 0U ? "server" : "client";
            endpoints[index] = take(NativeEndpoint::create(runner.context,
                load(kit / role / (index == 0U ? "yumed.json" : "yume.json")), kit / role,
                bindings(index == 0U ? server_handler : client_handler), std::move(options)));
        }
    });
    auto accepting = start(runner, endpoints[0]);
    auto connecting = start(runner, endpoints[1]);
    sessions[0] = take(await(accepting));
    sessions[1] = take(await(connecting));
    auto remote_promise = std::make_shared<std::promise<std::shared_ptr<StreamResponder>>>();
    auto remote_open = remote_promise->get_future();
    runner.sync([&] { server_handler->accepted = remote_promise; });
    auto local = open(runner, sessions[1], "echo");
    auto remote = await(remote_open);
    transfer(runner, local, remote, "before session closure");
    runner.sync([&] {
        local->async_read({}, [&](auto result) {
            if (!result.ok() && result.status().code() == StatusCode::Cancelled) ++reads;
        });
        // Keep the event loop here while a different thread stops the engine.
        // Delivery must wait for the context even though teardown has finished.
        sessions[0]->stop(Status(StatusCode::Closed));
        std::thread stopping([session = sessions[1]] { session->stop(); });
        stopping.join();
        CHECK(notices[1] == 0U && reads == 1U);
        CHECK(endpoints[1]->async_start_session([](auto) {}).code() == StatusCode::ResourceExhausted);
    });
    auto first_attempt = await(next_client);
    // The endpoint slot is free, but old carrier cancellation and front-door
    // admission still settle asynchronously. Retry a refused admission through
    // the same bounded helper used by the accept-loop tests.
    auto client_replacement = first_attempt.ok() ? take(std::move(first_attempt))
                                               : connect_eventually(runner, endpoints[1]);
    auto server_replacement = take(await(next_server));
    runner.sync([&] {
        CHECK(notices[0] == 1U && notices[1] == 1U);
        CHECK(start_status[0] == StatusCode::Ok && start_status[1] == StatusCode::Ok);
        CHECK(on_context[0] && on_context[1] && read_settled_first);
        CHECK(reasons[1] == StatusCode::Cancelled);
        CHECK(retired[0].expired() && retired[1].expired());
        sessions = {server_replacement, client_replacement};
    });
    remote_promise = std::make_shared<std::promise<std::shared_ptr<StreamResponder>>>();
    remote_open = remote_promise->get_future();
    runner.sync([&] { server_handler->accepted = remote_promise; });
    local = open(runner, sessions[1], "echo");
    remote = await(remote_open);
    transfer(runner, local, remote, "replacement after observer exception");
    runner.sync([&] {
        for (const auto& endpoint : endpoints) endpoint->close();
    });
    await(server_closed);
    await(client_closed);
    runner.finish_and_join();
    CHECK(notices[0] == 2U && notices[1] == 2U);
    CHECK(on_context[0] && on_context[1]);
    CHECK(reasons[0] == StatusCode::Closed && reasons[1] == StatusCode::Closed);
    CHECK(runner.exceptions.load() == 0U);
    endpoints = {};
    sessions = {};
    CHECK(runner.context->poll() == 0U);
}

// A client or admission that races the server's next accept retry receives
// cover and tries again. Only eventual acceptance is asserted, not timing.
std::shared_ptr<SessionEngine> connect_eventually(Runner& runner,
    const std::shared_ptr<NativeEndpoint>& client) {
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    for (;;) {
        auto attempt = start(runner, client);
        auto result = await(attempt);
        if (result.ok()) return std::move(result).take_value();
        CHECK(std::chrono::steady_clock::now() < deadline);
        std::this_thread::sleep_for(10ms);
    }
}

std::unique_ptr<Carrier> promote_eventually(AdmissionOnlyClient& admission) {
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    for (;;) {
        auto attempt = admission.promote();
        auto result = await(attempt);
        if (result.ok()) return std::move(result).take_value();
        CHECK(std::chrono::steady_clock::now() < deadline);
        std::this_thread::sleep_for(10ms);
    }
}

void test_accept_loop(const std::filesystem::path& kit) {
    Runner runner;
    const auto server_config = load(kit / "server/yumed.json");
    const auto client_config = load(kit / "client/yume.json");
    auto server_handler = std::make_shared<Handler>();
    auto client_handler = std::make_shared<Handler>();
    NativeEndpointOptions options;
    options.max_sessions = 1U;
    options.max_pending_starts = 1U;
    options.start_timeout = 5s;
    auto server = runner.sync([&] { return take(NativeEndpoint::create(runner.context,
        server_config, kit / "server", bindings(server_handler), options)); });
    options.connection_address = "127.0.0.1";
    auto client = runner.sync([&] { return take(NativeEndpoint::create(runner.context,
        client_config, kit / "client", bindings(client_handler), options)); });
    auto other = runner.sync([&] { return take(NativeEndpoint::create(runner.context,
        client_config, kit / "client", bindings(client_handler), options)); });
    unsigned failures = 0U; // Written on the runner, read after its drain.
    const NativeEndpoint::AcceptFailure count_failure = [&failures](Status) { ++failures; };
    NativeAcceptOptions accept;
    accept.retry_delay = 20ms;
    runner.sync([&] {
        CHECK(client->start_accepting(accept, count_failure).code() == StatusCode::InvalidArgument);
        CHECK(server->start_accepting(accept, {}).code() == StatusCode::InvalidArgument);
        auto oversized = accept;
        oversized.pending_per_listener = 2U;
        CHECK(server->start_accepting(oversized, count_failure).code() == StatusCode::InvalidArgument);
        auto immediate = accept;
        immediate.retry_delay = 0ms;
        CHECK(server->start_accepting(immediate, count_failure).code() == StatusCode::InvalidArgument);
        auto slow = accept;
        slow.retry_delay = 11s;
        CHECK(server->start_accepting(slow, count_failure).code() == StatusCode::InvalidArgument);
    });

    // A pending manual accept excludes the loop. Its session then holds the
    // only slot, so the loop starts with its accept refused and retried.
    auto manual = start(runner, server);
    runner.sync([&] {
        CHECK(server->start_accepting(accept, count_failure).code() == StatusCode::FailedPrecondition);
    });
    auto connecting = start(runner, client);
    auto first = take(await(connecting));
    auto first_server = take(await(manual));
    runner.sync([&] {
        CHECK(server->start_accepting(accept, count_failure).ok());
        CHECK(server->start_accepting(accept, count_failure).code() == StatusCode::FailedPrecondition);
        CHECK(server->async_start_session([](auto) {}).code() == StatusCode::FailedPrecondition);
    });
    auto refused = start(runner, other);
    CHECK(!await(refused).ok());

    // Ending that session frees the slot for a later retry. An engine keeps its
    // promoted carrier and admission reservation until destroyed, so release
    // the test's handles on the runner before ending each session.
    runner.sync([&] {
        first_server.reset();
        first->stop(Status(StatusCode::Closed));
    });
    auto second = connect_eventually(runner, other);
    auto remote_promise = std::make_shared<std::promise<std::shared_ptr<StreamResponder>>>();
    auto remote_future = remote_promise->get_future();
    runner.sync([&] { server_handler->accepted = remote_promise; });
    auto local = open(runner, second, "echo");
    auto remote = await(remote_future);
    transfer(runner, local, remote, "accepted by the endpoint loop");

    // A promoted carrier that never authenticates fails its start. The loop
    // re-arms, and a genuine client is accepted afterwards.
    runner.sync([&] {
        local.reset();
        remote.reset();
        second->stop(Status(StatusCode::Closed));
    });
    AdmissionOnlyClient admission(runner, client_config, kit / "client");
    auto silent = promote_eventually(admission);
    silent->close();
    auto third = connect_eventually(runner, client);
    CHECK(third->state() == SessionState::Active);

    // The full endpoint closes with its slot retry outstanding.
    client->close();
    other->close();
    server->close();
    runner.finish_and_join();
    CHECK(failures == 0U);
    local.reset();
    remote.reset();
    silent.reset();
    client.reset();
    other.reset();
    server.reset();
    CHECK(runner.context->poll() == 0U);
    first.reset();
    first_server.reset();
    second.reset();
    third.reset();
    CHECK(runner.context->poll() == 0U);
    CHECK(runner.exceptions.load() == 0U);
}

#ifdef __linux__
// Every listener keeps its own pending accept. Linux routes all of 127/8 to
// loopback, so the second listener needs no host configuration.
void test_accept_loop_listeners(const std::filesystem::path& kit) {
    Runner runner;
    const auto server_config = load(kit / "server/two-listeners.json");
    const auto client_config = load(kit / "client/yume.json");
    auto handler = std::make_shared<Handler>();
    unsigned failures = 0U; // Written on the runner, read after its drain.
    const NativeEndpoint::AcceptFailure count_failure = [&failures](Status) { ++failures; };
    NativeEndpointOptions options;
    options.max_sessions = 2U;
    options.max_pending_starts = 1U;
    options.start_timeout = 5s;
    // One pending start cannot serve two listeners without starving one.
    auto undersized = runner.sync([&] { return take(NativeEndpoint::create(runner.context,
        server_config, kit / "server", bindings(handler), options)); });
    runner.sync([&] {
        CHECK(undersized->start_accepting({}, count_failure).code() == StatusCode::InvalidArgument);
    });
    undersized->close();
    runner.sync([] {}); // Drain the listener close before rebinding below.
    options.max_pending_starts = 2U;
    auto server = runner.sync([&] { return take(NativeEndpoint::create(runner.context,
        server_config, kit / "server", bindings(handler), options)); });
    runner.sync([&] { CHECK(server->start_accepting({}, count_failure).ok()); });
    std::vector<std::shared_ptr<NativeEndpoint>> clients;
    std::vector<std::shared_ptr<SessionEngine>> sessions;
    for (const auto* address : {"127.0.0.1", "127.0.0.2"}) {
        NativeEndpointOptions client_options;
        client_options.max_sessions = 1U;
        client_options.max_pending_starts = 1U;
        client_options.start_timeout = 5s;
        client_options.connection_address = address;
        clients.push_back(runner.sync([&] { return take(NativeEndpoint::create(runner.context,
            client_config, kit / "client", bindings(handler), client_options)); }));
        auto connecting = start(runner, clients.back());
        sessions.push_back(take(await(connecting)));
        CHECK(sessions.back()->state() == SessionState::Active);
    }
    for (const auto& client : clients) client->close();
    server->close();
    runner.finish_and_join();
    CHECK(failures == 0U);
    clients.clear();
    server.reset();
    undersized.reset();
    CHECK(runner.context->poll() == 0U);
    sessions.clear();
    CHECK(runner.context->poll() == 0U);
    CHECK(runner.exceptions.load() == 0U);
}
#endif

#ifdef YUME_TEST_WRAP_ACCEPT
// A failed OS accept closes the FrontDoor listener. The loop must report that
// once and close the endpoint instead of retrying a listener that is gone.
void test_accept_loop_listener_failure(const std::filesystem::path& kit) {
    Runner runner;
    const auto server_config = load(kit / "server/yumed.json");
    auto handler = std::make_shared<Handler>();
    NativeEndpointOptions options;
    options.max_sessions = 1U;
    options.max_pending_starts = 1U;
    auto server = runner.sync([&] { return take(NativeEndpoint::create(runner.context,
        server_config, kit / "server", bindings(handler), options)); });
    auto reported = std::make_shared<std::promise<Status>>();
    auto failure = reported->get_future();
    const auto port = runner.sync([&] {
        CHECK(server->start_accepting({}, [reported](Status status) {
            reported->set_value(std::move(status));
        }).ok());
        injected_accept_error = EMFILE;
        return server->listener_endpoint(0U).port();
    });
    boost::asio::io_context io;
    boost::asio::ip::tcp::socket probe(io);
    probe.connect({boost::asio::ip::address_v4::loopback(), port});
    const auto status = await(failure);
    CHECK(status.code() == StatusCode::Closed);
    runner.sync([&] {
        CHECK(injected_accept_error == 0);
        CHECK(server->async_start_session([](auto) {}).code() == StatusCode::Closed);
    });
    boost::system::error_code ignored;
    probe.close(ignored);
    runner.finish_and_join();
    server.reset();
    CHECK(runner.context->poll() == 0U);
    CHECK(runner.exceptions.load() == 0U);
}
#endif

#ifdef YUME_NATIVE_TEST_ROUTES
class ObservedRoutes final : public RouteProvider {
public:
    explicit ObservedRoutes(std::shared_ptr<RouteProvider> provider) : provider_(std::move(provider)) {}
    const ProviderDescriptor& descriptor() const noexcept override { return provider_->descriptor(); }
    void async_open(const AuthorizedRouteRequest& request, CancellationToken cancellation,
                    Completion completion) override {
        provider_->async_open(request, std::move(cancellation), std::move(completion));
    }
    void cancel() noexcept override { ++cancellations; provider_->cancel(); }
    unsigned cancellations{0U}; // Read and written on the native context, or after its drain.
private:
    std::shared_ptr<RouteProvider> provider_;
};

template <typename Protocol>
void test_destination_route(const std::filesystem::path& kit, bool declared) {
    using Tcp = boost::asio::ip::tcp;
    using namespace yume::providers;
    constexpr bool is_tcp = std::is_same_v<Protocol, Tcp>;
    constexpr auto protocol = is_tcp ? NetworkProtocol::Tcp : NetworkProtocol::Udp;
    constexpr auto kind = is_tcp ? ServiceKind::ByteStream : ServiceKind::PacketChannel;
    Runner runner;
    std::unique_ptr<Tcp::acceptor> destination;
    auto destination_socket = std::make_shared<typename Protocol::socket>(runner.context->executor());
    typename Protocol::endpoint sender;
    std::uint16_t port = 0U;
    auto accepted_promise = std::make_shared<std::promise<boost::system::error_code>>();
    auto accepted_future = accepted_promise->get_future();
    runner.sync([&] {
        if constexpr (is_tcp) {
            destination = std::make_unique<Tcp::acceptor>(runner.context->executor(),
                Tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0U));
            port = destination->local_endpoint().port();
            destination->async_accept(*destination_socket, [accepted_promise](auto error) {
                accepted_promise->set_value(error);
            });
        } else {
            destination_socket->open(Protocol::v4());
            destination_socket->bind({boost::asio::ip::address_v4::loopback(), 0U});
            port = destination_socket->local_endpoint().port();
            accepted_promise->set_value({});
        }
    });
    unsigned protected_sockets = 0U;
    unsigned request_checks = 0U;
    unsigned resolved_checks = 0U;
    bool throw_request = false;
    bool refuse_resolved = false;
    auto routes = runner.sync([&] { return std::make_shared<ObservedRoutes>(
        take(AsioDirectRouteProvider::create(runner.context,
        [port, &resolved_checks, &refuse_resolved](const AuthorizedRouteRequest& request,
                                                  const RouteDestination& resolved) {
            ++resolved_checks;
            CHECK(request.peer_evidence().credential_evidence().size() == 32U);
            CHECK(request.service_name() == "echo");
            const std::array<std::uint8_t, 4> loopback{127U, 0U, 0U, 1U};
            return !refuse_resolved && resolved.protocol() == protocol &&
                resolved.address_kind() == RouteAddressKind::Ipv4 && resolved.port() == port &&
                std::equal(resolved.address_bytes().begin(), resolved.address_bytes().end(),
                           loopback.begin(), loopback.end())
                ? Status::success() : Status(StatusCode::FailedPrecondition);
        }, {},
        [&protected_sockets](NativeSocket socket) {
            CHECK(socket.protocol == protocol);
            ++protected_sockets;
            return Status::success();
        }))); });
    auto capabilities = mandatory_capabilities(ProviderKind::StreamHandler)
        .with(is_tcp ? Capability::DirectTcp : Capability::DirectUdp);
    if constexpr (!is_tcp) capabilities = capabilities.with(Capability::PacketChannels);
    auto descriptor = take(ProviderDescriptor::create("native-test.route",
        ProviderKind::StreamHandler, 1U, capabilities));
    auto policy = [port, &request_checks, &throw_request](const StreamOpenContext& context) {
            ++request_checks;
            CHECK(context.peer_evidence().credential_evidence().size() == 32U);
            CHECK(context.service_name() == "echo");
            CHECK(context.service_kind() == kind);
            if (throw_request) throw std::runtime_error("test route policy failure");
            // This fixture authorizes exactly one numeric destination. A DNS
            // name or another address/port never reaches resolution or connect.
            const auto* route = context.destination_if();
            const std::array<std::uint8_t, 4> loopback{127U, 0U, 0U, 1U};
            return route && route->protocol() == protocol &&
                route->address_kind() == RouteAddressKind::Ipv4 && route->port() == port &&
                std::equal(route->address_bytes().begin(), route->address_bytes().end(),
                           loopback.begin(), loopback.end())
                ? Status::success() : Status(StatusCode::FailedPrecondition);
        };
    auto handler = take(DirectRouteHandler::create(std::move(descriptor),
        kind, policy));
    const auto server_config = load(kit / "server" /
        (declared ? (is_tcp ? "direct-tcp.json" : "direct-udp.json") : "yumed.json"));
    const auto client_config = load(kit / "client" / (is_tcp ? "yume.json" : "routes-udp.json"));
    const std::vector<NativeServiceBinding> server_bindings = declared
        ? std::vector<NativeServiceBinding>{}
        : std::vector<NativeServiceBinding>{{"echo", handler}, {"denied", handler}};
    NativeEndpointOptions server_options;
    server_options.max_sessions = 1U;
    server_options.max_pending_starts = 1U;
    runner.sync([&] {
        auto missing = NativeEndpoint::create(runner.context, server_config, kit / "server",
            server_bindings, server_options);
        CHECK(!missing.ok() && missing.status().code() == StatusCode::FailedPrecondition);
    });
    server_options.route_provider = routes;
    if (declared) {
        runner.sync([&] {
            // Configured destinations are the request authority. The application
            // callback is an optional further restriction.
            auto config_options = server_options;
            config_options.route_provider = take(AsioDirectRouteProvider::create(runner.context,
                [](const AuthorizedRouteRequest&, const RouteDestination&) {
                    return Status(StatusCode::PermissionDenied);
                }));
            auto config_only = NativeEndpoint::create(runner.context, server_config,
                kit / "server", server_bindings, std::move(config_options));
            CHECK(config_only.ok());
            config_only.value()->close();
        });
        runner.sync([] {}); // Drain that listener close before later binds.
        runner.sync([&] {
            server_options.route_authorization = policy;
            auto missing_provider_options = server_options;
            missing_provider_options.route_provider.reset();
            auto missing_provider = NativeEndpoint::create(runner.context, server_config,
                kit / "server", server_bindings, std::move(missing_provider_options));
            CHECK(!missing_provider.ok() &&
                missing_provider.status().code() == StatusCode::FailedPrecondition);
            auto conflict = NativeEndpoint::create(runner.context, server_config,
                kit / "server", {{"echo", handler}}, server_options);
            CHECK(!conflict.ok() && conflict.status().code() == StatusCode::InvalidArgument);
        });
    }
    runner.sync([&] {
        // Explicit composition fails after state construction; declarations
        // refuse duplicate ownership earlier. Neither adopts the route owner.
        auto invalid = NativeEndpoint::create(runner.context, server_config, kit / "server",
            {{"unknown", handler}, {"denied", handler}}, server_options);
        CHECK(!invalid.ok());
    });
    runner.sync([] {}); // Drain the failed candidate's reserved rollback task.
    CHECK(runner.sync([&] { return routes->cancellations; }) == 0U);
    auto server = runner.sync([&] { return take(NativeEndpoint::create(runner.context,
        server_config, kit / "server", server_bindings, server_options)); });
    runner.sync([&] {
        // Listener failure happens after graph construction, including for
        // generated handlers. Rollback cannot cancel the live provider.
        auto conflict = NativeEndpoint::create(runner.context, server_config,
            kit / "server", server_bindings, server_options);
        CHECK(!conflict.ok() && conflict.status().code() == StatusCode::AddressInUse);
    });
    runner.sync([] {});
    CHECK(runner.sync([&] { return routes->cancellations; }) == 0U);
    NativeEndpointOptions client_options;
    client_options.connection_address = "127.0.0.1";
    auto client_handler = std::make_shared<Handler>(kind);
    auto client = runner.sync([&] { return take(NativeEndpoint::create(runner.context,
        client_config, kit / "client", bindings(client_handler), client_options)); });
    auto server_start = start(runner, server);
    auto client_start = start(runner, client);
    auto client_session = take(await(client_start));
    auto server_session = take(await(server_start));
    auto open_route = [&](std::string name, RouteDestination route) {
        auto promise = std::make_shared<std::promise<Result<std::shared_ptr<StreamResponder>>>>();
        auto result = promise->get_future();
        runner.sync([&, promise, name = std::move(name), route = std::move(route)]() mutable {
            client_session->async_open(std::move(name), kind,
                std::move(route), [promise](auto value) { promise->set_value(std::move(value)); });
        });
        return await(result);
    };
    CHECK(!open_route("echo", take(RouteDestination::dns_name(protocol,
        "localhost", port))).ok());
    CHECK(!open_route("denied", take(RouteDestination::ipv4(protocol,
        {127U, 0U, 0U, 1U}, port))).ok());
    if (declared) {
        // 127.0.0.2 is outside the configured 127.0.0.1/32. Configuration
        // refuses it before the application policy, resolution or a socket.
        CHECK(!open_route("echo", take(RouteDestination::ipv4(protocol,
            {127U, 0U, 0U, 2U}, port))).ok());
    }
    runner.sync([&] {
        CHECK(request_checks == 1U); // Credential refusal preceded destination policy.
        CHECK(resolved_checks == 0U && protected_sockets == 0U);
        throw_request = true;
    });
    CHECK(!open_route("echo", take(RouteDestination::ipv4(protocol,
        {127U, 0U, 0U, 1U}, port))).ok());
    runner.sync([&] {
        CHECK(resolved_checks == 0U && protected_sockets == 0U);
        throw_request = false;
        refuse_resolved = true;
    });
    CHECK(!open_route("echo", take(RouteDestination::ipv4(protocol,
        {127U, 0U, 0U, 1U}, port))).ok());
    runner.sync([&] {
        CHECK(resolved_checks == 1U && protected_sockets == 0U);
        refuse_resolved = false;
    });
    auto stream = take(open_route("echo", take(RouteDestination::ipv4(protocol,
        {127U, 0U, 0U, 1U}, port))));
    CHECK(!await(accepted_future));
    CHECK(runner.sync([&] { return protected_sockets; }) == 1U);

    std::vector<ReceivedRecord> records;
    for (const std::string outbound : {"authenticated YTP destination bytes", "second message"}) {
        std::vector<char> received(outbound.size());
        auto destination_read = std::make_shared<std::promise<std::size_t>>();
        auto read_future = destination_read->get_future();
        auto stream_write = std::make_shared<std::promise<Status>>();
        auto write_future = stream_write->get_future();
        runner.sync([&] {
            auto complete = [destination_read](auto error, auto bytes) {
                destination_read->set_value(error ? 0U : bytes);
            };
            if constexpr (is_tcp) {
                boost::asio::async_read(*destination_socket, boost::asio::buffer(received), complete);
            } else {
                destination_socket->async_receive_from(boost::asio::buffer(received), sender, complete);
            }
            stream->async_write(take(Buffer::copy_from(
                {reinterpret_cast<const std::byte*>(outbound.data()), outbound.size()}, outbound.size())), {},
                [stream_write](Status status, auto) { stream_write->set_value(std::move(status)); });
        });
        CHECK(await(write_future).ok());
        CHECK(await(read_future) == outbound.size());
        CHECK(std::equal(received.begin(), received.end(), outbound.begin(), outbound.end()));
        std::size_t received_bytes = 0U;
        while (received_bytes != outbound.size()) {
            auto incoming = std::make_shared<std::promise<Result<ReceivedRecord>>>();
            auto incoming_future = incoming->get_future();
            runner.sync([&] {
                stream->async_read({}, [incoming](auto result) { incoming->set_value(std::move(result)); });
                if (received_bytes == 0U) {
                    auto complete = [](auto error, auto) { CHECK(!error); };
                    if constexpr (is_tcp) {
                        boost::asio::async_write(*destination_socket, boost::asio::buffer(outbound), complete);
                    } else {
                        destination_socket->async_send_to(boost::asio::buffer(outbound), sender, complete);
                    }
                }
            });
            auto record = take(await(incoming_future));
            CHECK(record.payload().size() > 0U);
            CHECK(record.payload().size() <= outbound.size() - received_bytes);
            if constexpr (!is_tcp) CHECK(record.payload().size() == outbound.size());
            CHECK(std::equal(record.payload().bytes().begin(), record.payload().bytes().end(),
                reinterpret_cast<const std::byte*>(outbound.data() + received_bytes)));
            received_bytes += record.payload().size();
            records.push_back(std::move(record));
        }
    }
    // Keep receive credit and route handles alive across endpoint shutdown;
    // releasing either after the final drain must not schedule new work.
    client->close();
    server->close();
    runner.sync([&] {
        destination_socket->close();
        if (destination) destination->close();
    });
    runner.finish_and_join();
    CHECK(routes->cancellations == 1U);
    stream.reset();
    records.clear();
    server.reset();
    client.reset();
    handler.reset();
    server_options.route_provider.reset();
    routes.reset();
    server_session.reset();
    client_session.reset();
    CHECK(runner.context->poll() == 0U);
    CHECK(runner.exceptions.load() == 0U);
}
#endif

// Keep acceptance under test control after the real session has authorized the
// destination. This isolates the local SOCKS deadline from network timeouts.
#ifdef YUME_NATIVE_TEST_ROUTES
class DelayedRouteHandler final : public StreamHandler {
public:
    DelayedRouteHandler()
        : descriptor_(take(ProviderDescriptor::create("native-test.delayed-route",
            ProviderKind::StreamHandler, 1U,
            mandatory_capabilities(ProviderKind::StreamHandler).with(Capability::DirectTcp)))) {}
    const ProviderDescriptor& descriptor() const noexcept override { return descriptor_; }
    ServiceKind service_kind() const noexcept override { return ServiceKind::ByteStream; }
    Status authorize(const StreamOpenContext& context) override {
        CHECK(context.peer_evidence().credential_evidence().size() == 32U);
        const auto* destination = context.destination_if();
        CHECK(destination && destination->protocol() == NetworkProtocol::Tcp);
        return Status::success();
    }
    void on_open(StreamOpenContext, std::shared_ptr<StreamResponder>) override {
        throw std::runtime_error("SOCKS CONNECT omitted its destination");
    }
    void async_route(AuthorizedRouteRequest request, std::shared_ptr<RouteProvider>,
                     std::shared_ptr<StreamResponder> stream,
                     AcceptanceCompletion completion) override {
        CHECK(accepted && !acceptance);
        last_port = request.destination().port();
        acceptance = std::move(completion);
        accepted->set_value(std::move(stream));
        accepted.reset();
    }
    std::shared_ptr<std::promise<std::shared_ptr<StreamResponder>>> accepted;
    AcceptanceCompletion acceptance;
    std::uint16_t last_port{0U};
private:
    ProviderDescriptor descriptor_;
};

// Bounded reads on the test client while Runner drives the native context.
std::size_t read_socket(boost::asio::ip::tcp::socket& socket, std::span<std::uint8_t> bytes) {
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    for (;;) {
        boost::system::error_code error;
        const auto size = socket.read_some(boost::asio::buffer(bytes.data(), bytes.size()), error);
        if (error == boost::asio::error::eof) return 0U;
        if (!error) return size;
        CHECK(error == boost::asio::error::would_block || error == boost::asio::error::try_again);
        CHECK(std::chrono::steady_clock::now() < deadline);
        std::this_thread::sleep_for(1ms);
    }
}

void check_socks_reply(boost::asio::ip::tcp::socket& socket, std::uint8_t code) {
    const std::array<std::uint8_t, 12> expected{5, 0, 5, code, 0, 1, 0, 0, 0, 0, 0, 0};
    std::array<std::uint8_t, 12> reply{};
    for (std::size_t offset = 0; offset < reply.size();) {
        const auto read = read_socket(socket, std::span(reply).subspan(offset));
        CHECK(read != 0U);
        offset += read;
    }
    if (reply != expected) {
        throw std::runtime_error("SOCKS CONNECT reply: expected " + std::to_string(code) +
                                 ", got " + std::to_string(reply[3]));
    }
}

void check_socket_closed(boost::asio::ip::tcp::socket& socket) {
    std::array<std::uint8_t, 1> byte{};
    CHECK(read_socket(socket, byte) == 0U);
}

std::string read_record_text(Runner& runner, const std::shared_ptr<StreamResponder>& stream) {
    auto promise = std::make_shared<std::promise<Result<ReceivedRecord>>>();
    auto future = promise->get_future();
    runner.sync([&] {
        stream->async_read({}, [promise](auto result) { promise->set_value(std::move(result)); });
    });
    auto record = take(await(future));
    return {reinterpret_cast<const char*>(record.payload().bytes().data()), record.payload().size()};
}

void write_record_text(Runner& runner, const std::shared_ptr<StreamResponder>& stream,
                       std::string text) {
    auto promise = std::make_shared<std::promise<Status>>();
    auto future = promise->get_future();
    runner.sync([&] {
        stream->async_write(take(Buffer::copy_from(
            {reinterpret_cast<const std::byte*>(text.data()), text.size()}, text.size())), {},
            [promise](Status status, std::size_t) { promise->set_value(std::move(status)); });
    });
    CHECK(await(future).ok());
}

// A SOCKS5 UDP datagram for an IPv4 destination.
std::vector<std::uint8_t> socks_datagram(const std::array<std::uint8_t, 4>& address,
                                         std::uint16_t port, std::string_view payload) {
    std::vector<std::uint8_t> bytes{0, 0, 0, 1, address[0], address[1], address[2], address[3],
        static_cast<std::uint8_t>(port >> 8U), static_cast<std::uint8_t>(port)};
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

// Polls a nonblocking UDP socket. Nothing within the wait is nullopt.
std::optional<std::vector<std::uint8_t>> receive_datagram(boost::asio::ip::udp::socket& socket,
    boost::asio::ip::udp::endpoint& sender, std::chrono::milliseconds wait) {
    std::vector<std::uint8_t> bytes(65'536U);
    const auto deadline = std::chrono::steady_clock::now() + wait;
    for (;;) {
        boost::system::error_code error;
        const auto size = socket.receive_from(boost::asio::buffer(bytes), sender, 0, error);
        if (!error) {
            bytes.resize(size);
            return bytes;
        }
        CHECK(error == boost::asio::error::would_block || error == boost::asio::error::try_again);
        if (std::chrono::steady_clock::now() >= deadline) return std::nullopt;
        std::this_thread::sleep_for(1ms);
    }
}

std::string text_of(const std::optional<std::vector<std::uint8_t>>& bytes) {
    return bytes ? std::string(bytes->begin(), bytes->end()) : std::string("<nothing>");
}

// Sends UDP ASSOCIATE announcing client_port and returns the control connection.
// The relay endpoint named by the success reply is written to relay.
boost::asio::ip::tcp::socket associate_udp(boost::asio::io_context& io,
    const boost::asio::ip::tcp::endpoint& adapter, std::uint16_t client_port,
    boost::asio::ip::udp::endpoint& relay) {
    boost::asio::ip::tcp::socket control(io);
    control.connect(adapter);
    const std::array<std::uint8_t, 13> request{5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0,
        static_cast<std::uint8_t>(client_port >> 8U), static_cast<std::uint8_t>(client_port)};
    boost::asio::write(control, boost::asio::buffer(request));
    control.non_blocking(true);
    std::array<std::uint8_t, 12> reply{};
    for (std::size_t offset = 0; offset < reply.size();) {
        const auto read = read_socket(control, std::span(reply).subspan(offset));
        CHECK(read != 0U);
        offset += read;
    }
    // Method selection, then success naming the IPv4 loopback relay socket.
    const std::array<std::uint8_t, 10> expected{5, 0, 5, 0, 0, 1, 127, 0, 0, 1};
    CHECK(std::equal(expected.begin(), expected.end(), reply.begin()));
    relay = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(),
        static_cast<std::uint16_t>((reply[10] << 8U) | reply[11]));
    CHECK(relay.port() != 0U);
    return control;
}

// Holds every authorized packet OPEN so a test decides when it is accepted.
class HeldPacketHandler final : public StreamHandler {
public:
    struct HeldOpen final {
        std::uint16_t port{0U};
        std::shared_ptr<StreamResponder> stream;
        AcceptanceCompletion completion;
    };

    HeldPacketHandler()
        : descriptor_(take(ProviderDescriptor::create("native-test.held-packet-route",
            ProviderKind::StreamHandler, 1U,
            mandatory_capabilities(ProviderKind::StreamHandler)
                .with(Capability::DirectUdp).with(Capability::PacketChannels)))) {}
    const ProviderDescriptor& descriptor() const noexcept override { return descriptor_; }
    ServiceKind service_kind() const noexcept override { return ServiceKind::PacketChannel; }
    Status authorize(const StreamOpenContext& context) override {
        const auto* destination = context.destination_if();
        CHECK(destination && destination->protocol() == NetworkProtocol::Udp);
        return Status::success();
    }
    void on_open(StreamOpenContext, std::shared_ptr<StreamResponder>) override {
        throw std::runtime_error("SOCKS UDP omitted its destination");
    }
    void async_route(AuthorizedRouteRequest request, std::shared_ptr<RouteProvider>,
                     std::shared_ptr<StreamResponder> stream,
                     AcceptanceCompletion completion) override {
        opens.push_back({request.destination().port(), std::move(stream), std::move(completion)});
        if (arrived && opens.size() >= expected) std::exchange(arrived, nullptr)->set_value();
    }
    std::vector<HeldOpen> opens;
    std::size_t expected{0U};
    std::shared_ptr<std::promise<void>> arrived;

private:
    ProviderDescriptor descriptor_;
};

// A session that ends right after AUTH counts as a failed attempt. Without
// backoff, a path that drops every connection after AUTH would make the client
// redial in a tight loop and fill the server's shared admission replay cache.
void test_client_short_session_backoff(const std::filesystem::path& kit) {
    using Clock = std::chrono::steady_clock;
    Runner runner;
    auto handler = std::make_shared<DelayedRouteHandler>();
    NativeEndpointOptions server_options;
    server_options.max_sessions = 2U;
    server_options.max_pending_starts = 1U;
    server_options.route_provider = runner.sync([&] {
        return take(yume::providers::AsioDirectRouteProvider::create(runner.context,
            [](const auto&, const auto&) { return Status(StatusCode::PermissionDenied); }));
    });
    auto server = runner.sync([&] {
        return take(NativeEndpoint::create(runner.context, load(kit / "server/yumed.json"),
            kit / "server", {{"echo", handler}, {"denied", handler}}, server_options));
    });
    constexpr auto backoff = 1s;
    std::vector<Clock::time_point> authenticated;
    std::vector<Clock::time_point> ended;
    std::promise<void> first_auth;
    std::promise<void> second_auth;
    auto first_ready = first_auth.get_future();
    auto second_ready = second_auth.get_future();
    auto client = runner.sync([&] {
        NativeClientRuntimeOptions options;
        options.reconnect_initial = backoff;
        // Every session here ends sooner than this, so each end backs off.
        options.reconnect_max = 60s;
        return take(NativeClientRuntime::create(runner.context,
            load(kit / "client/runtime-client.json"), kit / "client", [&](std::string_view message) {
                if (message == "session ended, reconnecting") ended.push_back(Clock::now());
                if (message != "session authenticated") return;
                authenticated.push_back(Clock::now());
                if (authenticated.size() == 1U) first_auth.set_value();
                if (authenticated.size() == 2U) second_auth.set_value();
            }, options));
    });
    auto accepting = start(runner, server);
    runner.sync([&] { CHECK(client->start().ok()); });
    auto first = take(await(accepting));
    await(first_ready);
    auto next_accept = start(runner, server);
    // End the session at once, as a path that resets it after AUTH would.
    runner.sync([&] {
        first->stop();
        first.reset();
    });
    auto second = take(await(next_accept));
    await(second_ready);
    runner.sync([&] {
        CHECK(authenticated.size() == 2U && ended.size() == 1U);
        CHECK(authenticated[1] - ended[0] >= backoff);
        second.reset();
        client->close();
        server->close();
    });
    runner.finish_and_join();
    CHECK(runner.exceptions.load() == 0U);
    client.reset();
    server.reset();
    CHECK(runner.context->poll() == 0U);
}

void test_client_reconnect(const std::filesystem::path& kit) {
    Runner runner;
    auto handler = std::make_shared<DelayedRouteHandler>();
    NativeEndpointOptions server_options;
    server_options.max_sessions = 2U;
    server_options.max_pending_starts = 1U;
    server_options.route_provider = runner.sync([&] {
        return take(yume::providers::AsioDirectRouteProvider::create(runner.context,
            [](const auto&, const auto&) { return Status(StatusCode::PermissionDenied); }));
    });
    auto server = runner.sync([&] {
        return take(NativeEndpoint::create(runner.context, load(kit / "server/yumed.json"),
            kit / "server", {{"echo", handler}, {"denied", handler}}, server_options));
    });
    unsigned authenticated = 0U;
    unsigned reconnecting = 0U;
    unsigned stopped = 0U;
    bool reports_on_context = true;
    std::promise<void> initial_auth;
    std::promise<void> replacement_auth;
    auto initial_ready = initial_auth.get_future();
    auto replacement_ready = replacement_auth.get_future();
    std::vector<NativeClientState> transitions;
    bool status_on_context = true;
    auto client = runner.sync([&] {
        NativeClientRuntimeOptions options;
        options.reconnect_initial = 50ms;
        options.reconnect_max = 100ms;
        options.on_status = [&](const NativeClientStatus& status) {
            status_on_context = status_on_context && runner.context->running_in_this_thread();
            transitions.push_back(status.state);
        };
        return take(NativeClientRuntime::create(runner.context,
            load(kit / "client/runtime-client.json"), kit / "client", [&](std::string_view message) {
                reports_on_context = reports_on_context && runner.context->running_in_this_thread();
                if (message == "session ended, reconnecting") ++reconnecting;
                if (message != "session authenticated") return;
                ++authenticated;
                if (authenticated == 1U) initial_auth.set_value();
                if (authenticated == 2U) replacement_auth.set_value();
            }, options, [&](Status) { ++stopped; }));
    });
    auto accepting = start(runner, server);
    runner.sync([&] { CHECK(client->start().ok()); });
    auto first = take(await(accepting));
    await(initial_ready);
    // status() is readable from this non-context thread.
    const NativeClientStatus connected = client->status();
    CHECK(connected.state == NativeClientState::Connected);
    CHECK(connected.sessions == 1U && connected.failed_attempts == 0U);
    CHECK(connected.server_identity.size() == 64U);
    CHECK(connected.traffic.record_bytes_sent > 0U && connected.traffic.payload_bytes_sent == 0U);
    const auto socks = runner.sync([&] { return client->socks5_endpoints().at(0); });
    boost::asio::io_context local_io;
    const auto connect_socks = [&] {
        boost::asio::ip::tcp::socket socket(local_io);
        socket.connect(socks);
        const std::array<std::uint8_t, 13> request{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 1, 187};
        boost::asio::write(socket, boost::asio::buffer(request));
        socket.non_blocking(true);
        return socket;
    };
    auto request = [&](std::string_view payload) {
        auto accepted = std::make_shared<std::promise<std::shared_ptr<StreamResponder>>>();
        auto opened = accepted->get_future();
        runner.sync([&] { handler->accepted = accepted; });
        auto socket = connect_socks();
        auto stream = await(opened);
        runner.sync([&] { std::exchange(handler->acceptance, {})(Status::success()); });
        check_socks_reply(socket, 0x00);
        auto received = std::make_shared<std::promise<Result<ReceivedRecord>>>();
        auto read = received->get_future();
        runner.sync([&] {
            stream->async_read({}, [received](auto result) { received->set_value(std::move(result)); });
        });
        boost::asio::write(socket, boost::asio::buffer(payload.data(), payload.size()));
        const auto record = take(await(read));
        CHECK(record.payload().size() == payload.size());
        CHECK(std::equal(record.payload().bytes().begin(), record.payload().bytes().end(),
                         reinterpret_cast<const std::byte*>(payload.data())));
        runner.sync([&] { stream->close(Status(StatusCode::Closed)); });
    };
    request("before reconnect");
    const NativeClientStatus before_reconnect = client->status();
    CHECK(before_reconnect.traffic.payload_bytes_sent >= std::string_view("before reconnect").size());
    // Keep the next accept ready. No wall-clock threshold is needed to prove
    // replacement authentication and that the existing SOCKS listener uses it.
    auto next_accept = start(runner, server);
    runner.sync([&] { first->stop(); });
    auto second = take(await(next_accept));
    await(replacement_ready);
    CHECK(second != first);
    request("after reconnect");
    // The configured UNIX forward opens on the replacement session too.
    CHECK(runner.sync([&] { return client->forward_endpoints().empty(); }));
    {
        auto accepted = std::make_shared<std::promise<std::shared_ptr<StreamResponder>>>();
        auto opened = accepted->get_future();
        runner.sync([&] { handler->accepted = accepted; });
        boost::asio::local::stream_protocol::socket local(local_io);
        local.connect(boost::asio::local::stream_protocol::endpoint(
            (kit / "client/forward.sock").string()));
        boost::asio::write(local, boost::asio::buffer("forwarded", 9U));
        auto stream = await(opened);
        CHECK(runner.sync([&] { return handler->last_port; }) == 2222U);
        runner.sync([&] { std::exchange(handler->acceptance, {})(Status::success()); });
        CHECK(read_record_text(runner, stream) == "forwarded");
        runner.sync([&] { stream->close(Status(StatusCode::Closed)); });
    }
    const NativeClientStatus replaced = client->status();
    CHECK(replaced.state == NativeClientState::Connected && replaced.sessions == 2U);
    CHECK(replaced.server_identity == connected.server_identity);
    CHECK(!replaced.last_failure.ok());
    // Totals keep the first session's traffic after it ended.
    CHECK(replaced.traffic.payload_bytes_sent >
          before_reconnect.traffic.payload_bytes_sent);
    runner.sync([&] {
        CHECK(authenticated == 2U && reconnecting == 1U && reports_on_context);
        client->close();
        server->close();
    });
    CHECK(client->status().state == NativeClientState::Closed);
    CHECK(!std::filesystem::exists(kit / "client/forward.sock"));
    CHECK(client->status().traffic.payload_bytes_sent == replaced.traffic.payload_bytes_sent);
    CHECK(status_on_context);
    // Connecting, Connected, then after the server ends the first session a
    // short-session backoff or an immediate reconnect, and finally Closed.
    CHECK(transitions.size() >= 5U && transitions.front() == NativeClientState::Connecting &&
          transitions[1] == NativeClientState::Connected &&
          transitions.back() == NativeClientState::Closed);
    runner.finish_and_join();
    CHECK(authenticated == 2U && reconnecting == 1U && stopped == 0U);
    CHECK(runner.exceptions.load() == 0U);
    client.reset();
    server.reset();
    CHECK(runner.context->poll() == 0U);
}

// A non-allocation exception from adapter construction must stay inside the
// runtime's startup transaction, just like a throwing packet report copy.
void test_client_start_exception(const std::filesystem::path& kit) {
    Runner runner;
    auto client = runner.sync([&] {
        return take(NativeClientRuntime::create(runner.context,
            load(kit / "client/runtime-client.json"), kit / "client", {}));
    });
    bool injected = false;
    bool escaped = false;
    StatusCode result = StatusCode::Ok;
    runner.sync([&] {
        yume::test::before_allocate = [](std::size_t) {
            yume::test::before_allocate = nullptr;
            throw 42;
        };
        try {
            result = client->start().code();
        } catch (...) {
            escaped = true;
        }
        injected = yume::test::before_allocate == nullptr;
        yume::test::before_allocate = nullptr;
        client->close();
    });
    runner.finish_and_join();
    client.reset();
    CHECK(injected && !escaped && result == StatusCode::Internal);
    CHECK(runner.exceptions.load() == 0U && runner.context->poll() == 0U);
}

// A failed dial remains retryable until its timer cannot be armed. Failure
// then closes the listener before notifying, including under sustained OOM.
void test_client_reconnect_timer_failure(const std::filesystem::path& kit, bool sustained) {
    Runner runner;
    std::shared_ptr<NativeClientRuntime> client;
    std::promise<StatusCode> stopped;
    auto completed = stopped.get_future();
    unsigned notifications = 0U;
    unsigned allocation_failures = 0U;
    bool on_context = false;
    bool already_closed = false;
    // Hold every cached Asio block so the next retry must allocate. Otherwise
    // fault injection can miss timer initiation and hit a later dial instead.
    boost::asio::recycling_allocator<std::byte> allocator;
    std::array<std::byte*, BOOST_ASIO_RECYCLING_ALLOCATOR_CACHE_SIZE> cached{};
    const auto socks = runner.sync([&] {
        NativeClientRuntimeOptions options;
        options.reconnect_initial = options.reconnect_max = 20ms;
        client = take(NativeClientRuntime::create(runner.context,
            load(kit / "client/runtime-client.json"), kit / "client",
            [&](std::string_view message) {
                if (!message.starts_with("session failed")) return;
                for (auto& block : cached) if (!block) block = allocator.allocate(1U);
                allocation_failure_sustained = sustained;
                injected_allocation_failures = 0U;
                yume::test::before_allocate = fail_runtime_allocation;
            }, options, [&](Status status) {
                // Cleanup has already run while allocations were failing.
                yume::test::before_allocate = nullptr;
                for (auto*& block : cached) {
                    if (block) allocator.deallocate(std::exchange(block, nullptr), 1U);
                }
                allocation_failures = injected_allocation_failures;
                ++notifications;
                on_context = runner.context->running_in_this_thread();
                already_closed = client->start().code() == StatusCode::FailedPrecondition;
                client->close();
                client.reset(); // The callback may release the last public owner.
                runner.context->finish();
                stopped.set_value(status.code());
                throw 1; // Caller exceptions must not escape the event loop.
            }));
        CHECK(client->start().ok());
        return client->socks5_endpoints().at(0U);
    });
    const auto ready = completed.wait_for(3s);
    if (ready != std::future_status::ready) {
        runner.sync([&] {
            yume::test::before_allocate = nullptr;
            for (auto*& block : cached) {
                if (block) allocator.deallocate(std::exchange(block, nullptr), 1U);
            }
            client->close();
        });
    }
    runner.finish_and_join();
    CHECK(ready == std::future_status::ready);
    CHECK(completed.get() == StatusCode::ResourceExhausted);
    CHECK(notifications == 1U && allocation_failures != 0U && on_context && already_closed);
    CHECK(!client);
    boost::asio::io_context io;
    boost::asio::ip::tcp::socket probe(io);
    boost::system::error_code error;
    probe.connect(socks, error);
    CHECK(error == boost::asio::error::connection_refused);
    CHECK(runner.exceptions.load() == 0U && runner.context->poll() == 0U);
}

#ifdef YUME_TEST_WRAP_ACCEPT
// An OS accept failure first retries. Only failure to schedule that retry is
// terminal, and the callback can release the adapter from inside the handler.
void test_socks5_accept_retry(bool fail_retry, bool sustained) {
    Runner runner;
    std::shared_ptr<NativeSocks5Adapter> adapter;
    std::promise<StatusCode> stopped;
    auto completed = stopped.get_future();
    unsigned notifications = 0U;
    unsigned allocation_failures = 0U;
    bool on_context = false;
    const auto endpoint = runner.sync([&] {
        adapter = take(NativeSocks5Adapter::create(runner.context,
            {"echo", "127.0.0.1", 0U}, [] { return std::shared_ptr<SessionEngine>{}; }, {},
            [&](Status status) {
                yume::test::before_allocate = nullptr;
                allocation_failures = injected_allocation_failures;
                ++notifications;
                on_context = runner.context->running_in_this_thread();
                adapter->close();
                adapter.reset();
                runner.context->finish();
                stopped.set_value(status.code());
                throw 1;
            }));
        injected_accept_error = EMFILE;
        fail_accept_retry_allocation = fail_retry;
        allocation_failure_sustained = sustained;
        injected_allocation_failures = 0U;
        return adapter->local_endpoint();
    });
    boost::asio::io_context io;
    boost::asio::ip::tcp::socket probe(io);
    probe.connect(endpoint);
    if (fail_retry) {
        const auto ready = completed.wait_for(3s);
        if (ready != std::future_status::ready) {
            runner.sync([&] {
                yume::test::before_allocate = nullptr;
                adapter->close();
            });
        }
        runner.finish_and_join();
        CHECK(ready == std::future_status::ready);
        CHECK(completed.get() == StatusCode::ResourceExhausted);
        CHECK(notifications == 1U && allocation_failures != 0U && on_context && !adapter);
        boost::asio::ip::tcp::socket after(io);
        boost::system::error_code error;
        after.connect(endpoint, error);
        CHECK(error == boost::asio::error::connection_refused);
    } else {
        // The queued connection is accepted after the retry, then refused
        // normally because there is no active session.
        const std::array<std::uint8_t, 13> request{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 1, 187};
        boost::asio::write(probe, boost::asio::buffer(request));
        probe.non_blocking(true);
        check_socks_reply(probe, 0x01);
        runner.sync([&] {
            CHECK(injected_accept_error == 0);
            adapter->close();
            adapter.reset();
        });
        runner.finish_and_join();
        CHECK(notifications == 0U);
    }
    CHECK(runner.exceptions.load() == 0U && runner.context->poll() == 0U);
}
#endif

// A forward turns each local connection into an OPEN on its service with its
// fixed destination, then joins the two. Bytes sent before the peer accepts
// wait in the socket. A refused or expired OPEN, or no session, closes the
// local connection. The same holds for a UNIX socket listener.
void test_forward_adapter(const std::filesystem::path& kit) {
    namespace v1 = yume::config::v1;
    using Local = boost::asio::local::stream_protocol;
    Runner runner;
    auto handler = std::make_shared<DelayedRouteHandler>();
    auto client_handler = std::make_shared<Handler>();
    NativeEndpointOptions options;
    options.max_sessions = options.max_pending_starts = 1U;
    options.route_provider = runner.sync([&] {
        return take(yume::providers::AsioDirectRouteProvider::create(runner.context,
            [](const auto&, const auto&) { return Status(StatusCode::PermissionDenied); }));
    });
    auto server = runner.sync([&] {
        return take(NativeEndpoint::create(runner.context, load(kit / "server/yumed.json"),
            kit / "server", {{"echo", handler}, {"denied", handler}}, options));
    });
    options.route_provider.reset();
    options.connection_address = "127.0.0.1";
    auto client = runner.sync([&] {
        return take(NativeEndpoint::create(runner.context, load(kit / "client/yume.json"),
            kit / "client", bindings(client_handler), options));
    });
    auto accepting = start(runner, server);
    auto connecting = start(runner, client);
    auto server_session = take(await(accepting));
    auto client_session = take(await(connecting));
    NativeForwardLimits limits;
    limits.open_timeout = 500ms;
    const auto create = [&](const v1::ForwardAdapter& adapter, NativeSessionSource sessions) {
        return runner.sync([&] {
            return take(NativeForwardAdapter::create(runner.context, adapter, sessions, limits));
        });
    };
    const NativeSessionSource active = [client_session] { return client_session; };
    const v1::ForwardDestination destination{"127.0.0.1", 2222U};
    auto forward = create(v1::ForwardAdapter("echo", v1::LoopbackListener{"127.0.0.1", 0U},
                                             destination), active);
    const auto endpoint = runner.sync([&] { return forward->local_endpoint(); });
    CHECK(endpoint.port() != 0U);

    boost::asio::io_context local_io;
    const auto arm = [&] {
        auto promise = std::make_shared<std::promise<std::shared_ptr<StreamResponder>>>();
        auto opened = promise->get_future();
        runner.sync([&] { handler->accepted = promise; });
        return opened;
    };
    const auto accept_held = [&](Status status) {
        runner.sync([&] {
            auto acceptance = std::move(handler->acceptance);
            if (acceptance) acceptance(std::move(status));
        });
    };
    {
        auto opened = arm();
        boost::asio::ip::tcp::socket local(local_io);
        local.connect(endpoint);
        boost::asio::write(local, boost::asio::buffer("early", 5U));
        auto served = await(opened);
        CHECK(runner.sync([&] { return handler->last_port; }) == destination.port);
        accept_held(Status::success());
        CHECK(read_record_text(runner, served) == "early");
        write_record_text(runner, served, "reply");
        local.non_blocking(true);
        std::array<std::uint8_t, 5> reply{};
        for (std::size_t offset = 0; offset < reply.size();) {
            const auto read = read_socket(local, std::span(reply).subspan(offset));
            CHECK(read != 0U);
            offset += read;
        }
        CHECK(std::string(reply.begin(), reply.end()) == "reply");
    }
    {
        // Held acceptance: the OPEN expires and the connection closes.
        auto opened = arm();
        boost::asio::ip::tcp::socket local(local_io);
        local.connect(endpoint);
        (void)await(opened);
        local.non_blocking(true);
        check_socket_closed(local);
        accept_held(Status(StatusCode::Cancelled));
    }
    auto denied = create(v1::ForwardAdapter("denied", v1::LoopbackListener{"127.0.0.1", 0U},
                                            destination), active);
    {
        boost::asio::ip::tcp::socket local(local_io);
        local.connect(runner.sync([&] { return denied->local_endpoint(); }));
        local.non_blocking(true);
        check_socket_closed(local);
    }
    auto idle = create(v1::ForwardAdapter("echo", v1::LoopbackListener{"127.0.0.1", 0U},
                                          destination),
                       [] { return std::shared_ptr<SessionEngine>{}; });
    {
        boost::asio::ip::tcp::socket local(local_io);
        local.connect(runner.sync([&] { return idle->local_endpoint(); }));
        local.non_blocking(true);
        check_socket_closed(local);
    }
    std::string directory = "/tmp/yume-forward-XXXXXX";
    CHECK(::mkdtemp(directory.data()) != nullptr);
    const auto path = std::filesystem::path(directory) / "forward.sock";
    auto local_forward = create(v1::ForwardAdapter("echo", v1::UnixListener{path.string()},
                                                   destination), active);
    {
        auto opened = arm();
        Local::socket local(local_io);
        local.connect(Local::endpoint(path.string()));
        boost::asio::write(local, boost::asio::buffer("unix", 4U));
        auto served = await(opened);
        accept_held(Status::success());
        CHECK(read_record_text(runner, served) == "unix");
    }
    runner.sync([&] {
        for (const auto& adapter : {forward, denied, idle, local_forward}) adapter->close();
        client->close();
        server->close();
        server_session.reset();
        client_session.reset();
    });
    CHECK(!std::filesystem::exists(path));
    std::filesystem::remove(directory);
    runner.finish_and_join();
    CHECK(runner.exceptions.load() == 0U);
}

#if defined(YUME_TEST_MODULE_LAUNCHER) && defined(YUME_TEST_ECHO_MODULE)
// The daemon composition runs a module for a service, and a client forward
// without a destination reaches it. The module learns the client's identity
// from the header of its connection.
void test_module_through_forward(const std::filesystem::path& kit) {
    namespace v1 = yume::config::v1;
    std::string text;
    CHECK(read_text_file_bounded(kit / "server/yumed.json", v1::kMaxDocumentBytes, &text));
    auto document = nlohmann::json::parse(text);
    document["services"] = nlohmann::json::array(
        {{{"name", "echo"}, {"kind", "stream"}, {"max_concurrent_streams", 8}}});
    document["adapters"] = nlohmann::json::array(
        {{{"kind", "module"}, {"service", "echo"}, {"program", YUME_TEST_ECHO_MODULE}}});
    CHECK(read_text_file_bounded(kit / "server/credentials/authorized-keys.json",
                                 v1::kMaxDocumentBytes, &text));
    const std::string identity = nlohmann::json::parse(text)["keys"][0]["identity"]["sha256"];
    Runner runner;
    std::vector<std::string> reports;
    auto server = runner.sync([&] {
        NativeServerRuntimeOptions options;
        options.module_launcher = YUME_TEST_MODULE_LAUNCHER;
        options.report = [&reports](std::string_view line) { reports.emplace_back(line); };
        return take(NativeServerRuntime::create(runner.context, v1::Parse(document),
            kit / "server", [](Status) {}, std::move(options)));
    });
    runner.sync([&] { CHECK(server->start().ok()); });
    auto handler = std::make_shared<Handler>();
    NativeEndpointOptions client_options;
    client_options.max_sessions = client_options.max_pending_starts = 1U;
    client_options.connection_address = "127.0.0.1";
    auto client = runner.sync([&] { return take(NativeEndpoint::create(runner.context,
        load(kit / "client/yume.json"), kit / "client", bindings(handler), client_options)); });
    auto connecting = start(runner, client);
    auto session = take(await(connecting));
    auto forward = runner.sync([&] {
        return take(NativeForwardAdapter::create(runner.context,
            v1::ForwardAdapter("echo", v1::LoopbackListener{"127.0.0.1", 0U}, std::nullopt),
            [session] { return session; }));
    });
    boost::asio::io_context local_io;
    boost::asio::ip::tcp::socket local(local_io);
    local.connect(runner.sync([&] { return forward->local_endpoint(); }));
    boost::asio::write(local, boost::asio::buffer("module", 6U));
    local.non_blocking(true);
    const std::string expected = "hello " + identity + "\nmodule";
    std::string received;
    while (received.size() < expected.size()) {
        std::array<std::uint8_t, 256> bytes{};
        const auto read = read_socket(local, bytes);
        CHECK(read != 0U);
        received.append(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(read));
    }
    CHECK(received == expected);
    local.close();
    runner.sync([&] {
        forward->close();
        client->close();
        server->close();
        session.reset();
    });
    runner.finish_and_join();
    CHECK(runner.exceptions.load() == 0U);
    CHECK(!reports.empty() && reports.front().find("module echo: started") == 0U);
}
#endif

void test_socks5_deadlines(const std::filesystem::path& kit) {
    Runner runner;
    auto handler = std::make_shared<DelayedRouteHandler>();
    auto client_handler = std::make_shared<Handler>();
    NativeEndpointOptions options;
    options.max_sessions = options.max_pending_starts = 1U;
    options.route_provider = runner.sync([&] {
        return take(yume::providers::AsioDirectRouteProvider::create(runner.context,
            [](const auto&, const auto&) { return Status(StatusCode::PermissionDenied); }));
    });
    auto server = runner.sync([&] {
        return take(NativeEndpoint::create(runner.context, load(kit / "server/yumed.json"),
            kit / "server", {{"echo", handler}, {"denied", handler}}, options));
    });
    options.route_provider.reset();
    options.connection_address = "127.0.0.1";
    auto client = runner.sync([&] {
        return take(NativeEndpoint::create(runner.context, load(kit / "client/yume.json"),
            kit / "client", bindings(client_handler), options));
    });
    auto accepting = start(runner, server);
    auto connecting = start(runner, client);
    auto server_session = take(await(accepting));
    auto client_session = take(await(connecting));
    NativeSocks5Limits limits;
    limits.max_connections = 1U;
    limits.handshake_timeout = 200ms;
    limits.open_timeout = 500ms;
    auto adapter = runner.sync([&] {
        return take(NativeSocks5Adapter::create(runner.context,
            {"echo", "127.0.0.1", 0U}, [client_session] { return client_session; }, limits));
    });
    boost::asio::io_context local_io;
    auto begin_request = [&] {
        auto promise = std::make_shared<std::promise<std::shared_ptr<StreamResponder>>>();
        auto opened = promise->get_future();
        runner.sync([&] { handler->accepted = promise; });
        boost::asio::ip::tcp::socket socket(local_io);
        socket.connect(adapter->local_endpoint());
        const std::array<std::uint8_t, 13> request{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 1, 187};
        boost::asio::write(socket, boost::asio::buffer(request));
        socket.non_blocking(true);
        return std::pair{std::move(socket), await(opened)};
    };
    auto settle = [&](Status status) {
        runner.sync([&, status = std::move(status)]() mutable {
            auto completion = std::move(handler->acceptance);
            CHECK(completion);
            completion(std::move(status));
        });
    };
    auto wait_closed = [&](const std::shared_ptr<StreamResponder>& stream) {
        auto promise = std::make_shared<std::promise<Result<ReceivedRecord>>>();
        auto read = promise->get_future();
        runner.sync([stream, promise] {
            stream->async_read({}, [promise](auto result) { promise->set_value(std::move(result)); });
        });
        CHECK(!await(read).ok());
        CHECK(stream->terminated());
    };

    auto [expired, expired_stream] = begin_request();
    check_socks_reply(expired, 0x06);
    check_socket_closed(expired);
    wait_closed(expired_stream);
    settle(Status::success()); // Late acceptance cannot resurrect this OPEN.
    CHECK(expired_stream->terminated());

    // A released connection slot admits the next request on the same listener.
    for (const auto& [status, reply] : {
             std::pair{StatusCode::PermissionDenied, 0x02},
             std::pair{StatusCode::Internal, 0x04}}) {
        auto [refused, stream] = begin_request();
        settle(Status(status));
        check_socks_reply(refused, static_cast<std::uint8_t>(reply));
        check_socket_closed(refused);
        wait_closed(stream);
    }

    auto [healthy, healthy_stream] = begin_request();
    settle(Status::success());
    check_socks_reply(healthy, 0x00);
    // Once accepted, the old OPEN deadline must not close the established bridge.
    std::this_thread::sleep_for(600ms);
    auto sent = std::make_shared<std::promise<Status>>();
    auto sending = sent->get_future();
    runner.sync([healthy_stream, sent] {
        const std::array<std::byte, 4> bytes{std::byte{0}, std::byte{1}, std::byte{2}, std::byte{255}};
        healthy_stream->async_write(take(Buffer::copy_from(bytes, bytes.size())), {},
            [sent](Status status, std::size_t written) {
                CHECK(!status.ok() || written == 4U);
                sent->set_value(std::move(status));
            });
    });
    CHECK(await(sending).ok());
    std::array<std::uint8_t, 4> payload{};
    for (std::size_t offset = 0; offset < payload.size();) {
        const auto read = read_socket(healthy, std::span(payload).subspan(offset));
        CHECK(read != 0U);
        offset += read;
    }
    CHECK(payload == (std::array<std::uint8_t, 4>{0, 1, 2, 255}));
    runner.sync([&] { healthy_stream->close(Status(StatusCode::Closed)); });
    check_socket_closed(healthy);

    auto [stopped, stopped_stream] = begin_request();
    // Method selection was sent, but adapter shutdown must not invent a timeout reply.
    std::array<std::uint8_t, 2> method{};
    for (std::size_t offset = 0; offset < method.size();) {
        const auto read = read_socket(stopped, std::span(method).subspan(offset));
        CHECK(read != 0U);
        offset += read;
    }
    CHECK(method == (std::array<std::uint8_t, 2>{5, 0}));
    runner.sync([&] { adapter->close(); });
    check_socket_closed(stopped);
    wait_closed(stopped_stream);
    settle(Status::success());
    runner.sync([&] {
        CHECK(client_session->state() == SessionState::Active);
        CHECK(server_session->state() == SessionState::Active);
    });
    client->close();
    server->close();
    CHECK(runner.exceptions.load() == 0U);
    runner.finish_and_join();
}

// UDP ASSOCIATE over the production daemon composition: configured direct_udp
// destinations, per-identity grants and real UDP sockets on both sides.
void test_socks5_udp_associate(const std::filesystem::path& kit) {
    using Udp = boost::asio::ip::udp;
    Runner runner;
    bool server_stopped = false;
    auto server = runner.sync([&] {
        return take(NativeServerRuntime::create(runner.context, load(kit / "server/direct-udp.json"),
            kit / "server", [&](Status) { server_stopped = true; }));
    });
    runner.sync([&] { CHECK(server->start().ok()); });
    NativeEndpointOptions client_options;
    client_options.max_sessions = client_options.max_pending_starts = 1U;
    client_options.connection_address = "127.0.0.1";
    auto client = runner.sync([&] {
        return take(NativeEndpoint::create(runner.context, load(kit / "client/routes-udp.json"),
            kit / "client", bindings(std::make_shared<Handler>(ServiceKind::PacketChannel)),
            client_options));
    });
    auto connecting = start(runner, client);
    auto client_session = take(await(connecting));
    NativeSocks5Limits limits;
    limits.udp_retry_delay = 200ms;
    const NativeSessionSource sessions = [client_session] { return client_session; };
    auto adapters = runner.sync([&] {
        return std::array{
            take(NativeSocks5Adapter::create(runner.context,
                {"echo", "127.0.0.1", 0U, "echo"}, sessions, limits)),
            // The authenticated identity holds no packet grant for this service.
            take(NativeSocks5Adapter::create(runner.context,
                {"echo", "127.0.0.1", 0U, "denied"}, sessions, limits)),
            // Without a UDP service, UDP ASSOCIATE is unsupported.
            take(NativeSocks5Adapter::create(runner.context,
                {"echo", "127.0.0.1", 0U}, sessions, limits)),
        };
    });
    boost::asio::io_context local_io;
    const auto bound = [&](const char* address) {
        Udp::socket socket(local_io, Udp::endpoint(boost::asio::ip::make_address_v4(address), 0U));
        socket.non_blocking(true);
        return socket;
    };
    auto target = bound("127.0.0.1");
    auto outside = bound("127.0.0.2");
    auto app = bound("127.0.0.1");
    auto stranger = bound("127.0.0.1");
    const std::uint16_t target_port = target.local_endpoint().port();
    const auto send = [](Udp::socket& from, const Udp::endpoint& relay,
                         const std::array<std::uint8_t, 4>& address, std::uint16_t port,
                         std::string_view payload) {
        from.send_to(boost::asio::buffer(socks_datagram(address, port, payload)), relay);
    };
    Udp::endpoint exit;

    {
        boost::asio::ip::tcp::socket socket(local_io);
        socket.connect(adapters[2]->local_endpoint());
        const std::array<std::uint8_t, 13> request{5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0};
        boost::asio::write(socket, boost::asio::buffer(request));
        socket.non_blocking(true);
        check_socks_reply(socket, 0x07);
        check_socket_closed(socket);
    }

    Udp::endpoint relay;
    auto control = associate_udp(local_io, adapters[0]->local_endpoint(), 0U, relay);
    const std::string query(1'200U, 'q');
    send(app, relay, {127, 0, 0, 1}, target_port, query);
    auto received = receive_datagram(target, exit, 10s);
    CHECK(text_of(received) == query);
    // UDP allows an empty datagram. YTP cannot carry it, and it must not close
    // the flow the next reply needs.
    target.send_to(boost::asio::const_buffer(nullptr, 0U), exit);
    const std::string answer = "reply from the destination";
    target.send_to(boost::asio::buffer(answer), exit);
    Udp::endpoint from;
    received = receive_datagram(app, from, 10s);
    CHECK(received && from == relay);
    CHECK(*received == socks_datagram({127, 0, 0, 1}, target_port, answer));

    // The association now belongs to app's port. Outside 127.0.0.1/32 the
    // server refuses the OPEN before any socket, and the session keeps working.
    send(stranger, relay, {127, 0, 0, 1}, target_port, "from another local port");
    send(app, relay, {127, 0, 0, 2}, outside.local_endpoint().port(), "must not arrive");
    send(app, relay, {127, 0, 0, 1}, target_port, "after refusal");
    received = receive_datagram(target, exit, 10s);
    CHECK(text_of(received) == "after refusal");
    CHECK(!receive_datagram(outside, exit, 300ms));

    Udp::endpoint denied_relay;
    auto denied_control = associate_udp(local_io, adapters[1]->local_endpoint(), 0U, denied_relay);
    send(app, denied_relay, {127, 0, 0, 1}, target_port, "no packet grant");
    CHECK(!receive_datagram(target, exit, 300ms));
    send(app, relay, {127, 0, 0, 1}, target_port, "still permitted");
    received = receive_datagram(target, exit, 10s);
    CHECK(text_of(received) == "still permitted");

    // The relay socket closes with its TCP connection. A connected probe then
    // reports the port as refused.
    Udp::socket probe(local_io, Udp::v4());
    probe.connect(relay);
    probe.non_blocking(true);
    control.close();
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    for (bool closed = false; !closed;) {
        CHECK(std::chrono::steady_clock::now() < deadline);
        boost::system::error_code error;
        probe.send(boost::asio::buffer("x", 1U), 0, error);
        closed = error == boost::asio::error::connection_refused;
        std::this_thread::sleep_for(5ms);
        std::array<char, 1> byte{};
        probe.receive(boost::asio::buffer(byte), 0, error);
        closed = closed || error == boost::asio::error::connection_refused;
    }

    denied_control.close();
    runner.sync([&] {
        CHECK(!server_stopped);
        for (const auto& adapter : adapters) adapter->close();
    });
    client->close();
    server->close();
    runner.finish_and_join();
    CHECK(runner.exceptions.load() == 0U);
}

// The datagram budget of an association while its OPEN is held: the first 64
// datagrams wait, newer ones are dropped, and replies carry the destination.
void test_socks5_udp_backlog(const std::filesystem::path& kit) {
    using Udp = boost::asio::ip::udp;
    Runner runner;
    auto held = std::make_shared<HeldPacketHandler>();
    NativeEndpointOptions server_options;
    server_options.max_sessions = server_options.max_pending_starts = 1U;
    server_options.route_provider = runner.sync([&] {
        return take(yume::providers::AsioDirectRouteProvider::create(runner.context,
            [](const auto&, const auto&) { return Status(StatusCode::PermissionDenied); }));
    });
    auto server = runner.sync([&] {
        return take(NativeEndpoint::create(runner.context, load(kit / "server/packet-services.json"),
            kit / "server", {{"echo", held}, {"denied", held}}, server_options));
    });
    NativeEndpointOptions client_options;
    client_options.max_sessions = client_options.max_pending_starts = 1U;
    client_options.connection_address = "127.0.0.1";
    auto client = runner.sync([&] {
        return take(NativeEndpoint::create(runner.context, load(kit / "client/routes-udp.json"),
            kit / "client", bindings(std::make_shared<Handler>(ServiceKind::PacketChannel)),
            client_options));
    });
    auto accepting = start(runner, server);
    auto connecting = start(runner, client);
    auto server_session = take(await(accepting));
    auto client_session = take(await(connecting));
    auto adapter = runner.sync([&] {
        return take(NativeSocks5Adapter::create(runner.context, {"echo", "127.0.0.1", 0U, "echo"},
            [client_session] { return client_session; }));
    });
    const auto wait_for_opens = [&](std::size_t count) {
        auto promise = std::make_shared<std::promise<void>>();
        auto future = promise->get_future();
        runner.sync([&] {
            if (held->opens.size() >= count) {
                promise->set_value();
                return;
            }
            held->expected = count;
            held->arrived = promise;
        });
        CHECK(future.wait_for(10s) == std::future_status::ready);
    };
    const auto read_text = [&](const std::shared_ptr<StreamResponder>& stream) {
        auto promise = std::make_shared<std::promise<std::optional<std::string>>>();
        auto future = promise->get_future();
        // The record, and the receive credit it holds, is released on the runner.
        runner.sync([stream, promise] {
            stream->async_read({}, [promise](Result<ReceivedRecord> result) {
                if (!result.ok()) {
                    promise->set_value(std::nullopt);
                    return;
                }
                const auto bytes = result.value().payload().bytes();
                promise->set_value(std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
            });
        });
        return await(future);
    };

    boost::asio::io_context local_io;
    Udp::endpoint relay;
    auto control = associate_udp(local_io, adapter->local_endpoint(), 0U, relay);
    Udp::socket app(local_io, Udp::endpoint(boost::asio::ip::address_v4::loopback(), 0U));
    app.non_blocking(true);
    constexpr std::uint16_t held_port = 9U;
    constexpr std::uint16_t barrier_port = 10U;
    const auto send = [&](std::uint16_t port, std::string_view payload) {
        app.send_to(boost::asio::buffer(socks_datagram({127, 0, 0, 1}, port, payload)), relay);
    };
    send(held_port, "datagram-0");
    wait_for_opens(1U);
    for (int index = 1; index < 100; ++index) send(held_port, "datagram-" + std::to_string(index));
    // A new destination sends an OPEN of its own. Its arrival shows the relay
    // has handled every earlier datagram, in order.
    send(barrier_port, "barrier");
    wait_for_opens(2U);
    std::shared_ptr<StreamResponder> held_stream;
    runner.sync([&] {
        CHECK(held->opens.size() == 2U);
        CHECK(held->opens[0].port == held_port && held->opens[1].port == barrier_port);
        held_stream = held->opens[0].stream;
        std::exchange(held->opens[0].completion, {})(Status::success());
        std::exchange(held->opens[1].completion, {})(Status(StatusCode::PermissionDenied));
    });
    for (int index = 0; index < 64; ++index) {
        CHECK(read_text(held_stream) == "datagram-" + std::to_string(index));
    }
    send(held_port, "after acceptance");
    CHECK(read_text(held_stream) == std::string("after acceptance"));

    runner.sync([&] {
        const std::string_view reply = "held reply";
        held_stream->async_write(take(Buffer::copy_from(
            {reinterpret_cast<const std::byte*>(reply.data()), reply.size()}, reply.size())), {},
            [](Status status, std::size_t) { CHECK(status.ok()); });
    });
    Udp::endpoint from;
    const auto reply = receive_datagram(app, from, 10s);
    CHECK(reply && from == relay && *reply == socks_datagram({127, 0, 0, 1}, held_port, "held reply"));

    // Closing the TCP connection ends the association and its packet stream.
    control.close();
    CHECK(!read_text(held_stream));
    runner.sync([&] {
        CHECK(held_stream->terminated());
        held_stream.reset();
        held->opens.clear();
        adapter->close();
    });
    client->close();
    server->close();
    runner.finish_and_join();
    CHECK(runner.exceptions.load() == 0U);
}
#endif

void test_adapter_configuration_rejections(const std::filesystem::path& kit) {
    Runner runner;
    runner.sync([&] {
        for (const auto* role : {"server", "client"}) {
            auto unsupported = NativeEndpoint::create(runner.context,
                load(kit / role / "unsupported-adapter.json"), kit / role, {});
            CHECK(!unsupported.ok() &&
                unsupported.status().code() == StatusCode::FailedPrecondition);
        }
        NativeEndpointOptions unused_policy;
        unused_policy.route_authorization = [](const StreamOpenContext&) {
            return Status::success();
        };
        auto unused = NativeEndpoint::create(runner.context, load(kit / "server/yumed.json"),
            kit / "server", bindings(std::make_shared<Handler>()), std::move(unused_policy));
        CHECK(!unused.ok() && unused.status().code() == StatusCode::InvalidArgument);
        NativeEndpointOptions unused_packet_owner;
        unused_packet_owner.caller_runs_packet_adapters = true;
        auto no_packet = NativeEndpoint::create(runner.context, load(kit / "server/yumed.json"),
            kit / "server", bindings(std::make_shared<Handler>()), std::move(unused_packet_owner));
        CHECK(!no_packet.ok() && no_packet.status().code() == StatusCode::InvalidArgument);
    });
    runner.finish_and_join();
    CHECK(runner.context->poll() == 0U);
    CHECK(runner.exceptions.load() == 0U);
}

void run(const std::filesystem::path& kit) {
    Runner runner;
    auto server_handler = std::make_shared<Handler>();
    auto client_handler = std::make_shared<Handler>();
    const auto server_config = load(kit / "server/yumed.json");
    const auto client_config = load(kit / "client/yume.json");
    NativeEndpointOptions options;
    options.max_sessions = 1U;
    options.max_pending_starts = 1U;
    options.start_timeout = 5s;
    auto server = runner.sync([&] { return take(NativeEndpoint::create(runner.context,
        server_config, kit / "server", bindings(server_handler), options)); });
    options.connection_address = "127.0.0.1";
    auto client = runner.sync([&] { return take(NativeEndpoint::create(runner.context,
        client_config, kit / "client", bindings(client_handler), options)); });
    auto accepting = start(runner, server);
    // Keep this exact waiter beyond its AUTH budget before dialing. The old
    // admission-relative timeout consumed it before a client even arrived.
    CHECK(accepting.wait_for(5100ms) == std::future_status::timeout);
    runner.sync([&] {
        CHECK(server->async_start_session([](auto) {}).code() == StatusCode::ResourceExhausted);
    });
    auto connecting = start(runner, client);
    auto connected = await(connecting);
    if (!connected.ok()) std::cerr << "client bootstrap: " << connected.status().message() << '\n';
    auto accepted = await(accepting);
    if (!accepted.ok()) std::cerr << "server bootstrap: " << accepted.status().message() << '\n';
    auto client_session = take(std::move(connected));
    auto server_session = take(std::move(accepted));
    CHECK(server_session->state() == SessionState::Active);
    CHECK(client_session->state() == SessionState::Active);
    // Each side exposes the composite identity that YTP authenticated, not a
    // value derived from configuration or the outer TLS channel.
    const auto server_peer = client_session->authenticated_peer();
    const auto client_peer = server_session->authenticated_peer();
    CHECK(server_peer.ok() && server_peer.value().peer_role() == EndpointRole::Server);
    CHECK(client_peer.ok() && client_peer.value().peer_role() == EndpointRole::Client);
    CHECK(server_peer.value().credential_evidence().size() == 32U);
    CHECK(client_peer.value().credential_evidence().size() == 32U);

    auto remote_promise = std::make_shared<std::promise<std::shared_ptr<StreamResponder>>>();
    auto remote_future = remote_promise->get_future();
    runner.sync([server_handler, remote_promise] { server_handler->accepted = remote_promise; });
    auto local = open(runner, client_session, "echo");
    auto remote = await(remote_future);
    transfer(runner, local, remote, "native authenticated client bytes");
    transfer(runner, remote, local, "native authenticated server bytes");
    runner.sync([client_session, server_session] {
        CHECK(client_session->initiate_rekey().ok());
        CHECK(server_session->initiate_rekey().ok());
    });
    transfer(runner, local, remote, "after simultaneous directional rekey");

    auto peer_read = std::make_shared<std::promise<Result<ReceivedRecord>>>();
    auto closed = peer_read->get_future();
    runner.sync([remote, local, peer_read] {
        remote->async_read({}, [peer_read](auto result) { peer_read->set_value(std::move(result)); });
        CHECK(local->shutdown_write().ok());
    });
    const auto client_fin = await(closed);
    CHECK(!client_fin.ok() && client_fin.status().code() == StatusCode::EndOfStream);
    transfer(runner, remote, local, "response after client FIN");
    runner.sync([remote] { CHECK(remote->shutdown_write().ok()); });

    auto delayed_peer = std::make_shared<std::promise<std::shared_ptr<StreamResponder>>>();
    auto delayed_future = delayed_peer->get_future();
    auto opening = std::make_shared<std::promise<Result<std::shared_ptr<StreamResponder>>>>();
    auto open_future = opening->get_future();
    CancellationSource cancellation;
    runner.sync([&] {
        server_handler->hold_acceptance = true;
        server_handler->accepted = delayed_peer;
        client_session->async_open("echo", ServiceKind::ByteStream, std::nullopt,
            cancellation.token(), [opening](auto result) { opening->set_value(std::move(result)); });
    });
    auto delayed_stream = await(delayed_future);
    CHECK(open_future.wait_for(0ms) == std::future_status::timeout);
    auto aborted = std::make_shared<std::promise<Result<ReceivedRecord>>>();
    auto abort_future = aborted->get_future();
    runner.sync([&] {
        delayed_stream->async_read({}, [aborted](auto result) { aborted->set_value(std::move(result)); });
        cancellation.cancel();
    });
    auto cancelled_open = await(open_future);
    CHECK(!cancelled_open.ok() && cancelled_open.status().code() == StatusCode::Cancelled);
    CHECK(!await(abort_future).ok());
    runner.sync([&] {
        auto completion = std::move(server_handler->deferred_acceptance);
        CHECK(completion);
        server_handler->hold_acceptance = false;
        completion(Status::success()); // Late success cannot resurrect an aborted OPEN.
    });

    // Admission/authentication must not turn the advertised service list into
    // a grant: this identity is authorized for echo only. Refusal must leave
    // the authenticated connection usable for another service.
    const auto refused = open_result(runner, client_session, "denied");
    CHECK(!refused.ok());
    CHECK(client_session->state() == SessionState::Active);
    CHECK(server_session->state() == SessionState::Active);
    auto second_promise = std::make_shared<std::promise<std::shared_ptr<StreamResponder>>>();
    auto second_future = second_promise->get_future();
    runner.sync([server_handler, second_promise] { server_handler->accepted = second_promise; });
    auto second_local = open(runner, client_session, "echo");
    auto second_remote = await(second_future);
    transfer(runner, second_local, second_remote, "healthy after refusal");
    CHECK(server_handler->opens == 3U);

    auto pending_promise = std::make_shared<std::promise<Result<ReceivedRecord>>>();
    auto pending = pending_promise->get_future();
    runner.sync([second_remote, pending_promise] {
        second_remote->async_read({}, [pending_promise](auto result) { pending_promise->set_value(std::move(result)); });
    });
    client->close();
    server->close();
    CHECK(!await(pending).ok());
    runner.sync([server_session, client_session] {
        CHECK(server_session->state() == SessionState::Closed || server_session->state() == SessionState::Failed);
        CHECK(client_session->state() == SessionState::Closed || client_session->state() == SessionState::Failed);
    });
    CHECK(runner.exceptions.load() == 0U);
    runner.finish_and_join();
    // Handle destruction after final drain must not retain the context through
    // another cleanup task. Keep closed engines alive while dropping endpoints.
    client.reset();
    server.reset();
    CHECK(runner.context->poll() == 0U);
    client_session.reset();
    server_session.reset();
    CHECK(runner.context->poll() == 0U);
}
}  // namespace

int main(int argc, char** argv) {
    try {
        CHECK(argc == 2);
        test_adapter_configuration_rejections(argv[1]);
        run(argv[1]);
        test_session_ended_notifications(argv[1]);
#ifdef YUME_NATIVE_TEST_ROUTES
        test_client_short_session_backoff(argv[1]);
        test_client_reconnect(argv[1]);
        test_client_start_exception(argv[1]);
        test_client_reconnect_timer_failure(argv[1], false);
        test_client_reconnect_timer_failure(argv[1], true);
#ifdef YUME_TEST_WRAP_ACCEPT
        test_socks5_accept_retry(false, false);
        test_socks5_accept_retry(true, false);
        test_socks5_accept_retry(true, true);
#endif
        test_socks5_deadlines(argv[1]);
        test_socks5_udp_associate(argv[1]);
        test_socks5_udp_backlog(argv[1]);
        test_forward_adapter(argv[1]);
#if defined(YUME_TEST_MODULE_LAUNCHER) && defined(YUME_TEST_ECHO_MODULE)
        test_module_through_forward(argv[1]);
#endif
        test_destination_route<boost::asio::ip::tcp>(argv[1], false);
        test_destination_route<boost::asio::ip::tcp>(argv[1], true);
        test_destination_route<boost::asio::ip::udp>(argv[1], true);
#endif
        test_start_deadline_and_final_drain(argv[1]);
        test_stalled_lookup_close(argv[1]);
        test_identity_session_replacement(argv[1]);
        test_egress_pacing(argv[1]);
        test_credential_reload(argv[1]);
        test_promoted_server_auth_deadline(argv[1]);
        test_unanswered_rekey_watchdog(argv[1]);
        test_accept_loop(argv[1]);
#ifdef __linux__
        test_accept_loop_listeners(argv[1]);
#endif
#ifdef YUME_TEST_WRAP_ACCEPT
        test_accept_loop_listener_failure(argv[1]);
#endif
        std::cout << "native AUTH, named services, refusal, rekey and shutdown passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
