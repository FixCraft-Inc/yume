/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// The client's circuit pool over an in-memory session: four real circuit
// nodes, a routes view the operator signed and short pool timings, so the
// tests reach rotation, idle closing, the spare-failure rule, exclusion of a
// failed node and its return, cancellation while a circuit is being built
// and closing circuits from inside the pool's own loops.

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <exception>
#include <filesystem>
#include <functional>
#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <new>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

#include <boost/asio/post.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "common/service_name.hpp"
#include "runtime/circuit_host.hpp"
#include "runtime/circuit_node.hpp"
#include "runtime/circuit_pool.hpp"
#include "runtime/cluster_list.hpp"
#include "test_support/allocation_failure.hpp"
#include "test_support/circuit_fixtures.hpp"

namespace {

using namespace std::chrono_literals;
using namespace yume;
using engine::Buffer;
using engine::CancellationSource;
using engine::CancellationToken;
using engine::ReceivedRecord;
using engine::Result;
using engine::Status;
using engine::StatusCode;
using engine::StreamResponder;
using runtime::CircuitPool;
using runtime::CircuitPoolOptions;
using runtime::CircuitPoolStatus;
using runtime::circuit::CircuitService;
using test::EchoChannel;
using test::IoRuntime;
using test::PipeEnd;
using test::take;
namespace cc = providers::circuit;
namespace keys = providers::keys;
using Clock = std::chrono::steady_clock;
using OpenResult = Result<std::shared_ptr<StreamResponder>>;

int g_failures = 0;

#define CHECK(condition)                                        \
    do {                                                        \
        if (!(condition)) {                                     \
            std::cerr << __FILE__ << ':' << __LINE__            \
                      << ": check failed: " #condition << '\n'; \
            ++g_failures;                                       \
        }                                                       \
    } while (false)

const std::string kClient(64U, 'c');
// The entry first. west and south are exits, and every node has its own
// network tag, so the view holds four three-hop routes: north > east >
// west, north > east > south, north > south > west and north > west > south.
constexpr std::array<const char*, 4> kNodes{"north", "east", "west", "south"};

std::string public_pem(EVP_PKEY* key) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()),
                                                  BIO_free);
    if (!bio || PEM_write_bio_PUBKEY(bio.get(), key) != 1)
        throw std::runtime_error("PEM export failed");
    char* data = nullptr;
    const long size = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, static_cast<std::size_t>(size));
}

std::string composite_pem(const keys::CompositePrivate& key) {
    return public_pem(key.classical.get()) + public_pem(key.post_quantum.get());
}

// What the pool sees of its session: yume.routes serves the signed view,
// yume.circuit opens a stream into north's circuit service, and nothing
// else is served. Every completion runs later on the executor, as the
// session engine's do.
class TestSession final : public runtime::CircuitSession {
public:
    enum class Direct {
        Normal,
        ThrowAllocation,
        ThrowInternal,
        CompleteThenThrow,
        RetainThenThrow
    };

    struct Hooks final {
        std::shared_ptr<providers::AsioExecutionContext> context;
        std::shared_ptr<runtime::circuit::RoutesService> routes;
        std::shared_ptr<CircuitService> entry;
        // Circuit streams the session opens before it refuses the rest.
        std::size_t circuits_allowed{~std::size_t{0}};
    };

    explicit TestSession(Hooks hooks) : hooks_(std::move(hooks)) {}

    void async_open(std::string_view service_name, engine::ServiceKind,
                    std::optional<engine::RouteDestination> destination,
                    CancellationToken, Opened done) override {
        if (service_name == "internet" && destination) {
            ++direct_opens;
            switch (direct) {
                case Direct::Normal:
                    break;
                case Direct::ThrowAllocation:
                    throw std::bad_alloc();
                case Direct::ThrowInternal:
                    throw std::runtime_error("direct initiation failed");
                case Direct::CompleteThenThrow:
                    done(OpenResult(Status(StatusCode::NotFound)));
                    throw std::bad_alloc();
                case Direct::RetainThenThrow:
                    late_direct = std::move(done);
                    throw std::bad_alloc();
            }
        }
        auto [mine, theirs] = PipeEnd::pair(hooks_.context);
        auto result =
            std::make_shared<OpenResult>(Status(StatusCode::NotFound));
        if (service_name == common::kRoutesServiceName) {
            hooks_.routes->on_open(test::open_context(kClient), theirs);
            *result = OpenResult(mine);
        } else if (service_name == common::kCircuitServiceName) {
            ++circuit_opens;
            if (circuit_opens <= hooks_.circuits_allowed) {
                hooks_.entry->async_open(test::open_context(kClient), theirs,
                                         [](Status) {});
                *result = OpenResult(mine);
            } else {
                *result = OpenResult(Status(StatusCode::Closed));
            }
        }
        boost::asio::post(
            hooks_.context->executor(),
            [done = std::move(done), result] { done(std::move(*result)); });
    }

    std::size_t circuit_opens{0U};
    std::size_t direct_opens{0U};
    Direct direct{Direct::Normal};
    Opened late_direct;

private:
    Hooks hooks_;
};

struct Harness {
    Harness(IoRuntime& io, CircuitPoolOptions options,
            std::filesystem::path state = {})
        : runtime(io), crypto(std::make_shared<cc::CircuitCrypto>()) {
        runtime.sync([&] { start(std::move(options), std::move(state)); });
    }

    ~Harness() {
        // OpenSSL frees a library context's per-thread state only on the
        // thread that frees the context, and the nodes signed on this one.
        runtime.sync([this] {
            held.clear();
            if (pool) pool->close();
            pool.reset();
            session.reset();
            for (auto& [name, service] : services) service->close();
            for (const auto& link : links)
                link->close(Status(StatusCode::Cancelled));
            services.clear();
            links.clear();
            routes.reset();
            identities.clear();
            operator_key.reset();
            crypto.reset();
        });
    }

    void start(CircuitPoolOptions options, std::filesystem::path state) {
        operator_key = test::make_identity(*crypto);
        for (const auto* name : kNodes)
            identities[name] = test::make_identity(*crypto);
        for (std::size_t index = 0U; index < kNodes.size(); ++index) {
            const auto& key = *identities[kNodes[index]];
            std::string pem;
            for (const char value : composite_pem(key)) {
                if (value == '\n') {
                    pem += "\\n";
                } else {
                    pem.push_back(value);
                }
            }
            const bool exit = index >= 2U;
            nodes += std::string(nodes.empty() ? "" : ",") + "{\"name\":\"" +
                     kNodes[index] + "\",\"identity\":\"" +
                     key.identity.fingerprint + "\",\"identity_key\":\"" + pem +
                     "\",\"exit\":" + (exit ? "true" : "false") +
                     ",\"network\":\"" + std::string(15U, '0') +
                     static_cast<char>('1' + index) + "\"}";
        }
        publish_view(7U);
        routes = take(
            runtime::circuit::RoutesService::create([this] { return served; }));

        for (const auto* name : kNodes) start_node(name);

        runtime::NativeCircuitCredentials credentials;
        credentials.operator_key_pem = composite_pem(*operator_key);
        credentials.cluster = operator_key->identity.fingerprint;
        credentials.entry = identities["north"]->identity.fingerprint;
        credentials.state = std::move(state);
        // The initial view's serial is saved already. Tests that serve a
        // newer serial supply a private directory for its state file.
        credentials.saved = 7U;
        pool = take(CircuitPool::create(
            runtime.context(), std::move(credentials), std::move(options),
            [this](std::string_view text) { said.emplace_back(text); }));
        new_session();
    }

    // On the context: publish a newly signed view for the next fetch.
    void publish_view(std::uint64_t serial,
                      std::string_view not_after = "2099-01-01T00:00:00Z") {
        const std::string view = "{\"schema\":1,\"cluster\":\"" +
                                 operator_key->identity.fingerprint +
                                 "\",\"serial\":" + std::to_string(serial) +
                                 ",\"not_after\":\"" + std::string(not_after) +
                                 "\",\"nodes\":[" + nodes + "]}";
        const auto* bytes = reinterpret_cast<const std::byte*>(view.data());
        std::vector<std::byte> message(
            reinterpret_cast<const std::byte*>(
                runtime::cluster::kRoutesDomain.data()),
            reinterpret_cast<const std::byte*>(
                runtime::cluster::kRoutesDomain.data() +
                runtime::cluster::kRoutesDomain.size()));
        message.push_back(std::byte{0});
        message.insert(message.end(), bytes, bytes + view.size());
        auto next = std::make_shared<runtime::circuit::RoutesView>();
        next->view.assign(bytes, bytes + view.size());
        next->signature =
            keys::sign_composite(crypto->key_context(), *operator_key, message);
        served = std::move(next);
    }

    void start_node(const std::string& name) {
        runtime::circuit::NodeEnvironment environment;
        environment.context = runtime.context();
        environment.crypto = crypto;
        environment.identity = identities[name];
        // The pool's tests build more circuits than one client may at an
        // entry. The node's own bounds have their tests.
        environment.limits.circuits_per_client = 64U;
        environment.limits.client_circuits_per_second = 1000.0;
        environment.limits.client_circuit_burst = 1000.0;
        environment.is_peer = [this](std::string_view identity) {
            return std::any_of(
                identities.begin(), identities.end(), [&](const auto& node) {
                    return node.second->identity.fingerprint == identity;
                });
        };
        environment.open_next = [this, name](
                                    std::string_view peer, CancellationToken,
                                    runtime::circuit::StreamOpened done) {
            std::string target;
            for (const auto& [node, key] : identities) {
                if (key->identity.fingerprint == peer) target = node;
            }
            ++extends[target];
            if (hanging.contains(target)) {
                held.push_back(std::move(done));
                return;
            }
            if (target.empty() || stopped.contains(target)) {
                done(Result<std::shared_ptr<StreamResponder>>(
                    Status(StatusCode::NotFound)));
                return;
            }
            auto [mine, theirs] = PipeEnd::pair(runtime.context());
            links.push_back(mine);
            services[target]->async_open(
                test::open_context(identities[name]->identity.fingerprint),
                theirs, [](Status) {});
            done(Result<std::shared_ptr<StreamResponder>>(mine));
        };
        if (name == "west" || name == "south") {
            environment.open_exit =
                [this](const engine::StreamOpenContext&,
                       const ytp1::Destination&, CancellationToken,
                       runtime::circuit::ChannelOpened done) {
                    done(Result<std::unique_ptr<engine::ByteChannel>>(
                        std::make_unique<EchoChannel>(runtime.context())));
                };
        }
        services[name] = take(CircuitService::create(std::move(environment)));
    }

    // On the context: a fresh session, which ends the pool's circuits.
    void new_session(std::size_t circuits_allowed = ~std::size_t{0}) {
        TestSession::Hooks hooks;
        hooks.context = runtime.context();
        hooks.routes = routes;
        hooks.entry = services["north"];
        hooks.circuits_allowed = circuits_allowed;
        session = std::make_shared<TestSession>(std::move(hooks));
        pool->set_session(session);
    }

    std::future<OpenResult> open_async(CancellationToken cancellation = {},
                                       std::uint16_t port = 443U) {
        auto promise = std::make_shared<std::promise<OpenResult>>();
        auto future = promise->get_future();
        runtime.sync([&] {
            pool->open(take(engine::RouteDestination::ipv4(
                           engine::NetworkProtocol::Tcp, {192, 0, 2, 9}, port)),
                       "internet", std::move(cancellation),
                       [promise](OpenResult opened) {
                           promise->set_value(std::move(opened));
                       });
        });
        return future;
    }

    OpenResult open(std::uint16_t port = 443U) {
        auto future = open_async({}, port);
        if (future.wait_for(20s) != std::future_status::ready)
            return OpenResult(Status(StatusCode::Cancelled));
        return future.get();
    }

    // The circuits north holds, built or being built.
    std::size_t entry_circuits() {
        return runtime.sync(
            [&] { return services["north"]->status().circuits; });
    }

    std::size_t circuit_opens() {
        return runtime.sync([&] { return session->circuit_opens; });
    }

    CircuitPoolStatus status() {
        return runtime.sync([&] { return pool->status(); });
    }

    // Polls on the context until the check holds or 20 seconds pass.
    bool wait_until(const std::function<bool(const CircuitPoolStatus&)>& check,
                    std::chrono::milliseconds limit = 20s) {
        const auto deadline = Clock::now() + limit;
        while (Clock::now() < deadline) {
            if (check(status())) return true;
            std::this_thread::sleep_for(20ms);
        }
        return check(status());
    }

    void close(const std::shared_ptr<StreamResponder>& stream) {
        runtime.sync([&] { stream->close(Status(StatusCode::Cancelled)); });
    }

    // Whether bytes written to the stream come back from the exit.
    bool echoes(const std::shared_ptr<StreamResponder>& stream) {
        auto promise = std::make_shared<std::promise<bool>>();
        auto future = promise->get_future();
        runtime.sync([&] {
            auto buffer = take(
                Buffer::copy_from(std::as_bytes(std::span("ping", 4U)), 64U));
            stream->async_write(std::move(buffer), {},
                                [](Status, std::size_t) {});
            stream->async_read({}, [promise](Result<ReceivedRecord> result) {
                promise->set_value(result.ok() &&
                                   result.value().payload().size() > 0U);
            });
        });
        return future.wait_for(20s) == std::future_status::ready &&
               future.get();
    }

    IoRuntime& runtime;
    std::shared_ptr<cc::CircuitCrypto> crypto;
    std::shared_ptr<const keys::CompositePrivate> operator_key;
    std::map<std::string, std::shared_ptr<const keys::CompositePrivate>>
        identities;
    std::map<std::string, std::shared_ptr<CircuitService>> services;
    std::shared_ptr<runtime::circuit::RoutesService> routes;
    std::shared_ptr<const runtime::circuit::RoutesView> served;
    std::string nodes;
    std::vector<std::shared_ptr<PipeEnd>> links;
    std::shared_ptr<CircuitPool> pool;
    std::shared_ptr<TestSession> session;
    // Nodes whose previous hop cannot reach them.
    std::set<std::string> stopped;
    // Nodes whose previous hop never gets an answer: the extension waits
    // in held until the harness ends.
    std::set<std::string> hanging;
    std::vector<runtime::circuit::StreamOpened> held;
    // How often a node was asked to extend a circuit to each node.
    std::map<std::string, std::size_t> extends;
    std::vector<std::string> said;
};

std::size_t with_streams(const CircuitPoolStatus& status) {
    return static_cast<std::size_t>(
        std::count_if(status.circuits.begin(), status.circuits.end(),
                      [](const auto& route) { return route.streams != 0U; }));
}

const runtime::CircuitRoute* built_at(const CircuitPoolStatus& status,
                                      Clock::time_point built) {
    for (const auto& route : status.circuits) {
        if (route.built == built) return &route;
    }
    return nullptr;
}

CircuitPoolOptions fast(std::chrono::milliseconds rotation,
                        std::chrono::milliseconds idle,
                        std::chrono::milliseconds tick) {
    CircuitPoolOptions options;
    options.rotation = rotation;
    options.idle = idle;
    options.tick = tick;
    return options;
}

// A session builds a circuit before any stream asks for one, so the first
// stream does not wait for a build.
void test_build_at_session_start(IoRuntime& io) {
    Harness harness(io, fast(1h, 1h, 1h));
    CHECK(harness.wait_until([](const auto& status) {
        return status.serial == 7U && status.circuits.size() == 1U &&
               with_streams(status) == 0U;
    }));
    const auto opens =
        harness.runtime.sync([&] { return harness.session->circuit_opens; });
    auto stream = harness.open();
    CHECK(stream.ok() && harness.echoes(stream.value()));
    // The first stream took the circuit already built, and a new spare
    // follows it.
    CHECK(harness.wait_until([](const auto& status) {
        return status.circuits.size() == 2U && with_streams(status) == 1U;
    }));
    CHECK(harness.runtime.sync(
              [&] { return harness.session->circuit_opens; }) == opens + 1U);
    if (stream.ok()) harness.close(stream.value());
}

void test_window_capacity_selection(IoRuntime& io) {
    auto options = fast(1h, 1h, 1h);
    options.limits.circuit_window = options.limits.stream_window;
    Harness harness(io, options);
    auto first = harness.open();
    CHECK(first.ok());
    CHECK(harness.wait_until([](const auto& status) {
        return status.circuits.size() == 2U && with_streams(status) == 1U;
    }));
    auto second = harness.open();
    CHECK(second.ok());
    CHECK(harness.wait_until(
        [](const auto& status) { return with_streams(status) == 2U; }));
    if (first.ok()) harness.close(first.value());
    if (second.ok()) harness.close(second.value());
}

// New streams leave a circuit once it is older than the rotation time since
// its first stream, and the rotated circuit closes when its last stream
// ends. A stream never moves.
void test_rotation(IoRuntime& io) {
    Harness harness(io, fast(300ms, 1h, 50ms));
    auto first = harness.open();
    CHECK(first.ok());
    if (!first.ok()) return;
    // The spare is built next to the first stream's circuit.
    CHECK(harness.wait_until(
        [](const auto& status) { return status.circuits.size() == 2U; }));
    auto status = harness.status();
    CHECK(status.current_hops == 3U && with_streams(status) == 1U);
    Clock::time_point old{};
    for (const auto& route : status.circuits) {
        if (route.streams == 1U) old = route.built;
        CHECK(route.nodes.size() == 3U && route.nodes.front() == "north");
    }
    std::this_thread::sleep_for(600ms);
    auto second = harness.open();
    CHECK(second.ok());
    if (!second.ok()) return;
    status = harness.status();
    const auto* rotated = built_at(status, old);
    CHECK(rotated != nullptr && rotated->streams == 1U);
    CHECK(with_streams(status) == 2U);
    harness.close(first.value());
    CHECK(harness.wait_until(
        [old](const auto& now) { return built_at(now, old) == nullptr; }));
    CHECK(harness.echoes(second.value()));
    harness.close(second.value());
}

// A circuit without streams closes once idle, except one spare.
void test_idle_close(IoRuntime& io) {
    Harness harness(io, fast(1h, 300ms, 50ms));
    auto stream = harness.open();
    CHECK(stream.ok());
    if (!stream.ok()) return;
    CHECK(harness.wait_until(
        [](const auto& status) { return status.circuits.size() == 2U; }));
    harness.close(stream.value());
    CHECK(harness.wait_until([](const auto& status) {
        return status.circuits.size() == 1U && with_streams(status) == 0U;
    }));
    // The spare stays, however long it idles.
    std::this_thread::sleep_for(800ms);
    CHECK(harness.status().circuits.size() == 1U);
    auto again = harness.open();
    CHECK(again.ok() && harness.echoes(again.value()));
    if (again.ok()) harness.close(again.value());
}

// A spare that cannot be built while a circuit of the configured length
// works never shortens the route or asks for consent. It is tried again at
// the next tick, and streams keep using the working circuit.
void test_spare_failure(IoRuntime& io) {
    Harness harness(io, fast(1h, 1h, 200ms));
    harness.runtime.sync([&] { harness.new_session(1U); });
    auto first = harness.open();
    CHECK(first.ok());
    if (!first.ok()) return;
    const auto started = Clock::now();
    std::this_thread::sleep_for(1s);
    const auto tries =
        harness.runtime.sync([&] { return harness.session->circuit_opens; });
    const auto status = harness.status();
    CHECK(status.current_hops == 3U);
    CHECK(!status.proposal.has_value());
    CHECK(status.circuits.size() == 1U);
    // One try when the circuit was built, then at most one a tick.
    const auto ticks = static_cast<std::size_t>((Clock::now() - started) /
                                                std::chrono::milliseconds(200));
    CHECK(tries >= 2U && tries <= ticks + 3U);
    auto second = harness.open();
    CHECK(second.ok() && harness.echoes(second.value()));
    CHECK(harness.echoes(first.value()));
    harness.close(first.value());
    if (second.ok()) harness.close(second.value());
}

// A node a build failed at stays out of routes, in this session's view and
// in every later one.
void test_exclusion(IoRuntime& io) {
    Harness harness(io, fast(1h, 1h, 1h));
    harness.runtime.sync([&] { harness.stopped.insert("west"); });
    for (int round = 0; round < 6; ++round) {
        if (round != 0) harness.runtime.sync([&] { harness.new_session(); });
        auto stream = harness.open();
        CHECK(stream.ok());
        if (!stream.ok()) continue;
        CHECK(harness.echoes(stream.value()));
        const auto status = harness.status();
        CHECK(status.current_hops == 3U);
        for (const auto& route : status.circuits) {
            CHECK(route.nodes ==
                  (std::vector<std::string>{"north", "east", "south"}));
        }
        harness.close(stream.value());
    }
    const auto tried = harness.runtime.sync([&] { return harness.extends; });
    CHECK(!tried.contains("west") || tried.at("west") <= 1U);
}

// Polls from the test thread until the check holds or the limit passes.
bool eventually(const std::function<bool()>& check,
                std::chrono::milliseconds limit = 5s) {
    const auto deadline = Clock::now() + limit;
    while (Clock::now() < deadline) {
        if (check()) return true;
        std::this_thread::sleep_for(20ms);
    }
    return check();
}

// Every route's second hop hangs, so every build waits at north for 30
// seconds, the client's build timeout. A fresh session starts from that
// state once the first one's spare is built, so no earlier build waits.
void hang_every_build(Harness& harness) {
    CHECK(harness.wait_until(
        [](const auto& status) { return status.circuits.size() == 1U; }));
    harness.runtime.sync([&] {
        harness.hanging = {"east", "west", "south"};
        harness.new_session();
    });
}

// An open waiting for a circuit settles as soon as it is cancelled, from
// another thread, and not when the build it waits for ends. Another open
// behind it in the queue keeps waiting.
void test_cancel_while_building(IoRuntime& io) {
    Harness harness(io, fast(1h, 1h, 1h));
    hang_every_build(harness);
    CancellationSource first;
    CancellationSource second;
    auto waiting = harness.open_async(first.token());
    auto behind = harness.open_async(second.token());
    CHECK(eventually([&] { return harness.entry_circuits() == 1U; }));
    CHECK(waiting.wait_for(300ms) == std::future_status::timeout);
    second.cancel();
    CHECK(behind.wait_for(2s) == std::future_status::ready &&
          behind.get().status().code() == StatusCode::Cancelled);
    CHECK(waiting.wait_for(0s) == std::future_status::timeout);
    first.cancel();
    CHECK(waiting.wait_for(2s) == std::future_status::ready &&
          waiting.get().status().code() == StatusCode::Cancelled);
    // An open whose token is cancelled already settles at once.
    CancellationSource done;
    done.cancel();
    auto late = harness.open_async(done.token());
    CHECK(late.wait_for(2s) == std::future_status::ready &&
          late.get().status().code() == StatusCode::Cancelled);
    // The build itself goes on for the next open.
    CHECK(harness.entry_circuits() == 1U);
}

// Closing the pool ends a circuit still being built at once, so the entry
// does not hold it until the build times out.
void test_close_while_building(IoRuntime& io) {
    Harness harness(io, fast(1h, 1h, 1h));
    hang_every_build(harness);
    CHECK(eventually([&] { return harness.entry_circuits() == 1U; }));
    harness.runtime.sync([&] { harness.pool->close(); });
    CHECK(eventually([&] { return harness.entry_circuits() == 0U; }, 2s));
    CHECK(harness.open().status().code() == StatusCode::Closed);
}

void test_open_allocation_failures(IoRuntime& io) {
    Harness harness(io, fast(1h, 1h, 1h));
    io.sync([&] { harness.pool->set_session(nullptr); });
    const auto destination = take(engine::RouteDestination::ipv4(
        engine::NetworkProtocol::Tcp, {192, 0, 2, 9}, 443U));
    bool covered_all = false;
    for (std::size_t nth = 1U; nth <= 16U; ++nth) {
        std::size_t calls = 0U;
        bool fired = false;
        io.sync([&] {
            CircuitPool::Opened done = [&](OpenResult result) {
                ++calls;
                CHECK(!result.ok());
                CHECK(result.status().code() == StatusCode::ResourceExhausted ||
                      result.status().code() == StatusCode::FailedPrecondition);
            };
            test::arm_allocation_failure(nth);
            harness.pool->open(destination, "internet", {}, std::move(done));
            fired = test::disarm_allocation_failure();
            CHECK(calls == 1U);
        });
        if (!fired) {
            covered_all = true;
            break;
        }
    }
    CHECK(covered_all);
}

// With a circuit ready, the pool removes its waiter before converting a
// DNS destination and wrapping ClientCircuit's callback. Faults anywhere in
// that handoff must still settle the removed waiter's completion.
void test_circuit_handoff_allocation_failures(IoRuntime& io) {
    const auto destination = take(engine::RouteDestination::dns_name(
        engine::NetworkProtocol::Tcp, "a-long-destination.example", 443U));
    bool covered_all = false;
    for (std::size_t nth = 0U; nth <= 256U; ++nth) {
        // Each fault may change circuit health or retry state. Start the
        // next injection with an independent ready pool.
        Harness harness(io, fast(1h, 1h, 1h));
        CHECK(harness.wait_until([](const auto& status) {
            return status.current_hops == 3U && status.circuits.size() == 1U;
        }));
        struct Outcome final {
            std::promise<OpenResult> result;
            std::size_t calls{0U};
        };
        auto outcome = std::make_shared<Outcome>();
        auto future = outcome->result.get_future();
        bool fired = false;
        io.sync([&] {
            CircuitPool::Opened done = [outcome](OpenResult result) {
                ++outcome->calls;
                if (outcome->calls == 1U)
                    outcome->result.set_value(std::move(result));
            };
            // First establish that the same operation succeeds without
            // injection. The sweep must then reach another successful
            // operation beyond its final allocation.
            if (nth != 0U) test::arm_allocation_failure(nth);
            harness.pool->open(destination, "internet", {}, std::move(done));
            if (nth != 0U) fired = test::disarm_allocation_failure();
        });
        const bool ready = future.wait_for(2s) == std::future_status::ready;
        CHECK(ready);
        if (ready) {
            auto result = future.get();
            if (!fired) CHECK(result.ok());
            if (result.ok()) harness.close(result.value());
        }
        io.sync([&] { CHECK(outcome->calls == 1U); });
        if (nth != 0U && !fired) {
            std::cout << "pool handoff allocation sweep: " << nth - 1U
                      << " injected positions and successful control\n";
            covered_all = true;
            break;
        }
    }
    CHECK(covered_all);
}

void test_direct_handoff_exceptions(IoRuntime& io) {
    Harness harness(io, fast(1h, 1h, 1h));
    io.sync([&] {
        harness.stopped = {"west", "south"};
        harness.new_session();
    });
    CHECK(eventually([&] { return harness.status().proposal.has_value(); }));
    const auto proposed = harness.status().proposal;
    CHECK(proposed && proposed->hops == 1U);
    if (!proposed || proposed->hops != 1U) return;
    const auto destination = take(engine::RouteDestination::ipv4(
        engine::NetworkProtocol::Tcp, {192, 0, 2, 9}, 443U));
    io.sync([&] {
        CHECK(harness.pool->accept(proposed->id).ok());
        for (const auto behavior : {TestSession::Direct::ThrowAllocation,
                                    TestSession::Direct::ThrowInternal,
                                    TestSession::Direct::CompleteThenThrow,
                                    TestSession::Direct::RetainThenThrow}) {
            harness.session->direct = behavior;
            std::size_t calls = 0U;
            StatusCode status = StatusCode::Ok;
            const auto before = harness.session->direct_opens;
            harness.pool->open(destination, "internet", {}, [&](OpenResult r) {
                ++calls;
                status = r.status().code();
            });
            CHECK(harness.session->direct_opens == before + 1U);
            if (auto late =
                    std::exchange(harness.session->late_direct, nullptr))
                late(OpenResult(Status(StatusCode::NotFound)));
            CHECK(calls == 1U);
            const auto expected =
                behavior == TestSession::Direct::CompleteThenThrow
                    ? StatusCode::NotFound
                : behavior == TestSession::Direct::ThrowInternal
                    ? StatusCode::Internal
                    : StatusCode::ResourceExhausted;
            CHECK(status == expected);
        }
    });
}

// Holds the view open so the pool has waiters but no circuit teardown that
// depends on the in-memory transport fixture's allocating close handlers.
class WaitingSession final : public runtime::CircuitSession {
public:
    void async_open(std::string_view, engine::ServiceKind,
                    std::optional<engine::RouteDestination>, CancellationToken,
                    Opened done) override {
        waiting = std::move(done);
    }

    Opened waiting;
};

void test_pending_consent_session_lifetime(IoRuntime& io) {
    Harness harness(io, fast(1h, 1h, 1h));
    io.sync([&] {
        harness.stopped = {"west", "south"};
        harness.new_session();
    });
    CHECK(eventually([&] { return harness.status().proposal.has_value(); }));
    const auto proposal = harness.status().proposal;
    if (!proposal) return;
    io.sync([&] {
        auto waiting = std::make_shared<WaitingSession>();
        harness.pool->set_session(waiting);
        CHECK(!harness.pool->status().proposal);
        CHECK(harness.pool->accept(proposal->id).code() ==
              StatusCode::NotFound);
        auto done = std::exchange(waiting->waiting, nullptr);
        CHECK(!!done);
        if (done) done(OpenResult(Status(StatusCode::FailedPrecondition)));
        CHECK(!harness.pool->status().proposal);
        CHECK(harness.pool->accept(proposal->id).code() ==
              StatusCode::NotFound);
        harness.new_session();
    });
    // The replacement view must be able to make a fresh proposal rather
    // than remain stuck waiting for consent that was discarded.
    CHECK(eventually([&] { return harness.status().proposal.has_value(); }));
    const auto replacement = harness.status().proposal;
    if (!replacement) return;
    io.sync([&] {
        CHECK(harness.pool->accept(replacement->id).ok());
        harness.pool->set_session(std::make_shared<WaitingSession>());
        CHECK(harness.pool->status().accepted_hops == replacement->hops);
        CHECK(harness.pool->status().current_hops == replacement->hops);
    });
}

std::string utc_timestamp(std::chrono::system_clock::time_point when) {
    const auto seconds = std::chrono::system_clock::to_time_t(when);
    std::tm utc{};
    char text[32]{};
    if (!::gmtime_r(&seconds, &utc) ||
        std::strftime(text, sizeof(text), "%Y-%m-%dT%H:%M:%SZ", &utc) == 0U)
        throw std::runtime_error("cannot format view expiry");
    return text;
}

void test_pending_consent_expiry(IoRuntime& io) {
    Harness harness(io, fast(1h, 1h, 1h));
    const auto expires = std::chrono::floor<std::chrono::seconds>(
                             std::chrono::system_clock::now()) +
                         3s;
    io.sync([&] {
        harness.stopped = {"west", "south"};
        harness.publish_view(7U, utc_timestamp(expires));
        harness.new_session();
    });
    CHECK(eventually([&] { return harness.status().proposal.has_value(); }));
    const auto proposal = harness.status().proposal;
    if (!proposal) return;
    // The maintenance tick is an hour away. Acceptance and status must
    // notice expiry themselves without waiting for that timer.
    std::this_thread::sleep_until(expires + 1ms);
    io.sync([&] {
        CHECK(!harness.pool->status().proposal);
        CHECK(harness.pool->accept(proposal->id).code() ==
              StatusCode::NotFound);
        CHECK(harness.pool->status().accepted_hops == 0U);
    });
}

// This fixture writes only state and state.new. Cleanup uses the acquired
// directory descriptor and does not allocate, including on test failure.
class StateDirectory final {
public:
    StateDirectory() {
        if (!::mkdtemp(path_)) throw std::runtime_error("mkdtemp failed");
        directory_ = ::open(path_, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (directory_ < 0) {
            (void)::rmdir(path_);
            throw std::runtime_error("cannot open state directory");
        }
    }
    StateDirectory(const StateDirectory&) = delete;
    StateDirectory& operator=(const StateDirectory&) = delete;
    ~StateDirectory() {
        for (const char* name : {"state", "state.new"})
            CHECK(::unlinkat(directory_, name, 0) == 0 || errno == ENOENT);
        CHECK(::close(directory_) == 0);
        CHECK(::rmdir(path_) == 0);
    }
    std::filesystem::path state() const {
        return std::filesystem::path(path_) / "state";
    }

private:
    char path_[48]{"/tmp/yume-pool-state-XXXXXX"};
    int directory_{-1};
};

void test_pending_consent_view_refresh(IoRuntime& io) {
    StateDirectory directory;
    Harness harness(io, fast(1h, 1h, 20ms), directory.state());
    const auto expires = std::chrono::floor<std::chrono::seconds>(
                             std::chrono::system_clock::now()) +
                         3s;
    io.sync([&] {
        harness.stopped = {"west", "south"};
        harness.publish_view(7U, utc_timestamp(expires));
        harness.new_session();
    });
    CHECK(eventually([&] { return harness.status().proposal.has_value(); }));
    const auto old = harness.status().proposal;
    if (!old) return;
    // The same session fetches serial 8 when serial 7 expires.
    io.sync([&] { harness.publish_view(8U); });
    CHECK(harness.wait_until([](const auto& status) {
        return status.serial == 8U && status.proposal &&
               status.proposal->serial == 8U;
    }));
    const auto replacement = harness.status().proposal;
    if (!replacement) return;
    CHECK(replacement->id != old->id);
    io.sync([&] {
        CHECK(harness.pool->accept(old->id).code() == StatusCode::NotFound);
        CHECK(harness.pool->accept(replacement->id).ok());
        CHECK(harness.pool->status().accepted_hops == replacement->hops);
    });
}

void test_pending_consent_close(IoRuntime& io) {
    Harness harness(io, fast(1h, 1h, 1h));
    io.sync([&] {
        harness.stopped = {"west", "south"};
        harness.new_session();
    });
    CHECK(eventually([&] { return harness.status().proposal.has_value(); }));
    const auto proposal = harness.status().proposal;
    if (!proposal) return;
    io.sync([&] {
        harness.pool->close();
        CHECK(!harness.pool->status().proposal);
        CHECK(harness.pool->accept(proposal->id).code() ==
              StatusCode::NotFound);
        CHECK(harness.pool->status().accepted_hops == 0U);
    });
}

void test_waiter_close_without_allocations(IoRuntime& io) {
    Harness harness(io, fast(1h, 1h, 1h));
    io.sync(
        [&] { harness.pool->set_session(std::make_shared<WaitingSession>()); });
    auto first = harness.open_async();
    auto second = harness.open_async();
    CHECK(first.wait_for(0s) == std::future_status::timeout);
    CHECK(second.wait_for(0s) == std::future_status::timeout);
    io.sync([&] {
        test::before_allocate = [](std::size_t) { throw std::bad_alloc(); };
        harness.pool->close();
        test::before_allocate = nullptr;
    });
    CHECK(first.wait_for(1s) == std::future_status::ready &&
          first.get().status().code() == StatusCode::Closed);
    CHECK(second.wait_for(1s) == std::future_status::ready &&
          second.get().status().code() == StatusCode::Closed);
}

void test_accept_without_allocations(IoRuntime& io) {
    Harness harness(io, fast(1h, 1h, 1h));
    io.sync([&] {
        harness.stopped = {"west", "south"};
        harness.new_session();
    });
    CHECK(eventually([&] { return harness.status().proposal.has_value(); }));
    const auto proposed = harness.status().proposal;
    if (!proposed) return;
    io.sync([&] {
        test::before_allocate = [](std::size_t) { throw std::bad_alloc(); };
        const auto accepted = harness.pool->accept(proposed->id);
        test::before_allocate = nullptr;
        CHECK(accepted.ok());
        CHECK(harness.pool->status().accepted_hops == proposed->hops);
    });
}

// A new session ends the earlier session's build at once and builds again
// on the new one.
void test_new_session_while_building(IoRuntime& io) {
    Harness harness(io, fast(1h, 1h, 1h));
    hang_every_build(harness);
    CHECK(eventually([&] { return harness.entry_circuits() == 1U; }));
    harness.runtime.sync([&] { harness.new_session(); });
    CHECK(eventually([&] { return harness.circuit_opens() == 1U; }));
    // The old build has ended and only the new one waits at north.
    CHECK(eventually([&] { return harness.entry_circuits() == 1U; }, 2s));
    std::this_thread::sleep_for(300ms);
    CHECK(harness.entry_circuits() == 1U);
}

bool through(const CircuitPoolStatus& status, std::string_view node) {
    return std::any_of(
        status.circuits.begin(), status.circuits.end(), [&](const auto& route) {
            return std::find(route.nodes.begin(), route.nodes.end(), node) !=
                   route.nodes.end();
        });
}

// A node that stopped stays out of routes while it is excluded, and once it
// is back and its exclusion has passed, circuits are built through it again.
void test_node_return(IoRuntime& io) {
    auto options = fast(100ms, 1h, 50ms);
    options.exclusion = 500ms;
    Harness harness(io, options);
    harness.runtime.sync([&] {
        harness.stopped.insert("west");
        harness.new_session();
    });
    std::vector<std::shared_ptr<StreamResponder>> streams;
    // Each stream rotates the circuit it took, so the pool keeps building.
    for (int index = 0; index < 4; ++index) {
        auto stream = harness.open();
        CHECK(stream.ok());
        if (!stream.ok()) return;
        CHECK(harness.echoes(stream.value()));
        streams.push_back(stream.value());
        CHECK(!through(harness.status(), "west"));
        std::this_thread::sleep_for(150ms);
    }
    harness.runtime.sync([&] { harness.stopped.clear(); });
    const auto returned = Clock::now();
    bool rebuilt = false;
    while (!rebuilt && Clock::now() - returned < 10s) {
        auto stream = harness.open();
        CHECK(stream.ok());
        if (!stream.ok()) break;
        CHECK(harness.echoes(stream.value()));
        streams.push_back(stream.value());
        rebuilt = through(harness.status(), "west");
        std::this_thread::sleep_for(150ms);
    }
    CHECK(rebuilt);
    for (const auto& stream : streams) harness.close(stream);
}

// With both exits stopped no route of three or two hops exists, so the pool
// proposes the direct session and refuses streams. Once the exits are back
// it returns to three hops by itself: the proposal ends and streams flow
// without any answer from the user.
void test_route_returns_without_consent(IoRuntime& io) {
    auto options = fast(1h, 1h, 50ms);
    options.exclusion = 500ms;
    options.recheck = 100ms;
    Harness harness(io, options);
    harness.runtime.sync([&] {
        harness.stopped = {"west", "south"};
        harness.new_session();
    });
    CHECK(eventually([&] { return harness.status().proposal.has_value(); }));
    const auto proposed = harness.status();
    CHECK(proposed.current_hops == 0U && proposed.proposal &&
          proposed.proposal->hops == 1U);
    CHECK(harness.open().status().code() == StatusCode::PermissionDenied);
    harness.runtime.sync([&] { harness.stopped.clear(); });
    CHECK(eventually([&] {
        const auto status = harness.status();
        return status.current_hops == 3U && !status.proposal &&
               status.accepted_hops == 0U;
    }));
    auto stream = harness.open();
    CHECK(stream.ok() && harness.echoes(stream.value()));
    if (stream.ok()) harness.close(stream.value());
}

// Circuits close inside the pool's loops over them: rotation in its timer,
// a new session and the pool's own close. Each closed circuit reports to the
// pool from inside close(), which must not change the list being walked.
void test_close_inside_loops(IoRuntime& io) {
    Harness harness(io, fast(200ms, 1h, 50ms));
    std::vector<std::shared_ptr<StreamResponder>> streams;
    for (int index = 0; index < 3; ++index) {
        auto stream = harness.open();
        CHECK(stream.ok());
        if (stream.ok()) streams.push_back(stream.value());
        // Each later stream finds the earlier circuit rotated.
        std::this_thread::sleep_for(400ms);
    }
    CHECK(harness.wait_until(
        [](const auto& status) { return with_streams(status) == 3U; }));
    // Every rotated circuit loses its last stream at once, so one timer
    // pass closes all of them.
    harness.runtime.sync([&] {
        for (const auto& stream : streams)
            stream->close(Status(StatusCode::Cancelled));
    });
    CHECK(harness.wait_until(
        [](const auto& status) { return with_streams(status) == 0U; }));
    auto after = harness.open();
    CHECK(after.ok() && harness.echoes(after.value()));
    CHECK(harness.wait_until(
        [](const auto& status) { return status.circuits.size() == 2U; }));
    // A new session ends every circuit, one of them carrying a stream.
    harness.runtime.sync([&] { harness.new_session(); });
    CHECK(harness.status().circuits.empty());
    auto next = harness.open();
    CHECK(next.ok() && harness.echoes(next.value()));
    CHECK(harness.wait_until(
        [](const auto& status) { return status.circuits.size() == 2U; }));
    // Closing the pool ends the rest, and later opens are refused.
    harness.runtime.sync([&] { harness.pool->close(); });
    CHECK(harness.status().circuits.empty());
    CHECK(harness.open().status().code() == StatusCode::Closed);
}

}  // namespace

int main() {
    try {
        IoRuntime io;
        test_build_at_session_start(io);
        test_window_capacity_selection(io);
        test_rotation(io);
        test_idle_close(io);
        test_spare_failure(io);
        test_exclusion(io);
        test_cancel_while_building(io);
        test_close_while_building(io);
        test_open_allocation_failures(io);
        test_circuit_handoff_allocation_failures(io);
        test_direct_handoff_exceptions(io);
        test_pending_consent_session_lifetime(io);
        test_pending_consent_expiry(io);
        test_pending_consent_view_refresh(io);
        test_pending_consent_close(io);
        test_waiter_close_without_allocations(io);
        test_accept_without_allocations(io);
        test_new_session_while_building(io);
        test_node_return(io);
        test_route_returns_without_consent(io);
        test_close_inside_loops(io);
    } catch (const std::exception& error) {
        std::cerr << "circuit pool test aborted: " << error.what() << '\n';
        return 1;
    }
    if (g_failures != 0) {
        std::cerr << g_failures << " circuit pool check(s) failed\n";
        return 1;
    }
    std::cout << "circuit pool tests passed\n";
    return 0;
}
