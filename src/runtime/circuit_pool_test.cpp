/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// The client's circuit pool over an in-memory session: four real circuit
// nodes, a routes view the operator signed and short pool timings, so the
// tests reach rotation, idle closing, the spare-failure rule, exclusion of a
// failed node and closing circuits from inside the pool's own loops.

#include <algorithm>
#include <chrono>
#include <exception>
#include <functional>
#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio/post.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "common/service_name.hpp"
#include "runtime/circuit_host.hpp"
#include "runtime/circuit_node.hpp"
#include "runtime/circuit_pool.hpp"
#include "runtime/cluster_list.hpp"
#include "test_support/circuit_fixtures.hpp"

namespace {

using namespace std::chrono_literals;
using namespace yume;
using engine::Buffer;
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
    struct Hooks final {
        std::shared_ptr<providers::AsioExecutionContext> context;
        std::shared_ptr<runtime::circuit::RoutesService> routes;
        std::shared_ptr<CircuitService> entry;
        // Circuit streams the session opens before it refuses the rest.
        std::size_t circuits_allowed{~std::size_t{0}};
    };

    explicit TestSession(Hooks hooks) : hooks_(std::move(hooks)) {}

    void async_open(std::string_view service_name, engine::ServiceKind,
                    std::optional<engine::RouteDestination>, CancellationToken,
                    Opened done) override {
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

private:
    Hooks hooks_;
};

struct Harness {
    Harness(IoRuntime& io, CircuitPoolOptions options)
        : runtime(io), crypto(std::make_shared<cc::CircuitCrypto>()) {
        runtime.sync([&] { start(std::move(options)); });
    }

    ~Harness() {
        // OpenSSL frees a library context's per-thread state only on the
        // thread that frees the context, and the nodes signed on this one.
        runtime.sync([this] {
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

    void start(CircuitPoolOptions options) {
        operator_key = test::make_identity(*crypto);
        for (const auto* name : kNodes)
            identities[name] = test::make_identity(*crypto);
        std::string nodes;
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
        const std::string view =
            "{\"schema\":1,\"cluster\":\"" +
            operator_key->identity.fingerprint +
            "\",\"serial\":7,\"not_after\":\"2099-01-01T00:00:00Z\","
            "\"nodes\":[" +
            nodes + "]}";
        const auto* bytes = reinterpret_cast<const std::byte*>(view.data());
        std::vector<std::byte> message(
            reinterpret_cast<const std::byte*>(
                runtime::cluster::kRoutesDomain.data()),
            reinterpret_cast<const std::byte*>(
                runtime::cluster::kRoutesDomain.data() +
                runtime::cluster::kRoutesDomain.size()));
        message.push_back(std::byte{0});
        message.insert(message.end(), bytes, bytes + view.size());
        auto served = std::make_shared<runtime::circuit::RoutesView>();
        served->view.assign(bytes, bytes + view.size());
        served->signature =
            keys::sign_composite(crypto->key_context(), *operator_key, message);
        routes = take(runtime::circuit::RoutesService::create(
            [served] { return served; }));

        for (const auto* name : kNodes) start_node(name);

        runtime::NativeCircuitCredentials credentials;
        credentials.operator_key_pem = composite_pem(*operator_key);
        credentials.cluster = operator_key->identity.fingerprint;
        credentials.entry = identities["north"]->identity.fingerprint;
        // The view's serial is saved already, so no state file is written.
        credentials.saved = 7U;
        pool = take(CircuitPool::create(
            runtime.context(), std::move(credentials), std::move(options),
            [this](std::string_view text) { said.emplace_back(text); }));
        new_session();
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

    OpenResult open(std::uint16_t port = 443U) {
        auto promise = std::make_shared<std::promise<OpenResult>>();
        auto future = promise->get_future();
        runtime.sync([&] {
            pool->open(take(engine::RouteDestination::ipv4(
                           engine::NetworkProtocol::Tcp, {192, 0, 2, 9}, port)),
                       "internet", {}, [promise](OpenResult opened) {
                           promise->set_value(std::move(opened));
                       });
        });
        if (future.wait_for(20s) != std::future_status::ready)
            return OpenResult(Status(StatusCode::Cancelled));
        return future.get();
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
    std::vector<std::shared_ptr<PipeEnd>> links;
    std::shared_ptr<CircuitPool> pool;
    std::shared_ptr<TestSession> session;
    // Nodes whose previous hop cannot reach them.
    std::set<std::string> stopped;
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
        test_rotation(io);
        test_idle_close(io);
        test_spare_failure(io);
        test_exclusion(io);
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
