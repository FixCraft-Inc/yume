/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Circuit nodes and the client over in-memory streams: builds, relaying,
// exits, flow control and every refusal the node or client must make, on one
// execution thread with no network.

#include <atomic>
#include <chrono>
#include <exception>
#include <functional>
#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio/post.hpp>

#include "runtime/circuit_client.hpp"
#include "runtime/circuit_node.hpp"
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
namespace cc = yume::providers::circuit;
namespace c1 = yume::circuit1;
namespace keys = yume::providers::keys;
using runtime::circuit::CircuitService;
using runtime::circuit::ClientCircuit;
using test::destination;
using test::EchoChannel;
using test::IoRuntime;
using test::make_identity;
using test::open_context;
using test::PipeEnd;
using test::take;

int g_failures = 0;

#define CHECK(condition)                                        \
    do {                                                        \
        if (!(condition)) {                                     \
            std::cerr << __FILE__ << ':' << __LINE__            \
                      << ": check failed: " #condition << '\n'; \
            ++g_failures;                                       \
        }                                                       \
    } while (false)

// A destination that always has data and discards what it is sent. It
// counts its closes in closed.
class SourceChannel final : public engine::ByteChannel {
public:
    SourceChannel(std::shared_ptr<providers::AsioExecutionContext> context,
                  std::shared_ptr<std::atomic<int>> closed)
        : context_(std::move(context)), closed_count_(std::move(closed)) {}
    engine::ExecutorAffinity executor_affinity() const noexcept override {
        return context_->affinity();
    }
    std::size_t max_read_size() const noexcept override { return 65536U; }
    std::size_t max_write_size() const noexcept override { return 65536U; }
    void async_read(std::size_t max_bytes, CancellationToken,
                    ReadCompletion completion) override {
        if (closed_) {
            boost::asio::post(
                context_->executor(), [completion = std::move(completion)] {
                    completion(Result<Buffer>(Status(StatusCode::Closed)));
                });
            return;
        }
        auto shared = std::make_shared<Buffer>(take(Buffer::allocate(
            std::min<std::size_t>(max_bytes, 65536U), 65536U)));
        boost::asio::post(context_->executor(),
                          [completion = std::move(completion), shared] {
                              completion(Result<Buffer>(std::move(*shared)));
                          });
    }
    void async_write(Buffer buffer, CancellationToken,
                     WriteCompletion completion) override {
        const auto size = buffer.size();
        boost::asio::post(context_->executor(),
                          [completion = std::move(completion), size] {
                              completion(Status::success(), size);
                          });
    }
    Status shutdown_write() noexcept override { return Status::success(); }
    void cancel() noexcept override {}
    void close() noexcept override {
        if (!std::exchange(closed_, true)) ++*closed_count_;
    }

private:
    std::shared_ptr<providers::AsioExecutionContext> context_;
    std::shared_ptr<std::atomic<int>> closed_count_;
    bool closed_{false};
};

ytp1::Destination named(std::uint16_t port) {
    ytp1::Destination result;
    result.transport = ytp1::TransportProtocol::Tcp;
    result.address_kind = ytp1::AddressKind::Dns;
    result.dns_name = "missing.example";
    result.port = port;
    return result;
}

// Three nodes, north, east and west, with west an exit. Each open_next
// makes an in-memory stream to the named node unless redirected.
struct Cluster {
    explicit Cluster(IoRuntime& io, bool every_exit = false)
        : runtime(io),
          crypto(std::make_shared<cc::CircuitCrypto>()),
          exit_everywhere(every_exit) {
        for (const auto* name : {"north", "east", "west", "stranger"}) {
            identities[name] = make_identity(*crypto);
        }
        for (const auto* name : {"north", "east", "west"}) {
            runtime::circuit::NodeEnvironment environment;
            environment.context = runtime.context();
            environment.crypto = crypto;
            environment.identity = identities[name];
            environment.is_peer = [this](std::string_view identity) {
                for (const auto* node : {"north", "east", "west"}) {
                    if (identities[node]->identity.fingerprint == identity)
                        return true;
                }
                return false;
            };
            const std::string self = name;
            environment.open_next = [this, self](
                                        std::string_view peer,
                                        CancellationToken,
                                        runtime::circuit::StreamOpened done) {
                std::string target;
                for (const auto& [node, service] : services) {
                    if (identities[node]->identity.fingerprint == peer)
                        target = node;
                }
                if (const auto redirect = redirects.find(self + ">" + target);
                    redirect != redirects.end()) {
                    target = redirect->second;
                }
                if (target.empty()) {
                    done(Result<std::shared_ptr<StreamResponder>>(
                        Status(StatusCode::NotFound)));
                    return;
                }
                auto [mine, theirs] = PipeEnd::pair(runtime.context());
                links.push_back(mine);
                // A node that takes the stream and never answers.
                if (target == "silent") {
                    client_ends.push_back(theirs);
                    done(Result<std::shared_ptr<StreamResponder>>(mine));
                    return;
                }
                services[target]->async_open(
                    open_context(identities[self]->identity.fingerprint),
                    theirs, [](Status) {});
                done(Result<std::shared_ptr<StreamResponder>>(mine));
            };
            if (std::string(name) == "west" || exit_everywhere) {
                environment.open_exit =
                    [this](const engine::StreamOpenContext&,
                           const ytp1::Destination& to, CancellationToken,
                           runtime::circuit::ChannelOpened done) {
                        // As the route provider reports a refusal, a
                        // failed lookup or connection and a connect timeout.
                        const std::map<std::uint16_t, StatusCode> failures{
                            {25, StatusCode::PermissionDenied},
                            {26, StatusCode::NotFound},
                            {27, StatusCode::Closed}};
                        if (const auto failure = failures.find(to.port);
                            failure != failures.end()) {
                            done(Result<std::unique_ptr<engine::ByteChannel>>(
                                Status(failure->second)));
                            return;
                        }
                        if (to.port == 19) {
                            done(Result<std::unique_ptr<engine::ByteChannel>>(
                                std::make_unique<SourceChannel>(
                                    runtime.context(), sources_closed)));
                            return;
                        }
                        done(Result<std::unique_ptr<engine::ByteChannel>>(
                            std::make_unique<EchoChannel>(runtime.context())));
                    };
            }
            services[name] =
                take(CircuitService::create(std::move(environment)));
        }
    }
    ~Cluster() {
        runtime.sync([this] {
            for (auto& [name, service] : services) service->close();
            for (const auto& link : links)
                link->close(Status(StatusCode::Cancelled));
            // OpenSSL frees a library context's per-thread state, such as
            // the random generator ML-DSA signing created, only for the
            // thread that frees the context. The nodes signed on this
            // thread, so the keys and contexts go here too.
            services.clear();
            links.clear();
            client_ends.clear();
            identities.clear();
            crypto.reset();
        });
    }

    // A client stream into north, and a circuit over it.
    // Each call is a new client unless one is named, so rate bounds stay
    // out of the way of tests that do not test them.
    std::shared_ptr<ClientCircuit> circuit(
        const std::vector<std::string>& route, std::string client = {},
        Status* accepted = nullptr,
        runtime::circuit::ClientLimits limits = {}) {
        if (client.empty()) {
            client = std::to_string(++clients);
            client.insert(0, 64U - client.size(), 'e');
        }
        return runtime.sync([&] {
            auto [mine, theirs] = PipeEnd::pair(runtime.context());
            client_ends.push_back(mine);
            Status acceptance;
            services[route.front()]->async_open(
                open_context(client), theirs,
                [&](Status status) { acceptance = status; });
            if (accepted) *accepted = acceptance;
            std::vector<keys::CompositePublic> hops;
            for (const auto& name : route)
                hops.push_back(identities[name]->identity);
            return take(ClientCircuit::create(runtime.context(), crypto, mine,
                                              hops, limits));
        });
    }

    Status build(const std::shared_ptr<ClientCircuit>& circuit) {
        auto promise = std::make_shared<std::promise<Status>>();
        auto future = promise->get_future();
        runtime.sync([&] {
            circuit->build(
                [promise](Status status) { promise->set_value(status); });
        });
        if (future.wait_for(20s) != std::future_status::ready)
            return Status(StatusCode::Cancelled);
        return future.get();
    }

    Result<std::shared_ptr<StreamResponder>> open(
        const std::shared_ptr<ClientCircuit>& circuit, std::uint16_t port) {
        return open(circuit, destination(port));
    }
    Result<std::shared_ptr<StreamResponder>> open(
        const std::shared_ptr<ClientCircuit>& circuit,
        const ytp1::Destination& to) {
        auto promise = std::make_shared<
            std::promise<Result<std::shared_ptr<StreamResponder>>>>();
        auto future = promise->get_future();
        runtime.sync([&] {
            circuit->open_stream(
                to, [promise](Result<std::shared_ptr<StreamResponder>> r) {
                    promise->set_value(std::move(r));
                });
        });
        if (future.wait_for(20s) != std::future_status::ready)
            return Result<std::shared_ptr<StreamResponder>>(
                Status(StatusCode::Cancelled));
        return future.get();
    }

    IoRuntime& runtime;
    std::shared_ptr<cc::CircuitCrypto> crypto;
    std::shared_ptr<std::atomic<int>> sources_closed{
        std::make_shared<std::atomic<int>>(0)};
    bool exit_everywhere{false};
    std::size_t clients{0U};
    std::map<std::string, std::shared_ptr<const keys::CompositePrivate>>
        identities;
    std::map<std::string, std::shared_ptr<CircuitService>> services;
    std::map<std::string, std::string> redirects;
    std::vector<std::shared_ptr<PipeEnd>> links;
    std::vector<std::shared_ptr<PipeEnd>> client_ends;
};

// Writes data into a stream, shuts it, and reads back until the end.
std::vector<std::byte> echo(IoRuntime& io,
                            const std::shared_ptr<StreamResponder>& stream,
                            const std::vector<std::byte>& data) {
    auto received = std::make_shared<std::vector<std::byte>>();
    auto done = std::make_shared<std::promise<Status>>();
    auto future = done->get_future();
    io.sync([&] {
        std::size_t offset = 0U;
        while (offset < data.size()) {
            const auto chunk =
                std::min<std::size_t>(data.size() - offset, 60000U);
            auto buffer = take(Buffer::copy_from(
                std::span(data).subspan(offset, chunk), 65536U));
            stream->async_write(std::move(buffer), {},
                                [](Status, std::size_t) {});
            offset += chunk;
        }
        (void)stream->shutdown_write();
        auto reader = std::make_shared<std::function<void()>>();
        *reader = [stream, received, done, reader] {
            stream->async_read({}, [stream, received, done,
                                    reader](Result<ReceivedRecord> result) {
                if (!result.ok()) {
                    done->set_value(result.status());
                    *reader = nullptr;
                    return;
                }
                auto record = std::move(result).take_value();
                const auto bytes = record.payload().bytes();
                received->insert(received->end(), bytes.begin(), bytes.end());
                (*reader)();
            });
        };
        (*reader)();
    });
    if (future.wait_for(20s) != std::future_status::ready) {
        std::cerr << "echo did not finish\n";
        ++g_failures;
        return {};
    }
    CHECK(future.get().code() == StatusCode::EndOfStream);
    return *received;
}

std::vector<std::byte> pattern(std::size_t size) {
    std::vector<std::byte> data(size);
    for (std::size_t index = 0U; index < size; ++index)
        data[index] = static_cast<std::byte>(index * 7U + 3U);
    return data;
}

void test_three_hops(Cluster& cluster) {
    auto circuit = cluster.circuit({"north", "east", "west"});
    CHECK(cluster.build(circuit).ok());
    CHECK(cluster.runtime.sync([&] { return circuit->ready(); }));
    CHECK(cluster.runtime.sync([&] { return circuit->hop_times().size(); }) ==
          3U);
    auto stream = cluster.open(circuit, 443);
    CHECK(stream.ok());
    if (!stream.ok()) return;
    // More than the stream window both ways, so credit must flow.
    const auto data = pattern(900U * 1024U);
    CHECK(echo(cluster.runtime, stream.value(), data) == data);
    const auto status = cluster.runtime.sync(
        [&] { return cluster.services["west"]->status(); });
    CHECK(status.circuits == 1U);
    const auto north = cluster.runtime.sync(
        [&] { return cluster.services["north"]->status(); });
    CHECK(north.entry_circuits == 1U && north.relayed_circuits == 1U);
    // Each link's circuits are counted on their own at each end, so no
    // count names both neighbours of one circuit.
    const auto east = cluster.runtime.sync(
        [&] { return cluster.services["east"]->status(); });
    const auto fingerprint = [&](const char* name) {
        return cluster.identities[name]->identity.fingerprint;
    };
    using Counts = std::pair<std::size_t, std::size_t>;
    const auto counts = [](const runtime::circuit::NodeStatus& node,
                           const std::string& peer) {
        for (const auto& link : node.links) {
            if (link.peer_identity == peer)
                return Counts(link.inbound, link.outbound);
        }
        return Counts(0U, 0U);
    };
    CHECK(north.links.size() == 1U &&
          counts(north, fingerprint("east")) == Counts(0U, 1U));
    CHECK(east.links.size() == 2U &&
          counts(east, fingerprint("north")) == Counts(1U, 0U) &&
          counts(east, fingerprint("west")) == Counts(0U, 1U));
    CHECK(status.links.size() == 1U &&
          counts(status, fingerprint("east")) == Counts(1U, 0U));
    // Two streams on one circuit at once.
    auto first = cluster.open(circuit, 80);
    auto second = cluster.open(circuit, 22);
    CHECK(first.ok() && second.ok());
    if (first.ok() && second.ok()) {
        CHECK(echo(cluster.runtime, first.value(), pattern(1000U)) ==
              pattern(1000U));
        CHECK(echo(cluster.runtime, second.value(), pattern(70000U)) ==
              pattern(70000U));
    }
    cluster.runtime.sync([&] { circuit->close(); });
}

// Reads and releases drain bytes of an endless stream, then reads and keeps
// records until none arrives for half a second. Returns how many bytes it
// kept: what the client's window let the exit send ahead of the reader.
std::size_t sent_ahead(Cluster& cluster,
                       const std::shared_ptr<StreamResponder>& stream,
                       std::size_t drain) {
    struct Reader {
        std::size_t drained{0U};
        std::size_t kept_bytes{0U};
        std::vector<ReceivedRecord> kept;
        std::chrono::steady_clock::time_point last{
            std::chrono::steady_clock::now()};
    };
    auto reader = std::make_shared<Reader>();
    auto next = std::make_shared<std::function<void()>>();
    *next = [stream, reader, next, drain] {
        stream->async_read(
            {}, [reader, next, drain](Result<ReceivedRecord> result) {
                if (!result.ok()) return;
                auto record = std::move(result).take_value();
                // A record released here returns its credit.
                if (reader->drained < drain) {
                    reader->drained += record.payload().size();
                } else {
                    reader->kept_bytes += record.payload().size();
                    reader->kept.push_back(std::move(record));
                }
                reader->last = std::chrono::steady_clock::now();
                if (*next) (*next)();
            });
    };
    cluster.runtime.sync([&] { (*next)(); });
    const auto deadline = std::chrono::steady_clock::now() + 20s;
    while (std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(100ms);
        const bool quiet = cluster.runtime.sync([&] {
            return reader->drained >= drain &&
                   std::chrono::steady_clock::now() - reader->last > 500ms;
        });
        if (quiet) break;
    }
    return cluster.runtime.sync([&] {
        CHECK(reader->drained >= drain);
        *next = nullptr;
        stream->close(Status(StatusCode::Cancelled));
        reader->kept.clear();
        return reader->kept_bytes;
    });
}

// The client grows a stream's window as its reader drains it, up to 1 MiB,
// and not past the circuit's total.
void test_window_growth(Cluster& cluster) {
    const std::size_t first_window =
        runtime::circuit::ClientLimits{}.stream_window;
    auto circuit = cluster.circuit({"north", "east", "west"});
    CHECK(cluster.build(circuit).ok());
    auto stream = cluster.open(circuit, 19);
    CHECK(stream.ok());
    if (stream.ok()) {
        const auto ahead = sent_ahead(cluster, stream.value(), 3U << 20U);
        CHECK(ahead > first_window && ahead <= (1U << 20U));
    }
    cluster.runtime.sync([&] { circuit->close(); });

    runtime::circuit::ClientLimits capped;
    capped.circuit_window = capped.stream_window;
    auto held = cluster.circuit({"north", "west"}, {}, nullptr, capped);
    CHECK(cluster.build(held).ok());
    auto small = cluster.open(held, 19);
    CHECK(small.ok());
    if (small.ok())
        CHECK(sent_ahead(cluster, small.value(), 3U << 20U) <= first_window);
    cluster.runtime.sync([&] { held->close(); });
}

// A client that finished writing and then drops the stream before the exit
// finished ends it at the exit, which closes the destination.
void test_dropped_after_done(Cluster& cluster) {
    auto circuit = cluster.circuit({"north", "west"});
    CHECK(cluster.build(circuit).ok());
    auto stream = cluster.open(circuit, 19);
    CHECK(stream.ok());
    if (stream.ok()) {
        const int before = cluster.sources_closed->load();
        cluster.runtime.sync([&] {
            CHECK(stream.value()->shutdown_write().ok());
            stream.value()->close(Status(StatusCode::Cancelled));
        });
        const auto deadline = std::chrono::steady_clock::now() + 10s;
        while (cluster.sources_closed->load() == before &&
               std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(20ms);
        CHECK(cluster.sources_closed->load() == before + 1);
    }
    cluster.runtime.sync([&] { circuit->close(); });
}

void test_two_hops_and_refusals(Cluster& cluster) {
    auto circuit = cluster.circuit({"north", "west"});
    CHECK(cluster.build(circuit).ok());
    auto refused = cluster.open(circuit, 25);
    CHECK(!refused.ok() &&
          refused.status().code() == StatusCode::PermissionDenied);
    // A destination the exit could not reach is a route failure, which
    // SOCKS5 answers as host unreachable, never as not allowed. Only a name
    // can have failed to resolve.
    const auto failed = [&](const ytp1::Destination& to,
                            std::string_view message) {
        auto result = cluster.open(circuit, to);
        return !result.ok() && result.status().code() == StatusCode::Internal &&
               result.status().message() == message;
    };
    CHECK(failed(destination(26), "the destination could not be reached"));
    CHECK(failed(named(26), "the destination's name did not resolve"));
    CHECK(failed(destination(27), "the destination did not answer in time"));
    auto stream = cluster.open(circuit, 443);
    CHECK(stream.ok());
    if (stream.ok())
        CHECK(echo(cluster.runtime, stream.value(), pattern(10U)) ==
              pattern(10U));
    cluster.runtime.sync([&] { circuit->close(); });

    // A middle that is no exit refuses a stream.
    auto short_circuit = cluster.circuit({"north", "east"});
    CHECK(cluster.build(short_circuit).ok());
    auto none = cluster.open(short_circuit, 443);
    CHECK(!none.ok() && none.status().code() == StatusCode::PermissionDenied);
    cluster.runtime.sync([&] { short_circuit->close(); });
}

void test_extend_failures(Cluster& cluster) {
    // A node north does not know.
    auto unknown = cluster.circuit({"north", "stranger"});
    CHECK(!cluster.build(unknown).ok());
    const auto failure =
        cluster.runtime.sync([&] { return unknown->failure(); });
    CHECK(failure && failure->hop == 2U &&
          failure->reason == c1::CircuitReason::Refused);

    // north quietly routes toward east through west instead: west signs as
    // west, and the client refuses.
    cluster.redirects["north>east"] = "west";
    auto hidden = cluster.circuit({"north", "east", "west"});
    CHECK(!cluster.build(hidden).ok());
    const auto caught = cluster.runtime.sync([&] { return hidden->failure(); });
    CHECK(caught && caught->hop == 2U &&
          caught->reason == c1::CircuitReason::Protocol);

    // east takes the extension and never answers. The client blames the
    // hop it was extending to, not the entry that forwarded the request.
    cluster.redirects["north>east"] = "silent";
    runtime::circuit::ClientLimits limits;
    limits.build_timeout = 300ms;
    auto quiet =
        cluster.circuit({"north", "east", "west"}, {}, nullptr, limits);
    CHECK(!cluster.build(quiet).ok());
    const auto timed_out =
        cluster.runtime.sync([&] { return quiet->failure(); });
    CHECK(timed_out && timed_out->hop == 2U &&
          timed_out->reason == c1::CircuitReason::Timeout);
    cluster.runtime.sync([&] { quiet->close(); });
    cluster.redirects.clear();
}

void test_middle_loss(Cluster& cluster) {
    auto circuit = cluster.circuit({"north", "east", "west"});
    CHECK(cluster.build(circuit).ok());
    auto closed = std::make_shared<std::promise<void>>();
    auto future = closed->get_future();
    cluster.runtime.sync([&] {
        circuit->on_closed([closed] { closed->set_value(); });
        // The link north opened to east ends.
        for (const auto& link : cluster.links)
            link->close(Status(StatusCode::Cancelled));
    });
    CHECK(future.wait_for(20s) == std::future_status::ready);
    const auto failure =
        cluster.runtime.sync([&] { return circuit->failure(); });
    CHECK(failure && failure->hop == 1U &&
          failure->reason == c1::CircuitReason::Unreachable);
}

void test_client_bounds(Cluster& cluster) {
    std::vector<std::shared_ptr<ClientCircuit>> held;
    const std::string client(64, 'd');
    for (int index = 0; index < 4; ++index) {
        Status accepted;
        held.push_back(cluster.circuit({"north", "west"}, client, &accepted));
        CHECK(accepted.ok());
    }
    Status fifth;
    auto refused = cluster.circuit({"north", "west"}, client, &fifth);
    CHECK(fifth.code() == StatusCode::ResourceExhausted);
    const auto status = cluster.runtime.sync(
        [&] { return cluster.services["north"]->status(); });
    CHECK(status.refused_client_circuits >= 1U &&
          status.refused >= status.refused_client_circuits);
    cluster.runtime.sync([&] {
        for (const auto& circuit : held) circuit->close();
        refused->close();
    });
}

// The exit grants at most 8 MiB of stream window across one circuit, so
// with 256 KiB windows the 33rd stream at once is refused.
void test_circuit_window_total(Cluster& cluster) {
    auto circuit = cluster.circuit({"north", "west"});
    CHECK(cluster.build(circuit).ok());
    std::vector<std::shared_ptr<StreamResponder>> held;
    for (int index = 0; index < 32; ++index) {
        auto stream = cluster.open(circuit, 443);
        CHECK(stream.ok());
        if (stream.ok()) held.push_back(stream.value());
    }
    auto refused = cluster.open(circuit, 443);
    CHECK(!refused.ok() && refused.status().code() == StatusCode::ResourceExhausted);
    const auto status = cluster.runtime.sync(
        [&] { return cluster.services["west"]->status(); });
    CHECK(status.refused_streams >= 1U && status.exit_streams == 32U);
    cluster.runtime.sync([&] {
        for (const auto& stream : held) stream->close(Status(StatusCode::Cancelled));
        circuit->close();
    });
}

// A one-hop circuit adds no privacy, so even an exit refuses its stream.
void test_one_hop_exit_refused(IoRuntime& io) {
    Cluster everywhere(io, true);
    auto circuit = everywhere.circuit({"north"});
    CHECK(everywhere.build(circuit).ok());
    auto refused = everywhere.open(circuit, 443);
    CHECK(!refused.ok() &&
          refused.status().code() == StatusCode::PermissionDenied);
    auto two = everywhere.circuit({"north", "east"});
    CHECK(everywhere.build(two).ok());
    auto allowed = everywhere.open(two, 443);
    CHECK(allowed.ok());
    everywhere.runtime.sync([&] {
        circuit->close();
        two->close();
    });
}

}  // namespace

int main() {
    try {
        IoRuntime io;
        {
            Cluster cluster(io);
            test_three_hops(cluster);
            test_window_growth(cluster);
            test_dropped_after_done(cluster);
            test_two_hops_and_refusals(cluster);
            test_extend_failures(cluster);
            test_client_bounds(cluster);
            test_circuit_window_total(cluster);
            test_middle_loss(cluster);
        }
        test_one_hop_exit_refused(io);
    } catch (const std::exception& error) {
        std::cerr << "circuit runtime test aborted: " << error.what() << '\n';
        return 1;
    }
    if (g_failures != 0) {
        std::cerr << g_failures << " circuit runtime check(s) failed\n";
        return 1;
    }
    std::cout << "circuit runtime tests passed\n";
    return 0;
}
