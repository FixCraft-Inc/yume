/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/circuit_pool.hpp"

#include <algorithm>
#include <array>
#include <deque>
#include <map>
#include <new>
#include <random>
#include <utility>

#include <boost/asio/basic_waitable_timer.hpp>
#include <boost/asio/post.hpp>

#include "common/service_name.hpp"
#include "providers/circuit_crypto.hpp"
#include "runtime/circuit_routes.hpp"
#include "runtime/client_routes.hpp"
#include "runtime/plain_http_guard.hpp"
#include "ytp/security.hpp"

namespace yume::runtime {
namespace {

using engine::Buffer;
using engine::CancellationToken;
using engine::ReceivedRecord;
using engine::Result;
using engine::RouteDestination;
using engine::Status;
using engine::StatusCode;
using engine::StreamResponder;
using Clock = std::chrono::steady_clock;
using Timer = boost::asio::basic_waitable_timer<
    Clock, boost::asio::wait_traits<Clock>,
    providers::AsioExecutionContext::Executor>;

// The exit grants 8 MiB of 256 KiB stream windows per circuit (CLUSTER_1).
constexpr std::size_t kStreamsPerCircuit = 32U;

Result<ytp1::Destination> circuit_destination(const RouteDestination& route) {
    if (route.protocol() != engine::NetworkProtocol::Tcp)
        return Result<ytp1::Destination>(Status(StatusCode::InvalidArgument));
    ytp1::Destination destination;
    destination.transport = ytp1::TransportProtocol::Tcp;
    destination.port = route.port();
    switch (route.address_kind()) {
        case engine::RouteAddressKind::Ipv4:
            destination.address_kind = ytp1::AddressKind::Ipv4;
            destination.address_length = 4U;
            std::copy(route.address_bytes().begin(),
                      route.address_bytes().end(), destination.address.begin());
            break;
        case engine::RouteAddressKind::Ipv6:
            destination.address_kind = ytp1::AddressKind::Ipv6;
            destination.address_length = 16U;
            std::copy(route.address_bytes().begin(),
                      route.address_bytes().end(), destination.address.begin());
            break;
        case engine::RouteAddressKind::DnsName:
            destination.address_kind = ytp1::AddressKind::Dns;
            destination.dns_name.assign(route.dns_name());
            break;
    }
    return Result<ytp1::Destination>(std::move(destination));
}

const char* reason_name(circuit1::CircuitReason reason) noexcept {
    switch (reason) {
        case circuit1::CircuitReason::Unreachable:
            return "unreachable";
        case circuit1::CircuitReason::Busy:
            return "busy";
        case circuit1::CircuitReason::Timeout:
            return "timeout";
        case circuit1::CircuitReason::Protocol:
            return "protocol";
        case circuit1::CircuitReason::Refused:
            return "refused";
        case circuit1::CircuitReason::Closing:
            return "closing";
    }
    return "unknown";
}

std::string hex(std::span<const std::byte> bytes) {
    constexpr char kDigits[] = "0123456789abcdef";
    std::string text;
    for (const auto byte : bytes) {
        text.push_back(kDigits[std::to_integer<unsigned>(byte) >> 4U]);
        text.push_back(kDigits[std::to_integer<unsigned>(byte) & 15U]);
    }
    return text;
}

class EngineCircuitSession final : public CircuitSession {
public:
    explicit EngineCircuitSession(
        std::shared_ptr<engine::SessionEngine> session)
        : session_(std::move(session)) {}

    void async_open(std::string_view service_name, engine::ServiceKind kind,
                    std::optional<RouteDestination> destination,
                    CancellationToken cancellation, Opened done) override {
        session_->async_open(service_name, kind, std::move(destination),
                             std::move(cancellation), std::move(done));
    }

private:
    std::shared_ptr<engine::SessionEngine> session_;
};

}  // namespace

std::shared_ptr<CircuitSession> engine_circuit_session(
    std::shared_ptr<engine::SessionEngine> session) {
    if (!session) return nullptr;
    return std::make_shared<EngineCircuitSession>(std::move(session));
}

struct CircuitPool::State final : std::enable_shared_from_this<State> {
    struct Waiter final {
        RouteDestination destination;
        std::string direct_service;
        CancellationToken cancellation;
        Opened done;
    };

    struct Entry final {
        std::shared_ptr<circuit::ClientCircuit> circuit;
        std::vector<cluster::RouteNode> route;
        Clock::time_point built{};
        std::optional<Clock::time_point> first_stream;
        std::optional<Clock::time_point> idle_since;
    };

    enum class View { Idle, Fetching, Ready, Failed };

    State(std::shared_ptr<providers::AsioExecutionContext> runner,
          NativeCircuitCredentials credentials, CircuitPoolOptions settings,
          Report sink)
        : context(std::move(runner)),
          circuits(std::move(credentials)),
          options(std::move(settings)),
          report(std::move(sink)),
          current_hops(options.hops),
          tick(context->executor()) {}

    std::shared_ptr<providers::AsioExecutionContext> context;
    std::shared_ptr<const providers::circuit::CircuitCrypto> crypto;
    NativeCircuitCredentials circuits;
    CircuitPoolOptions options;
    Report report;

    std::shared_ptr<CircuitSession> session;
    // Callbacks of an earlier session carry an older generation and change
    // nothing.
    std::uint64_t generation{0U};
    View view{View::Idle};
    std::string stopped;
    std::optional<circuit::RouteChooser> chooser;
    std::chrono::system_clock::time_point view_expires{};
    std::uint64_t serial{0U};
    std::map<std::string, std::chrono::milliseconds, std::less<>> measured;
    std::map<std::string, Clock::time_point, std::less<>> excluded;

    std::vector<Entry> entries;
    std::deque<Waiter> waiters;
    bool building{false};
    std::size_t attempts{0U};
    std::size_t current_hops;
    std::size_t accepted_hops{0U};
    std::optional<RouteProposal> proposal;
    std::optional<Clock::time_point> next_recheck;
    // A spare is not built again before this, after one failed.
    Clock::time_point spare_after{};
    Timer tick;
    bool ticking{false};
    bool closed{false};

    void say(std::string_view text) noexcept {
        if (!report) return;
        try {
            report(text);
        } catch (...) {
        }
    }

    static void settle(
        Opened& done,
        Result<std::shared_ptr<StreamResponder>> result) noexcept {
        auto completion = std::move(done);
        done = nullptr;
        if (!completion) return;
        try {
            completion(std::move(result));
        } catch (...) {
        }
    }

    void fail_waiters(const Status& status) noexcept {
        auto failing = std::move(waiters);
        waiters.clear();
        for (auto& waiter : failing)
            settle(waiter.done,
                   Result<std::shared_ptr<StreamResponder>>(status));
    }

    std::size_t allowed_min() const noexcept {
        std::size_t lowest = options.min_hops;
        if (accepted_hops != 0U) lowest = std::min(lowest, accepted_hops);
        return lowest;
    }

    // Keeps the node that stopped a failed build out of routes.
    void exclude_failed(const std::vector<cluster::RouteNode>& route,
                        const std::optional<circuit::CircuitFailure>& failure) {
        const auto* node =
            failure ? circuit::stopped_at(route, failure->hop) : nullptr;
        if (!node) return;
        const auto& identity = node->identity.fingerprint;
        excluded[identity] = Clock::now() + circuit::RouteChooser::kExclusion;
        if (chooser) chooser->exclude(identity, Clock::now());
    }

    std::mt19937_64 fresh_random() {
        std::random_device device;
        std::seed_seq seed{device(), device(), device(), device()};
        return std::mt19937_64(seed);
    }

    void arm_tick() noexcept {
        if (ticking || closed) return;
        ticking = true;
        try {
            tick.expires_after(options.tick);
            tick.async_wait([weak = weak_from_this()](
                                const boost::system::error_code& error) {
                const auto self = weak.lock();
                if (!self) return;
                self->ticking = false;
                if (error || self->closed) return;
                self->maintain();
            });
        } catch (...) {
            ticking = false;
        }
    }

    // Closes idle and rotated circuits, retries a stopped view and, while a
    // shorter route is in use, tries the configured length again.
    void maintain() noexcept {
        const auto now = Clock::now();
        try {
            std::size_t spares = 0U;
            for (auto& entry : entries) {
                if (entry.circuit->closed()) continue;
                const auto streams = entry.circuit->streams();
                if (streams != 0U) {
                    entry.idle_since.reset();
                    continue;
                }
                if (!entry.idle_since) entry.idle_since = now;
                const bool rotated =
                    entry.first_stream &&
                    now - *entry.first_stream >= options.rotation;
                const bool idle = now - *entry.idle_since >= options.idle;
                const bool current =
                    entry.route.size() == current_hops && !rotated;
                if (rotated || (idle && !(current && spares++ == 0U)))
                    entry.circuit->close();
            }
            if (view == View::Failed && session) {
                view = View::Idle;
            } else if (view == View::Ready &&
                       std::chrono::system_clock::now() >= view_expires) {
                view = View::Idle;
            }
            if (current_hops < options.hops && !building &&
                view == View::Ready &&
                (!next_recheck || now >= *next_recheck)) {
                next_recheck = now + options.recheck;
                probe_configured();
            }
        } catch (...) {
        }
        pump();
        arm_tick();
    }

    void set_session(std::shared_ptr<CircuitSession> next) {
        if (next == session) return;
        ++generation;
        session = std::move(next);
        for (auto& entry : entries) entry.circuit->close();
        entries.clear();
        building = false;
        attempts = 0U;
        view = View::Idle;
        chooser.reset();
        pump();
    }

    void fetch_view() {
        view = View::Fetching;
        const auto current = generation;
        session->async_open(
            common::kRoutesServiceName, engine::ServiceKind::ByteStream,
            std::nullopt, {},
            [weak = weak_from_this(),
             current](Result<std::shared_ptr<StreamResponder>> opened) {
                const auto self = weak.lock();
                if (!self || self->generation != current || self->closed) {
                    if (opened.ok())
                        opened.value()->close(Status(StatusCode::Cancelled));
                    return;
                }
                if (!opened.ok()) return self->view_failed(opened.status());
                self->read_view(std::move(opened).take_value(), current,
                                std::make_shared<std::vector<std::byte>>());
            });
    }

    void read_view(std::shared_ptr<StreamResponder> stream,
                   std::uint64_t current,
                   std::shared_ptr<std::vector<std::byte>> received) {
        stream->async_read({}, [weak = weak_from_this(), stream, current,
                                received](
                                   Result<ReceivedRecord> result) mutable {
            const auto self = weak.lock();
            if (!self || self->generation != current || self->closed) {
                stream->close(Status(StatusCode::Cancelled));
                return;
            }
            if (!result.ok()) {
                stream->close(Status(StatusCode::Closed));
                if (result.status().code() != StatusCode::EndOfStream)
                    return self->view_failed(result.status());
                return self->view_received(*received);
            }
            const auto bytes = result.value().payload().bytes();
            if (received->size() + bytes.size() >
                ytp1::kCompositeSignatureSize + cluster::kMaxListBytes) {
                stream->close(Status(StatusCode::ResourceExhausted));
                return self->view_failed(
                    Status::diagnostic(StatusCode::InvalidArgument,
                                       "the entry's routes view is too long"));
            }
            received->insert(received->end(), bytes.begin(), bytes.end());
            self->read_view(std::move(stream), current, std::move(received));
        });
    }

    void view_received(const std::vector<std::byte>& bytes) {
        auto accepted = accept_served_routes(circuits, bytes,
                                             std::chrono::system_clock::now());
        if (!accepted.ok()) return view_failed(accepted.status());
        view_expires = accepted.value().not_after;
        serial = accepted.value().serial;
        auto created = circuit::RouteChooser::create(
            std::move(accepted).take_value(), circuits.entry);
        if (!created.ok()) return view_failed(created.status());
        chooser.emplace(std::move(created).take_value());
        for (const auto& [identity, time] : measured)
            chooser->record(identity, time);
        const auto now = Clock::now();
        for (const auto& [identity, until] : excluded) {
            if (until > now)
                chooser->exclude(identity,
                                 until - circuit::RouteChooser::kExclusion);
        }
        view = View::Ready;
        stopped.clear();
        pump();
    }

    void view_failed(const Status& status) {
        view = View::Failed;
        chooser.reset();
        stopped = status.message().empty()
                      ? "the entry's routes view failed its checks"
                      : status.message();
        say("circuits stopped: " + stopped);
        fail_waiters(
            Status::diagnostic(StatusCode::FailedPrecondition, stopped));
    }

    bool usable(const Entry& entry, Clock::time_point now) const {
        return entry.route.size() == current_hops && entry.circuit->ready() &&
               !entry.circuit->closed() &&
               entry.circuit->streams() < kStreamsPerCircuit &&
               !(entry.first_stream &&
                 now - *entry.first_stream >= options.rotation);
    }

    void pump() noexcept {
        try {
            pump_now();
        } catch (const std::bad_alloc&) {
            fail_waiters(Status(StatusCode::ResourceExhausted));
        } catch (...) {
            fail_waiters(Status(StatusCode::Internal));
        }
    }

    void pump_now() {
        if (closed) return fail_waiters(Status(StatusCode::Closed));
        std::erase_if(entries, [](const Entry& entry) {
            return entry.circuit->closed();
        });
        // A new session fetches its view and builds a circuit before the
        // first stream asks for one. A view that failed its checks is asked
        // for again only when a stream waits.
        if (waiters.empty() && (!session || view == View::Failed)) return;
        if (!session) {
            return fail_waiters(Status::diagnostic(
                StatusCode::FailedPrecondition, "the client has no session"));
        }
        if (view == View::Idle) return fetch_view();
        if (view == View::Fetching) return;
        if (view == View::Failed) {
            return fail_waiters(
                Status::diagnostic(StatusCode::FailedPrecondition, stopped));
        }
        const auto now = Clock::now();
        while (!waiters.empty()) {
            auto& waiter = waiters.front();
            if (waiter.cancellation.is_cancelled()) {
                settle(waiter.done, Result<std::shared_ptr<StreamResponder>>(
                                        Status(StatusCode::Cancelled)));
                waiters.pop_front();
                continue;
            }
            if (current_hops == 0U) {
                // A proposal waits for the user.
                const auto id = proposal ? proposal->id : std::string();
                fail_waiters(Status::diagnostic(
                    StatusCode::PermissionDenied,
                    "the route needs your consent: yume --accept-route " + id));
                return;
            }
            if (current_hops == 1U) {
                auto next = std::move(waiter);
                waiters.pop_front();
                open_direct(std::move(next));
                continue;
            }
            if (!options.plain_http_allowed &&
                waiter.destination.port() == 80U) {
                settle(
                    waiter.done,
                    Result<std::shared_ptr<StreamResponder>>(Status::diagnostic(
                        StatusCode::PermissionDenied,
                        "plain HTTP is refused on circuits")));
                waiters.pop_front();
                continue;
            }
            const auto found = std::find_if(
                entries.begin(), entries.end(),
                [&](const Entry& entry) { return usable(entry, now); });
            if (found == entries.end()) break;
            if (!found->first_stream) found->first_stream = now;
            auto next = std::move(waiter);
            waiters.pop_front();
            open_on(*found, std::move(next));
        }
        // Build when a stream waits, or keep one spare circuit ready, from
        // the start of the session.
        const bool spare = std::any_of(
            entries.begin(), entries.end(), [&](const Entry& entry) {
                return usable(entry, now) && entry.circuit->streams() == 0U;
            });
        const bool building_needed =
            !waiters.empty() || (!spare && now >= spare_after);
        if (building_needed && !building && current_hops >= 2U)
            start_build(current_hops, false);
    }

    void open_direct(Waiter waiter) {
        session->async_open(
            waiter.direct_service, engine::ServiceKind::ByteStream,
            waiter.destination, waiter.cancellation,
            [done = std::move(waiter.done)](
                Result<std::shared_ptr<StreamResponder>> result) mutable {
                settle(done, std::move(result));
            });
    }

    void open_on(Entry& entry, Waiter waiter) {
        auto destination = circuit_destination(waiter.destination);
        if (!destination.ok()) {
            return settle(waiter.done, Result<std::shared_ptr<StreamResponder>>(
                                           destination.status()));
        }
        const bool guard = !options.plain_http_allowed;
        entry.circuit->open_stream(
            destination.value(),
            [done = std::move(waiter.done),
             guard](Result<std::shared_ptr<StreamResponder>> result) mutable {
                if (result.ok() && guard) {
                    try {
                        result = Result<std::shared_ptr<StreamResponder>>(
                            guard_plain_http(std::move(result).take_value()));
                    } catch (...) {
                        result = Result<std::shared_ptr<StreamResponder>>(
                            Status(StatusCode::ResourceExhausted));
                    }
                }
                settle(done, std::move(result));
            });
    }

    // Builds one circuit of hops nodes. probe builds the configured length
    // while a shorter one is in use and changes the length only on success.
    void start_build(std::size_t hops, bool probe) {
        if (!chooser) return;
        auto random = fresh_random();
        auto route = chooser->choose(hops, Clock::now(), random);
        if (!route) {
            if (!probe) length_failed(hops);
            return;
        }
        building = true;
        const auto current = generation;
        session->async_open(
            common::kCircuitServiceName, engine::ServiceKind::PacketChannel,
            std::nullopt, {},
            [weak = weak_from_this(), current, route = std::move(*route),
             probe](Result<std::shared_ptr<StreamResponder>> opened) mutable {
                const auto self = weak.lock();
                if (!self || self->generation != current || self->closed) {
                    if (opened.ok())
                        opened.value()->close(Status(StatusCode::Cancelled));
                    return;
                }
                if (!opened.ok()) {
                    self->building = false;
                    return self->build_failed(route, std::nullopt, probe);
                }
                self->build_on(std::move(opened).take_value(), std::move(route),
                               current, probe);
            });
    }

    void build_on(std::shared_ptr<StreamResponder> stream,
                  std::vector<cluster::RouteNode> route, std::uint64_t current,
                  bool probe) {
        std::vector<providers::keys::CompositePublic> hops;
        hops.reserve(route.size());
        for (const auto& node : route) hops.push_back(node.identity);
        auto limits = options.limits;
        limits.streams_per_circuit =
            std::min(limits.streams_per_circuit, kStreamsPerCircuit);
        auto created = circuit::ClientCircuit::create(
            context, crypto, std::move(stream), std::move(hops), limits);
        if (!created.ok()) {
            building = false;
            return build_failed(route, std::nullopt, probe);
        }
        auto built = std::move(created).take_value();
        built->build([weak = weak_from_this(), built, route = std::move(route),
                      current, probe](Status status) mutable {
            const auto self = weak.lock();
            if (!self || self->generation != current || self->closed) {
                built->close();
                return;
            }
            self->building = false;
            if (!status.ok()) {
                const auto failure = built->failure();
                built->close();
                return self->build_failed(route, failure, probe);
            }
            self->built(std::move(built), std::move(route), probe);
        });
    }

    void built(std::shared_ptr<circuit::ClientCircuit> circuit,
               std::vector<cluster::RouteNode> route, bool probe) {
        const auto times = circuit->hop_times();
        for (std::size_t hop = 1U; hop < times.size() && hop < route.size();
             ++hop) {
            const auto& identity = route[hop].identity.fingerprint;
            measured[identity] = times[hop];
            if (chooser) chooser->record(identity, times[hop]);
        }
        attempts = 0U;
        if (probe || route.size() > current_hops) {
            if (current_hops != route.size()) {
                say("routes of " + std::to_string(route.size()) +
                    " hops work again");
            }
            current_hops = route.size();
            accepted_hops = 0U;
            proposal.reset();
            next_recheck.reset();
        }
        // A circuit closes inside loops over entries, such as rotation in
        // maintain() and close(), and pump() erases closed entries, so it
        // runs later, never inside close(). If the post fails, the next
        // tick pumps.
        circuit->on_closed([weak = weak_from_this()] {
            const auto self = weak.lock();
            if (!self) return;
            try {
                boost::asio::post(self->context->executor(), [weak] {
                    if (const auto later = weak.lock()) later->pump();
                });
            } catch (...) {
            }
        });
        entries.push_back(
            Entry{std::move(circuit), std::move(route), Clock::now(), {}, {}});
        pump();
    }

    void build_failed(const std::vector<cluster::RouteNode>& route,
                      const std::optional<circuit::CircuitFailure>& failure,
                      bool probe) {
        std::string names;
        for (const auto& node : route)
            names += (names.empty() ? "" : " > ") + node.name;
        say("a circuit through " + names + " could not be built" +
            (failure ? " (hop " + std::to_string(failure->hop) + ", " +
                           reason_name(failure->reason) + ")"
                     : std::string()));
        exclude_failed(route, failure);
        if (probe) return pump();
        // A spare failed while a circuit of this length still works: try
        // another spare at the next tick, and change nothing else.
        const auto now = Clock::now();
        if (route.size() == current_hops &&
            std::any_of(
                entries.begin(), entries.end(),
                [&](const Entry& entry) { return usable(entry, now); })) {
            spare_after = now + options.tick;
            return pump();
        }
        if (++attempts < options.attempts) {
            start_build(route.size(), false);
            return;
        }
        length_failed(route.size());
    }

    // No route of hops nodes could be built. A shorter length the user
    // approved, in the configuration or by accepting a proposal, is used at
    // once. Otherwise the next shorter length is proposed and streams wait
    // for the answer.
    void length_failed(std::size_t hops) {
        attempts = 0U;
        const std::size_t shorter = hops - 1U;
        if (shorter >= 1U && shorter >= allowed_min()) {
            say("no route of " + std::to_string(hops) +
                " hops could be built, using " + std::to_string(shorter) +
                " hops as approved");
            current_hops = shorter;
            next_recheck = Clock::now() + options.recheck;
            if (shorter >= 2U) {
                start_build(shorter, false);
            } else {
                pump();
            }
            return;
        }
        current_hops = 0U;
        propose(shorter);
        fail_waiters(Status::diagnostic(
            StatusCode::PermissionDenied,
            "the route needs your consent: yume --accept-route " +
                (proposal ? proposal->id : std::string("(no route)"))));
    }

    void propose(std::size_t hops) {
        proposal.reset();
        if (hops < 1U || !chooser) {
            say("no route can be built, and none is shorter");
            return;
        }
        std::vector<cluster::RouteNode> route;
        if (hops == 1U) {
            route.push_back(*chooser->view().find(circuits.entry));
        } else {
            auto random = fresh_random();
            auto chosen = chooser->choose(hops, Clock::now(), random);
            if (!chosen) return propose(hops - 1U);
            route = std::move(*chosen);
        }
        RouteProposal next;
        next.hops = hops;
        next.serial = serial;
        std::chrono::milliseconds total{0};
        bool complete = true;
        std::vector<std::byte> fields;
        const auto add = [&](std::string_view text) {
            const auto* start = reinterpret_cast<const std::byte*>(text.data());
            fields.insert(fields.end(), start, start + text.size());
            fields.push_back(std::byte{0});
        };
        add(std::to_string(hops));
        for (std::size_t index = 0U; index < route.size(); ++index) {
            next.nodes.push_back(route[index].name);
            add(route[index].identity.fingerprint);
            if (index == 0U) continue;
            const auto found = measured.find(route[index].identity.fingerprint);
            if (found == measured.end()) {
                complete = false;
            } else {
                total += found->second;
            }
        }
        add(std::to_string(serial));
        if (complete && hops >= 2U) next.latency = total;
        const auto digest = crypto->key_context().digest({fields});
        next.id = hex(std::span(digest).first(8));
        std::string nodes;
        for (const auto& name : next.nodes)
            nodes += (nodes.empty() ? "" : ", ") + name;
        say("no route of " + std::to_string(options.hops) +
            " hops can be built. Proposed: " + std::to_string(hops) +
            (hops == 1U ? " hop" : " hops") + " (" + nodes + "). " +
            shorter_route_cost(hops) + " Accept with yume --accept-route " +
            next.id);
        proposal = std::move(next);
    }

    void probe_configured() {
        if (!session || !chooser) return;
        start_build(options.hops, true);
    }
};

CircuitPool::CircuitPool(std::shared_ptr<State> state) noexcept
    : state_(std::move(state)) {}

CircuitPool::~CircuitPool() {
    close();
}

Result<std::shared_ptr<CircuitPool>> CircuitPool::create(
    std::shared_ptr<providers::AsioExecutionContext> context,
    NativeCircuitCredentials credentials, CircuitPoolOptions options,
    Report report) {
    using Created = Result<std::shared_ptr<CircuitPool>>;
    if (!context || options.hops < 2U || options.hops > 3U ||
        options.min_hops < 1U || options.min_hops > options.hops ||
        options.attempts == 0U ||
        options.tick <= std::chrono::milliseconds::zero())
        return Created(Status(StatusCode::InvalidArgument));
    try {
        auto state =
            std::make_shared<State>(std::move(context), std::move(credentials),
                                    std::move(options), std::move(report));
        state->crypto =
            std::make_shared<const providers::circuit::CircuitCrypto>();
        return Created(
            std::shared_ptr<CircuitPool>(new CircuitPool(std::move(state))));
    } catch (const std::bad_alloc&) {
        return Created(Status(StatusCode::ResourceExhausted));
    } catch (...) {
        return Created(Status(StatusCode::ProviderMismatch));
    }
}

void CircuitPool::set_session(
    std::shared_ptr<CircuitSession> session) noexcept {
    try {
        state_->set_session(std::move(session));
        state_->arm_tick();
    } catch (...) {
        state_->fail_waiters(Status(StatusCode::Internal));
    }
}

void CircuitPool::open(const RouteDestination& destination,
                       std::string direct_service,
                       CancellationToken cancellation, Opened done) noexcept {
    try {
        state_->waiters.push_back(
            State::Waiter{destination, std::move(direct_service),
                          std::move(cancellation), std::move(done)});
    } catch (...) {
        State::settle(done, Result<std::shared_ptr<StreamResponder>>(
                                Status(StatusCode::ResourceExhausted)));
        return;
    }
    state_->pump();
}

CircuitPoolStatus CircuitPool::status() const {
    const auto& state = *state_;
    CircuitPoolStatus result;
    result.hops = state.options.hops;
    result.min_hops = state.options.min_hops;
    result.accepted_hops = state.accepted_hops;
    result.current_hops =
        state.view == State::View::Failed ? 0U : state.current_hops;
    result.plain_http_allowed = state.options.plain_http_allowed;
    result.serial = state.serial;
    result.stopped = state.stopped;
    result.proposal = state.proposal;
    for (const auto& entry : state.entries) {
        if (entry.circuit->closed()) continue;
        CircuitRoute route;
        for (const auto& node : entry.route) route.nodes.push_back(node.name);
        route.built = entry.built;
        route.streams = entry.circuit->streams();
        result.circuits.push_back(std::move(route));
    }
    return result;
}

engine::Status CircuitPool::accept(std::string_view id) noexcept {
    auto& state = *state_;
    if (!state.proposal || state.proposal->id != id)
        return Status(StatusCode::NotFound);
    const std::size_t hops = state.proposal->hops;
    state.accepted_hops = hops;
    state.current_hops = hops;
    state.proposal.reset();
    state.attempts = 0U;
    state.next_recheck = Clock::now() + state.options.recheck;
    state.say("accepted routes of " + std::to_string(hops) +
              (hops == 1U ? " hop" : " hops") + " until " +
              std::to_string(state.options.hops) + " hops work again");
    state.pump();
    return Status::success();
}

void CircuitPool::close() noexcept {
    auto& state = *state_;
    if (state.closed) return;
    state.closed = true;
    boost::system::error_code ignored;
    state.tick.cancel(ignored);
    for (auto& entry : state.entries) entry.circuit->close();
    state.entries.clear();
    state.fail_waiters(Status(StatusCode::Closed));
}

}  // namespace yume::runtime
