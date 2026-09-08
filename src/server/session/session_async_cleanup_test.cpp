/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Session write submission and teardown under injected failure. The
 * invariants are that every byte handed to the HTTP/2 carrier has a recorded
 * completion owner, that the retained frame and byte counters always describe
 * exactly what is queued, and that one misbehaving completion cannot stop
 * teardown from settling the rest.
 */

#include "server/session/session.hpp"
#include "core/stealth/cover_profile.hpp"
#include "core/stealth/h2_carrier.hpp"
#include "test_support/allocation_failure.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace yume::server {

struct SessionAsyncCleanupTestPeer {
    using PendingWrite = Session::PendingWrite;

    static void activate_carrier(Session& session,
                                 std::unique_ptr<obfs::H2Carrier> carrier) {
        session.v2_h2_carrier_ = std::move(carrier);
        session.v2_h2_tunnel_active_ = true;
    }

    static void queue_app_write(
        Session& session,
        std::shared_ptr<std::vector<std::uint8_t>> data,
        std::function<void(const boost::system::error_code&, std::size_t)>
            handler) {
        const std::size_t size = data->size();
        session.queue_encoded_write_on_strand(
            std::move(data), protocol::DATA, 0, size, std::move(handler));
    }

    // Reproduces the state a stalled peer produces: the carrier still holds
    // the application record, so it has not reached the TLS write queue and
    // close is the only thing left that can settle it. Driving a real peer
    // window from a fixture would test nghttp2's scheduler, not this queue.
    static void retain_app_write(
        Session& session,
        std::shared_ptr<std::vector<std::uint8_t>> data,
        std::function<void(const boost::system::error_code&, std::size_t)>
            handler) {
        const std::size_t size = data->size();
        session.v2_h2_pending_app_writes_.push_back(
            {std::move(data), protocol::DATA, 0, size, std::move(handler)});
        ++session.v2_h2_app_write_frames_;
        session.v2_h2_app_write_bytes_ += size;
    }

    static std::size_t pending_app_writes(const Session& session) {
        return session.v2_h2_pending_app_writes_.size();
    }

    static bool accounting_matches_queue(const Session& session) {
        std::size_t bytes = 0;
        for (const auto& pending : session.v2_h2_pending_app_writes_) {
            if (pending.data) bytes += pending.data->size();
        }
        return session.v2_h2_app_write_frames_ ==
                   session.v2_h2_pending_app_writes_.size() &&
               session.v2_h2_app_write_bytes_ == bytes;
    }

    static std::size_t carrier_output_bytes(const Session& session) {
        return session.v2_h2_carrier_
            ? session.v2_h2_carrier_->queued_output_bytes() : 0U;
    }

    static bool is_open(const Session& session) {
        return session.close_state_ == Session::CloseState::Open;
    }

    static void enqueue_tls_write(
        Session& session,
        std::shared_ptr<std::vector<std::uint8_t>> data,
        std::function<void(const boost::system::error_code&, std::size_t)>
            handler) {
        const std::size_t size = data->size();
        session.enqueue_tls_write_on_strand(
            std::move(data), protocol::DATA, 0, size, std::move(handler));
    }

    static std::uint32_t write_queue_depth(const Session& session) {
        return session.write_queue_depth_;
    }

    static bool write_in_flight(const Session& session) {
        return session.write_in_flight_;
    }

    static void pause_dispatch(Session& session, bool paused) {
        session.write_in_flight_ = paused;
    }

    static void dispatch(Session& session) { session.do_write(); }

    static void finish_close(Session& session) {
        session.finish_transport_close();
    }

    static auto& socket(Session& session) { return session.stream_.next_layer(); }

    static std::size_t batched_writes(const Session& session) {
        return session.in_flight_write_ ? session.in_flight_write_->batch.size()
                                        : 0;
    }

    // A batch held by the jitter timer has not reached async_write yet.
    static bool delayed_write_armed(Session& session) {
        return session.delayed_write_timer_.expiry() >
               std::chrono::steady_clock::now();
    }

    static void begin_close(Session& session, const std::string& reason) {
        session.close_reason_ = reason;
        session.begin_close();
    }
};

}  // namespace yume::server

namespace {

using yume::obfs::H2Bytes;
using yume::obfs::H2Carrier;
using yume::obfs::H2CarrierRole;
using Peer = yume::server::SessionAsyncCleanupTestPeer;

void check(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "session async cleanup: %s\n", message);
        std::exit(1);
    }
}

void pump(H2Carrier& from, H2Carrier& to) {
    for (int i = 0; i < 16; ++i) {
        auto bytes = from.TakeOutbound();
        if (bytes.empty()) return;
        to.Feed(bytes);
        check(!to.failed(), "the HTTP/2 pump failed");
    }
    check(false, "the HTTP/2 pump did not quiesce");
}

// Mirrors the profiled Chrome exchange the production carrier performs before
// a tunnel is admitted, so SendBinary reaches a live carrier stream.
void open_carrier(H2Carrier& client, H2Carrier& server) {
    check(client.StartClient("cover.example"), "StartClient failed");
    pump(client, server);
    pump(server, client);
    auto requests = server.TakeRequests();
    check(requests.size() == 1, "the priming GET did not arrive");
    check(server.RespondHttp(requests[0].stream_id, 200,
                             {{"content-type", "text/html"}}, {}),
          "the priming response was refused");
    pump(server, client);

    pump(client, server);
    requests = server.TakeRequests();
    const auto& profile = yume::cover_profile::active();
    check(requests.size() == profile.assets.size(),
          "the profiled asset requests did not arrive");
    for (const auto& request : requests) {
        check(server.RespondHttp(request.stream_id, 200,
                                 {{"content-type", "text/plain"}},
                                 H2Bytes{'o', 'k'}),
              "an asset response was refused");
    }
    pump(server, client);
    pump(client, server);
    check(client.priming_complete(), "priming never completed");

    check(client.SubmitExtendedConnect("/carrier"),
          "the extended CONNECT was refused");
    pump(client, server);
    requests = server.TakeRequests();
    check(requests.size() == 1, "the extended CONNECT did not arrive");
    check(server.AcceptCarrier(requests[0].stream_id),
          "the carrier was not accepted");
    pump(server, client);
    pump(client, server);
    check(client.carrier_active() && server.carrier_active(),
          "the carrier never became active");
}

struct Fixture {
    boost::asio::io_context io;
    boost::asio::ssl::context tls{boost::asio::ssl::context::tls};
    yume::server::ServerConfig config;
    std::shared_ptr<yume::server::Session> session;

    explicit Fixture(std::uint32_t jitter_ms = 0) {
        config.obfs_jitter_ms = jitter_ms;
        session = std::make_shared<yume::server::Session>(
            boost::asio::ip::tcp::socket(io), tls, config,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, 11,
            nullptr);
    }
};

void test_close_releases_a_live_read_when_allocations_keep_failing() {
    Fixture fixture;
    using Tcp = boost::asio::ip::tcp;
    Tcp::acceptor listener(fixture.io, {boost::asio::ip::address_v4::loopback(), 0});
    Tcp::socket remote(fixture.io);
    remote.connect(listener.local_endpoint());
    listener.accept(Peer::socket(*fixture.session));
    std::array<char, 1> buffer{};
    bool read_finished = false;
    Peer::socket(*fixture.session).async_read_some(
        boost::asio::buffer(buffer),
        [&](const boost::system::error_code& ec, std::size_t) {
            check(ec == boost::asio::error::operation_aborted,
                  "closing the socket did not cancel its live read");
            read_finished = true;
        });
    const std::string reason = "test";
    bool escaped = false;
    yume::test::fail_allocations.store(true);
    try {
        Peer::begin_close(*fixture.session, reason);
    } catch (...) {
        escaped = true;
    }
    yume::test::fail_allocations.store(false);
    check(!escaped, "allocation failure escaped session close");
    check(!Peer::socket(*fixture.session).is_open(),
          "a failed close deadline left the socket open");
    fixture.io.run_for(std::chrono::milliseconds(100));
    check(read_finished, "session close left its read outstanding");
}

void test_live_carrier_write_never_outruns_its_owner() {
    for (std::size_t nth = 1;; ++nth) {
        H2Carrier client(H2CarrierRole::Client);
        auto server_carrier = std::make_unique<H2Carrier>(H2CarrierRole::Server);
        open_carrier(client, *server_carrier);
        (void)server_carrier->TakeOutbound();

        Fixture fixture;
        Peer::activate_carrier(*fixture.session, std::move(server_carrier));
        const std::size_t output_before =
            Peer::carrier_output_bytes(*fixture.session);

        // Build the payload and completion before arming. Failing to
        // construct one is the caller's own failure and never starts a write.
        auto data = std::make_shared<std::vector<std::uint8_t>>(512, 0x5a);
        std::size_t completions = 0;
        bool escaped = false;
        std::function<void(const boost::system::error_code&, std::size_t)>
            completion = [&](const boost::system::error_code&, std::size_t) {
                ++completions;
            };
        yume::test::arm_allocation_failure(nth);
        try {
            Peer::queue_app_write(*fixture.session, std::move(data),
                                  std::move(completion));
        } catch (...) {
            escaped = true;
        }
        const bool fired = yume::test::disarm_allocation_failure();
        if (!fired) {
            check(nth > 1, "the write path performed no allocation at all");
            break;
        }

        check(!escaped, "an allocation failure escaped the write path");
        check(Peer::accounting_matches_queue(*fixture.session),
              "the retained write counters stopped matching the queue");
        const std::size_t owners = Peer::pending_app_writes(*fixture.session);
        if (!Peer::is_open(*fixture.session)) {
            // A failure the write path could not absorb closes the session,
            // and closing settles every pending write exactly once.
            check(owners == 0, "close left a completion owner queued");
            check(completions == 1,
                  "close did not settle the write exactly once");
        } else if (Peer::carrier_output_bytes(*fixture.session) >
                   output_before) {
            check(owners == 1,
                  "carrier bytes were queued with no completion owner");
            check(completions == 0,
                  "a submitted write settled before its carrier flush");
        } else {
            check(completions <= 1, "a refused write settled more than once");
        }
        fixture.io.poll();
    }
}

void test_refused_carrier_submission_settles_and_restores_capacity() {
    Fixture fixture;
    // A carrier with no admitted tunnel refuses SendBinary, which is the
    // production path taken when the peer resets the carrier stream.
    Peer::activate_carrier(*fixture.session,
                           std::make_unique<H2Carrier>(H2CarrierRole::Server));

    std::size_t completions = 0;
    boost::system::error_code observed;
    Peer::queue_app_write(
        *fixture.session,
        std::make_shared<std::vector<std::uint8_t>>(64, 0x11),
        [&](const boost::system::error_code& ec, std::size_t) {
            ++completions;
            observed = ec;
        });
    check(completions == 1, "a refused submission did not settle once");
    check(observed == boost::asio::error::fault,
          "a refused submission reported an unrelated error");
    check(Peer::pending_app_writes(*fixture.session) == 0,
          "a refused submission left a completion owner queued");
    check(Peer::accounting_matches_queue(*fixture.session),
          "a refused submission left retained write capacity");
    check(!Peer::is_open(*fixture.session),
          "a refused carrier submission left the session open");
    fixture.io.poll();
}

void test_close_settles_every_pending_write_when_one_throws() {
    H2Carrier client(H2CarrierRole::Client);
    auto server_carrier = std::make_unique<H2Carrier>(H2CarrierRole::Server);
    open_carrier(client, *server_carrier);

    Fixture fixture;
    Peer::activate_carrier(*fixture.session, std::move(server_carrier));

    std::size_t settled = 0;
    for (int index = 0; index < 3; ++index) {
        Peer::retain_app_write(
            *fixture.session,
            std::make_shared<std::vector<std::uint8_t>>(96U * 1024U, 0x22),
            [&, index](const boost::system::error_code& ec, std::size_t) {
                check(ec == boost::asio::error::operation_aborted,
                      "a close settlement reported an unrelated error");
                ++settled;
                if (index == 1) throw std::runtime_error("completion boom");
            });
    }
    check(Peer::pending_app_writes(*fixture.session) == 3,
          "the carrier writes were not retained for close");
    check(Peer::accounting_matches_queue(*fixture.session),
          "the retained write counters did not match the queue");

    Peer::begin_close(*fixture.session, "async cleanup test");
    check(settled == 3,
          "close stopped settling pending writes at a throwing completion");
    check(Peer::pending_app_writes(*fixture.session) == 0,
          "close left a pending carrier write queued");
    check(Peer::accounting_matches_queue(*fixture.session),
          "close left retained write capacity");
    check(!Peer::is_open(*fixture.session), "close left the session open");
    fixture.io.poll();
}

// A dispatched batch has already left the queue, so its completions and the
// depth they hold can only be released by the batch owner. One misbehaving
// completion must not take its siblings, the retained depth or the next
// dispatch with it.
void test_dispatched_batch_settles_every_write_when_one_throws() {
    Fixture fixture;
    std::size_t settled = 0;
    // Hold the dispatcher while all three are queued so they land in one
    // batch. Enqueuing without this dispatches the first immediately and
    // leaves the other two behind it, which is a different path.
    Peer::pause_dispatch(*fixture.session, true);
    for (int index = 0; index < 3; ++index) {
        Peer::enqueue_tls_write(
            *fixture.session,
            std::make_shared<std::vector<std::uint8_t>>(48, 0x31),
            [&, index](const boost::system::error_code&, std::size_t) {
                ++settled;
                if (index == 1) throw std::runtime_error("completion boom");
            });
    }
    Peer::pause_dispatch(*fixture.session, false);
    Peer::dispatch(*fixture.session);
    check(Peer::batched_writes(*fixture.session) == 3,
          "the three writes did not reach one batch");
    // The socket was never connected, so the write fails and the completion
    // runs with an error rather than never running at all.
    fixture.io.poll();
    check(settled == 3,
          "a throwing completion stopped its siblings from settling");
    check(Peer::write_queue_depth(*fixture.session) == 0,
          "a settled batch left retained write depth behind");
    check(!Peer::write_in_flight(*fixture.session),
          "a settled batch left the dispatcher wedged");
}

// A delayed batch is held by a timer rather than by the queue. Cancelling it
// during close must settle the batch, not destroy its completions.
void test_close_settles_a_delayed_batch() {
    // The configured jitter is a uniform 0..N, so a single attempt can draw
    // zero and never arm the timer. Retry until the delayed path is actually
    // observed and require that it was, rather than passing on a draw that
    // skipped it.
    bool observed_delay = false;
    for (int attempt = 0; attempt < 64 && !observed_delay; ++attempt) {
        Fixture fixture(200);
        std::size_t settled = 0;
        boost::system::error_code observed;
        Peer::pause_dispatch(*fixture.session, true);
        for (int index = 0; index < 2; ++index) {
            Peer::enqueue_tls_write(
                *fixture.session,
                std::make_shared<std::vector<std::uint8_t>>(64, 0x32),
                [&](const boost::system::error_code& ec, std::size_t) {
                    ++settled;
                    observed = ec;
                });
        }
        Peer::pause_dispatch(*fixture.session, false);
        Peer::dispatch(*fixture.session);
        check(Peer::batched_writes(*fixture.session) == 2,
              "the two writes did not reach one batch");
        if (!Peer::delayed_write_armed(*fixture.session)) {
            continue;   // this attempt drew a zero delay
        }
        observed_delay = true;
        check(settled == 0, "the jitter delay did not hold the batch");
        check(Peer::write_in_flight(*fixture.session),
              "a delayed batch did not keep the dispatcher busy");

        Peer::begin_close(*fixture.session, "delayed batch test");
        fixture.io.poll();
        check(settled == 2, "close did not settle the delayed batch");
        check(observed == boost::asio::error::operation_aborted,
              "a cancelled delayed batch reported an unrelated error");
        check(Peer::write_queue_depth(*fixture.session) == 0,
              "a cancelled delayed batch left retained write depth behind");
        check(!Peer::write_in_flight(*fixture.session),
              "a cancelled delayed batch left the dispatcher wedged");
    }
    check(observed_delay, "the delayed write path was never exercised");
}

// A write that has left the queue but not yet reached the batch has no owner
// at all. Sweeping the failure across the dispatch allocations proves the
// admitted completion is answered and its retained depth released whichever
// one fails.
void test_dispatch_allocation_never_loses_an_admitted_write() {
    for (std::size_t nth = 1; nth <= 12; ++nth) {
        Fixture fixture;
        std::size_t settled = 0;
        // Build the completion before arming: constructing a call argument is
        // the caller's own failure and never admits a write.
        std::function<void(const boost::system::error_code&, std::size_t)>
            completion = [&](const boost::system::error_code&, std::size_t) {
                ++settled;
            };
        auto data = std::make_shared<std::vector<std::uint8_t>>(48, 0x31);
        Peer::pause_dispatch(*fixture.session, true);
        Peer::enqueue_tls_write(*fixture.session, std::move(data),
                                std::move(completion));
        Peer::pause_dispatch(*fixture.session, false);

        yume::test::arm_allocation_failure(nth);
        Peer::dispatch(*fixture.session);
        const bool fired = yume::test::disarm_allocation_failure();

        Peer::begin_close(*fixture.session, "dispatch allocation probe");
        Peer::finish_close(*fixture.session);
        fixture.io.poll();
        check(settled == 1,
              "an admitted write was not settled exactly once at close");
        check(Peer::write_queue_depth(*fixture.session) == 0,
              "an admitted write left retained depth at close");
        // The reported losses were at dispatch allocations 2, 3 and 4, so the
        // sweep has to reach them rather than stopping early and passing on a
        // path it never took.
        check(fired || nth > 4,
              "the sweep stopped before the reported dispatch allocations");
        if (!fired) break;
    }
}

// Asio can fail inside its own executor delivery and destroy the completion
// handler with every reference it held. The session's own reference to the
// dispatched batch is what still answers those callers at terminal close.
void test_undelivered_completion_is_settled_by_terminal_close() {
    Fixture fixture;
    using Tcp = boost::asio::ip::tcp;
    Tcp::acceptor listener(fixture.io,
                           {boost::asio::ip::address_v4::loopback(), 0});
    Tcp::socket peer(fixture.io);
    peer.connect(listener.local_endpoint());
    listener.accept(Peer::socket(*fixture.session));

    std::size_t settled = 0;
    std::function<void(const boost::system::error_code&, std::size_t)>
        completion = [&](const boost::system::error_code&, std::size_t) {
            ++settled;
        };
    auto data = std::make_shared<std::vector<std::uint8_t>>(48, 0x31);
    Peer::enqueue_tls_write(*fixture.session, std::move(data),
                            std::move(completion));

    // The failure lands inside asio's type-erased executor query while it
    // delivers the completion, so the handler never runs and is destroyed.
    yume::test::arm_allocation_failure(1);
    try {
        fixture.io.poll();
    } catch (...) {
        // Contained by the worker loop in production. The point here is what
        // the session still owns afterwards.
    }
    yume::test::disarm_allocation_failure();

    Peer::begin_close(*fixture.session, "undelivered completion probe");
    Peer::finish_close(*fixture.session);
    fixture.io.poll();
    check(settled == 1,
          "an undelivered completion was not settled by terminal close");
    check(Peer::write_queue_depth(*fixture.session) == 0,
          "an undelivered completion left retained depth at close");
}

}  // namespace

int main() {
    test_close_releases_a_live_read_when_allocations_keep_failing();
    test_live_carrier_write_never_outruns_its_owner();
    test_refused_carrier_submission_settles_and_restores_capacity();
    test_close_settles_every_pending_write_when_one_throws();
    test_dispatched_batch_settles_every_write_when_one_throws();
    test_close_settles_a_delayed_batch();
    test_dispatch_allocation_never_loses_an_admitted_write();
    test_undelivered_completion_is_settled_by_terminal_close();
    std::puts("session async cleanup: passed");
    return 0;
}
