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

    static void begin_close(Session& session, const std::string& reason) {
        session.close_reason_ = reason;
        session.begin_close();
    }

    static auto& socket(Session& session) { return session.stream_.next_layer(); }
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

    Fixture()
        : session(std::make_shared<yume::server::Session>(
              boost::asio::ip::tcp::socket(io), tls, config,
              nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, 11,
              nullptr)) {}
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

}  // namespace

int main() {
    test_close_releases_a_live_read_when_allocations_keep_failing();
    test_live_carrier_write_never_outruns_its_owner();
    test_refused_carrier_submission_settles_and_restores_capacity();
    test_close_settles_every_pending_write_when_one_throws();
    std::puts("session async cleanup: passed");
    return 0;
}
