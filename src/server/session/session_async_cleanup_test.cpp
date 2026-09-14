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
#include "server/runtime/manager.hpp"
#include "core/stealth/cover_profile.hpp"
#include "core/stealth/h2_carrier.hpp"
#include "test_support/allocation_failure.hpp"
#include "test_support/tls_identity.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <new>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yume::server {

struct SessionAsyncCleanupTestPeer {
    using PendingWrite = Session::PendingWrite;
    using CodecStream = Session::CodecStream;

    static void arm_session_timers(Session& session, std::size_t& cancelled) {
        // The waits retain the session just like the production deadline
        // handlers. Close must release them without waiting for expiry or
        // relying on delivery of another cancelled socket operation.
        const std::array timers{
            &session.tls_handshake_timer_, &session.preface_timer_,
            &session.idle_timer_, &session.frame_read_timer_,
            &session.ratchet_timer_, &session.transport_shutdown_timer_,
            &session.delayed_write_timer_, &session.http_idle_timer_};
        for (auto* timer : timers) {
            timer->expires_after(std::chrono::hours(1));
            timer->async_wait(boost::asio::bind_executor(
                session.strand_,
                [self = session.shared_from_this(), &cancelled](
                    const boost::system::error_code& ec) {
                    if (ec == boost::asio::error::operation_aborted) {
                        ++cancelled;
                    }
                }));
        }
    }

    static std::shared_ptr<CodecStream> retain_codec(
        Session& session, runtime::InboundCredit credit) {
        auto codec = std::make_shared<CodecStream>(session.stream_.get_executor());
        codec->inbound_credit = std::move(credit);
        codec->response_reserved_bytes = 4096;
        codec->response_body.resize(codec->response_reserved_bytes);
        session.codec_response_bytes_ += codec->response_reserved_bytes;
        session.codec_streams_.emplace(1, codec);
        session.arm_codec_timer(1, std::chrono::hours(1), "codec deadline");
        return codec;
    }

    static bool codecs_released(Session& session) {
        std::lock_guard<std::mutex> lock(session.streams_mutex_);
        return session.codec_streams_.empty() && session.codec_response_bytes_ == 0;
    }

    static void schedule_idle_check(Session& session) {
        session.schedule_idle_check();
    }

    static void enable_shaping(Session& session, Manager& manager) {
        session.manager_ = &manager;
        session.authenticated_ = true;
        session.bandwidth_fair_key_ = "lifecycle";
    }

    static void close_stream(Session& session) {
        session.handle_close(1, "test");
    }

    static void queue_tcp_egress(Session& session,
                                 boost::asio::ip::tcp::socket socket,
                                 runtime::InboundCredit credit) {
        auto remote = std::make_shared<Session::RemoteStream>(session.stream_.get_executor());
        remote->socket = std::move(socket);
        remote->connected = true;
        session.streams_.emplace(1, remote);
        session.enqueue_remote_write(1, crypto::Bytes(128, 0x43), std::move(credit));
    }

    static void queue_udp_egress(Session& session,
                                 boost::asio::ip::udp::socket socket,
                                 runtime::InboundCredit credit) {
        auto remote = std::make_shared<Session::UdpStream>(session.stream_.get_executor());
        remote->socket = std::move(socket);
        session.udp_streams_.emplace(1, remote);
        session.enqueue_udp_write(1, crypto::Bytes(128, 0x44), std::move(credit));
    }

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

    // Isolate ownership of an application record retained by the carrier.
    // This control does not establish resource bounds for a real stalled peer.
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

class PrivateDirectory {
public:
    PrivateDirectory() {
        std::random_device random;
        for (unsigned attempt = 0; attempt < 64; ++attempt) {
            auto candidate = std::filesystem::temp_directory_path() /
                ("yume-egress-" + std::to_string(random()) + "-" + std::to_string(random()));
            if (!std::filesystem::create_directory(candidate)) continue;
            path_ = std::move(candidate);
            try {
                std::filesystem::permissions(path_, std::filesystem::perms::owner_all);
            } catch (...) {
                std::error_code ignored;
                std::filesystem::remove_all(path_, ignored);
                throw;
            }
            return;
        }
        throw std::runtime_error("cannot create egress test directory");
    }
    ~PrivateDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }
    PrivateDirectory(const PrivateDirectory&) = delete;
    PrivateDirectory& operator=(const PrivateDirectory&) = delete;
    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

void test_close_cancels_every_session_timer() {
    for (const bool allocation_failure : {false, true}) {
        std::size_t cancelled = 0;
        Fixture fixture;
        Peer::arm_session_timers(*fixture.session, cancelled);
        const std::weak_ptr<yume::server::Session> lifetime = fixture.session;
        const std::string reason = "test";
        bool escaped = false;
        yume::test::fail_allocations.store(allocation_failure);
        try {
            Peer::begin_close(*fixture.session, reason);
            Peer::finish_close(*fixture.session);
        } catch (...) {
            escaped = true;
        }
        yume::test::fail_allocations.store(false);
        check(!escaped, "failure escaped close with live session timers");
        fixture.session.reset();
        fixture.io.poll();
        check(cancelled == 8, "close left a session timer pending");
        check(lifetime.expired(), "a cancelled timer retained the closed session");
    }
}

void test_close_releases_live_codec_backend() {
    for (const bool allocation_failure : {false, true}) {
        std::size_t released_bytes = 0;
        std::size_t reads_finished = 0;
        std::array<char, 1> buffer{};
        Fixture fixture;
        auto codec = Peer::retain_codec(
            *fixture.session,
            yume::runtime::InboundCredit(128, [&](std::size_t bytes) {
                check(Peer::codecs_released(*fixture.session),
                      "codec credit was released before detaching its state");
                released_bytes += bytes;
            }));
        using Tcp = boost::asio::ip::tcp;
        Tcp::acceptor listener(fixture.io, {boost::asio::ip::address_v4::loopback(), 0});
        Tcp::socket backend(fixture.io);
        backend.connect(listener.local_endpoint());
        listener.accept(codec->socket);
        codec->socket.async_read_some(
            boost::asio::buffer(buffer),
            [codec, self = fixture.session, &reads_finished](
                const boost::system::error_code& ec, std::size_t) {
                check(ec == boost::asio::error::operation_aborted,
                      "close did not cancel the blocked codec read");
                ++reads_finished;
            });
        const std::weak_ptr<yume::server::Session> lifetime = fixture.session;
        const std::weak_ptr<Peer::CodecStream> codec_lifetime = codec;
        const std::string reason = "test";
        bool escaped = false;
        yume::test::fail_allocations.store(allocation_failure);
        try {
            Peer::begin_close(*fixture.session, reason);
            Peer::finish_close(*fixture.session);
        } catch (...) {
            escaped = true;
        }
        yume::test::fail_allocations.store(false);
        check(!escaped, "failure escaped close with a live codec backend");
        check(Peer::codecs_released(*fixture.session),
              "close retained codec state or response reservations");
        check(!codec->socket.is_open(), "close left the codec backend socket open");
        check(released_bytes == 128, "close did not release codec receive credit once");
        codec.reset();
        fixture.session.reset();
        fixture.io.poll();
        check(reads_finished == 1, "close did not settle the codec read once");
        check(released_bytes == 128, "codec destruction released receive credit twice");
        check(lifetime.expired() && codec_lifetime.expired(),
              "the codec deadline retained a closed session or backend");
    }
}

void test_closed_session_cannot_rearm_idle_wait() {
    Fixture fixture;
    const std::weak_ptr<yume::server::Session> lifetime = fixture.session;
    Peer::begin_close(*fixture.session, "test");
    Peer::finish_close(*fixture.session);
    // Cancellation cannot recall a timer completion already ready with
    // success. Its late reschedule must not retain a closed session again.
    Peer::schedule_idle_check(*fixture.session);
    fixture.session.reset();
    fixture.io.poll();
    check(lifetime.expired(), "a late idle reschedule retained a closed session");
}

void test_codec_submission_failure_releases_admitted_state() {
    bool swept = false;
    for (std::size_t nth = 1; nth <= 128; ++nth) {
        std::size_t released = 0;
        Fixture fixture;
        // A failed initiation may release the executor's last work guard and
        // stop this otherwise idle fixture. Real sessions have other live I/O;
        // keep the executor running until terminal cleanup has been queued.
        auto executor_work = boost::asio::make_work_guard(fixture.io);
        const std::weak_ptr<yume::server::Session> lifetime = fixture.session;
        yume::runtime::InboundCredit credit(128, [&](std::size_t bytes) {
            released += bytes;
        });
        bool threw = false;
        yume::test::arm_allocation_failure(nth);
        try {
            (void)Peer::retain_codec(*fixture.session, std::move(credit));
        } catch (const std::bad_alloc&) {
            threw = true;
        }
        const bool fired = yume::test::disarm_allocation_failure();
        Peer::begin_close(*fixture.session, "test");
        Peer::finish_close(*fixture.session);
        check(Peer::codecs_released(*fixture.session),
              "failed codec/timer submission retained admitted state");
        fixture.session.reset();
        executor_work.reset();
        fixture.io.poll();
        check(released == 128, "failed codec submission lost or duplicated receive credit");
        check(lifetime.expired(), "failed codec submission retained the session");
        if (!fired) {
            check(nth > 1 && !threw, "codec failure sweep did not exercise allocations");
            swept = true;
            break;
        }
        check(threw, "codec allocation control did not propagate its injected failure");
    }
    check(swept, "codec failure sweep exceeded its bound");
}

void test_close_releases_delayed_egress_writes() {
    PrivateDirectory directory;
    yume::server::ServerConfig config;
    config.tls_cert = (directory.path() / "cert.pem").string();
    config.tls_key = (directory.path() / "key.pem").string();
    config.egress_mbps = 1;
    yume::test::write_tls_identity(config.tls_cert, config.tls_key);
    for (const bool datagram : {false, true}) {
        for (const bool stream_only : {false, true}) {
            for (const bool allocation_failure : {false, true}) {
                if (stream_only && allocation_failure) continue;
                std::size_t released = 0;
                Fixture fixture;
                yume::server::Manager manager(fixture.io, config);
                Peer::enable_shaping(*fixture.session, manager);
                // Reserve virtual service time, without allocating or sending this
                // payload. The following real write must wait far beyond the
                // teardown deadline, making an uncancelled delay observable.
                check(manager.reserve_egress_write("lifecycle", 1.0, 128U * 1024U * 1024U).count() == 0,
                      "the first egress reservation was unexpectedly delayed");
                yume::runtime::InboundCredit credit(128, [&](std::size_t bytes) {
                    released += bytes;
                });
                using Tcp = boost::asio::ip::tcp;
                using Udp = boost::asio::ip::udp;
                Tcp::acceptor listener(fixture.io, {boost::asio::ip::address_v4::loopback(), 0});
                Tcp::socket backend(fixture.io);
                Udp::socket datagram_backend(fixture.io, {boost::asio::ip::address_v4::loopback(), 0});
                if (datagram) {
                    Udp::socket socket(fixture.io);
                    socket.open(Udp::v4());
                    socket.connect(datagram_backend.local_endpoint());
                    Peer::queue_udp_egress(*fixture.session, std::move(socket), std::move(credit));
                } else {
                    Tcp::socket socket(fixture.io);
                    backend.connect(listener.local_endpoint());
                    listener.accept(socket);
                    Peer::queue_tcp_egress(*fixture.session, std::move(socket), std::move(credit));
                }
                fixture.io.poll();
                check(released == 0, "the egress control did not retain a delayed write");
                if (stream_only) {
                    Peer::close_stream(*fixture.session);
                    fixture.io.poll();
                    check(released == 128, "stream close retained delayed egress credit");
                    check(Peer::is_open(*fixture.session), "stream close closed the entire session");
                }
                const std::weak_ptr<yume::server::Session> lifetime = fixture.session;
                const std::string reason = "test";
                bool escaped = false;
                yume::test::fail_allocations.store(allocation_failure);
                try {
                    Peer::begin_close(*fixture.session, reason);
                    Peer::finish_close(*fixture.session);
                } catch (...) {
                    escaped = true;
                }
                yume::test::fail_allocations.store(false);
                check(!escaped, "failure escaped close with delayed egress");
                fixture.session.reset();
                fixture.io.restart();
                fixture.io.poll();
                check(released == 128, "close retained the delayed egress receive credit");
                check(lifetime.expired(), "an egress delay retained the closed session");
            }
        }
    }
}

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

void test_executor_destruction_releases_cancelled_handlers() {
    for (const bool allocation_failure : {false, true}) {
        boost::asio::ssl::context tls(boost::asio::ssl::context::tls);
        yume::server::ServerConfig config;
        auto io = std::make_unique<boost::asio::io_context>();
        auto session = std::make_shared<yume::server::Session>(
            boost::asio::ip::tcp::socket(*io), tls, config,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, 11, nullptr);
        const std::weak_ptr<yume::server::Session> lifetime = session;
        std::size_t timer_callbacks = 0;
        Peer::arm_session_timers(*session, timer_callbacks);
        auto buffer = std::make_shared<std::array<char, 1>>();
        const std::weak_ptr<std::array<char, 1>> buffer_lifetime = buffer;
        std::size_t read_callbacks = 0;
        std::size_t released = 0;
        using Tcp = boost::asio::ip::tcp;
        {
            Tcp::acceptor listener(*io, {boost::asio::ip::address_v4::loopback(), 0});
            Tcp::socket backend(*io);
            backend.connect(listener.local_endpoint());
            listener.accept(Peer::socket(*session));
            Peer::socket(*session).async_read_some(
                boost::asio::buffer(*buffer),
                [session, buffer, &read_callbacks,
                 credit = yume::runtime::InboundCredit(128, [&](std::size_t bytes) {
                     released += bytes;
                 })](const boost::system::error_code&, std::size_t) {
                    ++read_callbacks;
                });
        }
        std::size_t write_callbacks = 0;
        auto payload = std::make_shared<std::vector<std::uint8_t>>(128, 0x45);
        const std::weak_ptr<std::vector<std::uint8_t>> payload_lifetime = payload;
        Peer::pause_dispatch(*session, true);
        Peer::enqueue_tls_write(*session, std::move(payload),
            [&](const boost::system::error_code& ec, std::size_t) {
                check(ec == boost::asio::error::operation_aborted,
                      "executor-close reported an unrelated write result");
                ++write_callbacks;
            });
        const std::string reason = "executor destruction";
        Peer::begin_close(*session, reason);
        Peer::finish_close(*session);
        check(write_callbacks == 1, "close did not settle the queued write once");
        check(payload_lifetime.expired(), "close retained the queued payload");
        session.reset();
        buffer.reset();
        check(!lifetime.expired() && !buffer_lifetime.expired() && released == 0,
              "the executor destruction control had no retained handlers");
        // Destruction abandons these handlers without invoking them. Their
        // captures must release the session and credit even under allocation
        // failure; terminal close has already answered application writes.
        io->stop();
        yume::test::fail_allocations.store(allocation_failure);
        io.reset();
        yume::test::fail_allocations.store(false);
        check(lifetime.expired() && buffer_lifetime.expired(),
              "executor destruction retained a cancelled handler owner");
        check(released == 128, "executor destruction lost or duplicated credit");
        check(timer_callbacks == 0 && read_callbacks == 0 && write_callbacks == 1,
              "executor destruction invoked an abandoned handler");
    }
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

    std::array<char, 1> read_buffer{};
    std::size_t read_completions = 0;
    boost::system::error_code read_error;
    Peer::socket(*fixture.session).async_read_some(
        boost::asio::buffer(read_buffer),
        [&](const boost::system::error_code& ec, std::size_t) {
            ++read_completions;
            read_error = ec;
        });

    std::size_t settled = 0;
    boost::system::error_code write_error;
    std::function<void(const boost::system::error_code&, std::size_t)>
        completion = [&](const boost::system::error_code& ec, std::size_t) {
            ++settled;
            write_error = ec;
        };
    auto data = std::make_shared<std::vector<std::uint8_t>>(48, 0x31);
    Peer::enqueue_tls_write(*fixture.session, std::move(data),
                            std::move(completion));

    check(settled == 0 && Peer::batched_writes(*fixture.session) == 1,
          "the delivery probe did not retain an admitted write");

    // Require failed delivery with an unanswered batch. Otherwise an Asio
    // allocation change could let ordinary delivery satisfy the close checks.
    bool delivery_threw = false;
    yume::test::arm_allocation_failure(1);
    try {
        fixture.io.poll();
    } catch (const std::bad_alloc&) {
        delivery_threw = true;
    }
    const bool fired = yume::test::disarm_allocation_failure();
    check(fired, "the completion-delivery allocation failure did not fire");
    check(delivery_threw, "allocation failure did not interrupt delivery");
    check(settled == 0, "the application callback ran before terminal close");
    check(Peer::batched_writes(*fixture.session) == 1 &&
              Peer::write_queue_depth(*fixture.session) == 1 &&
              Peer::write_in_flight(*fixture.session),
          "failed delivery lost ownership of the admitted write");
    check(Peer::is_open(*fixture.session) &&
              Peer::socket(*fixture.session).is_open() && read_completions == 0,
          "the delivery failure did not leave a live session and read");

    Peer::begin_close(*fixture.session, "undelivered completion probe");
    Peer::finish_close(*fixture.session);
    check(settled == 1,
          "an undelivered completion was not settled by terminal close");
    check(write_error == boost::asio::error::operation_aborted,
          "terminal close reported an unrelated write error");
    check(Peer::write_queue_depth(*fixture.session) == 0 &&
              Peer::batched_writes(*fixture.session) == 0,
          "an undelivered completion left retained ownership at close");
    check(!Peer::is_open(*fixture.session) &&
              !Peer::socket(*fixture.session).is_open(),
          "terminal close left the session or socket open");
    fixture.io.poll();
    check(settled == 1, "executor drain settled the write a second time");
    check(read_completions == 1 &&
              read_error == boost::asio::error::operation_aborted,
          "terminal close did not cancel the outstanding read exactly once");
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2) {
        const std::string_view selected(argv[1]);
        if (selected == "session-timers") {
            test_close_cancels_every_session_timer();
        } else if (selected == "codec-close") {
            test_close_releases_live_codec_backend();
        } else if (selected == "idle-rearm") {
            test_closed_session_cannot_rearm_idle_wait();
        } else if (selected == "egress-close") {
            test_close_releases_delayed_egress_writes();
        } else if (selected == "executor-close") {
            test_executor_destruction_releases_cancelled_handlers();
        } else {
            return 2;
        }
        return 0;
    }
    if (argc != 1) return 2;
    test_close_cancels_every_session_timer();
    test_close_releases_live_codec_backend();
    test_closed_session_cannot_rearm_idle_wait();
    test_codec_submission_failure_releases_admitted_state();
    test_close_releases_delayed_egress_writes();
    test_close_releases_a_live_read_when_allocations_keep_failing();
    test_executor_destruction_releases_cancelled_handlers();
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
