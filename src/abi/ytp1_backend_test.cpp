/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Exercise the private blocking adapter with a deliberately paused executor.
// Including its implementation keeps test-only controls out of the embed API;
// this executable does not link the separately compiled backend archive.
#include "abi/ytp1_backend.cpp"
#include "test_support/allocation_failure.hpp"

#include <array>
#include <cstdlib>
#include <fstream>
#include <future>
#include <iostream>
#include <iterator>
#include <stdexcept>

#include <boost/asio/post.hpp>

namespace yume::embed {
namespace {

#define CHECK(condition) do { if (!(condition)) { \
    std::cerr << "check failed at " << __LINE__ << ": " #condition "\n"; \
    std::abort(); \
} } while (false)

class TestResponder final : public engine::StreamResponder {
public:
    explicit TestResponder(engine::ServiceKind kind = engine::ServiceKind::ByteStream,
                           std::size_t max_write = 3U)
        : kind_(kind), max_write_(max_write) {}
    engine::ExecutorAffinity executor_affinity() const noexcept override {
        return engine::ExecutorAffinity(77U);
    }
    engine::ServiceKind service_kind() const noexcept override {
        return kind_;
    }
    std::size_t max_write_size() const noexcept override { return max_write_; }
    bool terminated() const noexcept override { return terminated_; }
    void async_read(engine::CancellationToken, ReadCompletion completion) override {
        CHECK(!read_);
        read_ = std::move(completion);
    }
    void async_write(engine::Buffer data, engine::CancellationToken,
                     WriteCompletion completion) override {
        CHECK(!write_);
        ++write_count;
        write_size_ = data.size();
        writes.emplace_back(reinterpret_cast<const char*>(data.bytes().data()), data.size());
        write_ = std::move(completion);
    }
    Status shutdown_write() noexcept override {
        ++shutdown_count;
        return Status::success();
    }
    void close(Status reason) noexcept override {
        terminated_ = true;
        auto read = std::exchange(read_, {});
        auto write = std::exchange(write_, {});
        if (read) read(engine::Result<engine::ReceivedRecord>(reason));
        if (write) write(reason, 0U);
    }
    void data(std::size_t& credit_releases, std::string_view text = "abcdef") {
        const auto bytes = std::as_bytes(std::span(text.data(), text.size()));
        auto payload = engine::Buffer::copy_from(bytes, bytes.size());
        CHECK(payload.ok());
        auto read = std::exchange(read_, {});
        CHECK(read);
        read(engine::Result<engine::ReceivedRecord>(engine::ReceivedRecord(
            std::move(payload).take_value(), engine::CarrierCredit(
                bytes.size(), [&credit_releases, expected = bytes.size()](std::size_t size) {
                    CHECK(size == expected);
                    ++credit_releases;
                }))));
    }
    void fin() {
        auto read = std::exchange(read_, {});
        CHECK(read);
        read(engine::Result<engine::ReceivedRecord>(Status(StatusCode::EndOfStream)));
    }
    void sent() {
        auto write = std::exchange(write_, {});
        CHECK(write);
        write(Status::success(), write_size_);
    }
    bool has_pending_io() const noexcept { return bool(read_) || bool(write_); }
    std::size_t write_count{0U};
    std::size_t shutdown_count{0U};
    std::vector<std::string> writes;

private:
    const engine::ServiceKind kind_;
    const std::size_t max_write_;
    ReadCompletion read_;
    WriteCompletion write_;
    std::size_t write_size_{0U};
    std::atomic<bool> terminated_{false};
};

struct Fixture final {
    explicit Fixture(const v1::Config& config,
                     engine::ServiceKind kind = engine::ServiceKind::ByteStream,
                     std::size_t max_write = 3U)
        : responder(std::make_shared<TestResponder>(kind, max_write)) {
        auto context = providers::AsioExecutionContext::create(engine::ExecutorAffinity(77U));
        CHECK(context.ok());
        run = std::make_shared<NativeRun>(std::move(context).take_value(), config,
            std::filesystem::path{}, std::filesystem::path{},
            std::vector<BackendService>{{"tcp", BackendServiceKind::ByteStream},
                                        {"tcp", BackendServiceKind::Packet}},
            providers::AsioTcpSocketProtector{});
    }
    ~Fixture() {
        for (const auto& stream : streams) stream->close();
        drain();
        CHECK(!responder->has_pending_io());
    }
    template <typename Function>
    void on_runner(Function function) {
        boost::asio::post(run->context->executor(), std::move(function));
        run->context->poll();
    }
    std::shared_ptr<NativeStream> stream() {
        auto value = std::make_shared<NativeStream>(run, responder, BackendPeerIdentity{});
        streams.push_back(value);
        on_runner([value] { value->start_reading(); });
        return value;
    }
    void drain() {
        if (run->drained()) return;
        run->begin_stop();
        // NativeRun normally closes its NativeEndpoint here, which stops the
        // session and settles every responder callback. This fixture has no
        // endpoint: model that engine completion on the owning executor even
        // when stopping has already refused new stream control submissions.
        on_runner([this] { responder->close(Status(StatusCode::Closed)); });
        run->context->finish();
        run->run_until_drained();
    }
    std::shared_ptr<NativeRun> run;
    std::shared_ptr<TestResponder> responder;
    std::vector<std::shared_ptr<NativeStream>> streams;
};

void test_shutdown_deadlines(const v1::Config& config) {
    for (const std::uint32_t timeout : {0U, 20U}) {
        Fixture fixture(config);
        const auto stream = fixture.stream();
        std::string error;
        const auto before = Clock::now();
        CHECK(stream->shutdown_write(timeout, error) ==
              (timeout == 0U ? BackendIo::WouldBlock : BackendIo::Timeout));
        CHECK(Clock::now() - before < std::chrono::seconds(1));
        CHECK(fixture.responder->shutdown_count == 0U);
        CHECK(stream->write("x", 1U, 0U, error) == BackendIo::Closed);
        fixture.run->context->poll();
        CHECK(stream->shutdown_write(0U, error) == BackendIo::Ok);
        CHECK(stream->shutdown_write(0U, error) == BackendIo::Ok);
        CHECK(fixture.responder->shutdown_count == 1U);
    }
}

void test_write_admission_is_all_or_none(const v1::Config& config) {
    Fixture fixture(config);
    const auto stream = fixture.stream();
    std::string error;
    CHECK(stream->write("abcdef", 6U, 0U, error) == BackendIo::Ok);
    fixture.run->context->poll();
    CHECK(fixture.responder->write_count == 1U);
    CHECK(stream->write("later", 5U, 0U, error) == BackendIo::WouldBlock);
    CHECK(stream->write("later", 5U, 20U, error) == BackendIo::Timeout);
    CHECK(stream->shutdown_write(0U, error) == BackendIo::WouldBlock);
    CHECK(fixture.responder->shutdown_count == 0U);
    fixture.on_runner([&] { fixture.responder->sent(); fixture.responder->sent(); });
    CHECK(fixture.responder->write_count == 2U);
    CHECK(stream->write("x", 1U, 0U, error) == BackendIo::Ok);
    fixture.run->context->poll();
    CHECK(fixture.responder->write_count == 3U);
}

void test_partial_read_credit_and_terminal_precedence(const v1::Config& config) {
    for (const bool abort : {false, true}) {
        std::size_t releases = 0U; // Outlives the fixture's final record drain.
        Fixture fixture(config);
        const auto stream = fixture.stream();
        fixture.on_runner([&] { fixture.responder->data(releases); fixture.responder->fin(); });
        std::array<char, 6U> bytes{};
        std::size_t received = 0U;
        std::string error;
        CHECK(stream->read(bytes.data(), 2U, 0U, received, error) == BackendIo::Ok);
        CHECK(received == 2U && releases == 0U);
        fixture.run->context->poll();
        CHECK(releases == 0U);
        CHECK(stream->read(bytes.data() + 2U, 4U, 0U, received, error) == BackendIo::Ok);
        CHECK(received == 4U && std::string_view(bytes.data(), bytes.size()) == "abcdef");
        CHECK(releases == 0U);
        fixture.run->context->poll();
        CHECK(releases == 1U);
        CHECK(stream->read(bytes.data(), bytes.size(), 0U, received, error) == BackendIo::Eof);
        if (abort) fixture.on_runner([&] { fixture.responder->close(Status(StatusCode::Cancelled)); });
        else fixture.drain();
        CHECK(stream->read(bytes.data(), bytes.size(), 0U, received, error) == BackendIo::Closed);
        CHECK(received == 0U);
    }
}

void test_runner_failure_stops_and_drains(const v1::Config& config) {
    Fixture fixture(config);
    bool tail_ran = false;
    boost::asio::post(fixture.run->context->executor(), [] { throw std::runtime_error("delivery failed"); });
    boost::asio::post(fixture.run->context->executor(), [&] { tail_ran = true; });
    fixture.run->run_until_drained();
    CHECK(tail_ran && fixture.run->drained() && !fixture.run->running());
}

void test_termination_discards_unread_suffix(const v1::Config& config) {
    for (const bool abort : {false, true}) {
        std::size_t releases = 0U;
        Fixture fixture(config);
        const auto stream = fixture.stream();
        fixture.on_runner([&] { fixture.responder->data(releases); fixture.responder->fin(); });
        std::array<char, 2U> bytes{};
        std::size_t received = 0U;
        std::string error;
        CHECK(stream->read(bytes.data(), bytes.size(), 0U, received, error) == BackendIo::Ok);
        CHECK(received == 2U && releases == 0U);
        if (abort) fixture.on_runner([&] { fixture.responder->close(Status(StatusCode::Cancelled)); });
        else fixture.run->begin_stop();
        bytes.fill('!');
        CHECK(stream->read(bytes.data(), bytes.size(), 0U, received, error) == BackendIo::Closed);
        CHECK(received == 0U && bytes[0] == '!' && bytes[1] == '!');
    }
}

void test_accept_does_not_wait_for_runner(const v1::Config& config) {
    for (const bool rollback : {false, true}) {
        Fixture fixture(config);
        std::size_t completions = 0U;
        StatusCode outcome = StatusCode::Internal;
        fixture.on_runner([&] {
            auto peer = engine::PeerEvidence::create(engine::EndpointRole::Client,
                "device", "test", std::vector<std::byte>(32U, std::byte{1}));
            auto id = engine::StreamId::application(1U, engine::EndpointRole::Client);
            CHECK(peer.ok() && id.ok());
            auto open = engine::StreamOpenContext::create(id.value(), "tcp",
                engine::ServiceKind::ByteStream, std::move(peer).take_value());
            CHECK(open.ok());
            fixture.run->offer(0U, std::move(open).take_value(), fixture.responder,
                [&](Status status) { ++completions; outcome = status.code(); });
        });
        std::shared_ptr<NativeStream> accepted;
        std::string error;
        const auto before = Clock::now();
        CHECK(fixture.run->accept(0U, 0U, accepted, error) == BackendIo::Ok);
        CHECK(Clock::now() - before < std::chrono::seconds(1));
        CHECK(accepted && completions == 0U);
        fixture.streams.push_back(accepted);
        if (rollback) accepted->close();
        fixture.run->context->poll();
        CHECK(completions == 1U);
        CHECK(outcome == (rollback ? StatusCode::Cancelled : StatusCode::Ok));
    }
}

void test_abandoned_opens_release_waiting_capacity(const v1::Config& config) {
    Fixture fixture(config);
    std::size_t refusals = 0U;
    fixture.on_runner([&] {
        for (std::size_t index = 0U; index <= kMaxWaitingOpens; ++index) {
            const auto responder = std::make_shared<TestResponder>();
            auto peer = engine::PeerEvidence::create(engine::EndpointRole::Client,
                "device", "test", std::vector<std::byte>(32U, std::byte{1}));
            auto id = engine::StreamId::application(1U, engine::EndpointRole::Client);
            CHECK(peer.ok() && id.ok());
            auto open = engine::StreamOpenContext::create(id.value(), "tcp",
                engine::ServiceKind::ByteStream, std::move(peer).take_value());
            CHECK(open.ok());
            fixture.run->offer(0U, std::move(open).take_value(), responder,
                [&](Status status) { if (!status.ok()) ++refusals; });
            responder->close(Status(StatusCode::Cancelled));
        }
    });
    CHECK(refusals == 0U);
}

void test_packet_boundaries_and_credit(const v1::Config& config) {
    std::size_t releases = 0U;
    Fixture fixture(config, engine::ServiceKind::PacketChannel, 32U);
    const auto stream = fixture.stream();
    fixture.on_runner([&] {
        fixture.responder->data(releases, "first");
        fixture.responder->data(releases, "second");
        fixture.responder->data(releases, "x");
        fixture.responder->fin();
    });
    std::array<char, 16U> bytes{};
    std::array<BackendPacketSlot, 3U> slots{{{99U, 99U}, {99U, 99U}, {99U, 99U}}};
    std::size_t received = 99U;
    std::size_t required = 99U;
    std::string error;
    CHECK(stream->read_packets(nullptr, 0U, slots, 0U, received, required, error) ==
          BackendIo::BufferTooSmall);
    CHECK(received == 0U && required == 5U && slots[0].offset == 99U);
    CHECK(stream->read_packets(bytes.data(), 4U, slots, 0U, received, required, error) ==
          BackendIo::BufferTooSmall);
    fixture.run->context->poll();
    CHECK(releases == 0U && received == 0U && required == 5U);
    // The third packet fits after the first, but the second must not be skipped.
    CHECK(stream->read_packets(bytes.data(), 6U, slots, 0U, received, required, error) ==
          BackendIo::Ok);
    CHECK(received == 1U && required == 0U && slots[0].offset == 0U && slots[0].size == 5U);
    CHECK(slots[1].offset == 99U && std::string_view(bytes.data(), 5U) == "first");
    CHECK(releases == 0U);
    fixture.run->context->poll();
    CHECK(releases == 1U);
    CHECK(stream->read_packets(bytes.data(), bytes.size(), slots, 0U,
                               received, required, error) == BackendIo::Ok);
    CHECK(received == 2U && required == 0U && slots[0].offset == 0U && slots[0].size == 6U);
    CHECK(slots[1].offset == 6U && slots[1].size == 1U && slots[2].offset == 99U);
    CHECK(std::string_view(bytes.data(), 7U) == "secondx" && releases == 1U);
    fixture.run->context->poll();
    CHECK(releases == 3U);
    CHECK(stream->read_packets(bytes.data(), bytes.size(), slots, 0U,
                               received, required, error) == BackendIo::Eof);
    CHECK(received == 0U && required == 0U);
}

void test_packet_admission_and_copy(const v1::Config& config) {
    Fixture fixture(config, engine::ServiceKind::PacketChannel, 6U);
    const auto stream = fixture.stream();
    std::string error;
    const std::array<BackendPacketView, 2U> bad{{{"ok", 2U}, {"toolong", 7U}}};
    CHECK(stream->write_packets(bad, 0U, error) == BackendIo::Invalid);
    CHECK(stream->write_packets({}, 0U, error) == BackendIo::Invalid);
    const std::array<BackendPacketView, 1U> empty{{{"", 0U}}};
    CHECK(stream->write_packets(empty, 0U, error) == BackendIo::Invalid);
    fixture.run->context->poll();
    CHECK(fixture.responder->write_count == 0U);
    std::array<char, 3U> input{'a', 'b', 'c'};
    const std::array<BackendPacketView, 2U> batch{{{input.data(), input.size()}, {"de", 2U}}};
    CHECK(stream->write_packets(batch, 0U, error) == BackendIo::Ok);
    input.fill('!');
    fixture.run->context->poll();
    CHECK(fixture.responder->write_count == 1U && fixture.responder->writes[0] == "abc");
    CHECK(stream->write_packets(batch, 0U, error) == BackendIo::WouldBlock);
    CHECK(stream->write_packets(batch, 20U, error) == BackendIo::Timeout);
    fixture.on_runner([&] { fixture.responder->sent(); fixture.responder->sent(); });
    CHECK(fixture.responder->write_count == 2U && fixture.responder->writes[1] == "de");
    CHECK(stream->write_packets(batch, 0U, error) == BackendIo::Ok);
}

void test_packet_close_and_stop_wake_waiters(const v1::Config& config) {
    for (const bool stop : {false, true}) {
        Fixture fixture(config, engine::ServiceKind::PacketChannel, 6U);
        const auto stream = fixture.stream();
        const std::array<BackendPacketView, 1U> batch{{{"queued", 6U}}};
        std::string error;
        CHECK(stream->write_packets(batch, 0U, error) == BackendIo::Ok);
        fixture.run->context->poll();
        auto reader = std::async(std::launch::async, [stream] {
            char storage{};
            std::array<BackendPacketSlot, 1U> slots{};
            std::size_t received = 99U;
            std::size_t required = 99U;
            std::string message;
            const auto result = stream->read_packets(&storage, 1U, slots, 3000U,
                                                     received, required, message);
            CHECK(received == 0U && required == 0U);
            return result;
        });
        auto writer = std::async(std::launch::async, [stream, batch] {
            std::string message;
            return stream->write_packets(batch, 3000U, message);
        });
        CHECK(reader.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout);
        CHECK(writer.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout);
        if (stop) fixture.run->begin_stop();
        else stream->close();
        CHECK(reader.wait_for(std::chrono::seconds(1)) == std::future_status::ready);
        CHECK(writer.wait_for(std::chrono::seconds(1)) == std::future_status::ready);
        CHECK(reader.get() == BackendIo::Closed && writer.get() == BackendIo::Closed);
    }
}

void test_packet_accept_kind_separation(const v1::Config& config) {
    Fixture fixture(config, engine::ServiceKind::PacketChannel, 6U);
    const auto stream_index = fixture.run->waiting_index("tcp", BackendServiceKind::ByteStream);
    const auto packet_index = fixture.run->waiting_index("tcp", BackendServiceKind::Packet);
    CHECK(stream_index && packet_index && stream_index != packet_index);
    std::size_t accepted_count = 0U;
    fixture.on_runner([&] {
        auto peer = engine::PeerEvidence::create(engine::EndpointRole::Client,
            "device", "test", std::vector<std::byte>(32U, std::byte{1}));
        auto id = engine::StreamId::application(1U, engine::EndpointRole::Client);
        CHECK(peer.ok() && id.ok());
        auto open = engine::StreamOpenContext::create(id.value(), "tcp",
            engine::ServiceKind::PacketChannel, std::move(peer).take_value());
        CHECK(open.ok());
        fixture.run->offer(*packet_index, std::move(open).take_value(), fixture.responder,
            [&](Status status) { CHECK(status.ok()); ++accepted_count; });
    });
    std::shared_ptr<NativeStream> accepted;
    std::string error;
    CHECK(fixture.run->accept(*stream_index, 0U, accepted, error) == BackendIo::WouldBlock);
    CHECK(!accepted && accepted_count == 0U);
    CHECK(fixture.run->accept(*packet_index, 0U, accepted, error) == BackendIo::Ok);
    CHECK(accepted && accepted_count == 0U);
    fixture.streams.push_back(accepted);
    fixture.run->context->poll();
    CHECK(accepted_count == 1U);
}

void test_packet_stopped_fixture_releases_ownership(const v1::Config& config) {
    std::weak_ptr<NativeRun> weak_run;
    std::weak_ptr<NativeStream> weak_stream;
    {
        Fixture fixture(config, engine::ServiceKind::PacketChannel, 6U);
        const auto stream = fixture.stream();
        weak_run = fixture.run;
        weak_stream = stream;
        const std::array<BackendPacketView, 1U> batch{{{"queued", 6U}}};
        std::string error;
        CHECK(stream->write_packets(batch, 0U, error) == BackendIo::Ok);
        fixture.run->context->poll();
        CHECK(fixture.responder->has_pending_io());
        fixture.run->begin_stop();
    }
    CHECK(weak_stream.expired() && weak_run.expired());
}

void test_packet_allocation_rollback(const v1::Config& config) {
    std::size_t failures = 0U;
    bool completed = false;
    for (std::size_t nth = 1U; nth <= 64U; ++nth) {
        Fixture fixture(config, engine::ServiceKind::PacketChannel, 6U);
        const auto stream = fixture.stream();
        const std::array<BackendPacketView, 2U> batch{{{"first", 5U}, {"second", 6U}}};
        std::string error;
        BackendIo outcome = BackendIo::ResourceExhausted;
        yume::test::arm_allocation_failure(nth);
        try {
            outcome = stream->write_packets(batch, 0U, error);
        } catch (const std::bad_alloc&) {
            // The public ABI contains exceptions from the internal seam.
        }
        const bool fired = yume::test::disarm_allocation_failure();
        if (!fired) {
            CHECK(outcome == BackendIo::Ok);
            completed = true;
            break;
        }
        ++failures;
        CHECK(outcome == BackendIo::ResourceExhausted);
        fixture.run->context->poll();
        CHECK(fixture.responder->write_count == 0U);
        CHECK(stream->write_packets(batch, 0U, error) == BackendIo::Ok);
        fixture.run->context->poll();
        fixture.on_runner([&] { fixture.responder->sent(); fixture.responder->sent(); });
        CHECK((fixture.responder->writes == std::vector<std::string>{"first", "second"}));
    }
    CHECK(failures > 0U && completed);
}

void test_packet_close_discards_unread_on_runner(const v1::Config& config) {
    std::size_t releases = 0U;
    Fixture fixture(config, engine::ServiceKind::PacketChannel, 6U);
    const auto stream = fixture.stream();
    fixture.on_runner([&] {
        fixture.responder->data(releases, "first");
        fixture.responder->data(releases, "second");
    });
    stream->close();
    CHECK(releases == 0U);
    std::array<char, 6U> storage{};
    std::array<BackendPacketSlot, 1U> slots{{{99U, 99U}}};
    std::size_t count = 99U;
    std::size_t required = 99U;
    std::string error;
    CHECK(stream->read_packets(storage.data(), storage.size(), slots, 0U,
                               count, required, error) == BackendIo::Closed);
    CHECK(count == 0U && required == 0U && slots[0].offset == 99U);
    fixture.run->context->poll();
    CHECK(releases == 2U);
}

void test_packet_configured_batch_bound(const v1::Config& config) {
    std::size_t releases = 0U;
    Fixture fixture(config, engine::ServiceKind::PacketChannel, 6U);
    const auto stream = fixture.stream();
    const std::size_t limit = config.limits().max_packet_batch();
    CHECK(limit < kMaxPacketBatch);
    const std::vector<BackendPacketView> oversized(limit + 1U, {"x", 1U});
    std::string error;
    CHECK(stream->write_packets(oversized, 0U, error) == BackendIo::ResourceExhausted);
    fixture.run->context->poll();
    CHECK(fixture.responder->write_count == 0U);
    fixture.on_runner([&] {
        for (std::size_t i = 0U; i <= limit; ++i) fixture.responder->data(releases, "x");
    });
    std::array<char, kMaxPacketBatch> storage{};
    std::array<BackendPacketSlot, kMaxPacketBatch> slots{};
    std::size_t count = 0U;
    std::size_t required = 0U;
    CHECK(stream->read_packets(storage.data(), storage.size(), slots, 0U,
                               count, required, error) == BackendIo::Ok);
    CHECK(count == limit && required == 0U && releases == 0U);
    fixture.run->context->poll();
    CHECK(releases == limit);
    CHECK(stream->read_packets(storage.data(), storage.size(), slots, 0U,
                               count, required, error) == BackendIo::Ok);
    CHECK(count == 1U && required == 0U);
}

}  // namespace
}  // namespace yume::embed

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    std::ifstream input(argv[1]);
    if (!input) return 2;
    const std::string text{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    const auto config = yume::config::v1::ParseJson(text);
    yume::embed::test_shutdown_deadlines(config);
    yume::embed::test_write_admission_is_all_or_none(config);
    yume::embed::test_partial_read_credit_and_terminal_precedence(config);
    yume::embed::test_runner_failure_stops_and_drains(config);
    yume::embed::test_termination_discards_unread_suffix(config);
    yume::embed::test_accept_does_not_wait_for_runner(config);
    yume::embed::test_abandoned_opens_release_waiting_capacity(config);
    yume::embed::test_packet_boundaries_and_credit(config);
    yume::embed::test_packet_admission_and_copy(config);
    yume::embed::test_packet_close_and_stop_wake_waiters(config);
    yume::embed::test_packet_accept_kind_separation(config);
    yume::embed::test_packet_stopped_fixture_releases_ownership(config);
    yume::embed::test_packet_allocation_rollback(config);
    yume::embed::test_packet_close_discards_unread_on_runner(config);
    yume::embed::test_packet_configured_batch_bound(config);
    std::cout << "YTP embedding ownership and deadline checks passed\n";
}
