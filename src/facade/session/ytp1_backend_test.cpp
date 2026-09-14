/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Exercise the private blocking adapter with a deliberately paused executor.
// Including its implementation keeps test-only controls out of the embed API;
// this executable does not link the separately compiled backend archive.
#include "facade/session/ytp1_backend.cpp"

#include <array>
#include <cstdlib>
#include <fstream>
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
    engine::ExecutorAffinity executor_affinity() const noexcept override {
        return engine::ExecutorAffinity(77U);
    }
    engine::ServiceKind service_kind() const noexcept override {
        return engine::ServiceKind::ByteStream;
    }
    std::size_t max_write_size() const noexcept override { return 3U; }
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
    void data(std::size_t& credit_releases) {
        const std::array<std::byte, 6U> bytes{
            std::byte{'a'}, std::byte{'b'}, std::byte{'c'},
            std::byte{'d'}, std::byte{'e'}, std::byte{'f'}};
        auto payload = engine::Buffer::copy_from(bytes, bytes.size());
        CHECK(payload.ok());
        auto read = std::exchange(read_, {});
        CHECK(read);
        read(engine::Result<engine::ReceivedRecord>(engine::ReceivedRecord(
            std::move(payload).take_value(), engine::CarrierCredit(
                bytes.size(), [&credit_releases](std::size_t size) {
                    CHECK(size == 6U);
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
    std::size_t write_count{0U};
    std::size_t shutdown_count{0U};

private:
    ReadCompletion read_;
    WriteCompletion write_;
    std::size_t write_size_{0U};
    bool terminated_{false};
};

struct Fixture final {
    explicit Fixture(const v1::Config& config) {
        auto context = providers::AsioExecutionContext::create(engine::ExecutorAffinity(77U));
        CHECK(context.ok());
        run = std::make_shared<NativeRun>(std::move(context).take_value(), config,
            std::filesystem::path{},
            std::vector<BackendService>{{"tcp", BackendServiceKind::ByteStream}},
            providers::AsioTcpSocketProtector{});
    }
    ~Fixture() {
        for (const auto& stream : streams) stream->close();
        drain();
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
        run->context->finish();
        run->run_until_drained();
    }
    std::shared_ptr<NativeRun> run;
    std::shared_ptr<TestResponder> responder = std::make_shared<TestResponder>();
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
    std::cout << "YTP embedding ownership and deadline checks passed\n";
}
