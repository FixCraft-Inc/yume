/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/paced_stream.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio/post.hpp>

namespace {
using namespace yume::engine;
using yume::providers::AsioExecutionContext;
using yume::runtime::EgressLimiter;
using yume::runtime::pace_stream;
using Clock = std::chrono::steady_clock;
using std::chrono::milliseconds;

// One byte per microsecond, so 100'000 bytes take 100 ms.
constexpr std::uint64_t kFast = 1'000'000U;
// 100'000 bytes take 100 s: long enough to stay held for a whole test.
constexpr std::uint64_t kSlow = 1'000U;
constexpr std::size_t kChunk = 100'000U;

void check(bool condition, const char* description) {
    if (!condition) throw std::runtime_error(description);
}

template <typename T>
T require(Result<T> result) {
    check(result.ok(), "unexpected failure result");
    return std::move(result).take_value();
}

Buffer bytes(std::size_t size) { return require(Buffer::allocate(size, size)); }

class Inner final : public StreamResponder {
public:
    explicit Inner(ExecutorAffinity affinity) : affinity_(affinity) {}
    ExecutorAffinity executor_affinity() const noexcept override { return affinity_; }
    ServiceKind service_kind() const noexcept override { return ServiceKind::ByteStream; }
    std::size_t max_write_size() const noexcept override { return 1U << 20U; }
    bool terminated() const noexcept override { return terminated_.load(); }
    void async_read(CancellationToken, ReadCompletion completion) override {
        check(!pending_read, "the wrapper issued overlapping reads");
        if (terminated_.load()) {
            completion(Result<ReceivedRecord>(Status(StatusCode::Closed)));
        } else if (!records.empty()) {
            auto record = std::move(records.front());
            records.pop_front();
            completion(Result<ReceivedRecord>(std::move(record)));
        } else {
            pending_read = std::move(completion);
        }
    }
    void async_write(Buffer payload, CancellationToken, WriteCompletion completion) override {
        written.push_back({payload.size(), Clock::now()});
        completion(Status::success(), payload.size());
    }
    Status shutdown_write() noexcept override {
        ++shutdowns;
        writes_before_shutdown = written.size();
        return Status::success();
    }
    void close(Status) noexcept override {
        terminated_.store(true);
        ++closes;
        if (auto read = std::exchange(pending_read, {})) read(Result<ReceivedRecord>(Status(StatusCode::Closed)));
    }
    void push_record(std::size_t size) {
        ReceivedRecord record(bytes(size), CarrierCredit(size, [this](std::size_t released) {
            released_bytes += released;
        }));
        if (auto read = std::exchange(pending_read, {})) {
            read(Result<ReceivedRecord>(std::move(record)));
        } else {
            records.push_back(std::move(record));
        }
    }

    struct Write final {
        std::size_t size;
        Clock::time_point at;
    };
    std::vector<Write> written;
    std::deque<ReceivedRecord> records;
    ReadCompletion pending_read;
    std::atomic<bool> terminated_{false};
    std::size_t released_bytes{0U};
    std::size_t shutdowns{0U};
    std::size_t writes_before_shutdown{0U};
    std::size_t closes{0U};

private:
    ExecutorAffinity affinity_;
};

// The wrapper's calls must run on the context. The test thread drives it with
// poll(), which also runs expired timers, and posts each step.
class Harness final {
public:
    explicit Harness(std::uint64_t rate)
        : context(require(AsioExecutionContext::create(ExecutorAffinity(7U)))),
          limiter(std::make_shared<EgressLimiter>(rate)),
          inner(std::make_shared<Inner>(ExecutorAffinity(7U))) {
        stream = require(pace_stream(context, limiter, "client", [this] {
            ++weight_calls;
            return weight;
        }, inner));
    }
    ~Harness() {
        on_context([this] { stream->close(Status(StatusCode::Closed)); });
        context->finish();
        context->run();
    }

    template <typename Action>
    void on_context(Action action) {
        bool done = false;
        boost::asio::post(context->executor(), [&] {
            action();
            done = true;
        });
        while (!done) context->poll();
    }

    template <typename Predicate>
    bool wait_for(Predicate predicate, milliseconds limit) {
        const auto deadline = Clock::now() + limit;
        while (!predicate()) {
            if (Clock::now() > deadline) return false;
            context->poll();
            std::this_thread::sleep_for(milliseconds(1));
        }
        return true;
    }

    void write(std::size_t size, std::optional<Status>& outcome, CancellationToken token = {}) {
        on_context([&] {
            stream->async_write(bytes(size), std::move(token),
                                [&outcome](Status status, std::size_t) { outcome = std::move(status); });
        });
    }

    std::shared_ptr<AsioExecutionContext> context;
    std::shared_ptr<EgressLimiter> limiter;
    std::shared_ptr<Inner> inner;
    std::shared_ptr<StreamResponder> stream;
    double weight{1.0};
    std::size_t weight_calls{0U};
};

void test_factory_validation() {
    auto context = require(AsioExecutionContext::create(ExecutorAffinity(3U)));
    auto limiter = std::make_shared<EgressLimiter>(kFast);
    auto inner = std::make_shared<Inner>(ExecutorAffinity(3U));
    const auto weight = [] { return 1.0; };
    check(pace_stream(nullptr, limiter, "id", weight, inner).status().code() ==
              StatusCode::InvalidArgument, "a missing context was accepted");
    check(pace_stream(context, nullptr, "id", weight, inner).status().code() ==
              StatusCode::InvalidArgument, "a missing limiter was accepted");
    check(pace_stream(context, limiter, "", weight, inner).status().code() ==
              StatusCode::InvalidArgument, "an empty identity was accepted");
    check(pace_stream(context, limiter, "id", {}, inner).status().code() ==
              StatusCode::InvalidArgument, "a missing weight source was accepted");
    check(pace_stream(context, limiter, "id", weight, nullptr).status().code() ==
              StatusCode::InvalidArgument, "a missing stream was accepted");
    check(pace_stream(context, limiter, "id", weight, std::make_shared<Inner>(ExecutorAffinity(4U)))
              .status().code() == StatusCode::InvalidArgument,
          "a stream on another executor was accepted");
    const auto paced = require(pace_stream(context, limiter, "id", weight, inner));
    check(paced->service_kind() == ServiceKind::ByteStream &&
              paced->max_write_size() == inner->max_write_size() &&
              paced->executor_affinity() == ExecutorAffinity(3U) && !paced->terminated(),
          "the wrapper did not report its stream");
    context->finish();
    context->run();
}

void test_writes_are_paced() {
    Harness test(kFast);
    std::optional<Status> first;
    std::optional<Status> second;
    test.write(kChunk, first);
    check(first && first->ok() && test.inner->written.size() == 1U,
          "the first write did not pass at once");
    test.write(kChunk, second);
    check(!second && test.inner->written.size() == 1U, "the second write was not held");
    check(test.wait_for([&] { return second.has_value(); }, milliseconds(2'000)),
          "the held write never started");
    check(second->ok() && test.inner->written.size() == 2U, "the held write failed");
    check(test.inner->written[1].at - test.inner->written[0].at >= milliseconds(90),
          "the second write started before its reservation");
    check(test.weight_calls == 2U, "the weight was not read at each reservation");
}

void test_reads_are_paced_and_hold_credit() {
    Harness test(kFast);
    test.inner->push_record(kChunk);
    test.inner->push_record(kChunk);
    std::optional<Result<ReceivedRecord>> first;
    std::optional<Result<ReceivedRecord>> second;
    test.on_context([&] {
        test.stream->async_read({}, [&](Result<ReceivedRecord> result) { first.emplace(std::move(result)); });
    });
    check(first && first->ok(), "the first record was not delivered at once");
    first.reset();
    check(test.inner->released_bytes == kChunk, "a delivered record kept its credit");
    const auto requested = Clock::now();
    test.on_context([&] {
        test.stream->async_read({}, [&](Result<ReceivedRecord> result) { second.emplace(std::move(result)); });
    });
    check(!second && test.inner->released_bytes == kChunk,
          "the second record was not held with its credit");
    check(test.wait_for([&] { return second.has_value(); }, milliseconds(2'000)),
          "the held record was never delivered");
    check(second->ok() && Clock::now() - requested >= milliseconds(90),
          "the second record arrived before its reservation");
    second.reset();
    check(test.inner->released_bytes == 2U * kChunk, "the delivered record kept its credit");
}

void test_close_settles_held_operations() {
    Harness test(kSlow);
    std::optional<Status> first;
    std::optional<Status> held;
    test.write(kChunk, first);
    test.write(kChunk, held);
    test.inner->push_record(kChunk);
    std::optional<Result<ReceivedRecord>> read;
    test.on_context([&] {
        test.stream->async_read({}, [&](Result<ReceivedRecord> result) { read.emplace(std::move(result)); });
    });
    check(!held && !read, "operations were not held at a slow rate");
    test.on_context([&] { test.stream->close(Status(StatusCode::Cancelled)); });
    check(held && held->code() == StatusCode::Closed, "close did not settle the held write");
    check(read && read->status().code() == StatusCode::Closed, "close did not settle the held read");
    check(test.inner->written.size() == 1U && test.inner->closes == 1U,
          "a held write reached a closed stream");
    check(test.inner->released_bytes == kChunk, "close kept the held record's credit");
    std::optional<Status> later;
    test.write(1U, later);
    check(later && later->code() == StatusCode::Closed, "a write after close was accepted");
}

void test_termination_ends_waits() {
    Harness test(kSlow);
    std::optional<Status> first;
    std::optional<Status> held;
    test.write(kChunk, first);
    test.write(kChunk, held);
    check(!held, "the write was not held");
    test.inner->terminated_.store(true);
    check(test.wait_for([&] { return held.has_value(); }, milliseconds(2'000)),
          "a terminated stream kept its held write");
    check(held->code() == StatusCode::Closed && test.inner->written.size() == 1U,
          "a held write reached a terminated stream");
}

void test_cancellation_ends_waits() {
    Harness test(kSlow);
    std::optional<Status> first;
    std::optional<Status> held;
    CancellationSource source;
    test.write(kChunk, first);
    test.write(kChunk, held, source.token());
    source.cancel();
    check(test.wait_for([&] { return held.has_value(); }, milliseconds(2'000)),
          "a cancelled write stayed held");
    check(held->code() == StatusCode::Cancelled && test.inner->written.size() == 1U,
          "a cancelled write reached the stream");
}

void test_shutdown_follows_held_writes() {
    Harness test(kFast);
    std::optional<Status> first;
    std::optional<Status> held;
    test.write(kChunk, first);
    test.write(kChunk, held);
    Status shutdown(StatusCode::Internal);
    test.on_context([&] { shutdown = test.stream->shutdown_write(); });
    check(shutdown.ok() && test.inner->shutdowns == 0U, "shutdown overtook a held write");
    std::optional<Status> refused;
    test.write(1U, refused);
    check(refused && refused->code() == StatusCode::Closed, "a write after shutdown was accepted");
    check(test.wait_for([&] { return held.has_value(); }, milliseconds(2'000)),
          "the held write never started");
    check(test.inner->shutdowns == 1U && test.inner->writes_before_shutdown == 2U,
          "shutdown did not follow the held write");
    test.on_context([&] { shutdown = test.stream->shutdown_write(); });
    check(shutdown.ok() && test.inner->shutdowns == 2U, "a repeated shutdown did not reach the stream");
    check(test.stream->shutdown_write().code() == StatusCode::FailedPrecondition,
          "shutdown off the context was accepted");
}

void test_held_write_bound() {
    Harness test(kSlow);
    std::optional<Status> first;
    test.write(kChunk, first);
    std::vector<std::optional<Status>> held(17U);
    for (auto& outcome : held) test.write(1U, outcome);
    for (std::size_t index = 0U; index < 16U; ++index)
        check(!held[index], "a write within the bound was refused");
    check(held[16] && held[16]->code() == StatusCode::ResourceExhausted,
          "a write beyond the bound was accepted");
    test.on_context([&] { test.stream->close(Status(StatusCode::Cancelled)); });
    for (std::size_t index = 0U; index < 16U; ++index)
        check(held[index] && held[index]->code() == StatusCode::Closed,
              "close did not settle every held write");
}

void test_one_read_at_a_time() {
    Harness test(kFast);
    bool first_done = false;
    std::optional<Result<ReceivedRecord>> second;
    test.on_context([&] {
        test.stream->async_read({}, [&](Result<ReceivedRecord>) { first_done = true; });
        test.stream->async_read({}, [&](Result<ReceivedRecord> result) { second.emplace(std::move(result)); });
    });
    check(!first_done && second && second->status().code() == StatusCode::FailedPrecondition,
          "an overlapping read was accepted");
    bool threw = false;
    try {
        test.stream->async_read({}, [](Result<ReceivedRecord>) {});
    } catch (const std::logic_error&) {
        threw = true;
    }
    check(threw, "a read off the context was accepted");
    test.on_context([&] { test.stream->close(Status(StatusCode::Cancelled)); });
    check(first_done, "close did not settle the stream's own pending read");
}

void test_close_from_another_thread() {
    Harness test(kSlow);
    test.inner->push_record(kChunk);
    test.inner->push_record(kChunk);
    std::optional<Result<ReceivedRecord>> first;
    std::optional<Result<ReceivedRecord>> held;
    test.on_context([&] {
        test.stream->async_read({}, [&](Result<ReceivedRecord> result) { first.emplace(std::move(result)); });
    });
    first.reset();
    test.on_context([&] {
        test.stream->async_read({}, [&](Result<ReceivedRecord> result) { held.emplace(std::move(result)); });
    });
    check(!held, "the second record was not held");
    std::thread closer([&] { test.stream->close(Status(StatusCode::Cancelled)); });
    closer.join();
    check(test.inner->closes == 1U && !held, "an off-context close settled outside the context");
    check(test.wait_for([&] { return held.has_value(); }, milliseconds(1'000)),
          "an off-context close never settled the held read");
    check(held->status().code() == StatusCode::Closed, "the held read did not end as closed");
}

}  // namespace

int main() {
    try {
        test_factory_validation();
        test_writes_are_paced();
        test_reads_are_paced_and_hold_credit();
        test_close_settles_held_operations();
        test_termination_ends_waits();
        test_cancellation_ends_waits();
        test_shutdown_follows_held_writes();
        test_held_write_bound();
        test_one_read_at_a_time();
        test_close_from_another_thread();
        std::cout << "paced stream tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "paced stream test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
