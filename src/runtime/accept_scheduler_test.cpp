/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Deterministic pacing checks for the native server accept loop. A real Asio
// timer cannot be made to refuse scheduling on demand: its handler memory
// bypasses operator new and is recycled per thread. This driver can.
#include "runtime/accept_scheduler.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <vector>

namespace {
using yume::engine::Status;
using yume::engine::StatusCode;
using yume::runtime::AcceptScheduler;
using namespace std::chrono_literals;

#define CHECK(condition) do { if (!(condition)) { \
    std::cerr << "accept scheduler check failed at " << __LINE__ << ": " #condition "\n"; \
    std::abort(); \
} } while (false)

enum class Inline : std::uint8_t { None, Success, Failure };

class Driver final : public AcceptScheduler::Driver {
public:
    explicit Driver(std::size_t lanes) : stopped(lanes, false), retry(lanes, false) {}

    Status start_accept(std::size_t lane, AcceptScheduler::Clock::time_point armed_at) noexcept override {
        ++attempts;
        ++depth;
        max_depth = std::max(max_depth, depth);
        Status result = Status::success();
        if (refusal) {
            result = Status(*refusal);
        } else if (capacity == 0U) {
            result = Status(StatusCode::ResourceExhausted);
        } else {
            --capacity;
            ++accepted;
            if (inline_result == Inline::None) {
                pending.push_back({lane, armed_at});
            } else {
                if (inline_result == Inline::Failure) ++capacity;
                scheduler->settled(lane, armed_at, inline_result == Inline::Success);
            }
        }
        --depth;
        return result;
    }
    bool schedule_retry(std::size_t lane, std::chrono::milliseconds delay) noexcept override {
        ++schedules;
        CHECK(delay == expected_delay);
        if (!schedule_ok) return false;
        CHECK(!retry[lane]);
        retry[lane] = true;
        return true;
    }
    bool listener_stopped(std::size_t lane) const noexcept override { return stopped[lane]; }
    bool owner_closing() const noexcept override { return closing; }
    AcceptScheduler::Clock::time_point now() const noexcept override { return clock; }
    void failed(Status status) noexcept override { failures.push_back(status.code()); }

    // A session start from `lane` settles. Only success keeps its slot.
    void settle(std::size_t lane, bool succeeded) {
        const auto found = std::find_if(pending.begin(), pending.end(),
            [lane](const auto& start) { return start.lane == lane; });
        CHECK(found != pending.end());
        const auto armed_at = found->armed_at;
        pending.erase(found);
        if (!succeeded) ++capacity;
        scheduler->settled(lane, armed_at, succeeded);
    }
    void fire(std::size_t lane) {
        CHECK(retry[lane]);
        retry[lane] = false;
        scheduler->retry_due(lane);
    }
    std::size_t pending_on(std::size_t lane) const {
        return static_cast<std::size_t>(std::count_if(pending.begin(), pending.end(),
            [lane](const auto& start) { return start.lane == lane; }));
    }

    struct Start final {
        std::size_t lane;
        AcceptScheduler::Clock::time_point armed_at;
    };

    AcceptScheduler* scheduler{nullptr};
    std::optional<StatusCode> refusal;
    std::size_t capacity{1024U};
    Inline inline_result{Inline::None};
    bool schedule_ok{true};
    bool closing{false};
    std::chrono::milliseconds expected_delay{100};
    AcceptScheduler::Clock::time_point clock{};
    std::vector<bool> stopped;
    std::vector<bool> retry;
    std::vector<Start> pending;
    std::vector<StatusCode> failures;
    std::size_t attempts{0U}, accepted{0U}, schedules{0U}, depth{0U}, max_depth{0U};
};

void test_validation_and_fill() {
    Driver driver(3U);
    AcceptScheduler scheduler(driver, 3U);
    driver.scheduler = &scheduler;
    CHECK(scheduler.start(0U, 100ms).code() == StatusCode::InvalidArgument);
    CHECK(scheduler.start(2U, 0ms).code() == StatusCode::InvalidArgument);
    CHECK(!scheduler.started() && driver.attempts == 0U);
    CHECK(scheduler.start(2U, 100ms).ok());
    CHECK(scheduler.started());
    for (std::size_t lane = 0U; lane < 3U; ++lane) CHECK(driver.pending_on(lane) == 2U);
    CHECK(scheduler.start(2U, 100ms).code() == StatusCode::FailedPrecondition);
    CHECK(driver.attempts == 6U && driver.schedules == 0U && driver.failures.empty());

    AcceptScheduler empty(driver, 0U);
    CHECK(empty.start(1U, 100ms).code() == StatusCode::InvalidArgument);
}

void test_settlement_rearms_and_backs_off() {
    Driver driver(1U);
    AcceptScheduler scheduler(driver, 1U);
    driver.scheduler = &scheduler;
    CHECK(scheduler.start(1U, 100ms).ok());
    driver.settle(0U, true);
    CHECK(driver.attempts == 2U && driver.pending.size() == 1U);
    // A start that failed well after arming, such as an expired AUTH, re-arms.
    driver.clock += 150ms;
    driver.settle(0U, false);
    CHECK(driver.attempts == 3U && driver.pending.size() == 1U && driver.schedules == 0U);
    // One that failed as soon as it was armed waits for the retry.
    driver.clock += 10ms;
    driver.settle(0U, false);
    CHECK(driver.attempts == 3U && driver.pending.empty() && driver.retry[0U]);
    driver.clock += 100ms;
    driver.fire(0U);
    CHECK(driver.attempts == 4U && driver.pending.size() == 1U && driver.failures.empty());
}

void test_capacity_refusal_polls_without_spinning() {
    Driver driver(2U);
    driver.capacity = 1U;
    driver.expected_delay = 50ms;
    AcceptScheduler scheduler(driver, 2U);
    driver.scheduler = &scheduler;
    // The first lane takes the only slot. The second is refused while arming.
    CHECK(scheduler.start(1U, 50ms).ok());
    CHECK(driver.attempts == 2U && driver.pending_on(0U) == 1U && driver.retry[1U]);
    for (std::size_t round = 1U; round <= 5U; ++round) {
        driver.clock += 50ms;
        driver.fire(1U);
        CHECK(driver.attempts == 2U + round && driver.retry[1U]);
    }
    // A successful session keeps its slot, so its lane polls too.
    driver.settle(0U, true);
    CHECK(driver.attempts == 8U && driver.retry[0U] && driver.pending.empty());
    // A session ended: the next due retry takes the recovered slot.
    driver.capacity = 1U;
    driver.fire(1U);
    CHECK(driver.pending_on(1U) == 1U && !driver.retry[1U]);
    driver.fire(0U);
    CHECK(driver.pending_on(0U) == 0U && driver.retry[0U]);
    CHECK(driver.failures.empty());
}

void test_unschedulable_retry() {
    {
        // Nothing is pending, so nothing would ever re-arm the listener.
        Driver driver(2U);
        driver.refusal = StatusCode::ResourceExhausted;
        driver.schedule_ok = false;
        AcceptScheduler scheduler(driver, 2U);
        driver.scheduler = &scheduler;
        CHECK(scheduler.start(1U, 100ms).ok());
        CHECK(driver.failures.size() == 1U && driver.failures[0U] == StatusCode::ResourceExhausted);
        CHECK(driver.attempts == 1U);
        driver.refusal.reset();
        driver.schedule_ok = true;
        scheduler.retry_due(0U);
        scheduler.retry_due(1U);
        CHECK(driver.attempts == 1U && driver.schedules == 1U && driver.failures.size() == 1U);
    }
    {
        // A pending start on the same listener re-arms it when it settles.
        Driver driver(1U);
        AcceptScheduler scheduler(driver, 1U);
        driver.scheduler = &scheduler;
        CHECK(scheduler.start(2U, 100ms).ok());
        driver.schedule_ok = false;
        driver.settle(0U, false);
        CHECK(driver.failures.empty() && driver.pending.size() == 1U && !driver.retry[0U]);
        driver.schedule_ok = true;
        driver.clock += 200ms;
        driver.settle(0U, false);
        CHECK(driver.pending.size() == 2U && driver.failures.empty());
        // The last pending start then fails immediately with no retry available.
        driver.schedule_ok = false;
        driver.settle(0U, false);
        CHECK(driver.failures.empty() && driver.pending.size() == 1U);
        driver.settle(0U, false);
        CHECK(driver.failures.size() == 1U && driver.failures[0U] == StatusCode::ResourceExhausted);
        const auto attempts = driver.attempts;
        driver.schedule_ok = true;
        driver.clock += 1s;
        scheduler.retry_due(0U);
        CHECK(driver.attempts == attempts);
    }
}

void test_reentrant_inline_completion() {
    {
        // Inline failures back off instead of recursing or retrying at once.
        Driver driver(1U);
        driver.inline_result = Inline::Failure;
        AcceptScheduler scheduler(driver, 1U);
        driver.scheduler = &scheduler;
        CHECK(scheduler.start(4U, 100ms).ok());
        CHECK(driver.attempts == 1U && driver.retry[0U] && driver.max_depth == 1U);
    }
    {
        // Inline successes continue the same pass until capacity refuses.
        Driver driver(1U);
        driver.inline_result = Inline::Success;
        driver.capacity = 5U;
        AcceptScheduler scheduler(driver, 1U);
        driver.scheduler = &scheduler;
        CHECK(scheduler.start(2U, 100ms).ok());
        CHECK(driver.accepted == 5U && driver.attempts == 6U);
        CHECK(driver.max_depth == 1U && driver.retry[0U] && driver.failures.empty());
    }
}

void test_stopped_listener_and_close() {
    {
        Driver driver(2U);
        AcceptScheduler scheduler(driver, 2U);
        driver.scheduler = &scheduler;
        CHECK(scheduler.start(1U, 100ms).ok());
        driver.stopped[1U] = true;
        driver.clock += 1s;
        driver.settle(1U, false);
        CHECK(driver.failures.size() == 1U && driver.failures[0U] == StatusCode::Closed);
        driver.settle(0U, true);
        CHECK(driver.attempts == 2U && driver.schedules == 0U && driver.failures.size() == 1U);
    }
    {
        // Close with a retry outstanding: its delivery starts nothing.
        Driver driver(1U);
        AcceptScheduler scheduler(driver, 1U);
        driver.scheduler = &scheduler;
        CHECK(scheduler.start(1U, 100ms).ok());
        driver.settle(0U, false);
        CHECK(driver.retry[0U]);
        driver.closing = true;
        driver.fire(0U);
        CHECK(driver.attempts == 1U && driver.failures.empty());
    }
    {
        // A Closed refusal or a settlement during close schedules nothing, even
        // when the listener has already stopped.
        Driver driver(1U);
        driver.refusal = StatusCode::Closed;
        AcceptScheduler scheduler(driver, 1U);
        driver.scheduler = &scheduler;
        CHECK(scheduler.start(1U, 100ms).ok());
        CHECK(driver.attempts == 1U && driver.schedules == 0U && driver.failures.empty());

        Driver closing(1U);
        AcceptScheduler closing_scheduler(closing, 1U);
        closing.scheduler = &closing_scheduler;
        CHECK(closing_scheduler.start(1U, 100ms).ok());
        closing.closing = true;
        closing.stopped[0U] = true;
        closing.settle(0U, false);
        CHECK(closing.attempts == 1U && closing.schedules == 0U && closing.failures.empty());
    }
}

void test_lanes_are_independent() {
    Driver driver(2U);
    AcceptScheduler scheduler(driver, 2U);
    driver.scheduler = &scheduler;
    CHECK(scheduler.start(1U, 100ms).ok());
    driver.settle(0U, false);
    CHECK(driver.retry[0U] && !driver.retry[1U]);
    driver.settle(1U, true);
    CHECK(driver.attempts == 3U && driver.pending_on(1U) == 1U && driver.pending_on(0U) == 0U);
}

}  // namespace

int main() {
    test_validation_and_fill();
    test_settlement_rearms_and_backs_off();
    test_capacity_refusal_polls_without_spinning();
    test_unschedulable_retry();
    test_reentrant_inline_completion();
    test_stopped_listener_and_close();
    test_lanes_are_independent();
    std::cout << "native accept scheduling checks passed\n";
}
