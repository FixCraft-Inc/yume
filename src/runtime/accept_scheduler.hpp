/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

#include "engine/status.hpp"

namespace yume::runtime {

// Keeps a bounded number of server session starts pending on each listener.
// This is pacing policy only: the driver owns the starts, the retry timer, the
// clock and endpoint shutdown. Every call, including each driver callback, runs
// on the owner's single execution context. A driver may call settled() before
// start_accept() returns. That re-entry continues the current arming pass
// instead of recursing.
//
// While running, every listener has a pending start or a scheduled retry. If a
// retry cannot be scheduled for a listener with nothing pending, or a listener
// stops accepting, the scheduler stops and reports once. It never leaves a
// listener silently idle or retries without a delay.
class AcceptScheduler final {
public:
    using Clock = std::chrono::steady_clock;

    class Driver {
    public:
        // Starts one accept on `lane`. A refusal returns non-OK and never calls
        // settled(). An accepted start calls settled() exactly once, possibly
        // before returning. A Closed refusal means the owner is closing.
        virtual engine::Status start_accept(std::size_t lane,
                                            Clock::time_point armed_at) noexcept = 0;
        // Arranges exactly one later retry_due(lane), never before returning.
        // Returns false when nothing was scheduled.
        virtual bool schedule_retry(std::size_t lane,
                                    std::chrono::milliseconds delay) noexcept = 0;
        virtual bool listener_stopped(std::size_t lane) const noexcept = 0;
        virtual bool owner_closing() const noexcept = 0;
        virtual Clock::time_point now() const noexcept = 0;
        // Runs at most once. The scheduler starts nothing afterwards.
        virtual void failed(engine::Status status) noexcept = 0;

    protected:
        Driver() = default;
        Driver(const Driver&) = default;
        Driver& operator=(const Driver&) = default;
        ~Driver() = default;
    };

    AcceptScheduler(Driver& driver, std::size_t lanes)
        : driver_(driver), lanes_(lanes) {}

    AcceptScheduler(const AcceptScheduler&) = delete;
    AcceptScheduler& operator=(const AcceptScheduler&) = delete;

    // Arms every lane. A refusal changes nothing and reports nothing. After
    // success, failed() may already have run when this returns.
    engine::Status start(std::size_t pending_per_lane,
                         std::chrono::milliseconds retry_delay) noexcept {
        if (lanes_.empty() || pending_per_lane == 0U ||
            retry_delay <= std::chrono::milliseconds::zero()) {
            return engine::Status(engine::StatusCode::InvalidArgument);
        }
        if (phase_ != Phase::Idle) {
            return engine::Status(engine::StatusCode::FailedPrecondition);
        }
        pending_per_lane_ = pending_per_lane;
        retry_delay_ = retry_delay;
        phase_ = Phase::Running;
        for (std::size_t lane = 0U; lane < lanes_.size(); ++lane) arm(lane);
        return engine::Status::success();
    }

    // True once start() has succeeded, including after a reported failure.
    bool started() const noexcept { return phase_ != Phase::Idle; }

    // An accepted start from `lane` settled. Success re-arms at once. A failure
    // sooner than the retry delay after arming waits for a retry, so a listener
    // whose starts keep failing immediately cannot occupy the context.
    void settled(std::size_t lane, Clock::time_point armed_at,
                 bool succeeded) noexcept {
        auto& state = lanes_[lane];
        if (state.pending != 0U) --state.pending;
        if (!running()) return;
        if (succeeded) {
            arm(lane);
        } else if (driver_.listener_stopped(lane)) {
            fail(engine::StatusCode::Closed, "native listener stopped accepting");
        } else if (driver_.now() - armed_at < retry_delay_) {
            defer(lane);
        } else {
            arm(lane);
        }
    }

    void retry_due(std::size_t lane) noexcept {
        lanes_[lane].retry_scheduled = false;
        arm(lane);
    }

private:
    enum class Phase : std::uint8_t { Idle, Running, Failed };

    struct LaneState final {
        std::size_t pending{0U};
        bool retry_scheduled{false};
        bool arming{false};
        bool arm_again{false};
    };

    bool running() const noexcept {
        return phase_ == Phase::Running && !driver_.owner_closing();
    }

    void arm(std::size_t lane) noexcept {
        auto& state = lanes_[lane];
        if (state.arming) {
            state.arm_again = true;
            return;
        }
        state.arming = true;
        do {
            state.arm_again = false;
            while (running() && !state.retry_scheduled &&
                   state.pending < pending_per_lane_) {
                ++state.pending;
                const auto status = driver_.start_accept(lane, driver_.now());
                if (status.ok()) continue;
                --state.pending;
                if (status.code() != engine::StatusCode::Closed) defer(lane);
                break;
            }
        } while (state.arm_again);
        state.arming = false;
    }

    void defer(std::size_t lane) noexcept {
        auto& state = lanes_[lane];
        if (state.retry_scheduled || !running()) return;
        if (driver_.schedule_retry(lane, retry_delay_)) {
            state.retry_scheduled = true;
        } else if (state.pending == 0U) {
            // A pending start would re-arm this lane when it settles. With
            // none, no later event would.
            fail(engine::StatusCode::ResourceExhausted,
                 "accept retry could not be scheduled");
        }
    }

    void fail(engine::StatusCode code, std::string_view message) noexcept {
        if (phase_ != Phase::Running) return;
        phase_ = Phase::Failed;
        engine::Status status;
        try {
            status = engine::Status(code, message);
        } catch (...) {
            status = engine::Status(code);
        }
        driver_.failed(std::move(status));
    }

    Driver& driver_;
    std::vector<LaneState> lanes_;
    std::size_t pending_per_lane_{0U};
    std::chrono::milliseconds retry_delay_{0};
    Phase phase_{Phase::Idle};
};

}  // namespace yume::runtime
