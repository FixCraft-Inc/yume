/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <utility>

namespace yume::client {

// Revocable operation barrier for stack-owned connected-session executors.
// Handles retain the gate, not a lease. Each transport operation takes a
// short lease; teardown first revokes admission and then waits until all
// already-admitted operations have released their executor-bound objects.
class RuntimeLifetimeGate {
private:
    struct State {
        std::mutex mutex;
        std::condition_variable cv;
        bool active{false};
        bool revoked{false};
        std::size_t leases{0};
    };

public:
    class Lease {
    public:
        Lease() = default;
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;

        Lease(Lease&& other) noexcept
            : state_(std::move(other.state_)) {}

        Lease& operator=(Lease&& other) noexcept {
            if (this != &other) {
                release();
                state_ = std::move(other.state_);
            }
            return *this;
        }

        ~Lease() noexcept { release(); }

        explicit operator bool() const noexcept {
            return static_cast<bool>(state_);
        }

        void release() noexcept {
            auto state = std::move(state_);
            if (!state) return;
            {
                // Failing to take a valid process-local mutex is unrecoverable.
                // Because this function is noexcept, the runtime terminates
                // rather than silently leaking a lease and deadlocking teardown.
                std::lock_guard<std::mutex> lock(state->mutex);
                if (state->leases > 0) --state->leases;
            }
            state->cv.notify_all();
        }

    private:
        friend class RuntimeLifetimeGate;
        explicit Lease(std::shared_ptr<State> state)
            : state_(std::move(state)) {}

        std::shared_ptr<State> state_;
    };

    RuntimeLifetimeGate() : state_(std::make_shared<State>()) {}

    RuntimeLifetimeGate(const RuntimeLifetimeGate&) = delete;
    RuntimeLifetimeGate& operator=(const RuntimeLifetimeGate&) = delete;

    bool activate() {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (state_->revoked) return false;
        state_->active = true;
        return true;
    }

    Lease try_acquire() const {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (!state_->active || state_->revoked) return {};
        ++state_->leases;
        return Lease(state_);
    }

    bool active() const {
        std::lock_guard<std::mutex> lock(state_->mutex);
        return state_->active && !state_->revoked;
    }

    void revoke() {
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            state_->active = false;
            state_->revoked = true;
        }
        state_->cv.notify_all();
    }

    void wait_for_quiescence() const {
        const auto state = state_;
        std::unique_lock<std::mutex> lock(state->mutex);
        state->cv.wait(lock, [&state] { return state->leases == 0; });
    }

private:
    std::shared_ptr<State> state_;
};

}  // namespace yume::client
