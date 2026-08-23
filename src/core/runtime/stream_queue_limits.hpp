/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace yume::runtime {

inline constexpr std::size_t kMaxInboundQueuedBytes = 16U * 1024U * 1024U;
inline constexpr std::size_t kMaxInboundQueuedFrames = 64U;

class InboundQueueBudget {
public:
    bool can_enqueue(std::size_t bytes, std::string* reason = nullptr) const {
        if (queued_frames_ + 1U > kMaxInboundQueuedFrames) {
            if (reason) {
                *reason = "inbound queue frame count " + std::to_string(queued_frames_ + 1U) +
                          " exceeds max " + std::to_string(kMaxInboundQueuedFrames);
            }
            return false;
        }
        if (bytes > kMaxInboundQueuedBytes ||
            queued_bytes_ > kMaxInboundQueuedBytes - bytes) {
            if (reason) {
                const std::size_t attempted =
                    bytes > kMaxInboundQueuedBytes ? bytes : queued_bytes_ + bytes;
                *reason = "inbound queue bytes " + std::to_string(attempted) +
                          " exceeds max " + std::to_string(kMaxInboundQueuedBytes);
            }
            return false;
        }
        if (reason) {
            reason->clear();
        }
        return true;
    }

    void record_enqueue(std::size_t bytes) noexcept {
        queued_bytes_ += bytes;
        ++queued_frames_;
    }

    void record_dequeue(std::size_t bytes) noexcept {
        queued_bytes_ = bytes >= queued_bytes_ ? 0U : queued_bytes_ - bytes;
        if (queued_frames_ > 0U) {
            --queued_frames_;
        }
    }

    void clear() noexcept {
        queued_bytes_ = 0U;
        queued_frames_ = 0U;
    }

    std::size_t queued_bytes() const noexcept { return queued_bytes_; }
    std::size_t queued_frames() const noexcept { return queued_frames_; }

private:
    std::size_t queued_bytes_{0};
    std::size_t queued_frames_{0};
};

// Thread-safe admission for buffers that must be copied before they can be
// posted to their owning strand. A move-only reservation follows each buffer
// through executor backlog, the strand queue, and the in-flight operation, so
// none of those stages sit outside the advertised byte/frame limits.
class ConcurrentInboundQueueBudget {
private:
    struct State;

public:
    class Reservation {
    public:
        Reservation() = default;
        Reservation(const Reservation&) = delete;
        Reservation& operator=(const Reservation&) = delete;

        Reservation(Reservation&& other) noexcept
            : state_(std::move(other.state_))
            , bytes_(std::exchange(other.bytes_, 0U)) {}

        Reservation& operator=(Reservation&& other) noexcept {
            if (this != &other) {
                release_now();
                state_ = std::move(other.state_);
                bytes_ = std::exchange(other.bytes_, 0U);
            }
            return *this;
        }

        ~Reservation() noexcept { release_now(); }

        void release_now() noexcept;
        explicit operator bool() const noexcept {
            return state_ != nullptr;
        }

    private:
        friend class ConcurrentInboundQueueBudget;

        Reservation(std::shared_ptr<State> state, std::size_t bytes)
            : state_(std::move(state)), bytes_(bytes) {}

        std::shared_ptr<State> state_;
        std::size_t bytes_{0U};
    };

    ConcurrentInboundQueueBudget()
        : state_(std::make_shared<State>()) {}

    ConcurrentInboundQueueBudget(const ConcurrentInboundQueueBudget&) = delete;
    ConcurrentInboundQueueBudget& operator=(
        const ConcurrentInboundQueueBudget&) = delete;

    std::optional<Reservation> reserve(
        std::size_t bytes,
        std::string* reason = nullptr,
        bool* closed_by_rejection = nullptr) {
        std::lock_guard<std::mutex> lock(state_->mu);
        if (closed_by_rejection) {
            *closed_by_rejection = false;
        }
        if (state_->closed) {
            if (reason) {
                *reason = "inbound queue is closed";
            }
            return std::nullopt;
        }
        if (!state_->budget.can_enqueue(bytes, reason)) {
            // Proxy callers fail closed on saturation. Seal admission while
            // still holding the same lock as the rejected reservation so no
            // concurrent release/reserve can slip between rejection and close.
            state_->closed = true;
            state_->budget.clear();
            if (closed_by_rejection) {
                *closed_by_rejection = true;
            }
            return std::nullopt;
        }
        state_->budget.record_enqueue(bytes);
        return Reservation(state_, bytes);
    }

    bool close() noexcept {
        std::lock_guard<std::mutex> lock(state_->mu);
        if (state_->closed) {
            return false;
        }
        state_->closed = true;
        state_->budget.clear();
        return true;
    }

    std::size_t queued_bytes() const noexcept {
        std::lock_guard<std::mutex> lock(state_->mu);
        return state_->budget.queued_bytes();
    }

    std::size_t queued_frames() const noexcept {
        std::lock_guard<std::mutex> lock(state_->mu);
        return state_->budget.queued_frames();
    }

private:
    struct State {
        std::mutex mu;
        InboundQueueBudget budget;
        bool closed{false};
    };

    std::shared_ptr<State> state_;
};

inline void ConcurrentInboundQueueBudget::Reservation::release_now() noexcept {
    const std::size_t bytes = std::exchange(bytes_, 0U);
    auto state = std::move(state_);
    if (!state) {
        return;
    }
    std::lock_guard<std::mutex> lock(state->mu);
    state->budget.record_dequeue(bytes);
}

}  // namespace yume::runtime
