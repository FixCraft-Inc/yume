/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace yume::outbound::detail {

// UDP has no delivery guarantee to preserve when a local consumer or an OPEN
// handshake falls behind. Keep each backlog small and deterministic instead
// of allowing a datagram burst to consume unbounded process memory.
inline constexpr std::size_t kMaxUdpQueuedDatagrams = 64U;
inline constexpr std::size_t kMaxUdpQueuedBytes = 1U * 1024U * 1024U;

class UdpQueueBudget {
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

    private:
        friend class UdpQueueBudget;

        Reservation(std::shared_ptr<State> state, std::size_t bytes)
            : state_(std::move(state)), bytes_(bytes) {}

        std::shared_ptr<State> state_;
        std::size_t bytes_{0U};
    };

    UdpQueueBudget()
        : state_(std::make_shared<State>()) {}

    UdpQueueBudget(const UdpQueueBudget&) = delete;
    UdpQueueBudget& operator=(const UdpQueueBudget&) = delete;

    // The caller drops the newest datagram when admission fails. Unlike the
    // reliable-stream budget, saturation does not seal this queue: releasing
    // older datagrams immediately restores admission and keeps UDP usable.
    [[nodiscard]] std::optional<Reservation> try_reserve(
        std::size_t bytes) {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (state_->closed ||
            state_->queued_datagrams >= kMaxUdpQueuedDatagrams ||
            bytes > kMaxUdpQueuedBytes ||
            state_->queued_bytes > kMaxUdpQueuedBytes - bytes) {
            return std::nullopt;
        }
        ++state_->queued_datagrams;
        state_->queued_bytes += bytes;
        return Reservation(state_, bytes);
    }

    void close() noexcept {
        std::lock_guard<std::mutex> lock(state_->mutex);
        state_->closed = true;
    }

    [[nodiscard]] std::size_t queued_datagrams() const noexcept {
        std::lock_guard<std::mutex> lock(state_->mutex);
        return state_->queued_datagrams;
    }

    [[nodiscard]] std::size_t queued_bytes() const noexcept {
        std::lock_guard<std::mutex> lock(state_->mutex);
        return state_->queued_bytes;
    }

private:
    struct State {
        std::mutex mutex;
        std::size_t queued_datagrams{0U};
        std::size_t queued_bytes{0U};
        bool closed{false};
    };

    std::shared_ptr<State> state_;
};

inline void UdpQueueBudget::Reservation::release_now() noexcept {
    const std::size_t bytes = std::exchange(bytes_, 0U);
    auto state = std::move(state_);
    if (!state) {
        return;
    }
    std::lock_guard<std::mutex> lock(state->mutex);
    if (state->queued_datagrams > 0U) {
        --state->queued_datagrams;
    }
    state->queued_bytes = bytes >= state->queued_bytes
        ? 0U
        : state->queued_bytes - bytes;
}

// Several destinations can wait for OPEN at once, but they all share one
// session/server budget. Each per-destination queue therefore owns only RAII
// reservations into the common budget, not an independent limit.
class BudgetedUdpDatagramQueue {
public:
    using Bytes = std::vector<std::uint8_t>;

    explicit BudgetedUdpDatagramQueue(UdpQueueBudget& budget)
        : budget_(budget) {}

    BudgetedUdpDatagramQueue(const BudgetedUdpDatagramQueue&) = delete;
    BudgetedUdpDatagramQueue& operator=(
        const BudgetedUdpDatagramQueue&) = delete;

    [[nodiscard]] bool try_push(Bytes data) {
        auto reservation = budget_.try_reserve(data.size());
        if (!reservation) {
            return false;
        }
        queue_.push_back({std::move(data), std::move(*reservation)});
        return true;
    }

    [[nodiscard]] std::optional<Bytes> pop_front() {
        if (queue_.empty()) {
            return std::nullopt;
        }
        Bytes data = std::move(queue_.front().data);
        queue_.pop_front();
        return data;
    }

    void clear() noexcept { queue_.clear(); }

    [[nodiscard]] bool empty() const noexcept { return queue_.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return queue_.size(); }

private:
    struct Entry {
        Bytes data;
        UdpQueueBudget::Reservation reservation;
    };

    UdpQueueBudget& budget_;
    std::deque<Entry> queue_;
};

}  // namespace yume::outbound::detail
