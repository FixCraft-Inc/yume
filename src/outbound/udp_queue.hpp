/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <utility>
#include <vector>

#include "common/udp_queue_budget.hpp"

namespace yume::outbound::detail {

// The shared UDP backlog policy and its budget have one owner in
// common/udp_queue_budget.hpp.
inline constexpr std::size_t kMaxUdpQueuedDatagrams =
    common::kMaxUdpQueuedDatagrams;
inline constexpr std::size_t kMaxUdpQueuedBytes = common::kMaxUdpQueuedBytes;
using UdpQueueBudget = common::UdpQueueBudget;

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
