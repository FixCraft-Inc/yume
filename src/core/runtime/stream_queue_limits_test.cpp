/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/runtime/inbound_credit.hpp"
#include "core/runtime/stream_queue_limits.hpp"

#include <cassert>
#include <string>
#include <utility>

int main() {
    using yume::runtime::InboundCredit;
    using yume::runtime::ConcurrentInboundQueueBudget;
    using yume::runtime::InboundQueueBudget;
    using yume::runtime::kMaxInboundQueuedBytes;
    using yume::runtime::kMaxInboundQueuedFrames;

    InboundQueueBudget bytes;
    std::string reason;
    assert(bytes.can_enqueue(kMaxInboundQueuedBytes, &reason));
    assert(reason.empty());
    bytes.record_enqueue(kMaxInboundQueuedBytes);
    assert(bytes.queued_bytes() == kMaxInboundQueuedBytes);
    assert(bytes.queued_frames() == 1U);
    assert(!bytes.can_enqueue(1U, &reason));
    assert(!reason.empty());
    bytes.record_dequeue(kMaxInboundQueuedBytes);
    assert(bytes.queued_bytes() == 0U);
    assert(bytes.queued_frames() == 0U);

    InboundQueueBudget frames;
    for (std::size_t i = 0; i < kMaxInboundQueuedFrames; ++i) {
        assert(frames.can_enqueue(1U, &reason));
        frames.record_enqueue(1U);
    }
    assert(frames.queued_frames() == kMaxInboundQueuedFrames);
    assert(!frames.can_enqueue(1U, &reason));
    frames.record_dequeue(1U);
    assert(frames.can_enqueue(1U, &reason));
    frames.clear();
    assert(frames.queued_bytes() == 0U);
    assert(frames.queued_frames() == 0U);

    std::size_t released = 0U;
    {
        InboundCredit first(17U, [&released](std::size_t bytes) {
            released += bytes;
        });
        assert(first.size() == 17U);

        InboundCredit second(std::move(first));
        assert(!first);
        assert(second.size() == 17U);

        InboundCredit third(5U, [&released](std::size_t bytes) {
            released += bytes;
        });
        third = std::move(second);
        assert(released == 5U);
        assert(third.size() == 17U);
        third.release_now();
        third.release_now();
    }
    assert(released == 22U);

    ConcurrentInboundQueueBudget byte_budget;
    auto full = byte_budget.reserve(kMaxInboundQueuedBytes, &reason);
    assert(full.has_value());
    assert(byte_budget.queued_bytes() == kMaxInboundQueuedBytes);
    assert(byte_budget.queued_frames() == 1U);
    bool closed_by_rejection = false;
    assert(!byte_budget.reserve(
        1U, &reason, &closed_by_rejection).has_value());
    assert(closed_by_rejection);
    full->release_now();
    assert(byte_budget.queued_bytes() == 0U);

    ConcurrentInboundQueueBudget frame_budget;
    std::vector<ConcurrentInboundQueueBudget::Reservation> reservations;
    reservations.reserve(kMaxInboundQueuedFrames);
    for (std::size_t i = 0; i < kMaxInboundQueuedFrames; ++i) {
        auto reservation = frame_budget.reserve(1U, &reason);
        assert(reservation.has_value());
        reservations.push_back(std::move(*reservation));
    }
    closed_by_rejection = false;
    assert(!frame_budget.reserve(
        1U, &reason, &closed_by_rejection).has_value());
    assert(closed_by_rejection);
    reservations.clear();
    assert(!frame_budget.close());

    ConcurrentInboundQueueBudget explicitly_closed;
    assert(explicitly_closed.close());
    assert(!explicitly_closed.close());
    closed_by_rejection = true;
    assert(!explicitly_closed.reserve(
        1U, &reason, &closed_by_rejection).has_value());
    assert(!closed_by_rejection);

    return 0;
}
