/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/runtime/stream_queue_limits.hpp"

#include <cassert>
#include <string>

int main() {
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

    return 0;
}
