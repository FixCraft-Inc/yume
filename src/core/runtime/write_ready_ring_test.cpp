/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * The write scheduler's ready list under sustained allocation failure. A list
 * that can refuse an entry leaves a stream marked with nothing behind it,
 * which strands every frame already queued on that stream: the marker
 * suppresses each later mark, so no enqueue can rescue it. These cases hold
 * every allocation failing, so any allocation on the marking, selection or
 * rotation path fails them.
 */

#include "core/runtime/write_ready_ring.hpp"
#include "test_support/allocation_failure.hpp"

#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {

using Ring = yume::runtime::WriteReadyRing<5>;

void check(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "write ready ring: %s\n", message);
        std::exit(1);
    }
}

class FailedAllocations {
public:
    FailedAllocations() {
        yume::test::fail_allocations.store(true, std::memory_order_relaxed);
    }
    ~FailedAllocations() {
        yume::test::fail_allocations.store(false, std::memory_order_relaxed);
    }
};

void test_marks_and_takes_in_fifo_order() {
    Ring ring;
    {
        const FailedAllocations no_memory;
        for (int id = 1; id <= 200; ++id) {
            ring.mark(static_cast<std::uint8_t>(id), 2);
        }
        check(ring.size(2) == 200, "the ring lost marked streams");
        for (int id = 1; id <= 200; ++id) {
            const auto head = ring.front(2);
            check(head.has_value() && *head == id, "FIFO order was not kept");
            ring.take_front(2);
        }
    }
    check(!ring.front(2).has_value(), "the ring kept a taken stream");
    check(ring.size(2) == 0, "the ring kept a stale count");
}

void test_marking_is_idempotent_and_single_membership() {
    Ring ring;
    const FailedAllocations no_memory;
    ring.mark(7, 0);
    ring.mark(7, 0);
    ring.mark(7, 3);
    check(ring.size(0) == 1, "a repeated mark duplicated the stream");
    check(ring.size(3) == 0, "a marked stream joined a second priority");
    check(ring.marked(7), "the stream lost its marker");
    ring.take_front(0);
    check(!ring.marked(7), "take_front left the marker set");
    ring.mark(7, 3);
    check(ring.size(3) == 1, "a taken stream could not be marked again");
}

void test_rotation_never_drops_a_stream() {
    Ring ring;
    const FailedAllocations no_memory;
    for (std::uint8_t id = 1; id <= 4; ++id) {
        ring.mark(id, 1);
    }
    // A selector pass that skips every candidate must leave the list intact
    // and in its original order, with no allocation available to it. The
    // deque this replaced walked forward on each pop_front/push_back pair and
    // needed a fresh node after 507 rotations, which dropped the stream while
    // its marker stayed set. Rotate well past that.
    for (int pass = 0; pass < 4096; ++pass) {
        ring.rotate_front(1);
    }
    check(ring.size(1) == 4, "rotation lost a stream");
    for (std::uint8_t id = 1; id <= 4; ++id) {
        const auto head = ring.front(1);
        check(head.has_value() && *head == id, "rotation reordered the list");
        ring.take_front(1);
    }
    check(ring.size(1) == 0, "rotation left a stale count");
}

// The defect this structure replaces: a stream whose head was just dispatched
// must be re-markable immediately, with no later enqueue, close or synthetic
// callback available to rescue it.
void test_dispatched_stream_is_immediately_reschedulable() {
    Ring ring;
    const FailedAllocations no_memory;
    ring.mark(9, 2);
    for (int dispatch = 0; dispatch < 64; ++dispatch) {
        const auto head = ring.front(2);
        check(head.has_value() && *head == 9, "the stream was not selectable");
        ring.take_front(2);
        check(!ring.marked(9), "the marker outlived selection");
        ring.mark(9, 2);
        check(ring.marked(9), "the stream could not be re-marked");
    }
    check(ring.size(2) == 1, "repeated re-marking duplicated the stream");
}

void test_reset_clears_every_priority() {
    Ring ring;
    const FailedAllocations no_memory;
    for (std::size_t priority = 0; priority < 5; ++priority) {
        ring.mark(static_cast<std::uint8_t>(20 + priority), priority);
    }
    ring.reset();
    for (std::size_t priority = 0; priority < 5; ++priority) {
        check(ring.size(priority) == 0, "reset left a stale count");
        check(!ring.front(priority).has_value(), "reset left an entry");
        check(!ring.marked(static_cast<std::uint8_t>(20 + priority)),
              "reset left a marker");
    }
}

}  // namespace

int main() {
    test_marks_and_takes_in_fifo_order();
    test_marking_is_idempotent_and_single_membership();
    test_rotation_never_drops_a_stream();
    test_dispatched_stream_is_immediately_reschedulable();
    test_reset_clears_every_priority();
    std::puts("write ready ring: passed");
    return 0;
}
