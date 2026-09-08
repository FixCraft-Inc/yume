/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace yume::runtime {

// Priority-ordered ready list over the 256 stream ids of one connection.
//
// Marking, selecting and rotating a stream must not allocate. A ready list
// that can fail to accept an entry leaves the stream carrying a marker with
// nothing behind it, which silently strands every frame already queued on that
// stream: the marker suppresses each later mark, so no subsequent enqueue can
// rescue it and the frames only settle when the connection closes. Both write
// schedulers therefore share this fixed structure rather than a container that
// allocates on insertion.
//
// A stream belongs to at most one priority list at a time, so a single
// successor slot per stream is enough to hold every list at once.
template <std::size_t Priorities>
class WriteReadyRing {
public:
    static_assert(Priorities > 0, "a scheduler needs at least one priority");

    WriteReadyRing() noexcept { reset(); }

    void reset() noexcept {
        next_.fill(kNone);
        head_.fill(kNone);
        tail_.fill(kNone);
        priority_.fill(kUnmarked);
        count_.fill(0);
    }

    bool marked(std::uint8_t stream_id) const noexcept {
        return priority_[stream_id] != kUnmarked;
    }

    std::size_t size(std::size_t priority) const noexcept {
        return count_[priority];
    }

    // Ignored when the stream is already linked, which keeps its queue order.
    void mark(std::uint8_t stream_id, std::size_t priority) noexcept {
        if (marked(stream_id)) return;
        next_[stream_id] = kNone;
        if (tail_[priority] == kNone) {
            head_[priority] = stream_id;
        } else {
            next_[static_cast<std::uint8_t>(tail_[priority])] = stream_id;
        }
        tail_[priority] = stream_id;
        priority_[stream_id] = static_cast<std::int16_t>(priority);
        ++count_[priority];
    }

    std::optional<std::uint8_t> front(std::size_t priority) const noexcept {
        if (head_[priority] == kNone) return std::nullopt;
        return static_cast<std::uint8_t>(head_[priority]);
    }

    // Unlink the head of its list and clear its marker. The caller owns the
    // stream afterwards and must mark it again to reschedule it.
    void take_front(std::size_t priority) noexcept {
        const std::int16_t head = head_[priority];
        if (head == kNone) return;
        const auto stream_id = static_cast<std::uint8_t>(head);
        head_[priority] = next_[stream_id];
        if (head_[priority] == kNone) tail_[priority] = kNone;
        next_[stream_id] = kNone;
        priority_[stream_id] = kUnmarked;
        --count_[priority];
    }

    // Send the head to the back of its own list, keeping its marker, so one
    // pass over a priority can skip a stream without losing it.
    void rotate_front(std::size_t priority) noexcept {
        const std::int16_t head = head_[priority];
        if (head == kNone || head == tail_[priority]) return;
        const auto stream_id = static_cast<std::uint8_t>(head);
        head_[priority] = next_[stream_id];
        next_[stream_id] = kNone;
        next_[static_cast<std::uint8_t>(tail_[priority])] = stream_id;
        tail_[priority] = stream_id;
    }

private:
    static constexpr std::int16_t kNone = -1;
    static constexpr std::int16_t kUnmarked = -1;

    std::array<std::int16_t, 256> next_{};
    std::array<std::int16_t, 256> priority_{};
    std::array<std::int16_t, Priorities> head_{};
    std::array<std::int16_t, Priorities> tail_{};
    std::array<std::uint16_t, Priorities> count_{};
};

}  // namespace yume::runtime
