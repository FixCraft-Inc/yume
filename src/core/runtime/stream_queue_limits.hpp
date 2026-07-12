/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <string>

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

}  // namespace yume::runtime
