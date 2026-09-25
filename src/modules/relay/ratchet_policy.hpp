/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstdint>

namespace yume::relay::ratchet {

// How much one epoch key may protect before the next hybrid epoch replaces
// it. Both peers enforce the byte and frame limits. The time limit is local to
// the sender, because delivery can be delayed.
struct RatchetPolicy {
    std::uint64_t epoch_byte_limit{0};
    std::uint64_t epoch_frame_limit{0};
    std::chrono::milliseconds epoch_active_limit{0};

    friend constexpr bool operator==(const RatchetPolicy&,
                                     const RatchetPolicy&) = default;
};

// A protected frame is capped at 256 KiB whatever the policy. A policy
// changes how many one-use message keys share one hybrid epoch, never the
// AEAD, KEM, associated data or framing.
inline constexpr std::uint64_t kMaxProtectedPayload = 256ULL * 1024ULL;

// The policy relay channels use in both directions.
inline constexpr RatchetPolicy kExtremePolicy{
    256ULL * 1024ULL,
    512,
    std::chrono::milliseconds(500),
};

inline constexpr std::uint64_t kMinEpochByteLimit = kMaxProtectedPayload;
inline constexpr std::uint64_t kMaxEpochByteLimit = 1ULL << 40;  // 1 TiB
inline constexpr std::uint64_t kMinEpochFrameLimit = 1;
inline constexpr std::uint64_t kMaxEpochFrameLimit = 1ULL << 30;
inline constexpr auto kMinEpochActiveLimit = std::chrono::milliseconds(1);
inline constexpr auto kMaxEpochActiveLimit = std::chrono::hours(24);

constexpr bool IsRatchetPolicyValid(const RatchetPolicy& policy) noexcept {
    return policy.epoch_byte_limit >= kMinEpochByteLimit &&
           policy.epoch_byte_limit <= kMaxEpochByteLimit &&
           policy.epoch_frame_limit >= kMinEpochFrameLimit &&
           policy.epoch_frame_limit <= kMaxEpochFrameLimit &&
           policy.epoch_active_limit >= kMinEpochActiveLimit &&
           policy.epoch_active_limit <= kMaxEpochActiveLimit;
}

}  // namespace yume::relay::ratchet
