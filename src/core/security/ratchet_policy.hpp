/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>

namespace yume::ratchet {

enum class SecurityMode : std::uint8_t {
    Extreme,
    Normal,
    Soft,
    Ultimate,
};

struct RatchetPolicy {
    std::uint64_t epoch_byte_limit{0};
    std::uint64_t epoch_frame_limit{0};
    std::chrono::milliseconds epoch_active_limit{0};

    friend constexpr bool operator==(const RatchetPolicy&,
                                     const RatchetPolicy&) = default;
};

// A protected frame remains capped at 256 KiB independently of the selected
// policy. Profiles change how many one-use message keys share one hybrid epoch;
// they never change AEAD, KEM, AAD, or framing algorithms.
inline constexpr std::uint64_t kMaxProtectedPayload = 256U * 1024U;

inline constexpr RatchetPolicy kExtremePolicy{
    256U * 1024U,
    512,
    std::chrono::milliseconds(500),
};
inline constexpr RatchetPolicy kNormalPolicy{
    8ULL * 1024ULL * 1024ULL * 1024ULL,
    256ULL * 1024ULL,
    std::chrono::seconds(60),
};
inline constexpr RatchetPolicy kSoftPolicy{
    256ULL * 1024ULL * 1024ULL * 1024ULL,
    8ULL * 1024ULL * 1024ULL,
    std::chrono::minutes(30),
};

inline constexpr std::uint64_t kMinEpochByteLimit = kMaxProtectedPayload;
inline constexpr std::uint64_t kMaxEpochByteLimit = 1ULL << 40;  // 1 TiB
inline constexpr std::uint64_t kMinEpochFrameLimit = 1;
inline constexpr std::uint64_t kMaxEpochFrameLimit = 1ULL << 30;
inline constexpr auto kMinEpochActiveLimit = std::chrono::milliseconds(1);
inline constexpr auto kMaxEpochActiveLimit = std::chrono::hours(24);

struct SecurityProfileConfig {
    SecurityMode mode{SecurityMode::Extreme};
    std::optional<RatchetPolicy> custom_policy;
};

constexpr std::string_view SecurityModeName(SecurityMode mode) noexcept {
    switch (mode) {
        case SecurityMode::Extreme:
            return "extreme";
        case SecurityMode::Normal:
            return "normal";
        case SecurityMode::Soft:
            return "soft";
        case SecurityMode::Ultimate:
            return "ultimate";
    }
    return "extreme";
}

constexpr std::optional<SecurityMode> ParseSecurityMode(
    std::string_view name) noexcept {
    if (name == "extreme") return SecurityMode::Extreme;
    if (name == "normal") return SecurityMode::Normal;
    if (name == "soft") return SecurityMode::Soft;
    if (name == "ultimate") return SecurityMode::Ultimate;
    return std::nullopt;
}

constexpr bool IsRatchetPolicyValid(const RatchetPolicy& policy) noexcept {
    return policy.epoch_byte_limit >= kMinEpochByteLimit &&
           policy.epoch_byte_limit <= kMaxEpochByteLimit &&
           policy.epoch_frame_limit >= kMinEpochFrameLimit &&
           policy.epoch_frame_limit <= kMaxEpochFrameLimit &&
           policy.epoch_active_limit >= kMinEpochActiveLimit &&
           policy.epoch_active_limit <= kMaxEpochActiveLimit;
}

constexpr std::optional<RatchetPolicy> ResolveSecurityProfile(
    const SecurityProfileConfig& profile) noexcept {
    switch (profile.mode) {
        case SecurityMode::Extreme:
            return kExtremePolicy;
        case SecurityMode::Normal:
            return kNormalPolicy;
        case SecurityMode::Soft:
            return kSoftPolicy;
        case SecurityMode::Ultimate:
            if (profile.custom_policy.has_value() &&
                IsRatchetPolicyValid(*profile.custom_policy)) {
                return profile.custom_policy;
            }
            return std::nullopt;
    }
    return std::nullopt;
}

// Each endpoint advertises the largest inbound epoch it accepts. Choosing the
// component-wise minimum lets either side enforce a stricter compromise budget
// without permitting a peer to expand it.
constexpr RatchetPolicy NegotiateRatchetPolicy(
    const RatchetPolicy& local,
    const RatchetPolicy& peer) noexcept {
    return {
        local.epoch_byte_limit < peer.epoch_byte_limit
            ? local.epoch_byte_limit
            : peer.epoch_byte_limit,
        local.epoch_frame_limit < peer.epoch_frame_limit
            ? local.epoch_frame_limit
            : peer.epoch_frame_limit,
        local.epoch_active_limit < peer.epoch_active_limit
            ? local.epoch_active_limit
            : peer.epoch_active_limit,
    };
}

}  // namespace yume::ratchet
