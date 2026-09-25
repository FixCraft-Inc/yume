/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>

namespace yume::relay {

// Pending relay setup retains an ephemeral private key and an out-of-band
// secret at each endpoint, plus routing state at the relaying server. Keep one
// shared policy for both halves so a peer cannot outlive the server's
// corroborating state.
inline constexpr std::size_t kMaxPendingRelayInvitesPerEndpoint = 64;
inline constexpr std::size_t kMaxPendingRelayInvitesPerServer = 4096;
inline constexpr auto kPendingRelayInviteLifetime = std::chrono::minutes(2);

enum class PendingRelayInviteAdmission {
    Allowed,
    ServerLimit,
    OriginLimit,
    TargetLimit,
};

// Pure threshold policy shared by the runtime and its focused tests. Counts
// describe entries already retained; equality therefore rejects the next
// invite and keeps every bound exact under the server's registry lock.
constexpr PendingRelayInviteAdmission pending_relay_invite_admission(
        std::size_t server_count,
        std::size_t origin_count,
        std::size_t target_count) noexcept {
    if (server_count >= kMaxPendingRelayInvitesPerServer) {
        return PendingRelayInviteAdmission::ServerLimit;
    }
    if (origin_count >= kMaxPendingRelayInvitesPerEndpoint) {
        return PendingRelayInviteAdmission::OriginLimit;
    }
    if (target_count >= kMaxPendingRelayInvitesPerEndpoint) {
        return PendingRelayInviteAdmission::TargetLimit;
    }
    return PendingRelayInviteAdmission::Allowed;
}

constexpr bool pending_relay_invite_expired(
        std::chrono::steady_clock::time_point expires_at,
        std::chrono::steady_clock::time_point now) noexcept {
    return expires_at <= now;
}

static_assert(kMaxPendingRelayInvitesPerEndpoint > 0);
static_assert(kMaxPendingRelayInvitesPerServer >=
              kMaxPendingRelayInvitesPerEndpoint);

}  // namespace yume::relay
