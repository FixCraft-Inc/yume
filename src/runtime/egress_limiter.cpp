/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/egress_limiter.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>

namespace yume::runtime {
namespace {
using Clock = EgressLimiter::Clock;

// An idle identity's entry changes no reservation, so entries are pruned only
// to bound memory. A native server authorizes at most 1024 identities at once.
constexpr std::size_t kPruneThreshold = 4096U;
// A share never drops below one byte per second.
constexpr double kMinFairRate = 1.0;
// A 1 MiB frame at the minimum fair rate. Longer is clamped, which keeps the
// duration conversion in range for any byte count.
constexpr double kMaxServiceSeconds = 1'048'576.0;

Clock::duration service_time(std::size_t bytes, double bytes_per_second) noexcept {
    const double seconds = std::min(static_cast<double>(bytes) / bytes_per_second,
                                    kMaxServiceSeconds);
    const auto duration = std::chrono::duration_cast<Clock::duration>(
        std::chrono::duration<double>(seconds));
    // Every reservation advances its clocks by at least one tick.
    return std::max(duration, Clock::duration(1));
}

Clock::time_point saturating_add(Clock::time_point start, Clock::duration duration) noexcept {
    if (start > Clock::time_point::max() - duration) return Clock::time_point::max();
    return start + duration;
}
}  // namespace

EgressLimiter::EgressLimiter(std::uint64_t bytes_per_second)
    : bytes_per_second_(bytes_per_second) {
    if (bytes_per_second == 0U) throw std::invalid_argument("egress rate must be positive");
}

EgressLimiter::Clock::duration EgressLimiter::reserve(std::string_view identity, double weight,
                                                      std::size_t bytes, Clock::time_point now) {
    if (identity.empty() || bytes == 0U) return Clock::duration::zero();
    if (!std::isfinite(weight)) weight = kDefaultWeight;
    weight = std::clamp(weight, kMinWeight, kMaxWeight);

    std::lock_guard<std::mutex> lock(mutex_);
    auto current = identities_.find(identity);
    if (current == identities_.end()) {
        if (identities_.size() >= kPruneThreshold) prune_idle_locked(now);
        current = identities_.emplace(std::string(identity), IdentityState{}).first;
    }
    auto& state = current->second;
    state.weight = weight;

    double active_weight = weight;
    for (const auto& [key, other] : identities_) {
        if (&other != &state && other.next_available > now) active_weight += other.weight;
    }
    const double fair_rate = std::max(
        kMinFairRate, static_cast<double>(bytes_per_second_) * (weight / active_weight));

    const auto start = std::max(now, state.next_available);
    state.next_available = saturating_add(start, service_time(bytes, fair_rate));
    return start - now;
}

std::size_t EgressLimiter::tracked_identities() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return identities_.size();
}

void EgressLimiter::prune_idle_locked(Clock::time_point now) noexcept {
    for (auto it = identities_.begin(); it != identities_.end();) {
        if (it->second.next_available <= now) {
            it = identities_.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace yume::runtime
