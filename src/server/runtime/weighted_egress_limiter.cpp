/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/weighted_egress_limiter.hpp"

#include <algorithm>

namespace yume::server {

WeightedEgressLimiter::WeightedEgressLimiter(std::uint32_t cap_mbps)
    : bytes_per_second_(std::max<double>(
          1.0, static_cast<double>(cap_mbps) * 1'000'000.0 / 8.0)) {}

std::chrono::milliseconds WeightedEgressLimiter::reserve(
    const std::string& identity,
    double requested_weight,
    std::size_t bytes) {
    if (identity.empty() || bytes == 0 || bytes_per_second_ <= 0.0) {
        return std::chrono::milliseconds(0);
    }

    const double weight = std::clamp(requested_weight, 0.1, 100.0);
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mutex_);
    prune_inactive_locked(now);

    auto& current = identities_[identity];
    current.weight = weight;

    double active_weight = 0.0;
    bool current_counted = false;
    for (const auto& [active_identity, state] : identities_) {
        if (state.next_available > now) {
            active_weight += state.weight;
            if (active_identity == identity) {
                current_counted = true;
            }
        }
    }
    if (!current_counted) {
        active_weight += weight;
    }
    if (active_weight <= 0.0) {
        active_weight = weight;
    }

    const double share = weight / active_weight;
    const double fair_rate = std::max(1.0, bytes_per_second_ * share);
    auto start = current.next_available > now ? current.next_available : now;
    if (global_next_available_ > start) {
        start = global_next_available_;
    }

    const std::chrono::duration<double> service_seconds(
        static_cast<double>(bytes) / fair_rate);
    auto service_duration =
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(
            service_seconds);
    if (service_duration.count() <= 0) {
        service_duration = std::chrono::milliseconds(1);
    }
    current.next_available = start + service_duration;

    const std::chrono::duration<double> global_service_seconds(
        static_cast<double>(bytes) / bytes_per_second_);
    auto global_service_duration =
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(
            global_service_seconds);
    if (global_service_duration.count() <= 0) {
        global_service_duration = std::chrono::nanoseconds(1);
    }
    global_next_available_ = start + global_service_duration;

    if (start <= now) {
        return std::chrono::milliseconds(0);
    }
    const auto delay_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        start - now).count();
    return std::chrono::milliseconds((delay_ns + 999'999) / 1'000'000);
}

void WeightedEgressLimiter::prune_inactive_locked(
    std::chrono::steady_clock::time_point now) {
    if (identities_.size() <= 4096) {
        return;
    }
    const auto cutoff = now - std::chrono::minutes(5);
    for (auto it = identities_.begin(); it != identities_.end();) {
        if (it->second.next_available < cutoff) {
            it = identities_.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace yume::server
