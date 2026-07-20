/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace yume::server {

// Reservation-based aggregate shaper. Callers defer their asynchronous write
// by the returned interval; no limiter thread or blocking sleep is required.
// The global clock bounds first-batch bursts while the identity clocks
// converge active identities toward their configured weighted shares.
class WeightedEgressLimiter {
public:
    explicit WeightedEgressLimiter(std::uint32_t cap_mbps);

    std::chrono::milliseconds reserve(const std::string& identity,
                                      double weight,
                                      std::size_t bytes);

private:
    struct IdentityState {
        double weight{1.0};
        std::chrono::steady_clock::time_point next_available{};
    };

    void prune_inactive_locked(std::chrono::steady_clock::time_point now);

    double bytes_per_second_{0.0};
    std::mutex mutex_;
    std::unordered_map<std::string, IdentityState> identities_;
    std::chrono::steady_clock::time_point global_next_available_{};
};

}  // namespace yume::server
