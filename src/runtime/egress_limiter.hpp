/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace yume::runtime {

// A server's aggregate egress rate, shared between authenticated identities
// in proportion to their weights. A caller reserves each transfer before it
// starts and waits the returned interval. The limiter owns no thread or timer.
//
// Each identity has a clock that advances at its share of the rate. The share
// is the identity's weight over the total weight of busy identities, those
// whose clocks are still ahead of now, so the shares of busy identities sum to
// the whole rate. An identity that stops sending leaves the busy set once its
// clock passes, and the others' shares grow at their next reservation. A
// changed weight takes effect at the identity's next reservation.
//
// Transfers already scheduled keep the share they were reserved with. When
// another identity becomes busy, the total can exceed the rate until those
// transfers have started. An identity back from idle starts its first transfer
// at once. A separate aggregate clock advanced from each start would remove
// that overshoot but push every other identity's next start past a busy
// identity's own clock, leaving the rate unused: two busy identities would
// get half of it between them, whatever their weights.
class EgressLimiter final {
public:
    using Clock = std::chrono::steady_clock;

    static constexpr double kMinWeight = 0.1;
    static constexpr double kMaxWeight = 100.0;
    static constexpr double kDefaultWeight = 1.0;

    // bytes_per_second must be positive.
    explicit EgressLimiter(std::uint64_t bytes_per_second);

    EgressLimiter(const EgressLimiter&) = delete;
    EgressLimiter& operator=(const EgressLimiter&) = delete;

    // How long a transfer of bytes waits before it starts. The weight is
    // clamped to [kMinWeight, kMaxWeight], and a non-finite weight counts as
    // kDefaultWeight. Zero bytes and an empty identity never wait. Throws
    // std::bad_alloc when a new identity cannot be recorded.
    Clock::duration reserve(std::string_view identity, double weight,
                            std::size_t bytes, Clock::time_point now);

    std::uint64_t bytes_per_second() const noexcept { return bytes_per_second_; }
    // Identities currently held in memory, including idle ones not yet pruned.
    std::size_t tracked_identities() const;

private:
    struct IdentityState final {
        double weight{kDefaultWeight};
        Clock::time_point next_available{};
    };
    struct Hash final {
        using is_transparent = void;
        std::size_t operator()(std::string_view value) const noexcept {
            return std::hash<std::string_view>{}(value);
        }
    };

    void prune_idle_locked(Clock::time_point now) noexcept;

    const std::uint64_t bytes_per_second_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, IdentityState, Hash, std::equal_to<>> identities_;
};

}  // namespace yume::runtime
