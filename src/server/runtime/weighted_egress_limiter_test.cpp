/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/weighted_egress_limiter.hpp"

#include <stdexcept>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void test_aggregate_first_batch_is_bounded() {
    // 8 Mbit/s = 1,000,000 bytes/s. The second 500,000-byte reservation
    // must begin about 500 ms after the first even though it is a new identity.
    yume::server::WeightedEgressLimiter limiter(8);
    const auto first = limiter.reserve("client-a", 1.0, 500'000);
    const auto second = limiter.reserve("client-b", 1.0, 500'000);
    require(first.count() == 0, "first reservation should start immediately");
    require(second.count() >= 450 && second.count() <= 650,
            "second identity bypassed the aggregate egress clock");
}

void test_identity_clock_and_fractional_weight() {
    yume::server::WeightedEgressLimiter limiter(8);
    require(limiter.reserve("weighted", 1.5, 250'000).count() == 0,
            "first weighted reservation should start immediately");
    require(limiter.reserve("weighted", 1.5, 250'000).count() >= 200,
            "identity reservation clock did not pace repeated writes");
}

}  // namespace

int main() {
    test_aggregate_first_batch_is_bounded();
    test_identity_clock_and_fractional_weight();
    return 0;
}
