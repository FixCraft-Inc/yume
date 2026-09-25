/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/egress_limiter.hpp"

#include <array>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
using yume::runtime::EgressLimiter;
using Clock = EgressLimiter::Clock;
using std::chrono::milliseconds;

// 8 Mbit/s: one million bytes per second, so byte counts read as microseconds.
constexpr std::uint64_t kRate = 1'000'000U;
const Clock::time_point kStart = Clock::time_point() + std::chrono::hours(1);

void check(bool condition, std::string_view description) {
    if (!condition) throw std::runtime_error(std::string(description));
}

// Alone, an identity gets the whole rate and its own clock paces it.
void test_identity_clock_paces_repeated_transfers() {
    EgressLimiter limiter(kRate);
    check(limiter.reserve("client", 1.5, 250'000U, kStart) == Clock::duration::zero(),
          "the first weighted reservation waited");
    check(limiter.reserve("client", 1.5, 250'000U, kStart) == milliseconds(250),
          "the identity clock did not pace a repeated transfer");
    check(limiter.reserve("client", 1.5, 250'000U, kStart + milliseconds(600)) ==
              Clock::duration::zero(),
          "an identity that fell behind its clock still waited");
}

// A newly busy identity starts at once with its share, and the busy identity's
// next reservation is paced at the smaller share.
void test_new_identity_takes_its_share() {
    EgressLimiter limiter(kRate);
    check(limiter.reserve("first", 1.0, 500'000U, kStart) == Clock::duration::zero(),
          "the first identity waited");
    check(limiter.reserve("second", 1.0, 500'000U, kStart) == Clock::duration::zero(),
          "a newly busy identity waited for another identity");
    const auto turn = kStart + milliseconds(500);
    check(limiter.reserve("first", 1.0, 500'000U, turn) == Clock::duration::zero(),
          "the first identity waited past its own clock");
    check(limiter.reserve("first", 1.0, 500'000U, turn) == milliseconds(1'000),
          "the first identity kept the whole rate while another was busy");
}

// Each stream issues its next transfer as soon as the previous one starts,
// like a paced stream whose write completes at once. Counts the bytes whose
// transfers start between from and until.
struct Stream final {
    std::size_t owner;
    Clock::time_point ready;
};

struct Identity final {
    std::string name;
    double weight;
    std::size_t streams{1U};
    std::uint64_t bytes{0U};
};

void simulate(EgressLimiter& limiter, std::vector<Identity>& identities, std::size_t chunk,
              Clock::time_point from, Clock::time_point until) {
    std::vector<Stream> streams;
    for (std::size_t owner = 0U; owner < identities.size(); ++owner)
        for (std::size_t count = 0U; count < identities[owner].streams; ++count)
            streams.push_back({owner, kStart});
    for (;;) {
        Stream* next = &streams.front();
        for (auto& stream : streams)
            if (stream.ready < next->ready) next = &stream;
        if (next->ready >= until) return;
        auto& identity = identities[next->owner];
        const auto start = next->ready +
            limiter.reserve(identity.name, identity.weight, chunk, next->ready);
        if (start >= from && start < until) identity.bytes += chunk;
        next->ready = start;
    }
}

double ratio(const std::vector<Identity>& identities) {
    return static_cast<double>(identities[0].bytes) / static_cast<double>(identities[1].bytes);
}

double total(const std::vector<Identity>& identities) {
    double sum = 0.0;
    for (const auto& identity : identities) sum += static_cast<double>(identity.bytes);
    return sum;
}

// Busy identities split the rate by weight and together use all of it.
// Transport v2's limiter gave this pair half the rate, split evenly.
void test_weighted_shares() {
    EgressLimiter limiter(kRate);
    std::vector<Identity> identities{{"heavy", 3.0}, {"light", 1.0}};
    simulate(limiter, identities, 10'000U, kStart, kStart + std::chrono::seconds(10));
    check(ratio(identities) > 2.9 && ratio(identities) < 3.1, "weights did not divide the rate");
    check(total(identities) > 9.9e6 && total(identities) < 10.1e6,
          "busy identities did not use the whole rate");
}

// Opening more streams does not buy an identity a larger share.
void test_streams_do_not_buy_share() {
    EgressLimiter limiter(kRate);
    std::vector<Identity> identities{{"many", 1.0, 30U}, {"one", 1.0, 1U}};
    // The first second includes each stream's first transfer.
    simulate(limiter, identities, 10'000U, kStart + std::chrono::seconds(1),
             kStart + std::chrono::seconds(10));
    check(ratio(identities) > 0.97 && ratio(identities) < 1.03,
          "an identity's streams bought a larger share");
    check(total(identities) > 8.9e6 && total(identities) < 9.1e6,
          "the rate was not kept across many streams");
}

// An identity that stops sending leaves the busy set once its clock passes,
// so the remaining identity gets the whole rate again.
void test_idle_identity_leaves_the_share() {
    EgressLimiter limiter(kRate);
    std::vector<Identity> both{{"first", 1.0}, {"second", 1.0}};
    simulate(limiter, both, 10'000U, kStart, kStart + std::chrono::seconds(2));
    auto resumed = kStart + std::chrono::seconds(3);
    std::uint64_t bytes = 0U;
    while (resumed < kStart + std::chrono::seconds(5)) {
        resumed += limiter.reserve("second", 1.0, 10'000U, resumed);
        if (resumed < kStart + std::chrono::seconds(5)) bytes += 10'000U;
    }
    check(bytes > 1'950'000U && bytes <= 2'000'000U, "an idle identity kept its share");
}

Clock::duration replay(double weight) {
    EgressLimiter limiter(kRate);
    (void)limiter.reserve("other", 1.0, 100'000U, kStart);
    (void)limiter.reserve("tested", weight, 100'000U, kStart);
    return limiter.reserve("tested", weight, 100'000U, kStart);
}

void test_weight_bounds() {
    check(replay(0.0) == replay(EgressLimiter::kMinWeight), "a zero weight was not clamped");
    check(replay(-5.0) == replay(EgressLimiter::kMinWeight), "a negative weight was not clamped");
    check(replay(1e9) == replay(EgressLimiter::kMaxWeight), "a large weight was not clamped");
    check(replay(std::numeric_limits<double>::quiet_NaN()) ==
              replay(EgressLimiter::kDefaultWeight),
          "a NaN weight did not use the default");
    check(replay(std::numeric_limits<double>::infinity()) ==
              replay(EgressLimiter::kDefaultWeight),
          "an infinite weight did not use the default");
    check(replay(2.0) != replay(1.0), "the weight had no effect");
}

void test_ignored_reservations() {
    EgressLimiter limiter(kRate);
    check(limiter.reserve("client", 1.0, 0U, kStart) == Clock::duration::zero(),
          "zero bytes waited");
    check(limiter.reserve("", 1.0, 500'000U, kStart) == Clock::duration::zero(),
          "an empty identity waited");
    check(limiter.tracked_identities() == 0U, "an ignored reservation recorded state");
    check(limiter.reserve("client", 1.0, 500'000U, kStart) == Clock::duration::zero(),
          "an ignored reservation advanced a clock");
}

void test_idle_entries_are_pruned() {
    EgressLimiter limiter(kRate);
    for (std::size_t index = 0U; index < 4096U; ++index)
        (void)limiter.reserve("client-" + std::to_string(index), 1.0, 1U, kStart);
    check(limiter.tracked_identities() == 4096U, "identities were not tracked");
    // Every earlier clock has passed, so the next new identity prunes them all.
    const auto later = kStart + std::chrono::seconds(1);
    check(limiter.reserve("late", 1.0, 1'000U, later) == Clock::duration::zero(),
          "pruned identities still delayed a transfer");
    check(limiter.tracked_identities() == 1U, "idle identities were not pruned");
}

void test_extreme_values_stay_in_range() {
    EgressLimiter limiter(1U);
    (void)limiter.reserve("client", EgressLimiter::kMinWeight,
                          std::numeric_limits<std::size_t>::max(), kStart);
    const auto second = limiter.reserve("client", EgressLimiter::kMinWeight, 1U, kStart);
    check(second > Clock::duration::zero() && second <= std::chrono::hours(24 * 13),
          "an oversized transfer was not clamped");
    const auto near_end = Clock::time_point::max() - std::chrono::hours(1);
    (void)limiter.reserve("late", 1.0, std::numeric_limits<std::size_t>::max(), near_end);
    const auto saturated = limiter.reserve("late", 1.0, 1U, near_end);
    check(saturated >= std::chrono::minutes(59), "the clock did not saturate");
    bool refused = false;
    try {
        EgressLimiter zero(0U);
    } catch (const std::invalid_argument&) {
        refused = true;
    }
    check(refused, "a zero rate was accepted");
}

}  // namespace

int main() {
    try {
        test_identity_clock_paces_repeated_transfers();
        test_new_identity_takes_its_share();
        test_weighted_shares();
        test_streams_do_not_buy_share();
        test_idle_identity_leaves_the_share();
        test_weight_bounds();
        test_ignored_reservations();
        test_idle_entries_are_pruned();
        test_extreme_values_stay_in_range();
        std::cout << "egress limiter tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "egress limiter test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
