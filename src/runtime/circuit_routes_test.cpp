/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/circuit_routes.hpp"

#include <cstdlib>
#include <iostream>
#include <set>
#include <string>
#include <vector>

namespace {

using namespace std::chrono_literals;
using yume::runtime::circuit::RouteChooser;
namespace cluster = yume::runtime::cluster;

int g_failures = 0;

#define CHECK(condition)                                        \
    do {                                                        \
        if (!(condition)) {                                     \
            std::cerr << __FILE__ << ':' << __LINE__            \
                      << ": check failed: " #condition << '\n'; \
            ++g_failures;                                       \
        }                                                       \
    } while (false)

cluster::RouteNode node(const std::string& name, bool exit,
                        std::uint8_t network) {
    cluster::RouteNode result;
    result.name = name;
    result.identity.fingerprint = std::string(64, name[0]);
    result.exit = exit;
    result.network.fill(std::byte{network});
    return result;
}

// entry "a" on network 1, middles "b" (2) and "c" (3), exits "d" (4),
// "e" (1, the entry's network) and "f" (2, b's network).
cluster::Routes view() {
    cluster::Routes routes;
    routes.serial = 1U;
    routes.nodes = {node("a", false, 1), node("b", false, 2),
                    node("c", false, 3), node("d", true, 4),
                    node("e", true, 1),  node("f", true, 2)};
    return routes;
}

std::string id(char name) {
    return std::string(64, name);
}

std::string names(const std::vector<cluster::RouteNode>& route) {
    std::string text;
    for (const auto& hop : route) text += hop.name;
    return text;
}

std::set<std::string> drawn(const RouteChooser& chooser, std::size_t hops,
                            RouteChooser::Clock::time_point now,
                            int draws = 400) {
    std::mt19937_64 random(7U);
    std::set<std::string> seen;
    for (int draw = 0; draw < draws; ++draw) {
        const auto route = chooser.choose(hops, now, random);
        if (route) seen.insert(names(*route));
    }
    return seen;
}

void test_rules() {
    CHECK(!RouteChooser::create(view(), id('z')).ok());
    auto created = RouteChooser::create(view(), id('a'));
    CHECK(created.ok());
    if (!created.ok()) return;
    const auto& chooser = created.value();
    const auto now = RouteChooser::Clock::now();
    // Two hops: an exit that is not on the entry's network.
    CHECK((drawn(chooser, 2U, now) == std::set<std::string>{"ad", "af"}));
    // Three hops: distinct nodes, the exit last, no two on one network.
    CHECK((drawn(chooser, 3U, now) ==
           std::set<std::string>{"abd", "acd", "acf", "adf", "afd"}));
    CHECK(chooser.count(2U, now) == 2U && chooser.count(3U, now) == 5U);
    for (const std::size_t hops : {std::size_t{1}, std::size_t{4}}) {
        std::mt19937_64 random(1U);
        CHECK(!chooser.choose(hops, now, random) &&
              chooser.count(hops, now) == 0U);
    }
}

void test_exclusion() {
    constexpr auto kExclusion = std::chrono::minutes(5);
    auto chooser = RouteChooser::create(view(), id('a')).take_value();
    const auto now = RouteChooser::Clock::now();
    chooser.exclude(id('d'), now + kExclusion);
    CHECK((drawn(chooser, 2U, now) == std::set<std::string>{"af"}));
    CHECK((drawn(chooser, 2U, now + kExclusion - 1s) ==
           std::set<std::string>{"af"}));
    CHECK((drawn(chooser, 2U, now + kExclusion) ==
           std::set<std::string>{"ad", "af"}));
    chooser.exclude(id('f'), now + kExclusion);
    std::mt19937_64 random(3U);
    CHECK(!chooser.choose(2U, now, random) && chooser.count(2U, now) == 0U);
}

void test_measurements() {
    auto chooser = RouteChooser::create(view(), id('a')).take_value();
    const auto now = RouteChooser::Clock::now();
    // d at 100 ms and f at 151 ms: f is beyond 1.5 times the fastest.
    chooser.record(id('d'), 100ms);
    chooser.record(id('f'), 151ms);
    CHECK((drawn(chooser, 2U, now) == std::set<std::string>{"ad"}));
    // Exactly 1.5 times is still eligible, and a later measurement replaces
    // an earlier one.
    chooser.record(id('f'), 150ms);
    CHECK((drawn(chooser, 2U, now) == std::set<std::string>{"ad", "af"}));
    // A route with an unmeasured hop is always eligible, so the chooser
    // explores. b, c and d, f are measured except c.
    chooser.record(id('b'), 900ms);
    const auto three = drawn(chooser, 3U, now);
    CHECK(three.count("acd") == 1U && three.count("acf") == 1U &&
          three.count("abd") == 0U);
}

// A failed build names the hop it stopped at from 1 at the entry, and the
// entry is never the node to avoid.
void test_stopped_at() {
    const std::vector<cluster::RouteNode> route{
        node("a", false, 1), node("c", false, 2), node("d", true, 3)};
    using yume::runtime::circuit::stopped_at;
    CHECK(stopped_at(route, 0U) == nullptr);
    CHECK(stopped_at(route, 1U) == nullptr);
    CHECK(stopped_at(route, 2U) == &route[1]);
    CHECK(stopped_at(route, 3U) == &route[2]);
    CHECK(stopped_at(route, 4U) == nullptr);
}

}  // namespace

int main() {
    test_rules();
    test_exclusion();
    test_measurements();
    test_stopped_at();
    if (g_failures != 0) {
        std::cerr << g_failures << " route chooser check(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "route chooser tests passed\n";
    return EXIT_SUCCESS;
}
