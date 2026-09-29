/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// What the client's circuits report, apart from CircuitPool so that status
// readers need no crypto headers.
namespace yume::runtime {

// A shorter route the client would use. id is the first 16 hexadecimal
// digits of a digest of the hop count, the nodes' identities in order and
// the view's serial, so an answer to an older proposal accepts nothing.
struct RouteProposal final {
    std::string id;
    std::size_t hops{0U};
    // Node names, the entry first. One hop is the direct session.
    std::vector<std::string> nodes;
    std::uint64_t serial{0U};
    // The route's measured EXTEND time, when every hop has been measured.
    std::optional<std::chrono::milliseconds> latency;
};

struct CircuitRoute final {
    std::vector<std::string> nodes;
    std::chrono::steady_clock::time_point built{};
    std::size_t streams{0U};
};

struct CircuitPoolStatus final {
    std::size_t hops{0U};
    std::size_t min_hops{0U};
    // The shorter length the user accepted, or zero.
    std::size_t accepted_hops{0U};
    // The length new streams take now, or zero while none can be used.
    std::size_t current_hops{0U};
    bool plain_http_allowed{false};
    // The serial of the view in use, or zero before one is verified.
    std::uint64_t serial{0U};
    // Why circuits stopped when the view failed its checks, otherwise empty.
    std::string stopped;
    std::vector<CircuitRoute> circuits;
    std::optional<RouteProposal> proposal;
};

// What a route of hops, 1 or 2, gives up against three, in the words a
// proposal shows.
inline const char* shorter_route_cost(std::size_t hops) noexcept {
    return hops == 1U ? "Your entry server sees both who you are and every "
                        "site you visit, as a "
                        "direct connection does."
                      : "The exit's neighbour is your entry. A party that runs "
                        "both, or watches both, "
                        "can link you to the sites you visit.";
}

}  // namespace yume::runtime
