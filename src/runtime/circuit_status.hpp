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

// What a route of 1 or 2 hops gives up against three. A proposal carries
// both the code, control protocol 1's closed `cost` set that a client may
// show in its own language, and the English text, `gives_up`, which a
// client shows for a code it does not know. The GUI's catalog messages for
// these codes must carry these exact texts (tests/test_yume_translations.py).
enum class ShorterRouteCost : std::uint8_t {
    // One hop: the entry is also the exit.
    EntrySeesAll,
    // Two hops: the exit's only neighbour is the entry.
    EntryExitAdjacent,
};

inline ShorterRouteCost shorter_route_cost(std::size_t hops) noexcept {
    return hops == 1U ? ShorterRouteCost::EntrySeesAll
                      : ShorterRouteCost::EntryExitAdjacent;
}

inline const char* shorter_route_cost_code(ShorterRouteCost cost) noexcept {
    switch (cost) {
        case ShorterRouteCost::EntrySeesAll:
            return "entry_sees_all";
        case ShorterRouteCost::EntryExitAdjacent:
            return "entry_exit_adjacent";
    }
    return "unknown";
}

inline const char* shorter_route_cost_text(ShorterRouteCost cost) noexcept {
    switch (cost) {
        case ShorterRouteCost::EntrySeesAll:
            return "Your entry server sees both who you are and every site "
                   "you visit, as a direct connection does.";
        case ShorterRouteCost::EntryExitAdjacent:
            return "The exit's neighbour is your entry. A party that runs "
                   "both, or watches both, can link you to the sites you "
                   "visit.";
    }
    // Not reached. The wider loss is the safe text to show.
    return "Your entry server sees both who you are and every site you "
           "visit, as a direct connection does.";
}

}  // namespace yume::runtime
