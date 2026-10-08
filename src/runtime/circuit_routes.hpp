/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <map>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "runtime/cluster_list.hpp"

// How a client picks a circuit's route from the verified routes view
// (CLUSTER_DESIGN 6b, "Route choice"). The entry is the server the client's
// kit names. The other hops are distinct nodes, the last one an exit, and no
// two hops share a network tag. Among routes that pass, the chooser picks at
// random among those it has not measured and those within 1.5 times the
// fastest measured one, so it explores and avoids slow routes without
// always picking the same one. Nothing is kept on disk.
namespace yume::runtime::circuit {

class RouteChooser final {
public:
    using Clock = std::chrono::steady_clock;

    // InvalidArgument unless the view names the entry.
    static engine::Result<RouteChooser> create(cluster::Routes view,
                                               std::string_view entry_identity);

    // How long an EXTEND to this node took, from a build in this run. A
    // later measurement replaces an earlier one.
    void record(std::string_view identity, std::chrono::milliseconds time);
    // Keeps the node out of routes until then, or until a later time an
    // earlier call gave.
    void exclude(std::string_view identity, Clock::time_point until);

    // A route of hops nodes, the entry first, or nothing when no route of
    // that length passes the rules. hops is 2 or 3.
    std::optional<std::vector<cluster::RouteNode>> choose(
        std::size_t hops, Clock::time_point now, std::mt19937_64& random) const;
    // How many routes of that length pass the rules now.
    std::size_t count(std::size_t hops, Clock::time_point now) const;

    const cluster::Routes& view() const noexcept { return view_; }

private:
    RouteChooser(cluster::Routes view, std::size_t entry) noexcept;

    // Every route of hops nodes that passes the rules, by node index.
    std::vector<std::vector<std::size_t>> routes(std::size_t hops,
                                                 Clock::time_point now) const;

    cluster::Routes view_;
    std::size_t entry_{0U};
    std::map<std::string, std::chrono::milliseconds, std::less<>> measured_;
    std::map<std::string, Clock::time_point, std::less<>> excluded_until_;
};

// The node a failed build stopped at, which the client names by its hop
// from 1 at the entry. Null for the entry, which is the kit's server and is
// never avoided, and for a hop outside the route.
const cluster::RouteNode* stopped_at(std::span<const cluster::RouteNode> route,
                                     std::size_t hop) noexcept;

}  // namespace yume::runtime::circuit
