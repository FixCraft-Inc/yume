/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/circuit_routes.hpp"

#include <algorithm>
#include <utility>

namespace yume::runtime::circuit {

using engine::Result;
using engine::Status;
using engine::StatusCode;

RouteChooser::RouteChooser(cluster::Routes view, std::size_t entry) noexcept
    : view_(std::move(view)), entry_(entry) {}

Result<RouteChooser> RouteChooser::create(cluster::Routes view,
                                          std::string_view entry_identity) {
    for (std::size_t index = 0U; index < view.nodes.size(); ++index) {
        if (view.nodes[index].identity.fingerprint == entry_identity)
            return Result<RouteChooser>(RouteChooser(std::move(view), index));
    }
    return Result<RouteChooser>(Status::diagnostic(
        StatusCode::InvalidArgument,
        "the routes view does not name this client's entry"));
}

void RouteChooser::record(std::string_view identity,
                          std::chrono::milliseconds time) {
    const auto found = measured_.find(identity);
    if (found != measured_.end()) {
        found->second = time;
    } else {
        measured_.emplace(std::string(identity), time);
    }
}

void RouteChooser::exclude(std::string_view identity, Clock::time_point until) {
    const auto found = excluded_until_.find(identity);
    if (found != excluded_until_.end()) {
        found->second = std::max(found->second, until);
    } else {
        excluded_until_.emplace(std::string(identity), until);
    }
}

std::vector<std::vector<std::size_t>> RouteChooser::routes(
    std::size_t hops, Clock::time_point now) const {
    std::vector<std::vector<std::size_t>> found;
    if (hops != 2U && hops != 3U) return found;
    const auto usable = [&](std::size_t index) {
        if (index == entry_) return false;
        const auto excluded =
            excluded_until_.find(view_.nodes[index].identity.fingerprint);
        return excluded == excluded_until_.end() || excluded->second <= now;
    };
    const auto& nodes = view_.nodes;
    const auto& entry_network = nodes[entry_].network;
    for (std::size_t exit = 0U; exit < nodes.size(); ++exit) {
        if (!usable(exit) || !nodes[exit].exit ||
            nodes[exit].network == entry_network)
            continue;
        if (hops == 2U) {
            found.push_back({entry_, exit});
            continue;
        }
        for (std::size_t middle = 0U; middle < nodes.size(); ++middle) {
            if (middle == exit || !usable(middle) ||
                nodes[middle].network == entry_network ||
                nodes[middle].network == nodes[exit].network)
                continue;
            found.push_back({entry_, middle, exit});
        }
    }
    return found;
}

std::size_t RouteChooser::count(std::size_t hops, Clock::time_point now) const {
    return routes(hops, now).size();
}

std::optional<std::vector<cluster::RouteNode>> RouteChooser::choose(
    std::size_t hops, Clock::time_point now, std::mt19937_64& random) const {
    const auto candidates = routes(hops, now);
    if (candidates.empty()) return std::nullopt;
    // A route is measured when every hop after the entry is, and its cost is
    // the sum of those hops' EXTEND times.
    const auto cost = [&](const std::vector<std::size_t>& route)
        -> std::optional<std::chrono::milliseconds> {
        std::chrono::milliseconds total{0};
        for (std::size_t position = 1U; position < route.size(); ++position) {
            const auto found = measured_.find(
                view_.nodes[route[position]].identity.fingerprint);
            if (found == measured_.end()) return std::nullopt;
            total += found->second;
        }
        return total;
    };
    std::optional<std::chrono::milliseconds> fastest;
    for (const auto& route : candidates) {
        if (const auto known = cost(route);
            known && (!fastest || *known < *fastest))
            fastest = known;
    }
    std::vector<const std::vector<std::size_t>*> eligible;
    for (const auto& route : candidates) {
        const auto known = cost(route);
        // Within 1.5 times the fastest, in whole milliseconds without rounding
        // a fast route out.
        if (!known || !fastest || known->count() * 2 <= fastest->count() * 3)
            eligible.push_back(&route);
    }
    std::uniform_int_distribution<std::size_t> pick(0U, eligible.size() - 1U);
    std::vector<cluster::RouteNode> chosen;
    for (const auto index : *eligible[pick(random)])
        chosen.push_back(view_.nodes[index]);
    return chosen;
}

const cluster::RouteNode* stopped_at(std::span<const cluster::RouteNode> route,
                                     std::size_t hop) noexcept {
    if (hop < 2U || hop > route.size()) return nullptr;
    return &route[hop - 1U];
}

}  // namespace yume::runtime::circuit
