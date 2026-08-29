/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <iosfwd>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace yume::server {

// Text layout for a federation.topology document. The daemon owns the graph;
// this only draws it, so `yume-net-map` and the yumed attach console render one
// cluster the same way instead of each deriving its own picture.
//
// Deliberately free of socket, config, and runtime dependencies: it takes a
// parsed document and writes characters.

// One drawable box. Element 0 of a normalised list is always the reporting node.
struct TopologyBox {
    std::string id;
    std::string display;  // server_name when set, else the id
    std::string addr;     // "local:<port>" for self, "host:port" for a peer
    std::size_t local_endpoint_count{0};
    std::size_t active_channel_count{0};
    std::string state;    // "self" / "ready" / "connecting" / "not-started" / "error"
    std::string error;    // populated when state == "error"
    bool is_self{false};
};

// Flattens a federation.topology result object into boxes. Tolerates a missing
// or malformed `nodes` array by drawing the reporting node alone: a viewer must
// still render something useful when a peer list cannot be read.
std::vector<TopologyBox> topology_boxes(const nlohmann::json& topology);

// Renders the fan: the reporting node above a bus of peers. Falls back to a
// sorted table past kMaxDrawnPeers, where the drawing stops being clearer than
// a list. `ascii_only` swaps the box-drawing glyphs for 7-bit equivalents.
void render_topology(const std::vector<TopologyBox>& boxes,
                     bool ascii_only,
                     std::ostream& out);

inline constexpr std::size_t kMaxDrawnPeers = 6U;

}  // namespace yume::server
