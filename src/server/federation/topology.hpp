/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "core/protocol/control_protocol.hpp"
#include "server/federation/types.hpp"

namespace yume::server {

// Federation forwarding is not implemented: a node advertises only its own
// local endpoints (`federation.directory` emits list_local_endpoints), so every
// federated endpoint a node knows is exactly one link away. These two constants
// are the wire-visible statement of that boundary, reported by
// build_federation_topology_json so a consumer reads the hop budget instead of
// assuming one. `docs/protocol/YUME_2_0_FEDERATION_TRANSIT.md` records the
// design that would raise them and the gates it must pass first.
inline constexpr bool kFederationTransitSupported = false;
inline constexpr int kFederationMaxRouteHops = 1;

// Redacted view of one configured `--peer` / `--cluster-join` entry. The parsed
// FederationPeer carries filesystem paths to the pairwise PSK and the peer's
// carrier admission secret; those paths never leave the process, so this
// records only whether each was supplied.
struct ConfiguredFederationPeer {
    std::string id;
    std::string host;
    int port{0};
    bool tls_pin_present{false};
    bool psk_present{false};
    bool carrier_secret_present{false};
};

// A malformed `--peer` entry has no usable id, and a duplicate id cannot be a
// distinct named row. Counting rejected entries separately keeps the
// operator's view honest: a cluster with three input entries and one rejection
// must not look like a clean two-peer configuration.
struct ConfiguredFederationPeers {
    std::vector<ConfiguredFederationPeer> peers;
    std::size_t invalid_entries{0};
};

// The reporting node's own identity, as the topology graph's root.
struct FederationSelfNode {
    std::string server_id;
    std::string server_name;
    int listen_port{0};
    std::size_t local_endpoints{0};
    bool federation_enabled{false};
};

// Both builders are pure: no locks, no I/O, no access to live runtime state.
// Callers snapshot the inputs under their own mutexes and hand them over, which
// is what makes the response shape testable without a running cluster.

// `federation.status`: configuration and per-link liveness, never a secret path.
nlohmann::json build_federation_status_json(
    const FederationSelfNode& self,
    const ConfiguredFederationPeers& configured,
    const std::vector<FederationPeerStatus>& statuses);

// `federation.topology`: one graph for a cluster viewer. `nodes` holds peers
// only; the reporting node is `self`. Every node carries `route`/`hops` even
// while the hop budget is 1, so a consumer that draws paths does not have to
// change shape if forwarding is ever implemented.
nlohmann::json build_federation_topology_json(
    const FederationSelfNode& self,
    const ConfiguredFederationPeers& configured,
    const std::vector<FederationPeerStatus>& statuses,
    const std::vector<control::EndpointInfo>& remote_endpoints,
    const std::vector<control::ActiveRelayChannel>& channels);

}  // namespace yume::server
