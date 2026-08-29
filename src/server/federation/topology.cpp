/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/federation/topology.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <utility>

namespace yume::server {

namespace {

// One row per peer id, merged from configuration and live link state. A peer
// whose link never started still has to appear: an operator debugging a cluster
// needs to see the configured-but-dead node, not an absence.
struct MergedPeer {
    const ConfiguredFederationPeer* configured{nullptr};
    const FederationPeerStatus* status{nullptr};
    std::size_t endpoints{0};
};

std::map<std::string, MergedPeer> merge_peers(
        const ConfiguredFederationPeers& configured,
        const std::vector<FederationPeerStatus>& statuses) {
    std::map<std::string, MergedPeer> merged;
    for (const auto& peer : configured.peers) {
        merged[peer.id].configured = &peer;
    }
    for (const auto& status : statuses) {
        merged[status.id].status = &status;
    }
    return merged;
}

nlohmann::json peer_configuration_json(const ConfiguredFederationPeer* peer) {
    if (peer == nullptr) {
        return nlohmann::json(nullptr);
    }
    return nlohmann::json{
        {"host", peer->host},
        {"port", peer->port},
        {"tls_pin_present", peer->tls_pin_present},
        {"psk_present", peer->psk_present},
        {"carrier_secret_present", peer->carrier_secret_present},
    };
}

nlohmann::json peer_link_json(const FederationPeerStatus* status) {
    if (status == nullptr) {
        // Configured but never started: parsing, duplicate-id, or .onion
        // proxy rejection all leave a peer without a link.
        return nlohmann::json{
            {"state", "not-started"},
            {"ready", false},
            {"outbound_state", "not-started"},
            {"outbound_ready", false},
            {"inbound_connections", 0},
            {"last_error",
             "configured federation link was not started; see startup log"},
            {"last_handshake_ms", 0},
            {"channels_active", 0},
        };
    }
    return nlohmann::json{
        {"state", status->state},
        {"ready", status->ready},
        {"outbound_state", status->outbound_state},
        {"outbound_ready", status->outbound_ready},
        {"inbound_connections", status->inbound_connections},
        {"last_error", sanitize_federation_public_error(status->last_error)},
        {"last_handshake_ms", status->last_handshake_ms},
        {"channels_active", status->channels_active},
    };
}

nlohmann::json self_json(const FederationSelfNode& self) {
    return nlohmann::json{
        {"server_id", self.server_id},
        {"server_name", self.server_name},
        {"listen_port", self.listen_port},
        {"local_endpoints", self.local_endpoints},
        {"federation_enabled", self.federation_enabled},
    };
}

}  // namespace

nlohmann::json build_federation_status_json(
        const FederationSelfNode& self,
        const ConfiguredFederationPeers& configured,
        const std::vector<FederationPeerStatus>& statuses) {
    nlohmann::json result{
        {"schema_version", 1},
        {"enabled", self.federation_enabled},
        {"self", self_json(self)},
        {"invalid_peer_entries", configured.invalid_entries},
    };
    result["peers"] = nlohmann::json::array();
    for (const auto& [peer_id, merged] : merge_peers(configured, statuses)) {
        nlohmann::json peer{{"peer_id", peer_id}};
        peer["configuration"] = peer_configuration_json(merged.configured);
        peer.update(peer_link_json(merged.status));
        result["peers"].push_back(std::move(peer));
    }
    return result;
}

nlohmann::json build_federation_topology_json(
        const FederationSelfNode& self,
        const ConfiguredFederationPeers& configured,
        const std::vector<FederationPeerStatus>& statuses,
        const std::vector<control::EndpointInfo>& remote_endpoints,
        const std::vector<control::ActiveRelayChannel>& channels) {
    auto merged = merge_peers(configured, statuses);

    // Every cached remote endpoint was learned across exactly one authenticated
    // link, so its federation_peer_id names the node that advertised it. An
    // endpoint attributed to a peer that is no longer configured is counted
    // under that peer rather than dropped, so the total always reconciles with
    // the directory a client sees.
    for (const auto& endpoint : remote_endpoints) {
        if (!endpoint.remote || endpoint.federation_peer_id.empty()) {
            continue;
        }
        ++merged[endpoint.federation_peer_id].endpoints;
    }

    nlohmann::json result{
        {"schema_version", 1},
        {"self", self_json(self)},
        {"invalid_peer_entries", configured.invalid_entries},
        {"transit", {
            {"supported", kFederationTransitSupported},
            {"max_hops", kFederationMaxRouteHops},
        }},
    };

    result["nodes"] = nlohmann::json::array();
    result["edges"] = nlohmann::json::array();
    for (const auto& [peer_id, peer] : merged) {
        // One link snapshot feeds both the node row and its edge, so the two
        // can never disagree about the same link's state.
        const nlohmann::json link = peer_link_json(peer.status);

        nlohmann::json node{{"peer_id", peer_id}};
        node.update(link);
        node["configuration"] = peer_configuration_json(peer.configured);
        node["endpoints"] = peer.endpoints;
        // Direct links only, so the route to every known node is its own
        // single label. This stays a list rather than a scalar because a
        // consumer that draws paths should not have to change shape later.
        node["route"] = nlohmann::json::array({peer_id});
        node["hops"] = kFederationMaxRouteHops;
        result["nodes"].push_back(std::move(node));

        result["edges"].push_back({
            {"from", self.server_id},
            {"to", peer_id},
            {"kind", "federation-link"},
            {"state", link.at("state")},
            {"ready", link.at("ready")},
            {"outbound_ready", link.at("outbound_ready")},
            {"inbound_connections", link.at("inbound_connections")},
        });
    }

    result["channels"] = nlohmann::json::array();
    for (const auto& channel : channels) {
        result["channels"].push_back({
            {"channel_id", channel.channel_id},
            {"channel_kind", control::to_string(channel.channel_kind)},
            {"left_endpoint_id", channel.left_endpoint_id},
            {"right_endpoint_id", channel.right_endpoint_id},
            {"federated", channel.federated},
            {"route_hops", channel.route_hops},
            {"pending", channel.pending},
        });
    }
    return result;
}

}  // namespace yume::server
