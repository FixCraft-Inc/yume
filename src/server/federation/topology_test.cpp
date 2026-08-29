/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/federation/topology.hpp"
#include "server/federation/topology_render.hpp"

#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using yume::control::ActiveRelayChannel;
using yume::control::ChannelKind;
using yume::control::EndpointInfo;
using yume::server::ConfiguredFederationPeer;
using yume::server::ConfiguredFederationPeers;
using yume::server::FederationPeerStatus;
using yume::server::FederationSelfNode;
using yume::server::build_federation_status_json;
using yume::server::build_federation_topology_json;
using yume::server::render_topology;
using yume::server::topology_boxes;

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

FederationSelfNode SelfNode() {
    FederationSelfNode self;
    self.server_id = "11111111111111111111111111111111";
    self.server_name = "node-a";
    self.listen_port = 4443;
    self.local_endpoints = 2U;
    self.federation_enabled = true;
    return self;
}

ConfiguredFederationPeer ConfiguredPeer(std::string id) {
    ConfiguredFederationPeer peer;
    peer.id = std::move(id);
    peer.host = "peer.invalid";
    peer.port = 443;
    peer.tls_pin_present = true;
    peer.psk_present = true;
    peer.carrier_secret_present = true;
    return peer;
}

FederationPeerStatus ReadyStatus(std::string id) {
    FederationPeerStatus status;
    status.id = std::move(id);
    status.state = "ready";
    status.ready = true;
    status.outbound_state = "ready";
    status.outbound_ready = true;
    status.last_handshake_ms = 1730000000000LL;
    status.channels_active = 3U;
    return status;
}

EndpointInfo RemoteEndpoint(const std::string& peer_id,
                            const std::string& raw_id) {
    EndpointInfo endpoint;
    endpoint.endpoint_id = peer_id + ":" + raw_id;
    endpoint.remote = true;
    endpoint.federation_peer_id = peer_id;
    endpoint.remote_endpoint_id = raw_id;
    return endpoint;
}

// A reporting surface that echoes a configured peer's raw JSON would leak the
// operator's pairwise-PSK and carrier-secret file paths to every admin-socket
// reader. The redaction is the point of ConfiguredFederationPeer, so assert on
// the serialized bytes rather than on individual fields.
void CheckStatusRedactsSecretPaths() {
    ConfiguredFederationPeers configured;
    configured.peers.push_back(ConfiguredPeer("node-b"));
    configured.invalid_entries = 1U;

    const auto status = build_federation_status_json(
        SelfNode(), configured, {ReadyStatus("node-b")});
    const std::string encoded = status.dump();

    Check(encoded.find("psk_file") == std::string::npos,
          "federation status leaked a psk_file key");
    Check(encoded.find("carrier_secret_file") == std::string::npos,
          "federation status leaked a carrier_secret_file key");
    Check(encoded.find(".hex") == std::string::npos &&
              encoded.find(".pem") == std::string::npos,
          "federation status leaked a secret file path");

    Check(status.at("enabled").get<bool>(), "federation status lost enabled");
    Check(status.at("schema_version").get<int>() == 1,
          "federation status schema version is wrong");
    Check(status.at("invalid_peer_entries").get<std::size_t>() == 1U,
          "federation status dropped the invalid entry count");
    Check(status.at("peers").size() == 1U,
          "federation status peer count is wrong");

    const auto& peer = status["peers"][0];
    Check(peer.at("peer_id").get<std::string>() == "node-b",
          "federation status peer id is wrong");
    Check(peer.at("ready").get<bool>(), "federation status lost readiness");
    Check(peer.at("outbound_ready").get<bool>(),
          "federation status lost outbound readiness");
    Check(peer.at("channels_active").get<std::uint32_t>() == 3U,
          "federation status lost the active channel count");
    Check(peer.at("last_handshake_ms").get<std::int64_t>() ==
              1730000000000LL,
          "federation status lost the millisecond handshake timestamp");
    Check(peer.at("configuration").at("psk_present").get<bool>(),
          "federation status lost the psk presence flag");
    Check(peer.at("configuration").at("host").get<std::string>() ==
              "peer.invalid",
          "federation status lost the peer host");
}

void CheckInboundOnlyPeerIsReported() {
    FederationPeerStatus inbound;
    inbound.id = "bootstrap-client";
    inbound.state = "inbound-ready";
    inbound.ready = true;
    inbound.inbound_connections = 1U;
    inbound.last_handshake_ms = 1730000000001LL;

    const auto topology = build_federation_topology_json(
        SelfNode(), {}, {inbound}, {}, {});
    Check(topology.at("nodes").size() == 1U,
          "inbound-only federation peer disappeared from topology");
    const auto& node = topology["nodes"][0];
    Check(node.at("configuration").is_null(),
          "inbound-only peer acquired a synthetic dial configuration");
    Check(node.at("ready").get<bool>() &&
              !node.at("outbound_ready").get<bool>() &&
              node.at("inbound_connections").get<std::uint32_t>() == 1U,
          "inbound-only peer connectivity was reported as outbound");
}

void CheckPublicErrorIsTerminalSafeAndBounded() {
    ConfiguredFederationPeers configured;
    configured.peers.push_back(ConfiguredPeer("node-b"));
    auto peer_status = ReadyStatus("node-b");
    peer_status.last_error = "remote error\n";
    peer_status.last_error.push_back('\x1b');
    peer_status.last_error.append(700U, 'x');

    const auto status = build_federation_status_json(
        SelfNode(), configured, {peer_status});
    const auto& public_error = status["peers"][0].at("last_error");
    const auto error = public_error.get<std::string>();
    Check(error.size() == yume::server::kMaxFederationPublicErrorBytes,
          "federation status did not bound its public last_error");
    Check(error.find('\n') == std::string::npos &&
              error.find('\x1b') == std::string::npos,
          "federation status retained terminal control characters");
    Check(error.size() >= 3U &&
              error.compare(error.size() - 3U, 3U, "...") == 0,
          "truncated federation status error has no visible marker");
}

void CheckIpv6AddressRendering() {
    ConfiguredFederationPeers configured;
    auto peer = ConfiguredPeer("node-v6");
    peer.host = "2001:db8::1";
    peer.port = 9443;
    configured.peers.push_back(std::move(peer));
    const auto topology = build_federation_topology_json(
        SelfNode(), configured, {ReadyStatus("node-v6")}, {}, {});

    const auto boxes = topology_boxes(topology);
    Check(boxes.size() == 2U && boxes[1].addr == "[2001:db8::1]:9443",
          "topology renderer emitted an ambiguous IPv6 host and port");
}

// A peer whose link never started still has to appear, or an operator
// debugging a cluster cannot tell a rejected peer from an absent one.
void CheckConfiguredPeerWithoutLinkIsReported() {
    ConfiguredFederationPeers configured;
    configured.peers.push_back(ConfiguredPeer("node-b"));
    configured.peers.push_back(ConfiguredPeer("node-c"));

    const auto topology = build_federation_topology_json(
        SelfNode(), configured, {ReadyStatus("node-b")}, {}, {});

    Check(topology.at("nodes").size() == 2U,
          "a configured peer without a link disappeared from the topology");
    // merge_peers keys on a std::map, so rows are ordered by peer id.
    Check(topology["nodes"][1].at("peer_id").get<std::string>() == "node-c",
          "topology node ordering is not deterministic");
    Check(topology["nodes"][1].at("state").get<std::string>() ==
              "not-started",
          "a peer without a link was not reported as not-started");
    Check(!topology["nodes"][1].at("ready").get<bool>(),
          "a peer without a link was reported ready");
}

void CheckTopologyGroupsEndpointsByAdvertisingPeer() {
    ConfiguredFederationPeers configured;
    configured.peers.push_back(ConfiguredPeer("node-b"));
    configured.peers.push_back(ConfiguredPeer("node-c"));

    const std::vector<EndpointInfo> remote{
        RemoteEndpoint("node-b", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        RemoteEndpoint("node-b", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        RemoteEndpoint("node-c", "cccccccccccccccccccccccccccccccc"),
    };
    const auto topology = build_federation_topology_json(
        SelfNode(), configured,
        {ReadyStatus("node-b"), ReadyStatus("node-c")}, remote, {});

    Check(topology["nodes"][0].at("endpoints").get<std::size_t>() == 2U,
          "endpoints were not attributed to their advertising peer");
    Check(topology["nodes"][1].at("endpoints").get<std::size_t>() == 1U,
          "endpoints were not attributed to their advertising peer");
    Check(topology.at("self").at("local_endpoints").get<std::size_t>() == 2U,
          "self endpoint count is wrong");
}

// Every federated endpoint is exactly one authenticated link away while
// forwarding is unimplemented. The route/hops fields exist so a consumer that
// draws paths does not change shape later; they must not claim more than one.
void CheckSingleHopRouteContract() {
    ConfiguredFederationPeers configured;
    configured.peers.push_back(ConfiguredPeer("node-b"));

    const auto topology = build_federation_topology_json(
        SelfNode(), configured, {ReadyStatus("node-b")}, {}, {});

    Check(!topology.at("transit").at("supported").get<bool>(),
          "topology claimed transit support that is not implemented");
    Check(topology.at("schema_version").get<int>() == 1,
          "topology schema version is wrong");
    Check(topology.at("transit").at("max_hops").get<int>() == 1,
          "topology advertised a hop budget greater than one");

    const auto& node = topology["nodes"][0];
    Check(node.at("hops").get<int>() == 1, "a direct peer was not one hop away");
    Check(node.at("route").size() == 1U &&
              node["route"][0].get<std::string>() == "node-b",
          "the route to a direct peer is not its own single label");
}

void CheckEdgesAndChannels() {
    ConfiguredFederationPeers configured;
    configured.peers.push_back(ConfiguredPeer("node-b"));

    ActiveRelayChannel channel;
    channel.channel_id = "channel-1";
    channel.channel_kind = ChannelKind::bytes;
    channel.left_endpoint_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    channel.right_endpoint_id = "node-b:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    channel.federated = true;
    channel.route_hops = 1;
    channel.pending = false;

    const auto topology = build_federation_topology_json(
        SelfNode(), configured, {ReadyStatus("node-b")}, {}, {channel});

    Check(topology.at("edges").size() == 1U, "expected one federation edge");
    const auto& edge = topology["edges"][0];
    Check(edge.at("from").get<std::string>() == SelfNode().server_id,
          "an edge does not originate at the reporting node");
    Check(edge.at("to").get<std::string>() == "node-b",
          "an edge does not terminate at its peer");
    Check(edge.at("kind").get<std::string>() == "federation-link",
          "an edge lost its kind");
    Check(edge.at("ready").get<bool>(), "an edge lost its link readiness");

    Check(topology.at("channels").size() == 1U, "expected one channel");
    const auto& reported = topology["channels"][0];
    Check(reported.at("channel_kind").get<std::string>() == "bytes",
          "channel kind was not rendered");
    Check(reported.at("federated").get<bool>(), "channel lost its federated flag");
    Check(reported.at("route_hops").get<int>() == 1, "channel lost its hop count");
}

void CheckDisabledFederationStillDescribesItself() {
    FederationSelfNode self = SelfNode();
    self.federation_enabled = false;

    ConfiguredFederationPeers configured;
    configured.peers.push_back(ConfiguredPeer("node-b"));
    const auto topology = build_federation_topology_json(
        self, configured, {}, {}, {});
    Check(topology.at("nodes").size() == 1U,
          "a disabled node hid its configured peer");
    Check(topology.at("edges").size() == 1U,
          "a disabled node hid its configured edge");
    Check(topology["nodes"][0].at("state") == "not-started",
          "a disabled peer did not report that its link was not started");
    Check(!topology.at("self").at("federation_enabled").get<bool>(),
          "self did not report that federation is disabled");
    Check(topology.at("self").at("server_name").get<std::string>() == "node-a",
          "self identity is missing from a peerless topology");
}

void CheckRendererJoinsPeerTopBorders() {
    ConfiguredFederationPeers configured;
    configured.peers.push_back(ConfiguredPeer("node-b"));
    configured.peers.push_back(ConfiguredPeer("node-c"));
    const auto topology = build_federation_topology_json(
        SelfNode(), configured,
        {ReadyStatus("node-b"), ReadyStatus("node-c")}, {}, {});

    std::ostringstream rendered;
    render_topology(topology_boxes(topology), false, rendered);
    const std::string text = rendered.str();
    const auto peer_border = text.rfind('\n', text.size() - 2U);
    Check(peer_border != std::string::npos,
          "topology renderer produced no peer boxes");

    // The peer boxes start on row 7. Each vertical spoke must overwrite the
    // center of that box's top border with a tee; drawing the box afterwards
    // would silently erase both joins.
    std::istringstream lines(text);
    std::string line;
    for (int row = 0; row <= 7; ++row) {
        Check(static_cast<bool>(std::getline(lines, line)),
              "topology renderer produced too few rows");
        if (row == 5) {
            Check(line.find("┴") != std::string::npos,
                  "self spoke does not join the peer bus from above");
        }
    }
    std::size_t tees = 0;
    for (std::size_t pos = 0; (pos = line.find("┬", pos)) != std::string::npos;
         pos += std::string("┬").size()) {
        ++tees;
    }
    Check(tees == 2U, "peer top-border joins were overwritten");
}

// The renderer is fed by local IPC/ABI JSON and may also be used by tools on
// captured documents. Wrong field types must degrade to safe placeholders,
// not throw from nlohmann::json::value() or wrap a negative count into a huge
// unsigned number.
void CheckRendererToleratesMalformedDocuments() {
    const nlohmann::json malformed{
        {"self", {
            {"server_id", 7},
            {"server_name", nlohmann::json::array()},
            {"listen_port", 70000},
            {"local_endpoints", -1},
        }},
        {"nodes", nlohmann::json::array({
            nlohmann::json{
                {"peer_id", false},
                {"channels_active", -5},
                {"ready", "yes"},
                {"state", 1},
                {"last_error", nlohmann::json::object()},
                {"configuration", {
                    {"host", 9},
                    {"port", 99999},
                }},
            },
            "not-an-object",
        })},
    };

    const auto boxes = topology_boxes(malformed);
    Check(boxes.size() == 2U,
          "malformed topology did not retain self and valid object rows");
    Check(boxes[0].display == "(local)" && boxes[0].addr == "local" &&
              boxes[0].local_endpoint_count == 0U,
          "malformed self fields did not fall back safely");
    Check(boxes[1].display == "?" && boxes[1].addr.empty() &&
              boxes[1].active_channel_count == 0U && boxes[1].state == "?",
          "malformed peer fields did not fall back safely");

    std::ostringstream rendered;
    render_topology(boxes, true, rendered);
    Check(!rendered.str().empty(),
          "malformed topology produced no safe renderer output");
}

}  // namespace

int main() {
    CheckStatusRedactsSecretPaths();
    CheckPublicErrorIsTerminalSafeAndBounded();
    CheckIpv6AddressRendering();
    CheckInboundOnlyPeerIsReported();
    CheckConfiguredPeerWithoutLinkIsReported();
    CheckTopologyGroupsEndpointsByAdvertisingPeer();
    CheckSingleHopRouteContract();
    CheckEdgesAndChannels();
    CheckDisabledFederationStillDescribesItself();
    CheckRendererJoinsPeerTopBorders();
    CheckRendererToleratesMalformedDocuments();
    return 0;
}
