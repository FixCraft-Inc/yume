/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/protocol/directory_policy.hpp"

#include <stdexcept>
#include <string>

namespace {

using yume::control::DirectoryNamespace;
using yume::control::EndpointInfo;

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

std::string ValidIdentityBase64() {
    // Canonical base64 for exactly 256 zero bytes. Cryptographic PEM
    // canonicalization is the relay-v2 handshake's responsibility; the
    // directory layer enforces strict spelling and defensible size bounds.
    std::string encoded(340U, 'A');
    encoded.append("AA==");
    return encoded;
}

EndpointInfo ValidEndpoint(std::string id = "0123456789abcdef0123456789abcdef") {
    EndpointInfo endpoint;
    endpoint.endpoint_id = std::move(id);
    endpoint.display_name = "quiet-otter";
    endpoint.hostname = "workstation.local";
    endpoint.client_platform = "linux";
    endpoint.client_variant = "cli";
    endpoint.client_version = "0.2.0-alpha";
    endpoint.server_id = "server-a";
    endpoint.server_name = "server A";
    endpoint.auth_pubkey_b64 = ValidIdentityBase64();
    return endpoint;
}

nlohmann::json ValidEndpointJson(std::string id =
        "0123456789abcdef0123456789abcdef") {
    return yume::control::endpoint_to_json(
        ValidEndpoint(std::move(id)), true);
}

nlohmann::json ValidResponse() {
    return {
        {"cmd", "directory.list"},
        {"ok", true},
        {"request_id", "request-1"},
        {"server_id", "server-a"},
        {"server_name", "server A"},
        {"endpoints", nlohmann::json::array({ValidEndpointJson()})},
    };
}

nlohmann::json ValidPresence() {
    return {
        {"cmd", "presence.announce"},
        {"request_id", "request-2"},
        {"endpoint_kind", "client"},
        {"preferred_id", ""},
        {"preferred_name", "quiet otter"},
        {"hostname", "workstation.local"},
        {"client_platform", "linux"},
        {"client_variant", "cli"},
        {"client_version", "0.2.0-alpha"},
        {"relay_mode", "untrusted"},
        {"allow_chat", true},
        {"allow_file", true},
        {"allow_bytes", true},
        {"allow_inbound_admin", false},
        {"allow_outbound_admin", false},
    };
}

void CheckEndpointPolicy() {
    std::string error;
    auto endpoint = yume::control::try_directory_endpoint_from_json(
        ValidEndpointJson(), DirectoryNamespace::ClientVisible, &error);
    Check(endpoint.has_value(), "valid endpoint was rejected");
    Check(error.empty(), "valid endpoint populated an error");

    auto malformed = ValidEndpointJson();
    malformed["allow_chat"] = "yes";
    Check(!yume::control::try_directory_endpoint_from_json(
               malformed, DirectoryNamespace::ClientVisible),
          "string boolean was accepted");

    malformed = ValidEndpointJson();
    malformed["future_field"] = true;
    Check(!yume::control::try_directory_endpoint_from_json(
               malformed, DirectoryNamespace::ClientVisible),
          "unknown endpoint field was accepted");

    malformed = ValidEndpointJson();
    malformed["endpoint_id"] = "../peer";
    Check(!yume::control::try_directory_endpoint_from_json(
               malformed, DirectoryNamespace::ClientVisible),
          "endpoint traversal spelling was accepted");

    malformed = ValidEndpointJson();
    std::string noncanonical_identity = ValidIdentityBase64();
    noncanonical_identity[noncanonical_identity.size() - 3U] = 'R';
    malformed["auth_pubkey_b64"] = noncanonical_identity;
    Check(!yume::control::try_directory_endpoint_from_json(
               malformed, DirectoryNamespace::ClientVisible),
          "non-canonical base64 identity was accepted");

    malformed = ValidEndpointJson();
    malformed["auth_pubkey_b64"] = "YQ==";
    Check(!yume::control::try_directory_endpoint_from_json(
               malformed, DirectoryNamespace::ClientVisible),
          "undersized relay identity was accepted");

    malformed = ValidEndpointJson();
    malformed["controller_ids"] = nlohmann::json::array();
    for (std::size_t index = 0;
         index <= yume::control::kMaxDirectoryRelationshipsPerList; ++index) {
        malformed["controller_ids"].push_back(
            "controller-" + std::to_string(index));
    }
    Check(!yume::control::try_directory_endpoint_from_json(
               malformed, DirectoryNamespace::ClientVisible),
          "oversized relationship list was accepted");

    auto remote = ValidEndpoint("peer-a:remote-a");
    remote.remote = true;
    remote.federation_peer_id = "peer-a";
    remote.remote_endpoint_id = "remote-a";
    remote.server_id = "server-b";
    auto remote_json = yume::control::endpoint_to_json(remote, true);
    Check(yume::control::try_directory_endpoint_from_json(
              remote_json, DirectoryNamespace::ClientVisible).has_value(),
          "valid namespaced endpoint was rejected");
    Check(!yume::control::try_directory_endpoint_from_json(
               remote_json, DirectoryNamespace::FederationRaw),
          "pre-namespaced federation endpoint was accepted");
    remote_json["endpoint_id"] = "peer-a:other";
    Check(!yume::control::try_directory_endpoint_from_json(
               remote_json, DirectoryNamespace::ClientVisible),
          "inconsistent visible namespace was accepted");

    auto raw_with_federated_relationship = ValidEndpointJson();
    raw_with_federated_relationship["controller_ids"] =
        nlohmann::json::array({"other-peer:controller"});
    Check(yume::control::try_directory_endpoint_from_json(
              raw_with_federated_relationship,
              DirectoryNamespace::FederationRaw).has_value(),
          "valid federated relationship on a raw endpoint was rejected");

    auto duplicate_relationship = ValidEndpoint();
    duplicate_relationship.controller_ids = {"controller", "controller"};
    Check(!yume::control::directory_endpoint_accounted_bytes(
               duplicate_relationship, DirectoryNamespace::ClientVisible),
          "duplicate in-memory relationships were accepted");

    const auto visible =
        yume::control::try_make_federated_visible_endpoint_id(
            "edge-west_2.example", "remote-client");
    Check(visible && *visible == "edge-west_2.example:remote-client",
          "valid federated visible id was rejected");
    Check(!yume::control::try_make_federated_visible_endpoint_id(
               "ambiguous:peer", "remote-client"),
          "ambiguous federation peer id was accepted");
    Check(!yume::control::try_make_federated_visible_endpoint_id(
               "peer", "already:namespaced"),
          "namespaced raw endpoint id was accepted");
    Check(!yume::control::try_make_federated_visible_endpoint_id(
               std::string(yume::control::kMaxDirectoryFederationPeerIdBytes,
                           'p'),
               std::string(yume::control::kMaxDirectoryEndpointIdBytes, 'e')),
          "oversized combined visible endpoint id was accepted");
}

void CheckServerIdentityPolicy() {
    using yume::control::is_valid_directory_server_identity;
    Check(is_valid_directory_server_identity("server A", "Yume A", false),
          "safe non-federated server identity was rejected");
    Check(!is_valid_directory_server_identity("server A", "Yume A", true),
          "federation server id with spaces was accepted");
    Check(is_valid_directory_server_identity(
              "edge-west_2.example", "Yume edge", true),
          "valid federation server identity was rejected");
    Check(!is_valid_directory_server_identity(
               std::string(yume::control::kMaxDirectoryServerIdBytes + 1U,
                           's'),
               "Yume", false),
          "oversized server id was accepted");
    Check(!is_valid_directory_server_identity(
               "server", std::string(
                   yume::control::kMaxDirectoryServerNameBytes + 1U, 'n'),
               false),
          "oversized server name was accepted");
    Check(!is_valid_directory_server_identity("server", "bad\nname", false),
          "control character in server name was accepted");
}

void CheckResponsePolicy() {
    std::string error;
    const auto valid = yume::control::try_directory_response_from_json(
        ValidResponse(), DirectoryNamespace::ClientVisible, &error);
    Check(valid.has_value() && valid->endpoints.size() == 1U,
          "valid directory response was rejected");
    Check(error.empty(), "valid directory response populated an error");

    auto malformed = ValidResponse();
    malformed["ok"] = 1;
    Check(!yume::control::try_directory_response_from_json(
               malformed, DirectoryNamespace::ClientVisible),
          "integer ok flag was accepted");

    malformed = ValidResponse();
    malformed["extra"] = nlohmann::json::array();
    Check(!yume::control::try_directory_response_from_json(
               malformed, DirectoryNamespace::ClientVisible),
          "unknown response field was accepted");

    malformed = ValidResponse();
    malformed["endpoints"].push_back(malformed["endpoints"][0]);
    Check(!yume::control::try_directory_response_from_json(
               malformed, DirectoryNamespace::ClientVisible),
          "duplicate endpoint id was accepted");

    malformed = ValidResponse();
    malformed["endpoints"] = nlohmann::json::array();
    for (std::size_t index = 0;
         index <= yume::control::kMaxDirectoryEndpoints; ++index) {
        malformed["endpoints"].push_back(
            ValidEndpointJson("endpoint-" + std::to_string(index)));
    }
    Check(!yume::control::try_directory_response_from_json(
               malformed, DirectoryNamespace::ClientVisible),
          "oversized endpoint array was accepted");

    malformed = ValidResponse();
    malformed["endpoints"][0]["server_id"] = "server-b";
    Check(!yume::control::try_directory_response_from_json(
               malformed, DirectoryNamespace::ClientVisible),
          "inconsistent local server id was accepted");

    malformed = ValidResponse();
    malformed["server_id"] = "";
    malformed["endpoints"] = nlohmann::json::array();
    Check(!yume::control::try_directory_response_from_json(
               malformed, DirectoryNamespace::ClientVisible),
          "empty directory server id was accepted");

    // Each endpoint stays within its 64-KiB individual policy, while the
    // complete array crosses the independent 8-MiB aggregate policy.
    nlohmann::json relationships = nlohmann::json::array();
    for (std::size_t index = 0; index < 128U; ++index) {
        const std::string suffix = std::to_string(index);
        relationships.push_back(
            std::string(140U - suffix.size(), 'r') + suffix);
    }
    const std::string maximum_identity(
        yume::control::kMaxDirectoryIdentityBase64Bytes - 4U, 'A');
    malformed = ValidResponse();
    malformed["endpoints"] = nlohmann::json::array();
    for (std::size_t index = 0; index < 150U; ++index) {
        auto item = ValidEndpointJson("large-" + std::to_string(index));
        item["auth_pubkey_b64"] = maximum_identity + "AA==";
        item["controller_ids"] = relationships;
        item["controlled_target_ids"] = relationships;
        malformed["endpoints"].push_back(std::move(item));
    }
    Check(!yume::control::try_directory_response_from_json(
               malformed, DirectoryNamespace::ClientVisible),
          "over-budget directory response was accepted");

    auto federation = ValidResponse();
    federation["cmd"] = "federation.directory";
    Check(yume::control::try_directory_response_from_json(
              federation, DirectoryNamespace::FederationRaw).has_value(),
          "valid federation directory was rejected");
    auto invalid_federation_identity = federation;
    invalid_federation_identity["server_id"] = "ambiguous:server";
    invalid_federation_identity["endpoints"][0]["server_id"] =
        "ambiguous:server";
    Check(!yume::control::try_directory_response_from_json(
               invalid_federation_identity,
               DirectoryNamespace::FederationRaw),
          "invalid federation directory server identity was accepted");
    federation["endpoints"][0]["endpoint_id"] = "peer:already-namespaced";
    Check(!yume::control::try_directory_response_from_json(
               federation, DirectoryNamespace::FederationRaw),
          "namespaced raw federation id was accepted");
}

void CheckPresencePolicy() {
    std::string error;
    const auto valid = yume::control::try_presence_announcement_from_json(
        ValidPresence(), &error);
    Check(valid.has_value(), "valid presence announcement was rejected");
    Check(error.empty(), "valid presence announcement populated an error");

    auto malformed = ValidPresence();
    malformed["preferred_name"] = std::string(
        yume::control::kMaxDirectoryDisplayNameBytes + 1U, 'n');
    Check(!yume::control::try_presence_announcement_from_json(malformed),
          "oversized presence name was accepted");

    malformed = ValidPresence();
    malformed["allow_file"] = 1;
    Check(!yume::control::try_presence_announcement_from_json(malformed),
          "integer presence boolean was accepted");

    malformed = ValidPresence();
    malformed["unknown"] = false;
    Check(!yume::control::try_presence_announcement_from_json(malformed),
          "unknown presence field was accepted");
}

}  // namespace

int main() {
    CheckEndpointPolicy();
    CheckServerIdentityPolicy();
    CheckResponsePolicy();
    CheckPresencePolicy();
    return 0;
}
