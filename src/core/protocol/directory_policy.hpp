/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "core/protocol/control_protocol.hpp"

namespace yume::control {

// Directory records carry the composite relay identity, so they are much
// larger than ordinary control messages. These caps keep a complete response
// below the transport's 16-MiB frame ceiling even when every accepted record
// is near its individual maximum. The aggregate byte ledger is authoritative;
// the count cap prevents tiny-record fanout and map-growth attacks.
inline constexpr std::size_t kMaxDirectoryEndpoints = 256U;
inline constexpr std::size_t kMaxFederatedCachedEndpoints = 512U;
inline constexpr std::size_t kMaxDirectoryResponseBytes = 8U * 1024U * 1024U;
inline constexpr std::size_t kMaxDirectoryEndpointBytes = 64U * 1024U;
inline constexpr std::size_t kDirectoryEnvelopeOverheadBytes = 4096U;
inline constexpr std::size_t kDirectoryEndpointOverheadBytes = 2048U;

inline constexpr std::size_t kMaxDirectoryEndpointIdBytes = 255U;
inline constexpr std::size_t kMaxDirectoryDisplayNameBytes = 256U;
inline constexpr std::size_t kMaxDirectoryHostnameBytes = 255U;
inline constexpr std::size_t kMaxDirectoryClientVersionBytes = 128U;
inline constexpr std::size_t kMaxDirectoryServerIdBytes = 255U;
inline constexpr std::size_t kMaxDirectoryServerNameBytes = 256U;
inline constexpr std::size_t kMaxDirectoryFederationPeerIdBytes = 64U;
inline constexpr std::size_t kMaxDirectoryRelationshipsPerList = 256U;
inline constexpr std::size_t kMinDirectoryIdentityBytes = 256U;
inline constexpr std::size_t kMaxDirectoryIdentityBytes = 16U * 1024U;
inline constexpr std::size_t kMaxDirectoryIdentityBase64Bytes =
    4U * ((kMaxDirectoryIdentityBytes + 2U) / 3U);
inline constexpr std::size_t kMaxDirectoryRequestIdBytes = 128U;

enum class DirectoryNamespace {
    // A normal client receives local IDs plus canonical peer:remote IDs.
    ClientVisible,
    // A federation link receives only the peer's raw local IDs. The receiving
    // FederationManager is solely responsible for adding its authenticated
    // peer namespace.
    FederationRaw,
};

struct DirectoryResponse {
    std::string server_id;
    std::string server_name;
    std::vector<EndpointInfo> endpoints;
};

// Fixed endpoint grammar shared by strict directory parsing and server-side
// cache admission. A visible ID may contain exactly one namespace separator;
// a raw federation endpoint may not contain one.
bool is_valid_directory_endpoint_id(
    std::string_view value,
    DirectoryNamespace namespace_kind) noexcept;

// Builds the unambiguous trust-store/routing name for an endpoint learned
// through an authenticated federation link. Both components are validated
// before allocation and the result is constrained by the visible endpoint-ID
// policy.
std::optional<std::string> try_make_federated_visible_endpoint_id(
    std::string_view federation_peer_id,
    std::string_view raw_endpoint_id) noexcept;

// Startup and wire emission share one policy. Empty configured values are
// resolved to generated/default identities before this is called.
bool is_valid_directory_server_identity(
    std::string_view server_id,
    std::string_view server_name,
    bool federation_enabled) noexcept;

// Strict, allocation-bounded wire parsers. Unknown fields, implicit JSON type
// conversions, malformed base64, duplicate endpoint IDs, ambiguous remote
// namespaces, and over-budget records all fail closed.
std::optional<EndpointInfo> try_directory_endpoint_from_json(
    const nlohmann::json& json,
    DirectoryNamespace namespace_kind,
    std::string* error = nullptr) noexcept;

std::optional<DirectoryResponse> try_directory_response_from_json(
    const nlohmann::json& json,
    DirectoryNamespace namespace_kind,
    std::string* error = nullptr) noexcept;

// Returns the conservative wire-accounting cost only when the in-memory
// endpoint satisfies the same policy as the strict JSON parser.
std::optional<std::size_t> directory_endpoint_accounted_bytes(
    const EndpointInfo& endpoint,
    DirectoryNamespace namespace_kind) noexcept;

// Presence is the source of every local directory record. Parse it with the
// same field caps so a client cannot make yumed retain a multi-megabyte name,
// hostname, or version string before the directory response is assembled.
std::optional<PresenceAnnouncement> try_presence_announcement_from_json(
    const nlohmann::json& json,
    std::string* error = nullptr) noexcept;

}  // namespace yume::control
