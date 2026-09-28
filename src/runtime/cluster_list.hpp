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
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "engine/status.hpp"
#include "runtime/composite_keys.hpp"

namespace yume::runtime::cluster {

// A cluster list names one operator's nodes and the public material a peer
// needs to reach each of them. The operator signs it with a composite key
// kept off the nodes. The signature is an Ed25519 and ML-DSA-87 composite
// over kListDomain, one zero byte and the exact list bytes, and it is checked
// before the list is parsed.
inline constexpr std::string_view kListDomain = "yume-cluster-list/1";
inline constexpr std::size_t kMaxListBytes = std::size_t{1024} * 1024U;
inline constexpr std::size_t kMaxNodes = 64U;
inline constexpr std::size_t kMaxNameBytes = 63U;
inline constexpr std::size_t kMaxTrustBytes = std::size_t{16} * 1024U;

struct Node final {
    std::string name;
    // The TLS name a peer authenticates, and dials unless address is set.
    std::string host;
    // An optional IP literal dialed instead of resolving host, as a client
    // endpoint's connect_address. TLS still authenticates host.
    std::string address;
    std::uint16_t port{0U};
    // Its YTP/1 composite identity, whose fingerprint is the node's identity.
    keys::CompositePublic identity;
    // Its ML-KEM-1024 public key, DER encoded.
    std::vector<std::byte> mlkem_key;
    // The PEM certificates a peer trusts for this node's TLS.
    std::string tls_trust;
};

struct List final {
    // The operator key's composite fingerprint.
    std::string cluster;
    std::uint64_t serial{0U};
    std::chrono::system_clock::time_point not_after;
    std::vector<Node> nodes;

    // The node with this identity fingerprint, or nullptr.
    const Node* find(std::string_view identity) const noexcept;
};

// Verifies the signature under the operator's composite public key (two PEM
// blocks), then parses the list. The list must be schema 1, name the
// operator's fingerprint as its cluster, have 1 to 64 nodes with unique names
// and identities, and not have expired at now. Every failure is
// InvalidArgument except an expired list, which is FailedPrecondition, and a
// missing OpenSSL algorithm, which is ProviderMismatch.
engine::Result<List> verify_list(std::span<const std::byte> list,
                                 std::span<const std::byte> signature,
                                 std::string_view operator_key_pem,
                                 std::chrono::system_clock::time_point now);

// "YYYY-MM-DDTHH:MM:SSZ", as not_after is written. Nothing for any other text.
std::optional<std::chrono::system_clock::time_point> parse_utc(
    std::string_view text);

}  // namespace yume::runtime::cluster
