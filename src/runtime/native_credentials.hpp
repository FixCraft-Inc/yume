/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/socks5_credentials.hpp"
#include "config/v1/config.hpp"
#include "engine/stream_handler.hpp"

namespace yume::providers {
class OpenSslSecurityProviderFactory;
class Tls13SecureChannelProvider;
}  // namespace yume::providers

// Declared here so this header stays free of OpenSSL. Callers of
// load_signing_identity include providers/composite_keys.hpp.
namespace yume::providers::keys {
class KeyContext;
struct CompositePrivate;
}  // namespace yume::providers::keys

namespace yume::runtime {

// An admission secret has a single owner. Moves wipe the source; assignment
// wipes replaced storage. Clearing is best effort, not locked-memory storage.
class NativeAdmissionKey final {
public:
    explicit NativeAdmissionKey(std::span<const std::byte, 32> bytes) noexcept;
    NativeAdmissionKey(const NativeAdmissionKey&) = delete;
    NativeAdmissionKey& operator=(const NativeAdmissionKey&) = delete;
    NativeAdmissionKey(NativeAdmissionKey&& other) noexcept;
    NativeAdmissionKey& operator=(NativeAdmissionKey&& other) noexcept;
    ~NativeAdmissionKey();

    std::span<const std::byte, 32> bytes() const noexcept { return bytes_; }

private:
    std::array<std::byte, 32> bytes_{};
};

// Published as const with the same lifetime as the parsed security factory.
// Provider peer labels are verified composite fingerprints, never store names.
class NativeAuthorizationPolicy final {
public:
    struct Grant final {
        std::string peer_identity;
        std::string service_name;
        engine::ServiceKind service_kind;
    };

    // An optional bound on one identity's concurrent authenticated sessions.
    struct SessionLimit final {
        std::string peer_identity;
        std::size_t max_sessions;
    };

    // An optional share of the server's egress rate, relative to the other
    // busy identities. See EgressLimiter.
    struct EgressWeight final {
        std::string peer_identity;
        double weight;
    };

    // Cluster peers, recognized without any grant while the verified list
    // that names them is valid.
    struct Peers final {
        std::vector<std::string> identities;
        std::chrono::system_clock::time_point not_after;
    };

    NativeAuthorizationPolicy(engine::EndpointRole peer_role,
                              std::vector<Grant> grants,
                              std::vector<SessionLimit> session_limits = {},
                              std::vector<EgressWeight> egress_weights = {},
                              Peers peers = {}) noexcept;
    engine::Status authorize(
        const engine::StreamOpenContext& context) const noexcept;
    // The configured bound for an authenticated identity, or zero when its
    // store entry sets none.
    std::size_t max_sessions(std::string_view peer_identity) const noexcept;
    // The configured weight for an authenticated identity, or
    // EgressLimiter::kDefaultWeight when its store entry sets none.
    double egress_weight(std::string_view peer_identity) const noexcept;
    // Whether the identity may hold a session: an authorized-keys entry,
    // which always grants at least one service, or a cluster peer before
    // its list's not_after.
    bool recognizes(std::string_view peer_identity) const noexcept;
    // Whether the identity is a cluster peer before its list's not_after. A
    // peer is granted yume.circuit and nothing else.
    bool is_peer(std::string_view peer_identity) const noexcept;

private:
    engine::EndpointRole peer_role_;
    std::vector<Grant> grants_;
    std::vector<SessionLimit> session_limits_;
    std::vector<EgressWeight> egress_weights_;
    Peers peers_;
};

// Upper bound for an authorized-keys entry's optional max_sessions. It matches
// the largest native endpoint session capacity.
inline constexpr std::size_t kMaxSessionsPerIdentity = 1024U;

// One outbound cluster link: what a client session to a peer needs, built
// from the verified cluster list and this node's peer store.
struct NativeLinkCredentials final {
    std::string peer_name;
    std::string peer_identity;
    // The TLS name the link authenticates, the address it dials (host itself
    // when the list gives no address) and the port.
    std::string host;
    std::string dial;
    std::uint16_t port{0U};
    std::shared_ptr<providers::OpenSslSecurityProviderFactory> security_factory;
    std::shared_ptr<providers::Tls13SecureChannelProvider> tls_provider;
    NativeAdmissionKey admission_key;
    // A digest of everything the link is built from, this node's identity
    // and secrets included, so a reload can keep a link whose inputs did not
    // change.
    std::array<std::byte, 32> material{};
};

// A server's verified membership in its operator's cluster.
struct NativeClusterCredentials final {
    std::string cluster;
    std::uint64_t serial{0U};
    std::chrono::system_clock::time_point not_after;
    std::string self_name;
    // The file where this node keeps the newest list's serial, and the
    // serial it held when this list was loaded, zero without a file.
    std::filesystem::path state;
    std::uint64_t saved_serial{0U};
    // The operator-signed routes view and its signature, which yume.routes
    // serves as they are, and whether the view marks this node as an exit.
    std::vector<std::byte> routes;
    std::vector<std::byte> routes_signature;
    bool exit{false};
    // Peers this node accepts links from, as (identity, name).
    std::vector<std::pair<std::string, std::string>> inbound;
    std::vector<NativeLinkCredentials> links;
};

// Each peer may hold this many sessions to a node at once: its link and one
// replacing it.
inline constexpr std::size_t kMaxPeerSessions = 2U;

struct LoadedNativeCredentials final {
    std::shared_ptr<providers::OpenSslSecurityProviderFactory>
        security_factory;
    std::shared_ptr<providers::Tls13SecureChannelProvider> tls_provider;
    std::shared_ptr<const NativeAuthorizationPolicy> authorization;
    NativeAdmissionKey admission_key;
    // A client's SOCKS5 proxy credentials, when its configuration names them.
    std::optional<common::Socks5Credentials> socks5_credentials;
    // A server's cluster membership, when its configuration names one.
    std::optional<NativeClusterCredentials> cluster;
};

// References in config resolve against config_base_directory; references in
// authorization stores resolve against that store's directory. All files use
// the descriptor-checked protected-file contract. Credentials are fully parsed
// before publication and temporary private PEM, DER and PSKs are wiped.
// Client TLS authentication uses the explicit DNS name, independently of the
// address selected for TCP. An empty client name is rejected.
engine::Result<LoadedNativeCredentials> load_native_credentials(
    const config::v1::Config& config,
    const std::filesystem::path& config_base_directory,
    std::string_view tls_server_name = {}) noexcept;

// A server's composite identity as its circuit handshakes sign with it: the
// configured composite_key, read under the same protected-file contract and
// parsed in keys, which must outlive the result. InvalidArgument for a
// client configuration.
engine::Result<providers::keys::CompositePrivate> load_signing_identity(
    const config::v1::Config& config,
    const std::filesystem::path& config_base_directory,
    const providers::keys::KeyContext& keys) noexcept;

}  // namespace yume::runtime
