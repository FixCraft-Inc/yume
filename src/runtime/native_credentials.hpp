/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <cstddef>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "config/v1/config.hpp"
#include "engine/stream_handler.hpp"

namespace yume::providers {
class Ytp1OpenSslSecurityProviderFactory;
class Ytp1Tls13SecureChannelProvider;
}  // namespace yume::providers

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

    NativeAuthorizationPolicy(engine::EndpointRole peer_role,
                              std::vector<Grant> grants,
                              std::vector<SessionLimit> session_limits = {},
                              std::vector<EgressWeight> egress_weights = {}) noexcept;
    engine::Status authorize(
        const engine::StreamOpenContext& context) const noexcept;
    // The configured bound for an authenticated identity, or zero when its
    // store entry sets none.
    std::size_t max_sessions(std::string_view peer_identity) const noexcept;
    // The configured weight for an authenticated identity, or
    // EgressLimiter::kDefaultWeight when its store entry sets none.
    double egress_weight(std::string_view peer_identity) const noexcept;
    // Whether the policy grants this identity anything. A store entry always
    // grants at least one service, so this is store membership.
    bool recognizes(std::string_view peer_identity) const noexcept;

private:
    engine::EndpointRole peer_role_;
    std::vector<Grant> grants_;
    std::vector<SessionLimit> session_limits_;
    std::vector<EgressWeight> egress_weights_;
};

// Upper bound for an authorized-keys entry's optional max_sessions. It matches
// the largest native endpoint session capacity.
inline constexpr std::size_t kMaxSessionsPerIdentity = 1024U;

struct LoadedNativeCredentials final {
    std::shared_ptr<providers::Ytp1OpenSslSecurityProviderFactory>
        security_factory;
    std::shared_ptr<providers::Ytp1Tls13SecureChannelProvider> tls_provider;
    std::shared_ptr<const NativeAuthorizationPolicy> authorization;
    NativeAdmissionKey admission_key;
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

}  // namespace yume::runtime
