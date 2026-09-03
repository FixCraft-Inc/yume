/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "engine/byte_channel.hpp"

namespace yume::engine {

inline constexpr std::size_t kMaxPeerIdentityBytes = 512U;
inline constexpr std::size_t kMaxAuthenticationSchemeBytes = 128U;
inline constexpr std::size_t kMaxPeerEvidenceBytes = 16U * 1024U;
inline constexpr std::size_t kMaxExporterLabelBytes = 128U;
inline constexpr std::size_t kMaxExporterContextBytes = 1024U;
inline constexpr std::size_t kMaxExporterOutputBytes = 1024U;

// Identity established by YTP authentication. Possessing this type means the
// complete session-authentication policy succeeded; outer TLS metadata must
// use SecureChannelPeerEvidence instead.
class PeerEvidence final {
public:
    static Result<PeerEvidence> create(
        EndpointRole peer_role,
        std::string identity,
        std::string authentication_scheme,
        std::vector<std::byte> credential_evidence);

    EndpointRole peer_role() const noexcept { return peer_role_; }
    const std::string& identity() const noexcept { return identity_; }
    const std::string& authentication_scheme() const noexcept {
        return authentication_scheme_;
    }
    std::span<const std::byte> credential_evidence() const noexcept {
        return credential_evidence_;
    }

private:
    PeerEvidence(EndpointRole peer_role,
                 std::string identity,
                 std::string authentication_scheme,
                 std::vector<std::byte> credential_evidence) noexcept;

    EndpointRole peer_role_;
    std::string identity_;
    std::string authentication_scheme_;
    std::vector<std::byte> credential_evidence_;
};

// Bounded evidence about the peer observed by the outer secure channel. A
// TLS server normally has no client credential at this layer, so anonymous
// evidence is valid only for a client peer. It is never an application
// identity and must not be passed to handlers or route policy.
class SecureChannelPeerEvidence final {
public:
    static SecureChannelPeerEvidence anonymous_client() noexcept;
    static Result<SecureChannelPeerEvidence> authenticated(
        EndpointRole peer_role,
        std::string identity,
        std::string authentication_scheme,
        std::vector<std::byte> credential_evidence);

    EndpointRole peer_role() const noexcept { return peer_role_; }
    bool authenticated() const noexcept { return authenticated_; }
    const std::string& identity() const noexcept { return identity_; }
    const std::string& authentication_scheme() const noexcept {
        return authentication_scheme_;
    }
    std::span<const std::byte> credential_evidence() const noexcept {
        return credential_evidence_;
    }

private:
    SecureChannelPeerEvidence(
        EndpointRole peer_role,
        bool authenticated,
        std::string identity,
        std::string authentication_scheme,
        std::vector<std::byte> credential_evidence) noexcept;

    EndpointRole peer_role_;
    bool authenticated_{false};
    std::string identity_;
    std::string authentication_scheme_;
    std::vector<std::byte> credential_evidence_;
};

class SecureChannel : public ByteChannel {
public:
    ~SecureChannel() override = default;

    // Immutable provenance of the concrete instance. Session construction
    // compares this descriptor with the frozen suite graph; peer-evidence
    // strings are authentication metadata and never provider selection.
    virtual const ProviderDescriptor& descriptor() const noexcept = 0;
    virtual const SecureChannelPeerEvidence& peer_evidence() const noexcept = 0;
    virtual Result<Buffer> export_keying_material(
        std::string_view label,
        std::span<const std::byte> context,
        std::size_t output_size) = 0;
};

class SecureChannelProvider {
public:
    using Completion =
        std::function<void(Result<std::unique_ptr<SecureChannel>>)>;

    virtual ~SecureChannelProvider() = default;
    virtual const ProviderDescriptor& descriptor() const noexcept = 0;
    virtual void async_wrap(std::unique_ptr<ByteChannel> channel,
                            EndpointRole local_role,
                            CancellationToken cancellation,
                            Completion completion) = 0;
};

}  // namespace yume::engine
