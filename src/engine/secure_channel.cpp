/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "engine/secure_channel.hpp"

#include <algorithm>
#include <utility>

namespace yume::engine {
namespace {

bool valid_evidence_text(std::string_view value,
                         std::size_t max_size) noexcept {
    return !value.empty() && value.size() <= max_size &&
        std::all_of(value.begin(), value.end(), [](unsigned char byte) {
            return byte >= 0x21U && byte <= 0x7eU;
        });
}

}  // namespace

PeerEvidence::PeerEvidence(
    EndpointRole peer_role,
    std::string identity,
    std::string authentication_scheme,
    std::vector<std::byte> credential_evidence) noexcept
    : peer_role_(peer_role),
      identity_(std::move(identity)),
      authentication_scheme_(std::move(authentication_scheme)),
      credential_evidence_(std::move(credential_evidence)) {}

Result<PeerEvidence> PeerEvidence::create(
    EndpointRole peer_role,
    std::string identity,
    std::string authentication_scheme,
    std::vector<std::byte> credential_evidence) {
    if (!valid_evidence_text(identity, kMaxPeerIdentityBytes) ||
        !valid_evidence_text(authentication_scheme,
                             kMaxAuthenticationSchemeBytes)) {
        return Result<PeerEvidence>(Status(
            StatusCode::InvalidArgument,
            "authenticated peer identity or scheme is invalid"));
    }
    if (credential_evidence.empty() ||
        credential_evidence.size() > kMaxPeerEvidenceBytes) {
        return Result<PeerEvidence>(Status(
            StatusCode::InvalidArgument,
            "authenticated peer evidence is empty or exceeds its bound"));
    }
    return Result<PeerEvidence>(PeerEvidence(
        peer_role, std::move(identity), std::move(authentication_scheme),
        std::move(credential_evidence)));
}

SecureChannelPeerEvidence::SecureChannelPeerEvidence(
    EndpointRole peer_role,
    bool authenticated,
    std::string identity,
    std::string authentication_scheme,
    std::vector<std::byte> credential_evidence) noexcept
    : peer_role_(peer_role),
      authenticated_(authenticated),
      identity_(std::move(identity)),
      authentication_scheme_(std::move(authentication_scheme)),
      credential_evidence_(std::move(credential_evidence)) {}

SecureChannelPeerEvidence
SecureChannelPeerEvidence::anonymous_client() noexcept {
    return SecureChannelPeerEvidence(
        EndpointRole::Client, false, {}, {}, {});
}

Result<SecureChannelPeerEvidence>
SecureChannelPeerEvidence::authenticated(
    EndpointRole peer_role,
    std::string identity,
    std::string authentication_scheme,
    std::vector<std::byte> credential_evidence) {
    if (!valid_evidence_text(identity, kMaxPeerIdentityBytes) ||
        !valid_evidence_text(authentication_scheme,
                             kMaxAuthenticationSchemeBytes)) {
        return Result<SecureChannelPeerEvidence>(Status(
            StatusCode::InvalidArgument,
            "secure-channel peer identity or scheme is invalid"));
    }
    if (credential_evidence.empty() ||
        credential_evidence.size() > kMaxPeerEvidenceBytes) {
        return Result<SecureChannelPeerEvidence>(Status(
            StatusCode::InvalidArgument,
            "secure-channel peer evidence is empty or exceeds its bound"));
    }
    return Result<SecureChannelPeerEvidence>(SecureChannelPeerEvidence(
        peer_role, true, std::move(identity),
        std::move(authentication_scheme), std::move(credential_evidence)));
}

}  // namespace yume::engine
