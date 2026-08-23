/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

namespace yume::client::relay_v2 {

class PeerTrustError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

enum class PeerTrustMode : std::uint8_t {
    Tofu = 1,
    Pinned = 2,
};

enum class PeerTrustRequirement : std::uint8_t {
    Ordinary = 1,
    Admin = 2,
};

using ExplicitPeerPins =
    std::map<std::string, std::string, std::less<>>;

struct PeerTrustConfig {
    // Must be absolute. Every component is opened descriptor-relatively with
    // no-follow semantics. Ancestors must be root/current-user owned and not
    // shared-writable (a root-owned sticky directory such as /tmp is allowed);
    // the final directory is required to be current-user-owned and mode 0700.
    std::filesystem::path directory;
    PeerTrustMode mode{PeerTrustMode::Tofu};

    // Exact endpoint ID -> lowercase composite SHA-256 fingerprint. These
    // values are operator-provided/OOB authorization, not learned state.
    ExplicitPeerPins explicit_pins;
};

struct PeerTrustDecision {
    std::string fingerprint;
    bool pin_persisted{false};
    bool explicit_authorized{false};
    bool commit_required{false};
};

// Persistent relay-v2 peer identity policy.
//
// The canonical_identity input is the exact canonical two-PEM Ed25519 +
// ML-DSA-87 representation carried by relay-v2. The store validates it and
// retains only its composite fingerprint; public identity bytes are never
// copied into the store object or written to disk.
//
// Precheck is deliberately read-only. In particular, an unsolicited incoming
// invite may be prechecked without creating a TOFU pin. Call commit_verified
// only after the relay-v2 signature/key-exchange transcript has verified. An
// admin precheck based on a configured OOB pin authorizes only that verification
// attempt: no admin data path may open until commit_verified has durably
// materialized (or revalidated) the matching explicit marker.
class PeerTrustStore {
public:
    explicit PeerTrustStore(PeerTrustConfig config);

    PeerTrustDecision precheck(
        std::string_view endpoint_id,
        std::span<const std::uint8_t> canonical_identity,
        PeerTrustRequirement requirement =
            PeerTrustRequirement::Ordinary) const;

    PeerTrustDecision commit_verified(
        std::string_view endpoint_id,
        std::span<const std::uint8_t> canonical_identity,
        PeerTrustRequirement requirement =
            PeerTrustRequirement::Ordinary) const;

    const PeerTrustConfig& config() const noexcept { return config_; }

private:
    PeerTrustConfig config_;
};

bool IsValidPeerEndpointId(std::string_view endpoint_id) noexcept;
bool IsCanonicalCompositeFingerprint(std::string_view fingerprint) noexcept;

}  // namespace yume::client::relay_v2
