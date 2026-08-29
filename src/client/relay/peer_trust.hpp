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
#include <vector>

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

// Where an entry's authority comes from. Configured outranks the others: a
// fingerprint named by the current configuration is operator authorization,
// whether or not a durable record has materialized for it yet.
enum class PeerTrustSource : std::uint8_t {
    // Learned on first use: a durable pin with no explicit marker and no
    // configured fingerprint.
    Tofu = 1,
    // A durable explicit marker exists, materialized by a verified handshake
    // against an out-of-band fingerprint.
    Explicit = 2,
    // The active PeerTrustConfig names this endpoint's fingerprint.
    Configured = 3,
};

// One trusted peer, as a contacts surface sees it. This is identity policy
// only: it never carries public identity bytes, and there is nothing secret
// in it to wipe -- a composite fingerprint is a public digest.
struct PeerTrustEntry {
    std::string endpoint_id;
    // The durable pin when one exists, otherwise the configured fingerprint.
    std::string fingerprint;
    PeerTrustSource source{PeerTrustSource::Tofu};
    bool explicit_marker{false};
    // The configuration names a different fingerprint than the durable pin.
    // Every handshake for this peer fails closed until that is resolved, so a
    // contacts view must be able to show it rather than a healthy-looking row.
    bool configured_mismatch{false};
};

std::string_view to_string(PeerTrustSource source) noexcept;

// Enumeration bound. A trust directory is owner-only, so exceeding this means
// corruption or an already-compromised account; the listing refuses rather
// than truncating, because silently hiding a trusted peer is worse.
inline constexpr std::size_t kMaxListedPeerTrustEntries = 4096;

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

    // Every peer this store would recognise: durable pins on disk merged with
    // the fingerprints the configuration names. Ordered by endpoint ID, so a
    // caller renders a stable list. Read-only; never creates the directory.
    std::vector<PeerTrustEntry> list() const;

    // Removes a learned TOFU pin. Returns false when nothing was stored.
    //
    // Refuses anything that is operator authorization rather than learned
    // state: a fingerprint named by the configuration, or one with a durable
    // explicit marker. Deleting those would silently drop an out-of-band
    // decision that the operator, not this process, is entitled to reverse.
    bool forget(std::string_view endpoint_id) const;

    const PeerTrustConfig& config() const noexcept { return config_; }

private:
    PeerTrustConfig config_;
};

bool IsValidPeerEndpointId(std::string_view endpoint_id) noexcept;
bool IsCanonicalCompositeFingerprint(std::string_view fingerprint) noexcept;

}  // namespace yume::client::relay_v2
