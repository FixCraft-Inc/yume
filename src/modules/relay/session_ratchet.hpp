/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

#include <basefwx/crypto.hpp>

#include "modules/relay/frame.hpp"
#include "modules/relay/ratchet.hpp"

namespace yume::relay::ratchet {

enum class EndpointRole {
    Client,
    Server,
};

struct OpenResult {
    std::optional<Frame> application_frame;
    // Plaintext REKEY_ACK to queue like any other control frame. It is left
    // unsealed on purpose: a sending chain assigns sequence numbers when it
    // seals, so every frame must be sealed in the caller's single ordered write
    // path. Sealing it on the read path would let a data frame sealed later
    // reach the peer first, which the peer treats as a replay.
    std::optional<Frame> control_response;
    bool outbound_rekey_completed{false};
};

// A local view of the authenticated-ACK round-trip estimator. Nothing in it is
// sent or negotiated, and no field comes from a peer timestamp: every sample
// is this endpoint's own steady_clock time from sending an offer to accepting
// the authenticated ACK that answers it.
struct RekeyRttEstimate {
    // Samples folded in so far. Zero means the static fallback is in force.
    std::uint64_t samples{0};
    // RFC 6298 smoothed estimate and mean deviation.
    std::chrono::milliseconds smoothed{0};
    std::chrono::milliseconds variation{0};
    // Deadline the next offer would get, clamped into
    // [kMinRekeyAckDeadline, kMaxRekeyAckDeadline].
    std::chrono::milliseconds allowance{0};
};

// Both directional chains of one relay channel and the authenticated
// ML-KEM-1024 + X25519 epoch exchange between them. The implementation is
// hidden so ephemeral private keys stay out of callers' headers.
//
// outbound_window is how many future epochs this endpoint may have offered or
// prepared for sending, and inbound_window how many it accepts from the peer.
// Both are clamped into [kMinRekeyWindow, kMaxRekeyWindow].
//
// Only DATA is application data. REKEY_INIT and REKEY_ACK are the exchange's
// control frames, and any other frame type is refused.
class SessionRatchet {
public:
    // Takes both inputs under wiping ownership before any allocation, so an
    // allocation failure cannot release a root or PSK unwiped.
    SessionRatchet(EndpointRole role,
                   basefwx::crypto::SecureBytes initial_root,
                   basefwx::crypto::SecureBytes psk_key,
                   std::uint16_t outbound_window = kMinRekeyWindow,
                   std::uint16_t inbound_window = kMinRekeyWindow,
                   RatchetPolicy outbound_policy = kExtremePolicy,
                   RatchetPolicy inbound_policy = kExtremePolicy);
    SessionRatchet(EndpointRole role, Bytes initial_root, Bytes psk_key,
                   std::uint16_t outbound_window = kMinRekeyWindow,
                   std::uint16_t inbound_window = kMinRekeyWindow,
                   RatchetPolicy outbound_policy = kExtremePolicy,
                   RatchetPolicy inbound_policy = kExtremePolicy);
    SessionRatchet(const SessionRatchet&) = delete;
    SessionRatchet& operator=(const SessionRatchet&) = delete;
    SessionRatchet(SessionRatchet&&) noexcept;
    SessionRatchet& operator=(SessionRatchet&&) noexcept;
    ~SessionRatchet();

    bool ShouldStartRekey(
        const Frame& plaintext,
        std::chrono::steady_clock::time_point now) const;
    bool ApplicationWriteBlocked(
        const Frame& plaintext,
        std::chrono::steady_clock::time_point now) const;
    Frame BeginOutboundRekey(std::chrono::steady_clock::time_point now);
    Frame Seal(const Frame& plaintext,
               std::chrono::steady_clock::time_point now);
    OpenResult Open(const Frame& protected_frame,
                    std::chrono::steady_clock::time_point now);
    bool outbound_rekey_pending() const;
    std::optional<std::chrono::steady_clock::time_point> rekey_deadline() const;
    RekeyRttEstimate rekey_rtt_estimate() const;
    bool rekey_timed_out(std::chrono::steady_clock::time_point now) const;
    std::uint64_t outbound_epoch() const;
    std::uint64_t inbound_epoch() const;
    std::size_t outbound_rekeys_in_flight() const;
    std::size_t prepared_outbound_epochs() const;
    std::size_t prepared_inbound_epochs() const;
    std::uint16_t outbound_window() const;
    std::uint16_t inbound_window() const;
    RatchetPolicy outbound_policy() const;
    RatchetPolicy inbound_policy() const;

    static bool IsApplicationFrame(std::uint8_t type) noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::relay::ratchet
