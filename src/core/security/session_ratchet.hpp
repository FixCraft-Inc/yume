/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <memory>
#include <optional>

#include "core/protocol/protocol.hpp"
#include "core/security/ratchet.hpp"

namespace yume::ratchet {

enum class EndpointRole {
    Client,
    Server,
};

struct OpenResult {
    std::optional<protocol::Frame> application_frame;
    // Plaintext REKEY_ACK to queue like any other control frame. It is
    // deliberately not sealed here: a sending chain assigns sequence numbers at
    // seal time, so every frame must be sealed inside the caller's single
    // ordered write path. Sealing an ACK on the read path lets a data frame
    // sealed afterwards reach the wire first, which the peer sees as a
    // sequence gap and treats as a replay.
    std::optional<protocol::Frame> control_response;
    bool outbound_rekey_completed{false};
};

// Owns both independent directional chains and the authenticated ML-KEM +
// X25519 epoch exchange. The implementation is hidden so ephemeral private
// keys never leak into client/server session headers.
//
// `outbound_window` is the negotiated number of authenticated future epochs
// this endpoint may keep in flight or prepared for sending, and
// `inbound_window` is the number it will accept from the peer. Both are
// clamped into [kMinRekeyWindow, kMaxRekeyWindow]; passing
// `kMinRekeyWindow` for both reproduces the single-exchange behavior exactly.
class SessionRatchet {
public:
    SessionRatchet(EndpointRole role, Bytes initial_root, Bytes psk_key,
                   std::uint16_t outbound_window = kMinRekeyWindow,
                   std::uint16_t inbound_window = kMinRekeyWindow);
    SessionRatchet(const SessionRatchet&) = delete;
    SessionRatchet& operator=(const SessionRatchet&) = delete;
    SessionRatchet(SessionRatchet&&) noexcept;
    SessionRatchet& operator=(SessionRatchet&&) noexcept;
    ~SessionRatchet();

    bool ShouldStartRekey(
        const protocol::Frame& plaintext,
        std::chrono::steady_clock::time_point now) const;
    bool ApplicationWriteBlocked(
        const protocol::Frame& plaintext,
        std::chrono::steady_clock::time_point now) const;
    protocol::Frame BeginOutboundRekey(
        std::chrono::steady_clock::time_point now);
    protocol::Frame Seal(const protocol::Frame& plaintext,
                         std::chrono::steady_clock::time_point now);
    OpenResult Open(const protocol::Frame& protected_frame,
                    std::chrono::steady_clock::time_point now);

    bool outbound_rekey_pending() const;
    std::optional<std::chrono::steady_clock::time_point> rekey_deadline() const;
    bool rekey_timed_out(std::chrono::steady_clock::time_point now) const;
    std::uint64_t outbound_epoch() const;
    std::uint64_t inbound_epoch() const;

    // Exchanges whose ACK has not arrived yet.
    std::size_t outbound_rekeys_in_flight() const;
    // Authenticated future epochs ready to carry application data. A sender is
    // blocked at a hard boundary only when this is zero.
    std::size_t prepared_outbound_epochs() const;
    // Authenticated future epochs prepared for the peer's sending direction.
    std::size_t prepared_inbound_epochs() const;
    std::uint16_t outbound_window() const;
    std::uint16_t inbound_window() const;

    static bool IsApplicationFrame(std::uint8_t frame_type) noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::ratchet
