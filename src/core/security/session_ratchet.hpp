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
    // Already protected with the independent outbound chain. Callers must
    // queue this frame directly and must not seal it a second time.
    std::optional<protocol::Frame> control_response;
    bool outbound_rekey_completed{false};
};

// Owns both independent directional chains and the authenticated ML-KEM +
// X25519 epoch exchange. The implementation is hidden so ephemeral private
// keys never leak into client/server session headers.
class SessionRatchet {
public:
    SessionRatchet(EndpointRole role, Bytes initial_root, Bytes psk_key);
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

    static bool IsApplicationFrame(std::uint8_t frame_type) noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::ratchet
