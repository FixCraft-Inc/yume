/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <string_view>

#include "core/protocol/protocol.hpp"

namespace yume::server::authorization {

enum class SessionTier : std::uint8_t {
    Unauthenticated,
    Authorized,
    PreauthServiceOnly,
};

struct FrameContext {
    bool service_open{false};
    bool existing_service_stream{false};
};

// The preauth OPEN surface is intentionally narrower than the normal service
// parser: only the two-field {proto, service} object crosses the central tier
// gate. This prevents a payload from also carrying relay or generic-egress
// routing fields that another dispatcher branch could interpret.
bool preauth_service_open_payload(std::string_view payload);

// Central post-auth frame gate. A preauth-admitted identity is deliberately
// unable to reach any ordinary relay, codec, packet, reverse-listener, or
// control dispatcher. Only a named service stream and connection liveness are
// available until the key is promoted into authorized_keys.
bool post_auth_frame_allowed(SessionTier tier,
                             protocol::FrameType type,
                             const FrameContext& context = {});

// Claiming admin never upgrades an otherwise preauth-only identity. The
// visitor signature must be valid and that same visitor identity must already
// belong to a regular or operator trust store before the second factor is
// considered.
bool admin_claim_eligible(bool visitor_signature_valid,
                          bool visitor_authorized) noexcept;

// Admin is directional: the caller must be a trusted relay endpoint whose
// server-capped outbound bit is true, and the target's server-capped inbound
// bit must be true. Target outbound permission is intentionally irrelevant.
bool admin_attach_allowed(bool caller_trusted_relay,
                          bool caller_allow_outbound,
                          bool target_allow_inbound);

}  // namespace yume::server::authorization
