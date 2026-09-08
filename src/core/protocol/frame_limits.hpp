/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include "core/protocol/protocol.hpp"
#include "core/security/auth_v2.hpp"

namespace yume::protocol {

// AUTH challenge/response records are unencrypted. Account for the optional
// trailing pad and its length byte before any reader buffers their payload.
// The codec still checks the unpadded record against its own canonical limit.
constexpr std::size_t frame_payload_limit(std::uint8_t type,
                                         std::uint16_t flags) noexcept {
    if (type != AUTH) return kMaxFramePayloadBytes;
    return auth_v2::kMaxRecordBytes +
           ((flags & kFlagPadded) != 0 ? 256U : 0U);
}

}  // namespace yume::protocol
