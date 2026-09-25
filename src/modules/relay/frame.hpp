/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <vector>

namespace yume::relay {

// The inner frames a relay channel carries through its ratchet. The values
// are the transport-v2 frame numbers the relay v2 protocol was defined with.
// They are part of the ratchet's AEAD associated data, so they never change.
inline constexpr std::uint8_t kFrameData = 3;
inline constexpr std::uint8_t kFrameRekeyInit = 13;
inline constexpr std::uint8_t kFrameRekeyAck = 14;

// Set on every ratchet-sealed frame.
inline constexpr std::uint16_t kFlagInnerEncrypted = 0x8000;

struct FrameHeader {
    std::uint32_t len;
    std::uint8_t type;
    std::uint8_t stream_id;
    std::uint16_t flags;
};

struct Frame {
    FrameHeader header;
    std::vector<std::uint8_t> payload;
};

}  // namespace yume::relay
