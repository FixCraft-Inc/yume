/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>

#include "core/protocol/protocol.hpp"

namespace yume::server::detail {

// Lower values are selected first. Rekey traffic must remain ahead of DATA:
// starving an authenticated REKEY_INIT/ACK behind a saturated packet stream
// turns ordinary congestion into a transport-wide fail-closed ACK timeout
// (locally RTT-adaptive, bounded to 5..30 seconds).
inline constexpr int frame_write_priority(std::uint8_t frame_type,
                                          std::size_t payload_size) noexcept {
    switch (frame_type) {
        case protocol::PING:
        case protocol::PONG:
        case protocol::CONTROL:
        case protocol::REKEY_INIT:
        case protocol::REKEY_ACK:
            return 0;
        case protocol::OPEN:
        case protocol::CLOSE:
        case protocol::RLISTEN:
        case protocol::ROPEN:
        case protocol::SOPEN:
        case protocol::EXEC:
            return 1;
        case protocol::DATA:
            return payload_size <= 4096 ? 2 : 3;
        default:
            return 4;
    }
}

}  // namespace yume::server::detail
