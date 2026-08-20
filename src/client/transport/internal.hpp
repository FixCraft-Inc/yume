#pragma once

/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * ----------------------------------------------------------------
 * Internal helpers shared across the transport translation units that
 * implement yume::client::TransportCore. They are header-only and inline in
 * yume::client::detail so core/write/dispatch/crypto can share them. Each does:
 *     #include "client/transport/internal.hpp"
 *     using namespace detail;   // inside namespace yume::client
 * ---------------------------------------------------------------- */

#include <cstdint>
#include <string>
#include <vector>

#include "core/protocol/protocol.hpp"

namespace yume::client {
namespace detail {

// Must match the server's tolerance. Under Android/desktop upload
// congestion, encrypted DATA frames can sit behind large batched writes
// long enough to cross many hop ticks; accept the bounded adjacent-hop
// window instead of tearing down the whole transport on a stale frame.
inline constexpr std::uint64_t kHopDecryptWindow = 120;
inline constexpr std::size_t kMaxFramePayloadBytes = 16U * 1024U * 1024U;
inline constexpr std::size_t kMaxWriteBatchFrames = 64;
inline constexpr std::size_t kMaxWriteBatchBytes = 1024U * 1024U;

inline int frame_write_priority(const protocol::Frame& frame) {
    switch (frame.header.type) {
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
            return frame.payload.size() <= 4096 ? 2 : 3;
        default:
            return 4;
    }
}

inline std::string payload_to_string(const std::vector<uint8_t>& payload) {
    return std::string(payload.begin(), payload.end());
}

inline protocol::FrameHeader parse_header(const uint8_t* bytes) {
    protocol::FrameHeader header{};
    header.len = (static_cast<uint32_t>(bytes[0]) << 24) |
                 (static_cast<uint32_t>(bytes[1]) << 16) |
                 (static_cast<uint32_t>(bytes[2]) << 8) |
                 static_cast<uint32_t>(bytes[3]);
    header.type = bytes[4];
    header.stream_id = bytes[5];
    header.flags = static_cast<uint16_t>(bytes[6] << 8) |
                   static_cast<uint16_t>(bytes[7]);
    return header;
}

}  // namespace detail
}  // namespace yume::client
