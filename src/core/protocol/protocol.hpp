/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <cstdint>
#include <utility>
#include <vector>

namespace yume::protocol {

enum FrameType : uint8_t {
    AUTH = 1,
    OPEN,
    DATA,
    CLOSE,
    EXEC,
    ANON,
    RLISTEN,
    ROPEN,
    PING,
    PONG,
    CONTROL,
    SOPEN,
    REKEY_INIT,
    REKEY_ACK,
};

inline constexpr uint16_t kFlagOpenOk = 0x0001;
// CLOSE with this flag is a TCP half-close/FIN for the stream's send side.
// A plain CLOSE remains a full stream abort/teardown. This keeps HTTP uploads,
// CONNECT tunnels, and browser page-load completion from being truncated when
// one TCP direction finishes before the other.
inline constexpr uint16_t kFlagStreamFin = 0x0002;
// Trailing-padding flag (HTTP/2 DATA-style). When set, the payload's last
// byte is N, the count of pad bytes preceding it. The on-wire payload size
// is therefore actual_payload + N + 1. Senders only set this when an
// operator opted in via the obfs_pad_multiple config key. Receivers strip it
// transparently so handle_frame sees the original payload.
inline constexpr uint16_t kFlagPadded         = 0x4000;
inline constexpr uint16_t kFlagInnerEncrypted = 0x8000;

struct FrameHeader {
    uint32_t len;
    uint8_t type;
    uint8_t stream_id;
    uint16_t flags;
};

struct Frame {
    FrameHeader header;
    std::vector<uint8_t> payload;
};

// Encodes a frame. When `pad_multiple` > 0, the payload is padded with
// trailing zero bytes plus a 1-byte length so the total on-wire payload is a
// multiple of `pad_multiple`, and kFlagPadded is OR'd into the header flags.
// pad_multiple is clamped to [1, 256]; 0 means "no padding" and emits the
// payload unmodified. The receiver always strips the padding
// transparently via decode_frame / strip_padding (no caller awareness needed
// downstream).
std::vector<uint8_t> encode_frame(FrameType type,
                                 uint8_t stream_id,
                                 uint16_t flags,
                                 const std::vector<uint8_t>& payload,
                                 uint16_t pad_multiple = 0);

Frame decode_frame(const std::vector<uint8_t>& buffer);

// In-place strip of trailing padding when kFlagPadded is set in
// `frame.header.flags`. On success, returns true and clears kFlagPadded so
// downstream handlers see the original frame shape. On malformed padding
// (length byte points past the payload), returns false; the caller should
// close the session — a well-behaved peer can't produce that.
bool strip_padding(Frame& frame);

}  // namespace yume::protocol
