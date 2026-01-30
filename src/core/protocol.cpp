/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "core/protocol.hpp"

#include <algorithm>
#include <stdexcept>

namespace yume::protocol {

std::vector<uint8_t> encode_frame(FrameType type,
                                 uint8_t stream_id,
                                 uint16_t flags,
                                 const std::vector<uint8_t>& payload) {
    uint32_t len = static_cast<uint32_t>(payload.size());
    std::vector<uint8_t> out(8 + payload.size());

    out[0] = static_cast<uint8_t>((len >> 24) & 0xFF);
    out[1] = static_cast<uint8_t>((len >> 16) & 0xFF);
    out[2] = static_cast<uint8_t>((len >> 8) & 0xFF);
    out[3] = static_cast<uint8_t>(len & 0xFF);
    out[4] = static_cast<uint8_t>(type);
    out[5] = stream_id;
    out[6] = static_cast<uint8_t>((flags >> 8) & 0xFF);
    out[7] = static_cast<uint8_t>(flags & 0xFF);

    if (!payload.empty()) {
        std::copy(payload.begin(), payload.end(), out.begin() + 8);
    }
    return out;
}

Frame decode_frame(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 8) {
        throw std::runtime_error("decode_frame: buffer too small");
    }

    uint32_t len = (static_cast<uint32_t>(buffer[0]) << 24) |
                   (static_cast<uint32_t>(buffer[1]) << 16) |
                   (static_cast<uint32_t>(buffer[2]) << 8) |
                   (static_cast<uint32_t>(buffer[3]));

    if (buffer.size() < 8 + len) {
        throw std::runtime_error("decode_frame: incomplete payload");
    }

    Frame frame{};
    frame.header.len = len;
    frame.header.type = buffer[4];
    frame.header.stream_id = buffer[5];
    frame.header.flags = static_cast<uint16_t>(buffer[6] << 8) |
                         static_cast<uint16_t>(buffer[7]);

    frame.payload.assign(buffer.begin() + 8, buffer.begin() + 8 + len);
    return frame;
}

}  // namespace yume::protocol
