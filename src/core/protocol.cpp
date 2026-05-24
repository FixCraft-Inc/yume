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
                                 const std::vector<uint8_t>& payload,
                                 uint16_t pad_multiple) {
    std::vector<uint8_t> padded;
    const std::vector<uint8_t>* eff_payload = &payload;
    if (pad_multiple > 0) {
        uint16_t m = pad_multiple;
        if (m > 256) m = 256;
        // padded_size = ceil((payload.size() + 1) / m) * m, so we always
        // append at least the 1-byte length and at most m-1 extra zero
        // bytes. The length byte holds N = pad_count_excluding_self, which
        // fits in a byte because m <= 256.
        const std::size_t base = payload.size() + 1;
        const std::size_t pad_total = ((base + m - 1) / m) * m;
        const std::size_t n_zero = pad_total - base;
        padded.resize(pad_total);
        if (!payload.empty()) {
            std::copy(payload.begin(), payload.end(), padded.begin());
        }
        // zero-fill is already done by resize().
        padded.back() = static_cast<uint8_t>(n_zero);
        eff_payload = &padded;
        flags = static_cast<uint16_t>(flags | kFlagPadded);
    }

    const uint32_t len = static_cast<uint32_t>(eff_payload->size());
    std::vector<uint8_t> out(8 + eff_payload->size());

    out[0] = static_cast<uint8_t>((len >> 24) & 0xFF);
    out[1] = static_cast<uint8_t>((len >> 16) & 0xFF);
    out[2] = static_cast<uint8_t>((len >> 8) & 0xFF);
    out[3] = static_cast<uint8_t>(len & 0xFF);
    out[4] = static_cast<uint8_t>(type);
    out[5] = stream_id;
    out[6] = static_cast<uint8_t>((flags >> 8) & 0xFF);
    out[7] = static_cast<uint8_t>(flags & 0xFF);

    if (!eff_payload->empty()) {
        std::copy(eff_payload->begin(), eff_payload->end(), out.begin() + 8);
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

    if ((frame.header.flags & kFlagPadded) != 0 && !strip_padding(frame)) {
        throw std::runtime_error("decode_frame: malformed padding");
    }
    return frame;
}

bool strip_padding(Frame& frame) {
    if ((frame.header.flags & kFlagPadded) == 0) {
        return true;
    }
    if (frame.payload.empty()) {
        return false;
    }
    const uint8_t n = frame.payload.back();
    // The length byte itself is always present (1 byte) plus N zero
    // bytes preceding it. So the original payload size is
    // payload.size() - 1 - N.
    const std::size_t total_pad = static_cast<std::size_t>(n) + 1U;
    if (total_pad > frame.payload.size()) {
        return false;
    }
    frame.payload.resize(frame.payload.size() - total_pad);
    frame.header.flags = static_cast<uint16_t>(frame.header.flags & ~kFlagPadded);
    // Keep header.len matching the on-wire length so logs/diagnostics
    // that print "received N-byte payload" still reflect what came off
    // the socket; handlers only consume frame.payload.
    return true;
}

}  // namespace yume::protocol
