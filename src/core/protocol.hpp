#pragma once

#include <array>
#include <cstdint>
#include <utility>
#include <vector>

namespace yume::protocol {

enum FrameType : uint8_t { AUTH = 1, OPEN, DATA, CLOSE, EXEC, ANON, RLISTEN, ROPEN, PING, PONG, CONTROL, SOPEN };

inline constexpr uint16_t kFlagOpenOk = 0x0001;
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

std::vector<uint8_t> encode_frame(FrameType type,
                                 uint8_t stream_id,
                                 uint16_t flags,
                                 const std::vector<uint8_t>& payload);

Frame decode_frame(const std::vector<uint8_t>& buffer);

}  // namespace yume::protocol
