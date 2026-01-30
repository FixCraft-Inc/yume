#pragma once

#include <array>
#include <cstdint>
#include <utility>
#include <vector>

#include <boost/asio.hpp>

namespace yume::protocol {

enum FrameType : uint8_t { AUTH = 1, OPEN, DATA, CLOSE, EXEC, ANON };

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

template <typename SyncStream>
void send_frame(SyncStream& stream, const Frame& frame) {
    auto data = encode_frame(static_cast<FrameType>(frame.header.type),
                             frame.header.stream_id,
                             frame.header.flags,
                             frame.payload);
    boost::asio::write(stream, boost::asio::buffer(data));
}

template <typename SyncStream>
Frame read_frame(SyncStream& stream) {
    std::array<uint8_t, 8> header_buf{};
    boost::asio::read(stream, boost::asio::buffer(header_buf));

    uint32_t len = (static_cast<uint32_t>(header_buf[0]) << 24) |
                   (static_cast<uint32_t>(header_buf[1]) << 16) |
                   (static_cast<uint32_t>(header_buf[2]) << 8) |
                   (static_cast<uint32_t>(header_buf[3]));
    Frame frame{};
    frame.header.len = len;
    frame.header.type = header_buf[4];
    frame.header.stream_id = header_buf[5];
    frame.header.flags = static_cast<uint16_t>(header_buf[6] << 8) |
                         static_cast<uint16_t>(header_buf[7]);

    frame.payload.resize(len);
    if (len > 0) {
        boost::asio::read(stream, boost::asio::buffer(frame.payload));
    }
    return frame;
}

}  // namespace yume::protocol
