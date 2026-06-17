#pragma once

#include <array>

#include <boost/asio.hpp>

#include "core/protocol/protocol.hpp"

namespace yume::protocol {

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
