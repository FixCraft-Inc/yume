/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace yume::obfs {

using WebSocketBytes = std::vector<std::uint8_t>;

enum class WebSocketRole {
    Client,
    Server,
};

struct WebSocketFrameMetadata {
    std::uint8_t opcode{0};
    bool final{false};
    bool masked{false};
    std::uint64_t payload_bytes{0};
};

using WebSocketFrameObserver = void (*)(
    void* context, const WebSocketFrameMetadata& frame) noexcept;

// RFC 6455 framing used inside RFC 8441 DATA.  The codec deliberately exposes
// decoded binary payload as a byte stream because YUME's own frame parser sits
// above it.  It accepts fragmented binary messages and interleaved controls,
// enforces client masking, and bounds all retained input.
class WebSocketCodec {
public:
    explicit WebSocketCodec(WebSocketRole role);

    // The callback receives metadata only, after a complete inbound frame has
    // passed structural/opcode validation. It must be noexcept and must not
    // retain or inspect payload data (which is never supplied).
    void set_inbound_frame_observer(WebSocketFrameObserver observer,
                                    void* context) noexcept {
        inbound_frame_observer_ = observer;
        inbound_frame_observer_context_ = context;
    }

    WebSocketBytes EncodeBinary(const std::uint8_t* data, std::size_t size);
    WebSocketBytes EncodeBinary(const WebSocketBytes& data) {
        return EncodeBinary(data.data(), data.size());
    }
    WebSocketBytes EncodeBinaryFragmented(const std::uint8_t* data,
                                          std::size_t size,
                                          std::size_t first_fragment_bytes);
    WebSocketBytes EncodeBinaryFragmented(const WebSocketBytes& data,
                                          std::size_t first_fragment_bytes) {
        return EncodeBinaryFragmented(data.data(), data.size(),
                                      first_fragment_bytes);
    }
    WebSocketBytes EncodePing(const std::uint8_t* data, std::size_t size);
    WebSocketBytes EncodePing(const WebSocketBytes& data) {
        return EncodePing(data.data(), data.size());
    }
    WebSocketBytes EncodeClose(std::uint16_t code = 1000);

    void Feed(const std::uint8_t* data, std::size_t size);
    void Feed(const WebSocketBytes& data) { Feed(data.data(), data.size()); }

    WebSocketBytes TakeDecoded();
    WebSocketBytes TakeWireReplies();

    bool closed() const noexcept { return closed_; }
    bool failed() const noexcept { return !error_.empty(); }
    const std::string& error() const noexcept { return error_; }

private:
    WebSocketBytes EncodeFrame(std::uint8_t opcode,
                               const std::uint8_t* data,
                               std::size_t size,
                               bool final = true);
    void Process();
    void Fail(std::string reason);

    WebSocketRole role_;
    WebSocketBytes inbound_;
    WebSocketBytes decoded_;
    WebSocketBytes fragmented_;
    WebSocketBytes wire_replies_;
    bool fragmented_binary_{false};
    bool close_sent_{false};
    bool closed_{false};
    std::string error_;
    WebSocketFrameObserver inbound_frame_observer_{nullptr};
    void* inbound_frame_observer_context_{nullptr};
};

}  // namespace yume::obfs
