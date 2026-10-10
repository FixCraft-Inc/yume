/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
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

// Bytes produced by one or more complete inbound WebSocket frames. HTTP/2
// flow control applies to the WebSocket wire bytes carried in DATA. Framing
// and control bytes can be retired as soon as the codec handles them, while
// binary payload remains tied 1:1 to the returned tunnel bytes.
struct WebSocketDrain {
    WebSocketBytes tunnel_bytes;
    std::size_t immediately_consumable_wire_bytes{0};
};

using WebSocketFrameObserver = void (*)(
    void* context, const WebSocketFrameMetadata& frame) noexcept;

// One message payload held in two parts, such as an envelope header and the
// record behind it, so a sender need not join them before framing.
struct WebSocketPayload {
    std::span<const std::uint8_t> first;
    std::span<const std::uint8_t> second;

    std::size_t size() const noexcept { return first.size() + second.size(); }
    // The bytes [offset, offset + length) of first followed by second.
    WebSocketPayload part(std::size_t offset,
                          std::size_t length) const noexcept;
};

// XORs `size` bytes with the RFC 6455 masking key, starting at key byte
// `phase % 4`. Eight bytes at a time, so the result equals the per-byte
// definition for any alignment of `data`.
void ApplyWebSocketMask(std::uint8_t* data, std::size_t size,
                        const std::array<std::uint8_t, 4>& key,
                        std::size_t phase = 0) noexcept;

// RFC 6455 framing used inside RFC 8441 DATA.  The codec deliberately exposes
// decoded binary payload as a byte stream because YUME's own frame parser sits
// above it.  It accepts fragmented binary messages and interleaved controls,
// enforces client masking, and bounds all retained input.
class WebSocketCodec {
public:
    static constexpr std::size_t kDefaultMaxInboundBinaryMessageBytes =
        16U * 1024U * 1024U;

    explicit WebSocketCodec(
        WebSocketRole role,
        std::size_t max_inbound_binary_message_bytes =
            kDefaultMaxInboundBinaryMessageBytes);

    // The callback receives metadata only, after a complete inbound frame has
    // passed structural/opcode validation. It must be noexcept and must not
    // retain or inspect payload data (which is never supplied).
    void set_inbound_frame_observer(WebSocketFrameObserver observer,
                                    void* context) noexcept {
        inbound_frame_observer_ = observer;
        inbound_frame_observer_context_ = context;
    }

    // Each encoder appends complete frames to `out`. A client masks every
    // frame with a fresh key from RAND_bytes. On an exception `out` keeps
    // exactly the bytes it held before the call.
    void EncodeBinary(WebSocketBytes& out, WebSocketPayload payload);
    void EncodeBinary(WebSocketBytes& out, const std::uint8_t* data,
                      std::size_t size) {
        EncodeBinary(out, WebSocketPayload{{data, size}, {}});
    }
    void EncodeBinaryFragmented(WebSocketBytes& out, WebSocketPayload payload,
                                std::size_t first_fragment_bytes);
    void EncodeBinaryFragmented(WebSocketBytes& out, const std::uint8_t* data,
                                std::size_t size,
                                std::size_t first_fragment_bytes) {
        EncodeBinaryFragmented(out, WebSocketPayload{{data, size}, {}},
                               first_fragment_bytes);
    }
    void EncodePing(WebSocketBytes& out, const std::uint8_t* data,
                    std::size_t size);
    // RFC 6455 allows at most 123 bytes of UTF-8 reason after the code.
    void EncodeClose(WebSocketBytes& out, std::uint16_t code = 1000,
                     std::string_view reason = {});

    // The bytes one frame of `payload_bytes` takes on the wire in this role.
    std::size_t FrameBytes(std::size_t payload_bytes) const noexcept;

    void Feed(const std::uint8_t* data, std::size_t size);
    void Feed(const WebSocketBytes& data) { Feed(data.data(), data.size()); }

    WebSocketDrain TakeDrain();
    WebSocketBytes TakeWireReplies();

    bool closed() const noexcept { return closed_; }
    bool failed() const noexcept { return !error_.empty(); }
    const std::string& error() const noexcept { return error_; }

private:
    void EncodeFrame(WebSocketBytes& out, std::uint8_t opcode,
                     WebSocketPayload payload, bool final = true);
    void Process();
    void Fail(std::string reason);

    WebSocketRole role_;
    // Received bytes not yet parsed start at inbound_offset_. Parsing moves
    // the offset, and Feed drops the parsed prefix once before it appends.
    WebSocketBytes inbound_;
    std::size_t inbound_offset_{0};
    WebSocketBytes decoded_;
    WebSocketBytes fragmented_;
    WebSocketBytes wire_replies_;
    std::size_t immediately_consumable_wire_bytes_{0};
    std::size_t max_inbound_binary_message_bytes_;
    bool fragmented_binary_{false};
    bool close_sent_{false};
    bool closed_{false};
    std::string error_;
    WebSocketFrameObserver inbound_frame_observer_{nullptr};
    void* inbound_frame_observer_context_{nullptr};
};

}  // namespace yume::obfs
