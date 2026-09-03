/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/stealth/websocket_codec.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <utility>

namespace yume::obfs {
namespace {

constexpr std::size_t kMaxMessageBytes =
    WebSocketCodec::kDefaultMaxInboundBinaryMessageBytes;
constexpr std::size_t kMaxPendingBytes = 32U * 1024U * 1024U;

void AppendU16(WebSocketBytes& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

void AppendU64(WebSocketBytes& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
    }
}

std::uint64_t ReadU64(const std::uint8_t* data) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        value = (value << 8) | data[i];
    }
    return value;
}

}  // namespace

WebSocketCodec::WebSocketCodec(
    WebSocketRole role, std::size_t max_inbound_binary_message_bytes)
    : role_(role),
      max_inbound_binary_message_bytes_(max_inbound_binary_message_bytes) {
    if (max_inbound_binary_message_bytes_ == 0 ||
        max_inbound_binary_message_bytes_ > kMaxMessageBytes) {
        throw std::invalid_argument(
            "invalid WebSocket inbound binary message limit");
    }
    inbound_.reserve(4096);
    decoded_.reserve(4096);
    wire_replies_.reserve(256);
}

WebSocketBytes WebSocketCodec::EncodeFrame(std::uint8_t opcode,
                                           const std::uint8_t* data,
                                           std::size_t size,
                                           bool final) {
    if (size > kMaxMessageBytes) {
        throw std::runtime_error("WebSocket message exceeds 16 MiB");
    }
    const bool mask = role_ == WebSocketRole::Client;
    WebSocketBytes out;
    out.reserve(size + 14);
    out.push_back(static_cast<std::uint8_t>((final ? 0x80U : 0) |
                                            (opcode & 0x0fU)));
    const std::uint8_t mask_bit = mask ? 0x80U : 0;
    if (size < 126) {
        out.push_back(static_cast<std::uint8_t>(mask_bit | size));
    } else if (size <= std::numeric_limits<std::uint16_t>::max()) {
        out.push_back(static_cast<std::uint8_t>(mask_bit | 126U));
        AppendU16(out, static_cast<std::uint16_t>(size));
    } else {
        out.push_back(static_cast<std::uint8_t>(mask_bit | 127U));
        AppendU64(out, static_cast<std::uint64_t>(size));
    }

    std::array<std::uint8_t, 4> masking_key{};
    if (mask) {
        if (RAND_bytes(masking_key.data(),
                       static_cast<int>(masking_key.size())) != 1) {
            throw std::runtime_error(
                "failed to generate a WebSocket masking key");
        }
        out.insert(out.end(), masking_key.begin(), masking_key.end());
    }
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(mask ? static_cast<std::uint8_t>(data[i] ^ masking_key[i & 3U])
                           : data[i]);
    }
    return out;
}

WebSocketBytes WebSocketCodec::EncodeBinary(const std::uint8_t* data,
                                            std::size_t size) {
    if (closed_) {
        throw std::runtime_error("WebSocket is closed");
    }
    return EncodeFrame(0x2, data, size);
}

WebSocketBytes WebSocketCodec::EncodeBinaryFragmented(
    const std::uint8_t* data,
    std::size_t size,
    std::size_t first_fragment_bytes) {
    if (closed_) throw std::runtime_error("WebSocket is closed");
    if (first_fragment_bytes == 0 || first_fragment_bytes >= size) {
        throw std::runtime_error("invalid WebSocket binary fragmentation split");
    }
    WebSocketBytes first = EncodeFrame(0x2, data, first_fragment_bytes, false);
    WebSocketBytes last = EncodeFrame(0x0, data + first_fragment_bytes,
                                      size - first_fragment_bytes, true);
    first.reserve(first.size() + last.size());
    first.insert(first.end(), last.begin(), last.end());
    return first;
}

WebSocketBytes WebSocketCodec::EncodePing(const std::uint8_t* data,
                                          std::size_t size) {
    if (closed_) throw std::runtime_error("WebSocket is closed");
    if (size > 125) throw std::runtime_error("WebSocket PING exceeds 125 bytes");
    return EncodeFrame(0x9, data, size);
}

WebSocketBytes WebSocketCodec::EncodeClose(std::uint16_t code) {
    std::array<std::uint8_t, 2> payload{
        static_cast<std::uint8_t>((code >> 8) & 0xffU),
        static_cast<std::uint8_t>(code & 0xffU)};
    close_sent_ = true;
    return EncodeFrame(0x8, payload.data(), payload.size());
}

void WebSocketCodec::Feed(const std::uint8_t* data, std::size_t size) {
    if (failed() || size == 0) {
        return;
    }
    if (size > kMaxPendingBytes - inbound_.size()) {
        Fail("WebSocket input buffer limit exceeded");
        return;
    }
    inbound_.insert(inbound_.end(), data, data + size);
    Process();
}

void WebSocketCodec::Process() {
    while (!failed() && inbound_.size() >= 2) {
        const std::uint8_t first = inbound_[0];
        const std::uint8_t second = inbound_[1];
        const bool fin = (first & 0x80U) != 0;
        const bool masked = (second & 0x80U) != 0;
        const std::uint8_t opcode = first & 0x0fU;
        const bool control = (opcode & 0x08U) != 0;
        if ((first & 0x70U) != 0) {
            Fail("WebSocket RSV bits are unsupported (first byte=" +
                 std::to_string(first) + ")");
            return;
        }
        if (masked != (role_ == WebSocketRole::Server)) {
            Fail(role_ == WebSocketRole::Server
                     ? "WebSocket client frame is not masked"
                     : "WebSocket server frame is masked");
            return;
        }

        std::uint64_t payload_size = second & 0x7fU;
        std::size_t offset = 2;
        if (payload_size == 126) {
            if (inbound_.size() < 4) return;
            payload_size = (static_cast<std::uint16_t>(inbound_[2]) << 8) |
                           inbound_[3];
            offset = 4;
            if (payload_size < 126) {
                Fail("non-minimal WebSocket length");
                return;
            }
        } else if (payload_size == 127) {
            if (inbound_.size() < 10) return;
            payload_size = ReadU64(inbound_.data() + 2);
            offset = 10;
            if ((payload_size >> 63U) != 0 || payload_size <= 0xffffU) {
                Fail("invalid WebSocket 64-bit length");
                return;
            }
        }
        if (!control &&
            payload_size > max_inbound_binary_message_bytes_) {
            Fail("WebSocket binary message exceeds configured limit");
            return;
        }
        if (control && (!fin || payload_size > 125)) {
            Fail("invalid fragmented or oversized WebSocket control frame");
            return;
        }
        const std::size_t mask_bytes = masked ? 4 : 0;
        if (payload_size > std::numeric_limits<std::size_t>::max() - offset - mask_bytes) {
            Fail("WebSocket frame length overflow");
            return;
        }
        const std::size_t total = offset + mask_bytes + static_cast<std::size_t>(payload_size);
        if (inbound_.size() < total) return;

        std::array<std::uint8_t, 4> key{};
        if (masked) {
            std::copy_n(inbound_.data() + offset, 4, key.begin());
            offset += 4;
        }
        WebSocketBytes payload(static_cast<std::size_t>(payload_size));
        for (std::size_t i = 0; i < payload.size(); ++i) {
            const auto byte = inbound_[offset + i];
            payload[i] = masked ? static_cast<std::uint8_t>(byte ^ key[i & 3U]) : byte;
        }
        inbound_.erase(inbound_.begin(), inbound_.begin() + static_cast<std::ptrdiff_t>(total));

        switch (opcode) {
            case 0x0:
                if (!fragmented_binary_) {
                    Fail("unexpected WebSocket continuation");
                    return;
                }
                if (payload.size() > max_inbound_binary_message_bytes_ -
                                         fragmented_.size()) {
                    Fail("fragmented WebSocket binary message exceeds "
                         "configured limit");
                    return;
                }
                fragmented_.insert(fragmented_.end(), payload.begin(), payload.end());
                if (fin) {
                    if (fragmented_.size() > kMaxPendingBytes - decoded_.size()) {
                        Fail("decoded WebSocket buffer limit exceeded");
                        return;
                    }
                    if (decoded_.empty()) {
                        decoded_ = std::move(fragmented_);
                    } else {
                        decoded_.insert(decoded_.end(), fragmented_.begin(), fragmented_.end());
                        fragmented_.clear();
                    }
                    fragmented_binary_ = false;
                }
                break;
            case 0x2:
                if (fragmented_binary_) {
                    Fail("new WebSocket data frame during fragmentation");
                    return;
                }
                if (fin) {
                    if (payload.size() > kMaxPendingBytes - decoded_.size()) {
                        Fail("decoded WebSocket buffer limit exceeded");
                        return;
                    }
                    if (decoded_.empty()) {
                        decoded_ = std::move(payload);
                    } else {
                        decoded_.insert(decoded_.end(), payload.begin(), payload.end());
                    }
                } else {
                    fragmented_ = std::move(payload);
                    fragmented_binary_ = true;
                }
                break;
            case 0x8:
                if (payload.size() == 1) {
                    Fail("invalid one-byte WebSocket close payload");
                    return;
                }
                closed_ = true;
                if (!close_sent_) {
                    auto reply = EncodeFrame(0x8, payload.data(), payload.size());
                    wire_replies_.insert(wire_replies_.end(), reply.begin(), reply.end());
                    close_sent_ = true;
                }
                break;
            case 0x9: {
                auto pong = EncodeFrame(0xA, payload.data(), payload.size());
                wire_replies_.insert(wire_replies_.end(), pong.begin(), pong.end());
                break;
            }
            case 0xA:
                break;
            default:
                Fail(opcode == 0x1 ? "WebSocket text messages are not a YUME carrier"
                                   : "unsupported WebSocket opcode");
                return;
        }
        const std::size_t immediately_consumable =
            control ? total : total - static_cast<std::size_t>(payload_size);
        if (immediately_consumable >
            std::numeric_limits<std::size_t>::max() -
                immediately_consumable_wire_bytes_) {
            Fail("WebSocket flow-control accounting overflow");
            return;
        }
        immediately_consumable_wire_bytes_ += immediately_consumable;
        if (inbound_frame_observer_) {
            inbound_frame_observer_(
                inbound_frame_observer_context_,
                WebSocketFrameMetadata{
                    opcode, fin, masked, payload_size});
        }
    }
}

WebSocketDrain WebSocketCodec::TakeDrain() {
    WebSocketDrain drain;
    drain.tunnel_bytes.swap(decoded_);
    drain.immediately_consumable_wire_bytes =
        std::exchange(immediately_consumable_wire_bytes_, 0);
    return drain;
}

WebSocketBytes WebSocketCodec::TakeDecoded() {
    return TakeDrain().tunnel_bytes;
}

WebSocketBytes WebSocketCodec::TakeWireReplies() {
    WebSocketBytes out;
    out.swap(wire_replies_);
    return out;
}

void WebSocketCodec::Fail(std::string reason) {
    if (error_.empty()) error_ = std::move(reason);
}

}  // namespace yume::obfs
