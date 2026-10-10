/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "stealth/websocket_codec.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>

namespace yume::obfs {
namespace {

constexpr std::size_t kMaxMessageBytes =
    WebSocketCodec::kDefaultMaxInboundBinaryMessageBytes;
constexpr std::size_t kMaxPendingBytes = 32U * 1024U * 1024U;
// Input capacity a codec keeps once everything it holds has been parsed. A
// large message grows the buffer, and an idle carrier gives the rest back.
constexpr std::size_t kRetainedInboundBytes = 256U * 1024U;
constexpr std::size_t kMaxHeaderBytes = 14U;

std::size_t HeaderBytes(std::size_t size, bool masked) noexcept {
    const std::size_t length_bytes =
        size < 126U                                         ? 0U
        : size <= std::numeric_limits<std::uint16_t>::max() ? 2U
                                                            : 8U;
    return 2U + length_bytes + (masked ? 4U : 0U);
}

std::uint64_t ReadU64(const std::uint8_t* data) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        value = (value << 8) | data[i];
    }
    return value;
}

// Grows `out` for `extra` more bytes, at least doubling so a caller that
// appends frame after frame copies each byte a bounded number of times.
void ReserveFor(WebSocketBytes& out, std::size_t extra) {
    if (extra > out.max_size() - out.size()) {
        throw std::length_error("WebSocket output exceeds its maximum size");
    }
    const std::size_t needed = out.size() + extra;
    if (needed <= out.capacity()) return;
    out.reserve(
        std::max(needed, std::min(out.max_size(), out.capacity() * 2U)));
}

}  // namespace

void ApplyWebSocketMask(std::uint8_t* data, std::size_t size,
                        const std::array<std::uint8_t, 4>& key,
                        std::size_t phase) noexcept {
    // The key repeated in memory order from the phase, so XOR of a whole
    // word equals XOR of each byte with key[(phase + i) % 4].
    std::array<std::uint8_t, 8> pattern{};
    for (std::size_t i = 0; i < pattern.size(); ++i) {
        pattern[i] = key[(phase + i) & 3U];
    }
    std::uint64_t word = 0;
    std::memcpy(&word, pattern.data(), sizeof(word));
    std::size_t i = 0;
    for (; size - i >= sizeof(word); i += sizeof(word)) {
        std::uint64_t chunk = 0;
        std::memcpy(&chunk, data + i, sizeof(chunk));
        chunk ^= word;
        std::memcpy(data + i, &chunk, sizeof(chunk));
    }
    for (; i < size; ++i) {
        data[i] = static_cast<std::uint8_t>(data[i] ^ pattern[i & 7U]);
    }
}

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

WebSocketPayload WebSocketPayload::part(std::size_t offset,
                                        std::size_t length) const noexcept {
    WebSocketPayload result;
    if (offset < first.size()) {
        const std::size_t from_first = std::min(length, first.size() - offset);
        result.first = first.subspan(offset, from_first);
        result.second = second.first(length - from_first);
    } else {
        result.first = second.subspan(offset - first.size(), length);
    }
    return result;
}

std::size_t WebSocketCodec::FrameBytes(
    std::size_t payload_bytes) const noexcept {
    return HeaderBytes(payload_bytes, role_ == WebSocketRole::Client) +
           payload_bytes;
}

void WebSocketCodec::EncodeFrame(WebSocketBytes& out, std::uint8_t opcode,
                                 WebSocketPayload payload, bool final) {
    const std::size_t size = payload.size();
    if (size > kMaxMessageBytes) {
        throw std::runtime_error("WebSocket message exceeds 16 MiB");
    }
    const bool mask = role_ == WebSocketRole::Client;
    // Everything that can fail happens before `out` changes.
    std::array<std::uint8_t, 4> masking_key{};
    if (mask && RAND_bytes(masking_key.data(),
                           static_cast<int>(masking_key.size())) != 1) {
        throw std::runtime_error("failed to generate a WebSocket masking key");
    }
    const std::size_t header_bytes = HeaderBytes(size, mask);
    ReserveFor(out, header_bytes + size);

    std::array<std::uint8_t, kMaxHeaderBytes> header{};
    header[0] =
        static_cast<std::uint8_t>((final ? 0x80U : 0) | (opcode & 0x0fU));
    const std::uint8_t mask_bit = mask ? 0x80U : 0;
    std::size_t at = 2;
    if (size < 126) {
        header[1] = static_cast<std::uint8_t>(mask_bit | size);
    } else if (size <= std::numeric_limits<std::uint16_t>::max()) {
        header[1] = static_cast<std::uint8_t>(mask_bit | 126U);
        header[at++] = static_cast<std::uint8_t>((size >> 8) & 0xffU);
        header[at++] = static_cast<std::uint8_t>(size & 0xffU);
    } else {
        header[1] = static_cast<std::uint8_t>(mask_bit | 127U);
        const auto length = static_cast<std::uint64_t>(size);
        for (int shift = 56; shift >= 0; shift -= 8) {
            header[at++] = static_cast<std::uint8_t>((length >> shift) & 0xffU);
        }
    }
    if (mask) {
        std::copy(masking_key.begin(), masking_key.end(), header.begin() + at);
        at += masking_key.size();
    }
    out.insert(out.end(), header.begin(), header.begin() + at);
    const std::size_t payload_at = out.size();
    out.insert(out.end(), payload.first.begin(), payload.first.end());
    out.insert(out.end(), payload.second.begin(), payload.second.end());
    if (mask) ApplyWebSocketMask(out.data() + payload_at, size, masking_key);
}

void WebSocketCodec::EncodeBinary(WebSocketBytes& out,
                                  WebSocketPayload payload) {
    if (closed_) {
        throw std::runtime_error("WebSocket is closed");
    }
    EncodeFrame(out, 0x2, payload);
}

void WebSocketCodec::EncodeBinaryFragmented(WebSocketBytes& out,
                                            WebSocketPayload payload,
                                            std::size_t first_fragment_bytes) {
    if (closed_) throw std::runtime_error("WebSocket is closed");
    const std::size_t size = payload.size();
    if (first_fragment_bytes == 0 || first_fragment_bytes >= size) {
        throw std::runtime_error("invalid WebSocket binary fragmentation split");
    }
    const std::size_t before = out.size();
    ReserveFor(out, FrameBytes(first_fragment_bytes) +
                        FrameBytes(size - first_fragment_bytes));
    EncodeFrame(out, 0x2, payload.part(0, first_fragment_bytes), false);
    try {
        EncodeFrame(
            out, 0x0,
            payload.part(first_fragment_bytes, size - first_fragment_bytes),
            true);
    } catch (...) {
        out.resize(before);
        throw;
    }
}

void WebSocketCodec::EncodePing(WebSocketBytes& out, const std::uint8_t* data,
                                std::size_t size) {
    if (closed_) throw std::runtime_error("WebSocket is closed");
    if (size > 125) throw std::runtime_error("WebSocket PING exceeds 125 bytes");
    EncodeFrame(out, 0x9, WebSocketPayload{{data, size}, {}});
}

void WebSocketCodec::EncodeClose(WebSocketBytes& out, std::uint16_t code,
                                 std::string_view reason) {
    if (reason.size() > 123) {
        throw std::runtime_error("WebSocket close reason exceeds 123 bytes");
    }
    std::array<std::uint8_t, 125> payload{
        static_cast<std::uint8_t>((code >> 8) & 0xffU),
        static_cast<std::uint8_t>(code & 0xffU)};
    std::copy(reason.begin(), reason.end(), payload.begin() + 2);
    EncodeFrame(out, 0x8,
                WebSocketPayload{{payload.data(), 2 + reason.size()}, {}});
    close_sent_ = true;
}

void WebSocketCodec::Feed(const std::uint8_t* data, std::size_t size) {
    if (failed() || size == 0) {
        return;
    }
    if (size > kMaxPendingBytes - (inbound_.size() - inbound_offset_)) {
        Fail("WebSocket input buffer limit exceeded");
        return;
    }
    // Drop what earlier calls parsed, once, before appending.
    if (inbound_offset_ != 0) {
        inbound_.erase(
            inbound_.begin(),
            inbound_.begin() + static_cast<std::ptrdiff_t>(inbound_offset_));
        inbound_offset_ = 0;
    }
    inbound_.insert(inbound_.end(), data, data + size);
    Process();
    if (inbound_offset_ == inbound_.size()) {
        inbound_.clear();
        inbound_offset_ = 0;
        if (inbound_.capacity() > kRetainedInboundBytes) {
            WebSocketBytes().swap(inbound_);
        }
    }
}

void WebSocketCodec::Process() {
    while (!failed() && inbound_.size() - inbound_offset_ >= 2) {
        const std::uint8_t* const frame = inbound_.data() + inbound_offset_;
        const std::size_t available = inbound_.size() - inbound_offset_;
        const std::uint8_t first = frame[0];
        const std::uint8_t second = frame[1];
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
            if (available < 4) return;
            payload_size =
                (static_cast<std::uint16_t>(frame[2]) << 8) | frame[3];
            offset = 4;
            if (payload_size < 126) {
                Fail("non-minimal WebSocket length");
                return;
            }
        } else if (payload_size == 127) {
            if (available < 10) return;
            payload_size = ReadU64(frame + 2);
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
        if (available < total) return;

        std::array<std::uint8_t, 4> key{};
        if (masked) {
            std::copy_n(frame + offset, 4, key.begin());
            offset += 4;
        }
        // The frame is complete, so its payload is unmasked where it lies and
        // the input moves past it. inbound_ does not change again before the
        // next frame, so payload_data stays valid through the switch.
        std::uint8_t* const payload_data =
            inbound_.data() + inbound_offset_ + offset;
        const auto payload_length = static_cast<std::size_t>(payload_size);
        if (masked) ApplyWebSocketMask(payload_data, payload_length, key);
        std::uint8_t* const payload_end = payload_data + payload_length;
        inbound_offset_ += total;

        switch (opcode) {
            case 0x0:
                if (!fragmented_binary_) {
                    Fail("unexpected WebSocket continuation");
                    return;
                }
                if (payload_length >
                    max_inbound_binary_message_bytes_ - fragmented_.size()) {
                    Fail("fragmented WebSocket binary message exceeds "
                         "configured limit");
                    return;
                }
                fragmented_.insert(fragmented_.end(), payload_data,
                                   payload_end);
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
                    if (payload_length > kMaxPendingBytes - decoded_.size()) {
                        Fail("decoded WebSocket buffer limit exceeded");
                        return;
                    }
                    decoded_.insert(decoded_.end(), payload_data, payload_end);
                } else {
                    fragmented_.assign(payload_data, payload_end);
                    fragmented_binary_ = true;
                }
                break;
            case 0x8:
                if (payload_length == 1) {
                    Fail("invalid one-byte WebSocket close payload");
                    return;
                }
                closed_ = true;
                if (!close_sent_) {
                    EncodeFrame(
                        wire_replies_, 0x8,
                        WebSocketPayload{{payload_data, payload_length}, {}});
                    close_sent_ = true;
                }
                break;
            case 0x9:
                EncodeFrame(
                    wire_replies_, 0xA,
                    WebSocketPayload{{payload_data, payload_length}, {}});
                break;
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

WebSocketBytes WebSocketCodec::TakeWireReplies() {
    WebSocketBytes out;
    out.swap(wire_replies_);
    return out;
}

void WebSocketCodec::Fail(std::string reason) {
    if (error_.empty()) error_ = std::move(reason);
}

}  // namespace yume::obfs
