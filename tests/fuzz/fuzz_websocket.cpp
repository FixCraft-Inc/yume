/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "stealth/websocket_codec.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace {

using namespace yume::obfs;

// What one role encodes, the other decodes to exactly the same bytes. The
// input is the payload, split into the two parts a sender may hand over, sent
// as one frame, as fragments or with a ping between two messages, and fed to
// the peer in pieces.
void check_round_trip(const std::uint8_t* data, std::size_t size) {
    const bool client_sends = (data[0] & 2U) != 0U;
    WebSocketCodec sender(client_sends ? WebSocketRole::Client : WebSocketRole::Server);
    WebSocketCodec receiver(client_sends ? WebSocketRole::Server : WebSocketRole::Client);
    const std::span<const std::uint8_t> payload(data + 2U, size - 2U);
    const std::size_t split = payload.empty() ? 0U : data[1] % (payload.size() + 1U);
    const WebSocketPayload parts{payload.first(split), payload.subspan(split)};
    WebSocketBytes wire;
    std::size_t expected = payload.size();
    const unsigned mode = (data[0] >> 2U) % 3U;
    if (mode == 1U && payload.size() >= 2U) {
        sender.EncodeBinaryFragmented(wire, parts, 1U + data[1] % (payload.size() - 1U));
    } else if (mode == 2U) {
        sender.EncodeBinary(wire, parts);
        sender.EncodePing(wire, payload.data(), std::min<std::size_t>(payload.size(), 125U));
        sender.EncodeBinary(wire, payload.data(), payload.size());
        std::string reason(std::min<std::size_t>(payload.size(), 123U), 'a');
        for (std::size_t index = 0U; index < reason.size(); ++index) {
            reason[index] = static_cast<char>('a' + payload[index] % 26U);
        }
        sender.EncodeClose(wire, 1000, reason);
        expected *= 2U;
    } else {
        sender.EncodeBinary(wire, parts);
        if (wire.size() != sender.FrameBytes(payload.size())) __builtin_trap();
    }
    WebSocketBytes received;
    const std::size_t step = 1U + data[1] % 61U;
    for (std::size_t offset = 0U; offset < wire.size(); offset += step) {
        receiver.Feed(wire.data() + offset, std::min(step, wire.size() - offset));
        const auto drain = receiver.TakeDrain();
        received.insert(received.end(), drain.tunnel_bytes.begin(), drain.tunnel_bytes.end());
    }
    if (receiver.failed() || received.size() != expected ||
        !std::equal(payload.begin(), payload.end(), received.begin())) {
        __builtin_trap();
    }
    if (expected != payload.size() &&
        (!receiver.closed() ||
         !std::equal(payload.begin(), payload.end(), received.begin() +
                     static_cast<std::ptrdiff_t>(payload.size())))) {
        __builtin_trap();
    }
}

}  // namespace

// The WebSocket framing a peer sends inside an admitted HTTP/2 stream, before
// YTP/1 authenticates it. The input picks the role and the message limit,
// then holds chunks, each behind one length byte, so frame headers split
// across Feed calls are reached too. The same bytes then make one round trip.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    if (size < 2U) return 0;
    const auto role =
        (data[0] & 1U) != 0U ? WebSocketRole::Server : WebSocketRole::Client;
    // A small limit reaches the size refusals with short inputs.
    WebSocketCodec codec(role, 1U + std::size_t{data[1]} * 257U);
    std::size_t fed = 0U;
    std::size_t drained = 0U;
    std::size_t offset = 2U;
    while (offset < size) {
        const std::size_t length =
            std::min<std::size_t>(1U + data[offset], size - offset - 1U);
        ++offset;
        codec.Feed(data + offset, length);
        fed += length;
        offset += length;
        // Every wire byte is either framing the codec retires at once or
        // payload handed back as tunnel bytes, never both and never more.
        const auto drain = codec.TakeDrain();
        drained +=
            drain.tunnel_bytes.size() + drain.immediately_consumable_wire_bytes;
        if (drained > fed) __builtin_trap();
        (void)codec.TakeWireReplies();
    }
    check_round_trip(data, size);
    return 0;
}
