/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "stealth/websocket_codec.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>

// The WebSocket framing a peer sends inside an admitted HTTP/2 stream, before
// YTP/1 authenticates it. The input picks the role and the message limit,
// then holds chunks, each behind one length byte, so frame headers split
// across Feed calls are reached too.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    using namespace yume::obfs;
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
    return 0;
}
