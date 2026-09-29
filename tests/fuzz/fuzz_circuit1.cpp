/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "circuit/protocol.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

using namespace yume::circuit1;

// Every accepted encoding is canonical, so encoding what was decoded must
// give back the input exactly.
void same(std::span<const std::uint8_t> input,
          std::span<const std::uint8_t> encoded) {
    if (!std::equal(input.begin(), input.end(), encoded.begin(),
                    encoded.end())) {
        __builtin_trap();
    }
}

void check_begin(std::span<const std::uint8_t> payload) {
    if (const auto destination = DecodeBeginPayload(payload);
        destination.ok()) {
        const auto encoded = EncodeBeginPayload(*destination.value);
        if (!encoded.ok()) __builtin_trap();
        same(payload, *encoded.value);
    }
}

void check_relay(Direction direction, std::span<const std::uint8_t> input) {
    const auto message = DecodeRelayMessage(direction, input);
    if (!message.ok()) return;
    std::vector<std::uint8_t> encoded(input.size());
    if (!EncodeRelayMessage(direction, message.value->type,
                            message.value->stream, message.value->payload,
                            encoded)
             .ok()) {
        __builtin_trap();
    }
    same(input, encoded);
    if (message.value->type == RelayType::Begin)
        check_begin(message.value->payload);
    if (message.value->type == RelayType::Extend) {
        const auto extend = DecodeExtendPayload(message.value->payload);
        if (extend.ok()) {
            const auto again = EncodeExtendPayload(
                extend.value->next_identity,
                extend.value->client_handshake.first<kClientHandshakeBytes>());
            same(message.value->payload, again);
        }
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    // One byte past the largest cell exercises the size refusal.
    if (size > kBuckets[2] + 1U) return 0;
    const std::span<const std::uint8_t> input(data, size);

    if (const auto cell = DecodeCell(input); cell.ok()) {
        const auto encoded = EncodeCell(cell.value->command, cell.value->bucket,
                                        cell.value->body);
        if (!encoded.ok()) __builtin_trap();
        same(input, *encoded.value);
        // The cell decoder checks a CREATE body's size only, so its contents
        // take their own decoder.
        if (cell.value->command == Command::Create) {
            (void)DecodeCreate(cell.value->body);
        }
    }
    check_relay(Direction::Forward, input);
    check_relay(Direction::Backward, input);
    if (const auto client = DecodeClientHandshake(input); client.ok()) {
        same(input, EncodeClientHandshake(*client.value));
    }
    if (const auto hop = DecodeHopHandshake(input); hop.ok()) {
        same(input, EncodeHopHandshake(*hop.value));
    }
    if (const auto create = DecodeCreate(input); create.ok()) {
        const auto encoded = EncodeCreate(
            create.value->depth,
            create.value->client_handshake.first<kClientHandshakeBytes>());
        if (!encoded.ok()) __builtin_trap();
        same(input, *encoded.value);
    }
    check_begin(input);
    return 0;
}
