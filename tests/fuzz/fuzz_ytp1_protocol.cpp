/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "ytp/protocol.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace {

using namespace yume::ytp1;

void check_encoding(std::span<const std::uint8_t> input,
                    std::span<const std::uint8_t> encoded) {
    // Accepted wire encodings are canonical, including reserved bits and
    // field order. Re-encoding must preserve every input byte.
    if (!std::equal(input.begin(), input.end(), encoded.begin(), encoded.end())) {
        __builtin_trap();
    }
}

void check_payload(std::span<const std::uint8_t> input) {
    if (const auto open = DecodeOpen(input)) {
        const auto encoded = EncodeOpen(*open.value);
        if (!encoded) __builtin_trap();
        check_encoding(input, *encoded.value);
    }

    const auto manifest = DecodeCapabilityManifest(input);
    const auto validated = ValidateCapabilityManifestEncoding(input);
    if (manifest.ok() != validated.ok()) __builtin_trap();
    if (manifest) {
        const auto encoded = EncodeCapabilityManifest(*manifest.value);
        if (!encoded) __builtin_trap();
        check_encoding(input, *encoded.value);
    }

    if (const auto credit = DecodeCreditUpdate(input)) {
        const auto encoded = EncodeCreditUpdate(*credit.value);
        if (!encoded) __builtin_trap();
        check_encoding(input, *encoded.value);
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                    std::size_t size) {
    // Include one byte beyond the public limit to exercise refusal without
    // letting arbitrary fuzzer inputs create unbounded work.
    if (size > kDefaultMaxFramePayload + kFrameHeaderSize + 1) return 0;
    const std::span<const std::uint8_t> input(data, size);

    if (const auto header = DecodeFrameHeader(input)) {
        std::array<std::uint8_t, kFrameHeaderSize> encoded{};
        if (!EncodeFrameHeader(*header.value, encoded)) __builtin_trap();
        check_encoding(input, encoded);
    }
    if (const auto record = DecodeRecord(input)) {
        std::array<std::uint8_t, kFrameHeaderSize> encoded{};
        if (!EncodeFrameHeader(record.value->header, encoded)) __builtin_trap();
        check_encoding(input.first(kFrameHeaderSize), encoded);
        if (record.value->payload.size() != record.value->header.payload_length) {
            __builtin_trap();
        }
        check_payload(record.value->payload);
    }
    // Direct payload seeds reach OPEN/capability/credit parsing independently
    // of the outer record header, while records exercise their composition.
    check_payload(input);
    return 0;
}
