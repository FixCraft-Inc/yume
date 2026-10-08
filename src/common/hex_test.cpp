/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "common/hex.hpp"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace {

using yume::encoding::decode_lower_hex;
using yume::encoding::hex_lower;
using yume::encoding::is_lower_hex;

void test_encode() {
    const std::array<std::uint8_t, 0> empty{};
    const std::array<std::uint8_t, 5> vector{0x00, 0x01, 0x0f, 0x10, 0xff};

    const std::string empty_encoded = hex_lower(empty);
    const std::string vector_encoded = hex_lower(vector);

    assert(empty_encoded.empty());
    assert(vector_encoded == "00010f10ff");
    assert(vector_encoded.size() == vector.size() * 2U);

    const std::array<std::byte, 3> bytes{std::byte{0xa5}, std::byte{0x00},
                                         std::byte{0x7e}};
    assert(hex_lower(bytes) == "a5007e");
}

static_assert(is_lower_hex(""));
static_assert(is_lower_hex("0123456789abcdef"));
static_assert(!is_lower_hex("ABCDEF"));
static_assert(!is_lower_hex("0g"));
static_assert(!is_lower_hex(" 0"));
static_assert(!is_lower_hex(std::string_view("0\0", 2)));

void test_decode() {
    std::array<std::uint8_t, 5> out{};
    assert(decode_lower_hex("00010f10ff", out));
    assert((out == std::array<std::uint8_t, 5>{0x00, 0x01, 0x0f, 0x10, 0xff}));

    std::array<std::byte, 2> bytes{};
    assert(decode_lower_hex("a57e", bytes));
    assert(bytes[0] == std::byte{0xa5} && bytes[1] == std::byte{0x7e});

    std::array<std::uint8_t, 0> none{};
    assert(decode_lower_hex("", none));
    assert(!decode_lower_hex("00", none));
}

// A refused text leaves the output as it was, whatever position fails.
void test_decode_refuses_without_writing() {
    const std::array<std::uint8_t, 3> before{0x11, 0x22, 0x33};
    for (const char* text : {"0000", "00000000", "00000g", "g00000", "0000F0",
                             "0000:0", "0000/0", "0000`0"}) {
        auto out = before;
        assert(!decode_lower_hex(text, out));
        assert(out == before);
    }
}

}  // namespace

int main() {
    test_encode();
    test_decode();
    test_decode_refuses_without_writing();
    return 0;
}
