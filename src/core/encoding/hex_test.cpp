/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/encoding/hex.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <string>

int main() {
    const std::array<std::uint8_t, 0> empty{};
    const std::array<std::uint8_t, 5> vector{0x00, 0x01, 0x0f, 0x10, 0xff};

    const std::string empty_encoded = yume::encoding::hex_lower(empty);
    const std::string vector_encoded = yume::encoding::hex_lower(vector);

    assert(empty_encoded.empty());
    assert(vector_encoded == "00010f10ff");
    assert(vector_encoded.size() == vector.size() * 2U);
    return 0;
}
