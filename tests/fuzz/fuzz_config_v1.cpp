/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "config/v1/config.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                    std::size_t size) {
    using namespace yume::config::v1;
    if (size > kMaxDocumentBytes + 1) return 0;
    const std::string_view input(reinterpret_cast<const char*>(data), size);
    try {
        // Both the structural guard and typed schema parser execute here.
        // ParseJson never opens credential paths or configures a runtime.
        (void)ParseJson(input);
    } catch (const ValidationError&) {
        // Typed rejection is the expected result for malformed documents.
        // Other exceptions remain findings instead of being hidden.
    }
    return 0;
}
