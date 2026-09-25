/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "ytp/security.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                    std::size_t size) {
    using namespace yume::ytp1;
    if (size > kMaxAuthRecordSize + 1) return 0;
    const std::span<const std::uint8_t> input(data, size);
    if (const auto record = DecodeAuthRecord(input)) {
        // Unknown noncritical fields must survive; unknown critical fields,
        // duplicate IDs, reordered TLVs and wrong suite values must refuse.
        const auto encoded = EncodeAuthRecord(*record.value);
        if (!encoded || !std::equal(input.begin(), input.end(),
                                   encoded.value->begin(), encoded.value->end())) {
            __builtin_trap();
        }
    }
    return 0;
}
