/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace yume::security {

// Best-effort compiler-resistant clearing for ordinary byte vectors. This
// reduces secret lifetime in retained vector capacity; it is not a locked-page
// secure allocator and does not erase copies made elsewhere.
inline void secure_erase(std::vector<std::uint8_t>& bytes) noexcept {
    volatile std::uint8_t* cursor = bytes.data();
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        cursor[i] = 0;
    }
    bytes.clear();
}

}  // namespace yume::security
