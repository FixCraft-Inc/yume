/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

namespace yume::server {

inline std::uint32_t json_positive_u32(const nlohmann::json& json,
                                       const char* key) {
    const auto& entry = json.at(key);
    if (!entry.is_number_integer() && !entry.is_number_unsigned()) {
        throw std::invalid_argument(std::string(key) + " must be a positive integer");
    }
    const auto value = entry.get<std::int64_t>();
    if (value <= 0 ||
        static_cast<std::uint64_t>(value) >
            std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument(
            std::string(key) + " must be in the range 1..4294967295");
    }
    return static_cast<std::uint32_t>(value);
}

}  // namespace yume::server
