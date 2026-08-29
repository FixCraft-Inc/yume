/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <system_error>

namespace yume::server {

enum class RuntimeSessionSelector : std::uint8_t {
    SessionId,
    EndpointId,
    ClientIp,
};

// Selectors are deliberately typed. A value that happens to equal another
// identity field must never disconnect that session through an unintended
// fallback match.
inline bool runtime_session_selector_matches(
        RuntimeSessionSelector selector,
        std::string_view value,
        std::uint64_t session_id,
        std::string_view endpoint_id,
        std::string_view client_ip) noexcept {
    switch (selector) {
        case RuntimeSessionSelector::SessionId: {
            std::array<char, 20> encoded{};
            const auto result = std::to_chars(
                encoded.data(), encoded.data() + encoded.size(), session_id);
            return result.ec == std::errc{} &&
                value == std::string_view(
                    encoded.data(),
                    static_cast<std::size_t>(result.ptr - encoded.data()));
        }
        case RuntimeSessionSelector::EndpointId:
            return value == endpoint_id;
        case RuntimeSessionSelector::ClientIp:
            return value == client_ip;
    }
    return false;
}

}  // namespace yume::server
