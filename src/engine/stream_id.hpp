/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <optional>

#include "engine/status.hpp"
#include "engine/types.hpp"

namespace yume::engine {

// YTP/1 reserves stream zero for session control. Application stream IDs are
// 31-bit values: clients own odd IDs and servers own even IDs.
class StreamId final {
public:
    static constexpr std::uint32_t kMaxApplicationValue = 0x7fff'ffffU;

    static constexpr StreamId control() noexcept { return StreamId(0U); }

    static Result<StreamId> application(std::uint32_t value,
                                        EndpointRole owner);
    static Result<StreamId> peer_application(std::uint32_t value,
                                             EndpointRole local_role);

    constexpr std::uint32_t value() const noexcept { return value_; }
    constexpr bool is_control() const noexcept { return value_ == 0U; }
    constexpr bool owned_by(EndpointRole role) const noexcept {
        if (is_control()) {
            return false;
        }
        const bool odd = (value_ & 1U) != 0U;
        return role == EndpointRole::Client ? odd : !odd;
    }
    constexpr std::optional<EndpointRole> owner() const noexcept {
        if (is_control()) {
            return std::nullopt;
        }
        return (value_ & 1U) != 0U ? EndpointRole::Client
                                   : EndpointRole::Server;
    }

    friend constexpr bool operator==(StreamId, StreamId) noexcept = default;

private:
    explicit constexpr StreamId(std::uint32_t value) noexcept
        : value_(value) {}

    std::uint32_t value_{0U};
};

}  // namespace yume::engine
