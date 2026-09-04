/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>

namespace yume::engine {

enum class EndpointRole : std::uint8_t {
    Client,
    Server,
};

enum class ServiceKind : std::uint8_t {
    ByteStream,
    PacketChannel,
};

class ExecutorAffinity final {
public:
    constexpr ExecutorAffinity() noexcept = default;
    explicit constexpr ExecutorAffinity(std::uint64_t value) noexcept
        : value_(value) {}

    constexpr bool valid() const noexcept { return value_ != 0U; }
    constexpr std::uint64_t value() const noexcept { return value_; }

    friend constexpr bool operator==(ExecutorAffinity,
                                     ExecutorAffinity) noexcept = default;

private:
    std::uint64_t value_{0U};
};

}  // namespace yume::engine
