/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "engine/route_provider.hpp"
#include "engine/status.hpp"

// Bounded RFC 1928 message handling for the local SOCKS5 adapter. The listener
// is loopback-only by configuration, so only the no-authentication method is
// offered. Only CONNECT is supported.
namespace yume::runtime::socks5 {

inline constexpr std::uint8_t kVersion = 0x05;
inline constexpr std::uint8_t kMethodNoAuthentication = 0x00;
inline constexpr std::uint8_t kMethodNotAcceptable = 0xff;
// VER, NMETHODS and at most 255 methods.
inline constexpr std::size_t kMaxGreetingBytes = 257U;
// VER, CMD, RSV, ATYP, a length-prefixed 255-byte name and the port.
inline constexpr std::size_t kMaxRequestBytes = 262U;

enum class Reply : std::uint8_t {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    NotAllowed = 0x02,
    HostUnreachable = 0x04,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressNotSupported = 0x08,
};

enum class Parse : std::uint8_t {
    NeedMore,
    Complete,
    // Not SOCKS5. The connection closes without a reply.
    Invalid,
};

struct Greeting final {
    // On NeedMore, the minimum input size needed for the next parsing step.
    std::size_t required_bytes{0U};
    std::size_t consumed{0U};
    bool no_authentication{false};
};

Parse parse_greeting(std::span<const std::uint8_t> input, Greeting& out) noexcept;

struct Request final {
    // On NeedMore, the minimum input size needed for the next parsing step.
    std::size_t required_bytes{0U};
    std::size_t consumed{0U};
    // Succeeded carries a TCP destination. Any other reply is sent before
    // closing.
    Reply reply{Reply::GeneralFailure};
    std::optional<engine::RouteDestination> destination;
};

// Host names are ASCII-lowercased, and an IP literal sent as a name becomes a
// numeric destination. BIND and UDP ASSOCIATE complete with
// CommandNotSupported.
Parse parse_request(std::span<const std::uint8_t> input, Request& out) noexcept;

std::array<std::uint8_t, 2> method_reply(bool no_authentication) noexcept;
// BND.ADDR and BND.PORT are zero, so a local client learns nothing about the
// remote exit socket.
std::array<std::uint8_t, 10> reply(Reply code) noexcept;
// A refused OPEN or local failure as a SOCKS reply code.
Reply reply_for(const engine::Status& status) noexcept;

}  // namespace yume::runtime::socks5
