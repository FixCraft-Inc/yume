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
#include <vector>

#include "engine/route_provider.hpp"
#include "engine/status.hpp"

// Bounded RFC 1928 message handling for the local SOCKS5 adapter. The listener
// is loopback-only by configuration, so only the no-authentication method is
// offered. CONNECT and UDP ASSOCIATE are supported, BIND is not.
namespace yume::runtime::socks5 {

inline constexpr std::uint8_t kVersion = 0x05;
inline constexpr std::uint8_t kMethodNoAuthentication = 0x00;
inline constexpr std::uint8_t kMethodNotAcceptable = 0xff;
// VER, NMETHODS and at most 255 methods.
inline constexpr std::size_t kMaxGreetingBytes = 257U;
// VER, CMD, RSV, ATYP, a length-prefixed 255-byte name and the port.
inline constexpr std::size_t kMaxRequestBytes = 262U;
// RSV, FRAG, ATYP, a length-prefixed 255-byte name and the port.
inline constexpr std::size_t kMaxUdpHeaderBytes = 262U;

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

enum class Command : std::uint8_t {
    Connect,
    UdpAssociate,
};

struct Request final {
    // On NeedMore, the minimum input size needed for the next parsing step.
    std::size_t required_bytes{0U};
    std::size_t consumed{0U};
    // Any reply other than Succeeded is sent before closing.
    Reply reply{Reply::GeneralFailure};
    Command command{Command::Connect};
    // A successful CONNECT carries its TCP destination.
    std::optional<engine::RouteDestination> destination;
    // A successful UDP ASSOCIATE carries the UDP source port the client
    // announced, or zero when the first datagram will show it.
    std::uint16_t udp_source_port{0U};
};

// Host names are ASCII-lowercased, and an IP literal sent as a name becomes a
// numeric destination. UDP ASSOCIATE ignores the address its request names,
// because the relay only accepts datagrams from the TCP peer's own address.
// BIND completes with CommandNotSupported.
Parse parse_request(std::span<const std::uint8_t> input, Request& out) noexcept;

// One datagram a client sent to its UDP relay.
struct UdpDatagram final {
    engine::RouteDestination destination;
    std::size_t payload_offset{0U};
};

// Returns nullopt for a fragment, a malformed header, an unsupported name or a
// zero port. RFC 1928 lets a relay drop those silently.
std::optional<UdpDatagram> parse_udp_datagram(std::span<const std::uint8_t> datagram) noexcept;
// The header of a relayed reply. It names the destination the client
// addressed, in the same form, as the reply's source.
std::vector<std::uint8_t> udp_header(const engine::RouteDestination& source);

std::array<std::uint8_t, 2> method_reply(bool no_authentication) noexcept;
// BND.ADDR and BND.PORT are zero, so a local client learns nothing about the
// remote exit socket.
std::array<std::uint8_t, 10> reply(Reply code) noexcept;
// A successful UDP ASSOCIATE reply. BND names the local relay socket, which is
// where the client sends its datagrams.
std::vector<std::uint8_t> associate_reply(const engine::RouteDestination& relay);
// A refused OPEN or local failure as a SOCKS reply code.
Reply reply_for(const engine::Status& status) noexcept;

}  // namespace yume::runtime::socks5
