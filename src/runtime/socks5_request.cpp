/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/socks5_request.hpp"

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>

#include <boost/asio/ip/address.hpp>

namespace yume::runtime::socks5 {
namespace {
using engine::NetworkProtocol;
using engine::Result;
using engine::RouteAddressKind;
using engine::RouteDestination;
using engine::Status;
using engine::StatusCode;

constexpr std::uint8_t kCommandConnect = 0x01;
constexpr std::uint8_t kCommandUdpAssociate = 0x03;
constexpr std::uint8_t kAddressIpv4 = 0x01;
constexpr std::uint8_t kAddressName = 0x03;
constexpr std::uint8_t kAddressIpv6 = 0x04;

Parse complete(Request& out, std::size_t consumed, Reply reply) noexcept {
    out.consumed = consumed;
    out.reply = reply;
    out.command = Command::Connect;
    out.destination.reset();
    out.udp_source_port = 0U;
    return Parse::Complete;
}

std::optional<RouteDestination> take(Result<RouteDestination> result) {
    if (!result.ok()) return std::nullopt;
    return std::move(result).take_value();
}

std::uint16_t read_port(std::span<const std::uint8_t> bytes) noexcept {
    return static_cast<std::uint16_t>((static_cast<unsigned>(bytes[0]) << 8U) | bytes[1]);
}

std::optional<RouteDestination> destination_from_name(NetworkProtocol protocol,
                                                      std::string_view text,
                                                      std::uint16_t port) {
    std::string name(text);
    for (char& ch : name) {
        const auto byte = static_cast<unsigned char>(ch);
        if (byte < 0x21U || byte > 0x7eU) return std::nullopt;
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    }
    // Boost resolves an unknown interface name to scope 0, which would turn a
    // scoped literal into an unscoped destination.
    if (name.find('%') != std::string::npos) return std::nullopt;
    boost::system::error_code error;
    const auto address = boost::asio::ip::make_address(name, error);
    if (error) {
        return take(RouteDestination::dns_name(protocol, std::move(name), port));
    }
    if (address.is_v4()) {
        return take(RouteDestination::ipv4(protocol, address.to_v4().to_bytes(), port));
    }
    // A scope identifier has no place in a route destination.
    if (address.to_v6().scope_id() != 0U) return std::nullopt;
    return take(RouteDestination::ipv6(protocol, address.to_v6().to_bytes(), port));
}

// Decodes a complete address field of the given SOCKS5 type. Throws
// std::bad_alloc.
std::optional<RouteDestination> decode_destination(NetworkProtocol protocol,
                                                   std::uint8_t type,
                                                   std::span<const std::uint8_t> address,
                                                   std::uint16_t port) {
    if (type == kAddressIpv4) {
        std::array<std::uint8_t, 4> bytes{};
        std::copy(address.begin(), address.end(), bytes.begin());
        return take(RouteDestination::ipv4(protocol, bytes, port));
    }
    if (type == kAddressIpv6) {
        std::array<std::uint8_t, 16> bytes{};
        std::copy(address.begin(), address.end(), bytes.begin());
        return take(RouteDestination::ipv6(protocol, bytes, port));
    }
    return destination_from_name(
        protocol,
        std::string_view(reinterpret_cast<const char*>(address.data()), address.size()),
        port);
}

void append_address(std::vector<std::uint8_t>& out, const RouteDestination& destination) {
    switch (destination.address_kind()) {
    case RouteAddressKind::Ipv4:
        out.push_back(kAddressIpv4);
        break;
    case RouteAddressKind::Ipv6:
        out.push_back(kAddressIpv6);
        break;
    case RouteAddressKind::DnsName:
        // RouteDestination bounds names to 253 bytes.
        out.push_back(kAddressName);
        out.push_back(static_cast<std::uint8_t>(destination.dns_name().size()));
        out.insert(out.end(), destination.dns_name().begin(), destination.dns_name().end());
        break;
    }
    const auto address = destination.address_bytes();
    out.insert(out.end(), address.begin(), address.end());
    out.push_back(static_cast<std::uint8_t>(destination.port() >> 8U));
    out.push_back(static_cast<std::uint8_t>(destination.port()));
}

}  // namespace

Parse parse_greeting(std::span<const std::uint8_t> input, Greeting& out) noexcept {
    out.required_bytes = 2U;
    if (input.size() < 2U) return Parse::NeedMore;
    if (input[0] != kVersion || input[1] == 0U) return Parse::Invalid;
    const std::size_t total = 2U + input[1];
    out.required_bytes = total;
    if (input.size() < total) return Parse::NeedMore;
    const auto methods = input.subspan(2U, input[1]);
    out.consumed = total;
    out.no_authentication = std::find(methods.begin(), methods.end(),
                                      kMethodNoAuthentication) != methods.end();
    return Parse::Complete;
}

Parse parse_request(std::span<const std::uint8_t> input, Request& out) noexcept {
    out.required_bytes = 4U;
    if (input.size() < 4U) return Parse::NeedMore;
    if (input[0] != kVersion || input[2] != 0U) return Parse::Invalid;
    std::size_t offset = 4U;
    std::size_t length = 0U;
    switch (input[3]) {
    case kAddressIpv4:
        length = 4U;
        break;
    case kAddressIpv6:
        length = 16U;
        break;
    case kAddressName:
        out.required_bytes = 5U;
        if (input.size() < 5U) return Parse::NeedMore;
        offset = 5U;
        length = input[4];
        if (length == 0U) return complete(out, offset, Reply::AddressNotSupported);
        break;
    default:
        return complete(out, offset, Reply::AddressNotSupported);
    }
    const std::size_t total = offset + length + 2U;
    out.required_bytes = total;
    if (input.size() < total) return Parse::NeedMore;
    const std::uint16_t port = read_port(input.subspan(total - 2U));
    if (input[1] == kCommandUdpAssociate) {
        complete(out, total, Reply::Succeeded);
        out.command = Command::UdpAssociate;
        out.udp_source_port = port;
        return Parse::Complete;
    }
    if (input[1] != kCommandConnect) {
        return complete(out, total, Reply::CommandNotSupported);
    }
    if (port == 0U) return complete(out, total, Reply::GeneralFailure);
    try {
        auto destination = decode_destination(NetworkProtocol::Tcp, input[3],
                                              input.subspan(offset, length), port);
        if (!destination) return complete(out, total, Reply::AddressNotSupported);
        // Not complete(): GCC 14 at -O3 reports the string inside a just-reset
        // optional as maybe uninitialized when it is move-assigned afterwards.
        out.consumed = total;
        out.reply = Reply::Succeeded;
        out.command = Command::Connect;
        out.udp_source_port = 0U;
        out.destination = std::move(destination);
        return Parse::Complete;
    } catch (...) {
        return complete(out, total, Reply::GeneralFailure);
    }
}

std::optional<UdpDatagram> parse_udp_datagram(std::span<const std::uint8_t> datagram) noexcept {
    // RSV is two zero bytes. A nonzero FRAG marks a fragment, and this relay
    // does not reassemble fragments.
    if (datagram.size() < 4U || datagram[0] != 0U || datagram[1] != 0U || datagram[2] != 0U) {
        return std::nullopt;
    }
    std::size_t offset = 4U;
    std::size_t length = 0U;
    switch (datagram[3]) {
    case kAddressIpv4:
        length = 4U;
        break;
    case kAddressIpv6:
        length = 16U;
        break;
    case kAddressName:
        if (datagram.size() < 5U || datagram[4] == 0U) return std::nullopt;
        offset = 5U;
        length = datagram[4];
        break;
    default:
        return std::nullopt;
    }
    const std::size_t payload_offset = offset + length + 2U;
    if (datagram.size() < payload_offset) return std::nullopt;
    const std::uint16_t port = read_port(datagram.subspan(payload_offset - 2U));
    if (port == 0U) return std::nullopt;
    try {
        auto destination = decode_destination(NetworkProtocol::Udp, datagram[3],
                                              datagram.subspan(offset, length), port);
        if (!destination) return std::nullopt;
        return UdpDatagram{std::move(*destination), payload_offset};
    } catch (...) {
        return std::nullopt;
    }
}

std::vector<std::uint8_t> udp_header(const RouteDestination& source) {
    std::vector<std::uint8_t> header{0x00, 0x00, 0x00};
    append_address(header, source);
    return header;
}

std::array<std::uint8_t, 2> method_reply(bool no_authentication) noexcept {
    return {kVersion, no_authentication ? kMethodNoAuthentication : kMethodNotAcceptable};
}

std::array<std::uint8_t, 10> reply(Reply code) noexcept {
    return {kVersion, static_cast<std::uint8_t>(code), 0x00, kAddressIpv4,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
}

std::vector<std::uint8_t> associate_reply(const RouteDestination& relay) {
    std::vector<std::uint8_t> bytes{kVersion, static_cast<std::uint8_t>(Reply::Succeeded), 0x00};
    append_address(bytes, relay);
    return bytes;
}

Reply reply_for(const Status& status) noexcept {
    switch (status.code()) {
    case StatusCode::Ok:
        return Reply::Succeeded;
    // An unauthorized or unsupported OPEN arrives as FailedPrecondition or
    // NotFound.
    case StatusCode::PermissionDenied:
    case StatusCode::FailedPrecondition:
    case StatusCode::NotFound:
        return Reply::NotAllowed;
    // The route failed or the OPEN was cancelled. The adapter reports its
    // own deadline separately, since cancellation alone does not imply expiry.
    case StatusCode::Internal:
    case StatusCode::Cancelled:
        return Reply::HostUnreachable;
    default:
        return Reply::GeneralFailure;
    }
}

}  // namespace yume::runtime::socks5
