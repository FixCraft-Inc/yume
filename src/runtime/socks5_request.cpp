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
using engine::RouteDestination;
using engine::Status;
using engine::StatusCode;

constexpr std::uint8_t kCommandConnect = 0x01;
constexpr std::uint8_t kAddressIpv4 = 0x01;
constexpr std::uint8_t kAddressName = 0x03;
constexpr std::uint8_t kAddressIpv6 = 0x04;

Parse complete(Request& out, std::size_t consumed, Reply reply) noexcept {
    out.consumed = consumed;
    out.reply = reply;
    out.destination.reset();
    return Parse::Complete;
}

std::optional<RouteDestination> take(Result<RouteDestination> result) {
    if (!result.ok()) return std::nullopt;
    return std::move(result).take_value();
}

std::optional<RouteDestination> destination_from_name(std::string_view text,
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
        return take(RouteDestination::dns_name(NetworkProtocol::Tcp, std::move(name), port));
    }
    if (address.is_v4()) {
        return take(RouteDestination::ipv4(NetworkProtocol::Tcp,
                                           address.to_v4().to_bytes(), port));
    }
    // A scope identifier has no place in a route destination.
    if (address.to_v6().scope_id() != 0U) return std::nullopt;
    return take(RouteDestination::ipv6(NetworkProtocol::Tcp,
                                       address.to_v6().to_bytes(), port));
}

}  // namespace

Parse parse_greeting(std::span<const std::uint8_t> input, Greeting& out) noexcept {
    if (input.size() < 2U) return Parse::NeedMore;
    if (input[0] != kVersion || input[1] == 0U) return Parse::Invalid;
    const std::size_t total = 2U + input[1];
    if (input.size() < total) return Parse::NeedMore;
    const auto methods = input.subspan(2U, input[1]);
    out.consumed = total;
    out.no_authentication = std::find(methods.begin(), methods.end(),
                                      kMethodNoAuthentication) != methods.end();
    return Parse::Complete;
}

Parse parse_request(std::span<const std::uint8_t> input, Request& out) noexcept {
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
        if (input.size() < 5U) return Parse::NeedMore;
        offset = 5U;
        length = input[4];
        if (length == 0U) return complete(out, offset, Reply::AddressNotSupported);
        break;
    default:
        return complete(out, offset, Reply::AddressNotSupported);
    }
    const std::size_t total = offset + length + 2U;
    if (input.size() < total) return Parse::NeedMore;
    if (input[1] != kCommandConnect) {
        return complete(out, total, Reply::CommandNotSupported);
    }
    const auto port = static_cast<std::uint16_t>(
        (static_cast<unsigned>(input[total - 2U]) << 8U) | input[total - 1U]);
    if (port == 0U) return complete(out, total, Reply::GeneralFailure);

    const auto address = input.subspan(offset, length);
    try {
        std::optional<RouteDestination> destination;
        if (input[3] == kAddressIpv4) {
            std::array<std::uint8_t, 4> bytes{};
            std::copy(address.begin(), address.end(), bytes.begin());
            destination = take(RouteDestination::ipv4(NetworkProtocol::Tcp, bytes, port));
        } else if (input[3] == kAddressIpv6) {
            std::array<std::uint8_t, 16> bytes{};
            std::copy(address.begin(), address.end(), bytes.begin());
            destination = take(RouteDestination::ipv6(NetworkProtocol::Tcp, bytes, port));
        } else {
            destination = destination_from_name(
                std::string_view(reinterpret_cast<const char*>(address.data()),
                                 address.size()),
                port);
        }
        if (!destination) return complete(out, total, Reply::AddressNotSupported);
        out.consumed = total;
        out.reply = Reply::Succeeded;
        out.destination = std::move(destination);
        return Parse::Complete;
    } catch (...) {
        return complete(out, total, Reply::GeneralFailure);
    }
}

std::array<std::uint8_t, 2> method_reply(bool no_authentication) noexcept {
    return {kVersion, no_authentication ? kMethodNoAuthentication : kMethodNotAcceptable};
}

std::array<std::uint8_t, 10> reply(Reply code) noexcept {
    return {kVersion, static_cast<std::uint8_t>(code), 0x00, kAddressIpv4,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
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
    // The server could not set up the route, or the local deadline expired.
    case StatusCode::Internal:
    case StatusCode::Cancelled:
        return Reply::HostUnreachable;
    default:
        return Reply::GeneralFailure;
    }
}

}  // namespace yume::runtime::socks5
