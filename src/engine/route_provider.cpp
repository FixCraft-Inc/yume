/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "engine/route_provider.hpp"

#include <algorithm>
#include <array>
#include <new>
#include <span>
#include <utility>

namespace yume::engine {
namespace {

bool ascii_alphanumeric(char value) noexcept {
    const auto byte = static_cast<unsigned char>(value);
    return (byte >= 'a' && byte <= 'z') ||
           (byte >= '0' && byte <= '9');
}

bool valid_network_protocol(NetworkProtocol protocol) noexcept {
    switch (protocol) {
    case NetworkProtocol::Tcp:
    case NetworkProtocol::Udp:
        return true;
    }
    return false;
}

bool valid_dns_name(std::string_view name) noexcept {
    if (name.empty() || name.size() > kMaxRouteDnsNameBytes) {
        return false;
    }
    std::size_t start = 0U;
    while (start <= name.size()) {
        const std::size_t end = name.find('.', start);
        const std::string_view label = name.substr(
            start, end == std::string_view::npos ? name.size() - start
                                                 : end - start);
        if (label.empty() || label.size() > 63U ||
            !ascii_alphanumeric(label.front()) ||
            !ascii_alphanumeric(label.back()) ||
            !std::all_of(label.begin(), label.end(), [](char value) {
                return ascii_alphanumeric(value) || value == '-';
            })) {
            return false;
        }
        if (end == std::string_view::npos) {
            break;
        }
        start = end + 1U;
    }
    return true;
}

}  // namespace

RouteDestination::RouteDestination(NetworkProtocol protocol,
                                   RouteAddressKind address_kind,
                                   std::array<std::uint8_t, 16> address,
                                   std::uint8_t address_length,
                                   std::string dns_name,
                                   std::uint16_t port) noexcept
    : protocol_(protocol),
      address_kind_(address_kind),
      address_(address),
      address_length_(address_length),
      dns_name_(std::move(dns_name)),
      port_(port) {}

Result<RouteDestination> RouteDestination::ipv4(
    NetworkProtocol protocol,
    std::array<std::uint8_t, 4> address,
    std::uint16_t port) {
    if (!valid_network_protocol(protocol) || port == 0U) {
        return Result<RouteDestination>(Status(
            StatusCode::InvalidArgument,
            "route destination protocol or port is invalid"));
    }
    std::array<std::uint8_t, 16> storage{};
    std::copy(address.begin(), address.end(), storage.begin());
    return Result<RouteDestination>(RouteDestination(
        protocol, RouteAddressKind::Ipv4, storage, 4U, {}, port));
}

Result<RouteDestination> RouteDestination::ipv6(
    NetworkProtocol protocol,
    std::array<std::uint8_t, 16> address,
    std::uint16_t port) {
    if (!valid_network_protocol(protocol) || port == 0U) {
        return Result<RouteDestination>(Status(
            StatusCode::InvalidArgument,
            "route destination protocol or port is invalid"));
    }
    return Result<RouteDestination>(RouteDestination(
        protocol, RouteAddressKind::Ipv6, address, 16U, {}, port));
}

Result<RouteDestination> RouteDestination::dns_name(
    NetworkProtocol protocol,
    std::string name,
    std::uint16_t port) {
    if (!valid_network_protocol(protocol) || port == 0U ||
        !valid_dns_name(name)) {
        return Result<RouteDestination>(Status(
            StatusCode::InvalidArgument,
            "route destination DNS name, protocol, or port is invalid"));
    }
    return Result<RouteDestination>(RouteDestination(
        protocol, RouteAddressKind::DnsName, {}, 0U, std::move(name), port));
}

AuthorizedRouteRequest::AuthorizedRouteRequest(
    StreamId stream_id,
    std::string service_name,
    PeerEvidence peer_evidence,
    RouteDestination destination) noexcept
    : stream_id_(stream_id),
      service_name_(std::move(service_name)),
      peer_evidence_(std::move(peer_evidence)),
      destination_(std::move(destination)) {}

RouteConnection::RouteConnection(
    std::unique_ptr<ByteChannel> channel) noexcept
    : kind_(ServiceKind::ByteStream),
      byte_channel_(std::move(channel)) {}

RouteConnection::RouteConnection(
    std::unique_ptr<PacketChannel> channel) noexcept
    : kind_(ServiceKind::PacketChannel),
      packet_channel_(std::move(channel)) {}

Result<RouteConnection> RouteConnection::byte_stream(
    std::unique_ptr<ByteChannel> channel) {
    if (!channel) {
        return Result<RouteConnection>(Status(
            StatusCode::InvalidArgument,
            "byte-stream route channel must not be null"));
    }
    return Result<RouteConnection>(RouteConnection(std::move(channel)));
}

Result<RouteConnection> RouteConnection::packet_channel(
    std::unique_ptr<PacketChannel> channel) {
    if (!channel) {
        return Result<RouteConnection>(Status(
            StatusCode::InvalidArgument,
            "packet route channel must not be null"));
    }
    return Result<RouteConnection>(RouteConnection(std::move(channel)));
}

}  // namespace yume::engine
