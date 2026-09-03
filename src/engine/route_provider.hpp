/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>

#include "engine/byte_channel.hpp"
#include "engine/secure_channel.hpp"
#include "engine/stream_id.hpp"

namespace yume::engine {

inline constexpr std::size_t kMaxRouteHostBytes = 255U;
inline constexpr std::size_t kMaxRouteDnsNameBytes = 253U;

enum class NetworkProtocol : std::uint8_t {
    Tcp,
    Udp,
};

enum class RouteAddressKind : std::uint8_t {
    Ipv4,
    Ipv6,
    DnsName,
};

class RouteDestination final {
public:
    static Result<RouteDestination> ipv4(
        NetworkProtocol protocol,
        std::array<std::uint8_t, 4> address,
        std::uint16_t port);
    static Result<RouteDestination> ipv6(
        NetworkProtocol protocol,
        std::array<std::uint8_t, 16> address,
        std::uint16_t port);
    static Result<RouteDestination> dns_name(NetworkProtocol protocol,
                                             std::string name,
                                             std::uint16_t port);

    NetworkProtocol protocol() const noexcept { return protocol_; }
    RouteAddressKind address_kind() const noexcept { return address_kind_; }
    std::span<const std::uint8_t> address_bytes() const noexcept {
        return std::span<const std::uint8_t>(address_).first(address_length_);
    }
    std::string_view dns_name() const noexcept { return dns_name_; }
    std::uint16_t port() const noexcept { return port_; }

private:
    RouteDestination(NetworkProtocol protocol,
                     RouteAddressKind address_kind,
                     std::array<std::uint8_t, 16> address,
                     std::uint8_t address_length,
                     std::string dns_name,
                     std::uint16_t port) noexcept;

    NetworkProtocol protocol_;
    RouteAddressKind address_kind_;
    std::array<std::uint8_t, 16> address_{};
    std::uint8_t address_length_{0U};
    std::string dns_name_;
    std::uint16_t port_{0U};
};

class PacketChannel {
public:
    using ReceiveCompletion = std::function<void(Result<Buffer>)>;
    using SendCompletion = std::function<void(Status, std::size_t)>;

    virtual ~PacketChannel() = default;
    virtual ExecutorAffinity executor_affinity() const noexcept = 0;
    virtual std::size_t max_packet_size() const noexcept = 0;
    virtual void async_receive(CancellationToken cancellation,
                               ReceiveCompletion completion) = 0;
    virtual void async_send(Buffer packet,
                            CancellationToken cancellation,
                            SendCompletion completion) = 0;
    virtual void cancel() noexcept = 0;
    virtual void close() noexcept = 0;
};

class SessionEngine;

// Only SessionEngine can construct an AuthorizedRouteRequest. A RouteProvider
// therefore cannot be invoked through the supported API until the dispatcher
// has authenticated the peer and authorized the named service/destination.
class AuthorizedRouteRequest final {
public:
    AuthorizedRouteRequest(const AuthorizedRouteRequest&) = default;
    AuthorizedRouteRequest& operator=(const AuthorizedRouteRequest&) = default;
    AuthorizedRouteRequest(AuthorizedRouteRequest&&) noexcept = default;
    AuthorizedRouteRequest& operator=(AuthorizedRouteRequest&&) noexcept = default;

    StreamId stream_id() const noexcept { return stream_id_; }
    const std::string& service_name() const noexcept { return service_name_; }
    const PeerEvidence& peer_evidence() const noexcept {
        return peer_evidence_;
    }
    const RouteDestination& destination() const noexcept {
        return destination_;
    }

private:
    friend class SessionEngine;
    AuthorizedRouteRequest(StreamId stream_id,
                           std::string service_name,
                           PeerEvidence peer_evidence,
                           RouteDestination destination) noexcept;

    StreamId stream_id_;
    std::string service_name_;
    PeerEvidence peer_evidence_;
    RouteDestination destination_;
};

class RouteConnection final {
public:
    static Result<RouteConnection> byte_stream(
        std::unique_ptr<ByteChannel> channel);
    static Result<RouteConnection> packet_channel(
        std::unique_ptr<PacketChannel> channel);

    RouteConnection(const RouteConnection&) = delete;
    RouteConnection& operator=(const RouteConnection&) = delete;
    RouteConnection(RouteConnection&&) noexcept = default;
    RouteConnection& operator=(RouteConnection&&) noexcept = default;

    ServiceKind kind() const noexcept { return kind_; }
    ByteChannel* byte_channel_if() noexcept { return byte_channel_.get(); }
    PacketChannel* packet_channel_if() noexcept { return packet_channel_.get(); }
    std::unique_ptr<ByteChannel> take_byte_channel() noexcept {
        return std::move(byte_channel_);
    }
    std::unique_ptr<PacketChannel> take_packet_channel() noexcept {
        return std::move(packet_channel_);
    }

private:
    explicit RouteConnection(std::unique_ptr<ByteChannel> channel) noexcept;
    explicit RouteConnection(std::unique_ptr<PacketChannel> channel) noexcept;

    ServiceKind kind_;
    std::unique_ptr<ByteChannel> byte_channel_;
    std::unique_ptr<PacketChannel> packet_channel_;
};

class RouteProvider {
public:
    using Completion = std::function<void(Result<RouteConnection>)>;

    virtual ~RouteProvider() = default;
    virtual const ProviderDescriptor& descriptor() const noexcept = 0;
    virtual void async_open(const AuthorizedRouteRequest& request,
                            CancellationToken cancellation,
                            Completion completion) = 0;
    virtual void cancel() noexcept = 0;
};

}  // namespace yume::engine
