/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <functional>
#include <memory>

#include "common/ip_packet.hpp"
#include "engine/route_provider.hpp"

namespace yume::providers {

enum class IpPacketDirection { ToTunnel, FromTunnel };

// Validates a caller-owned IP device's packet I/O before it crosses a YTP packet
// stream. Compose with bridge_established_route after an authorized packet OPEN.
// There is no v2 bulk envelope: each underlying packet is one YTP PACKET.
//
// The caller must provide address policy for both directions, including assigned
// source/destination restrictions where needed. Before invoking policy, this
// adapter checks exact IPv4/IPv6 lengths, MTU and bounded option/extension
// chains. It rejects source routing, address-rewriting headers and opaque IPv6
// extensions that prevent inspection. Checksums, upper-layer protocols and
// fragment reassembly remain outside this adapter's contract. Policy refusal
// or exceptions fail closed.
// It does not attach a TUN, assign addresses, install routes/DNS or authorize OPEN.
// All operations and policy callbacks use the wrapped channel's context and
// cancellation contract; retained receive state survives adapter destruction.
class IpPacketChannel final : public engine::PacketChannel {
public:
    using AuthorizationPolicy = std::function<engine::Status(
        IpPacketDirection, const common::IpPacketInfo&)>;

    static engine::Result<std::unique_ptr<IpPacketChannel>> create(
        std::unique_ptr<engine::PacketChannel> channel,
        std::size_t mtu,
        AuthorizationPolicy authorization);

    IpPacketChannel(const IpPacketChannel&) = delete;
    IpPacketChannel& operator=(const IpPacketChannel&) = delete;
    ~IpPacketChannel() noexcept override;

    engine::ExecutorAffinity executor_affinity() const noexcept override;
    std::size_t max_packet_size() const noexcept override;
    void async_receive(engine::CancellationToken cancellation,
                       ReceiveCompletion completion) override;
    void async_send(engine::Buffer packet,
                    engine::CancellationToken cancellation,
                    SendCompletion completion) override;
    void cancel() noexcept override;
    void close() noexcept override;

private:
    struct State;
    explicit IpPacketChannel(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::providers
