/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <memory>
#include <string_view>

#include "engine/route_provider.hpp"
#include "providers/asio_execution_context.hpp"

namespace yume::providers {

// One Linux IFF_TUN | IFF_NO_PI queue. This provider transfers complete device
// packets; IpPacketChannel owns IP validation and source/destination policy.
// It creates an ephemeral interface and sets its MTU, but never changes
// addresses, routes, DNS or firewall rules.
// The operator must keep interface namespace, name, flags and MTU unchanged
// until close. An MTU increase cannot silently truncate an accepted packet.
class LinuxTunPacketChannel final : public engine::PacketChannel {
public:
    // Create one new, nonpersistent TUN using TUN_EXCL. An existing name is an
    // error, never attached or changed. Names are exact, never kernel templates.
    // This operation requires the kernel's normal TUN creation capability and
    // sets/verifies MTU before publication. Failure closes the new device.
    // Creation is synchronous and may occur outside the executor.
    static engine::Result<std::unique_ptr<LinuxTunPacketChannel>> create(
        std::shared_ptr<AsioExecutionContext> context,
        std::string_view interface_name, std::size_t mtu);

    LinuxTunPacketChannel(const LinuxTunPacketChannel&) = delete;
    LinuxTunPacketChannel& operator=(const LinuxTunPacketChannel&) = delete;
    ~LinuxTunPacketChannel() noexcept override;

    std::string_view interface_name() const noexcept;
    unsigned int interface_index() const noexcept;
    engine::ExecutorAffinity executor_affinity() const noexcept override;
    std::size_t max_packet_size() const noexcept override;

    // Initiate on context; wrong affinity throws before acceptance. One receive
    // and one send may be pending. Admission failures complete inline. Every
    // accepted operation completes once on context, after releasing its slot.
    void async_receive(engine::CancellationToken cancellation,
                       ReceiveCompletion completion) override;
    void async_send(engine::Buffer packet, engine::CancellationToken cancellation,
                    SendCompletion completion) override;

    // Cross-thread, nonallocating requests. cancel() preserves the channel and
    // cancels currently accepted operations. A token cancels only its operation.
    // close() is terminal. Retain/run context through all completion drain.
    void cancel() noexcept override;
    void close() noexcept override;

private:
    struct State;
    explicit LinuxTunPacketChannel(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::providers
