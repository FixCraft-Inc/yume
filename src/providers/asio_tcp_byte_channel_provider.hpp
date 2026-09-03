/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include <boost/asio/any_io_executor.hpp>

#include "engine/byte_channel.hpp"

namespace yume::providers {

inline constexpr std::string_view kAsioTcpByteChannelProviderId = "asio-tcp";
inline constexpr std::uint32_t kAsioTcpByteChannelProviderApiVersion = 1U;

// Provider-local bounds apply even when this source-level provider is embedded
// without the included runtime. Queue byte limits include operations accepted
// by callers but not yet started on the provider strand.
struct AsioTcpByteChannelLimits final {
    std::size_t max_pending_creates{32U};
    std::size_t max_active_channels{1024U};
    std::size_t max_resolved_endpoints{32U};
    std::size_t max_connect_attempts{16U};
    std::size_t max_read_bytes{64U * 1024U};
    std::size_t max_write_bytes{64U * 1024U};
    std::size_t max_queued_read_operations{64U};
    std::size_t max_queued_write_operations{64U};
    std::size_t max_queued_read_bytes{1024U * 1024U};
    std::size_t max_queued_write_bytes{1024U * 1024U};
    std::chrono::milliseconds resolve_timeout{10'000};
    // One deadline covers every bounded endpoint attempt, rather than granting
    // a fresh attacker-controlled delay for each DNS result.
    std::chrono::milliseconds connect_timeout{10'000};
};

// Invoked after a native TCP socket is open and before connect is attempted.
// The callback must not retain the borrowed handle. Exceptions are contained
// and fail the create operation closed.
using AsioTcpSocketProtector =
    std::function<engine::Status(std::uintptr_t native_handle)>;

class AsioTcpByteChannelProvider final : public engine::ByteChannelProvider {
public:
    static engine::Result<std::shared_ptr<AsioTcpByteChannelProvider>> create(
        boost::asio::any_io_executor executor,
        engine::ExecutorAffinity executor_affinity,
        std::string remote_host,
        std::uint16_t remote_port,
        AsioTcpByteChannelLimits limits = {},
        AsioTcpSocketProtector socket_protector = {});

    AsioTcpByteChannelProvider(const AsioTcpByteChannelProvider&) = delete;
    AsioTcpByteChannelProvider& operator=(
        const AsioTcpByteChannelProvider&) = delete;
    ~AsioTcpByteChannelProvider() noexcept override;

    const engine::ProviderDescriptor& descriptor() const noexcept override;
    void async_create(engine::EndpointRole role,
                      engine::CancellationToken cancellation,
                      Completion completion) override;

    // Cancels creates and channel operations currently owned by this provider.
    // The provider remains reusable; later creates are admitted normally.
    void cancel() noexcept;

    engine::ExecutorAffinity executor_affinity() const noexcept;
    const std::string& remote_host() const noexcept;
    std::uint16_t remote_port() const noexcept;
    const AsioTcpByteChannelLimits& limits() const noexcept;

private:
    class Impl;
    explicit AsioTcpByteChannelProvider(std::shared_ptr<Impl> impl) noexcept;

    std::shared_ptr<Impl> impl_;
};

}  // namespace yume::providers
