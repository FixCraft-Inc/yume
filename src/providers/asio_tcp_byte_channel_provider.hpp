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

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/local/stream_protocol.hpp>

#include "engine/byte_channel.hpp"
#include "providers/asio_execution_context.hpp"
#include "providers/system_resolver.hpp"

namespace yume::providers {

inline constexpr std::string_view kAsioTcpByteChannelProviderId = "asio-tcp";
inline constexpr std::uint32_t kAsioTcpByteChannelProviderApiVersion = 1U;

// Native I/O shares one caller-owned execution context. Async initiation must
// occur on that context; wrong-affinity initiation throws before acceptance.
// Admission failures may complete inline on the context. shutdown_write()
// returns FailedPrecondition for wrong affinity, preserving its noexcept API.
// cancel()/close() remain callable from other threads and use reserved control
// dispatch. Keep the context running until channel and operation cleanup drains.
using AsioTcpSocket = boost::asio::basic_stream_socket<
    boost::asio::ip::tcp, AsioExecutionContext::Executor>;
using AsioUnixSocket = boost::asio::basic_stream_socket<
    boost::asio::local::stream_protocol, AsioExecutionContext::Executor>;

// Provider-local bounds apply even when this source-level provider is embedded
// without the included runtime. Queue byte limits include every accepted
// operation until completion.
struct AsioTcpChannelLimits {
    std::size_t max_active_channels{1024U};
    std::size_t max_read_bytes{64U * 1024U};
    std::size_t max_write_bytes{64U * 1024U};
    std::size_t max_queued_read_operations{64U};
    std::size_t max_queued_write_operations{64U};
    std::size_t max_queued_read_bytes{1024U * 1024U};
    std::size_t max_queued_write_bytes{1024U * 1024U};
};

struct AsioTcpByteChannelLimits final : AsioTcpChannelLimits {
    std::size_t max_pending_creates{32U};
    // The system resolver returns at most resolver_protocol::kMaxAddresses.
    std::size_t max_resolved_endpoints{32U};
    std::size_t max_connect_attempts{16U};
    std::chrono::milliseconds resolve_timeout{10'000};
    // One deadline covers every bounded endpoint attempt, rather than granting
    // a fresh attacker-controlled delay for each DNS result.
    std::chrono::milliseconds connect_timeout{10'000};
};

// Bounded ownership for connected TCP or UNIX stream sockets that a listener
// accepted or a caller connected. Adopted channels use the same queue,
// cancellation, half-close, and cleanup implementation as client-created
// channels. The owner contains no listener, remote-host, resolver, or
// connection policy.
// Channels retain their own lifetime after owner destruction, which cancels
// current operations without closing those channels.
class AsioTcpAcceptedChannelOwner final {
public:
    static engine::Result<std::shared_ptr<AsioTcpAcceptedChannelOwner>> create(
        std::shared_ptr<AsioExecutionContext> context,
        AsioTcpChannelLimits limits = {});

    AsioTcpAcceptedChannelOwner(const AsioTcpAcceptedChannelOwner&) = delete;
    AsioTcpAcceptedChannelOwner& operator=(
        const AsioTcpAcceptedChannelOwner&) = delete;
    ~AsioTcpAcceptedChannelOwner() noexcept;

    // Consumes one already-connected, exclusively owned socket with no pending
    // operations. Closed, unconnected, or differently-executed sockets fail
    // closed and are not published. Adoption is synchronous and may occur outside
    // the execution context when the socket has no concurrent users.
    engine::Result<std::unique_ptr<engine::ByteChannel>> adopt(
        AsioTcpSocket socket);
    engine::Result<std::unique_ptr<engine::ByteChannel>> adopt(
        AsioUnixSocket socket);

    // Cancels current channel operations without closing the channels or
    // preventing later adoption.
    void cancel() noexcept;

    engine::ExecutorAffinity executor_affinity() const noexcept;
    const AsioTcpChannelLimits& limits() const noexcept;

private:
    class Impl;
    explicit AsioTcpAcceptedChannelOwner(std::shared_ptr<Impl> impl) noexcept;

    std::shared_ptr<Impl> impl_;
};

// Invoked after a native TCP socket is open and before connect is attempted.
// The callback must not retain the borrowed handle. Exceptions are contained
// and fail the create operation closed.
using AsioTcpSocketProtector =
    std::function<engine::Status(std::uintptr_t native_handle)>;

class AsioTcpByteChannelProvider final : public engine::ByteChannelProvider {
public:
    // A numeric remote_host is dialed directly. A hostname needs a resolver
    // on the same context, and creation refuses one without it. The provider
    // cancels its lookups but does not close the shared resolver.
    static engine::Result<std::shared_ptr<AsioTcpByteChannelProvider>> create(
        std::shared_ptr<AsioExecutionContext> context,
        std::string remote_host,
        std::uint16_t remote_port,
        AsioTcpByteChannelLimits limits = {},
        AsioTcpSocketProtector socket_protector = {},
        std::shared_ptr<SystemResolver> resolver = {});

    AsioTcpByteChannelProvider(const AsioTcpByteChannelProvider&) = delete;
    AsioTcpByteChannelProvider& operator=(
        const AsioTcpByteChannelProvider&) = delete;
    ~AsioTcpByteChannelProvider() noexcept override;

    const engine::ProviderDescriptor& descriptor() const noexcept override;
    // Requires the supplied context; wrong affinity throws before admission.
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
