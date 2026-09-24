/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>

#include <boost/asio/ip/tcp.hpp>

#include "config/v1/config.hpp"
#include "engine/status.hpp"
#include "providers/asio_execution_context.hpp"
#include "runtime/native_session_source.hpp"

namespace yume::runtime {

struct NativeForwardLimits final {
    // Local connections still waiting for their stream. Accepting pauses at
    // this count. Every local socket, bridged ones included, also counts
    // toward the same bound in the channel owner.
    std::size_t max_connections{256U};
    // Bounds one authenticated OPEN, including the server's route setup.
    // Expiry cancels the OPEN and closes the local connection.
    std::chrono::milliseconds open_timeout{30'000};
};

// One local listener that turns every connection into an authenticated
// byte-stream OPEN on the adapter's service. The OPEN carries the adapter's
// destination when it names one, and the server's policy for the service
// decides the rest. Once the peer accepts, the connection and the stream are
// joined by the shared route bridge. A connection made while no session is
// active, or whose OPEN is refused or expires, is closed. LocalListener owns
// the loopback and UNIX socket rules.
//
// Creation, close and every callback run on the supplied single-runner
// context. The caller closes the adapter, calls finish() and drains. Close
// ends bridged connections too. on_stopped runs once after a listener failure
// that cannot be retried closes the adapter. Synchronous creation failure uses
// the returned status. An explicit close does not notify.
class NativeForwardAdapter final {
public:
    using Stopped = std::function<void(engine::Status)>;

    static engine::Result<std::shared_ptr<NativeForwardAdapter>> create(
        std::shared_ptr<providers::AsioExecutionContext> context,
        const config::v1::ForwardAdapter& adapter,
        NativeSessionSource sessions,
        NativeForwardLimits limits = {},
        Stopped on_stopped = {});

    NativeForwardAdapter(const NativeForwardAdapter&) = delete;
    NativeForwardAdapter& operator=(const NativeForwardAdapter&) = delete;
    ~NativeForwardAdapter() noexcept;

    // The bound endpoint of a TCP listener, or a default endpoint.
    boost::asio::ip::tcp::endpoint local_endpoint() const noexcept;
    void close() noexcept;

private:
    struct State;
    explicit NativeForwardAdapter(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::runtime
