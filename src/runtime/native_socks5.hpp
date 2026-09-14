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
#include "engine/session_engine.hpp"
#include "engine/status.hpp"
#include "providers/asio_execution_context.hpp"

namespace yume::runtime {

struct NativeSocks5Limits final {
    std::size_t max_connections{256U};
    // The greeting and the request must both arrive within this time.
    std::chrono::milliseconds handshake_timeout{10'000};
    // Bounds one authenticated OPEN, including the server's route setup.
    std::chrono::milliseconds open_timeout{30'000};
};

// Returns the current active session, or null when none is available.
using NativeSessionSource = std::function<std::shared_ptr<engine::SessionEngine>()>;

// One loopback SOCKS5 listener. A CONNECT request becomes an authenticated
// byte-stream OPEN on the configured service. After the peer accepts it, the
// local socket and the stream are joined by the shared route bridge. Only the
// no-authentication method and CONNECT are offered. A request is refused when
// no session is active rather than queued.
//
// Creation, close and every callback run on the supplied single-runner
// context. The caller closes the adapter, calls finish() and drains. Bridged
// streams end with their session or either socket.
class NativeSocks5Adapter final {
public:
    static engine::Result<std::shared_ptr<NativeSocks5Adapter>> create(
        std::shared_ptr<providers::AsioExecutionContext> context,
        const config::v1::Socks5Adapter& adapter,
        NativeSessionSource sessions,
        NativeSocks5Limits limits = {});

    NativeSocks5Adapter(const NativeSocks5Adapter&) = delete;
    NativeSocks5Adapter& operator=(const NativeSocks5Adapter&) = delete;
    ~NativeSocks5Adapter() noexcept;

    boost::asio::ip::tcp::endpoint local_endpoint() const noexcept;
    // Stops accepting and closes every connection not yet handed to the bridge.
    void close() noexcept;

private:
    struct State;
    explicit NativeSocks5Adapter(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::runtime
