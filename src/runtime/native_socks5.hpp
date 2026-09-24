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
#include "runtime/native_session_source.hpp"

namespace yume::runtime {

struct NativeSocks5Limits final {
    // Local connections still in their handshake or holding a UDP association.
    // Accepting pauses at this count. Every local TCP socket, bridged CONNECT
    // streams included, also counts toward the same bound in the channel owner.
    std::size_t max_connections{256U};
    // The greeting and the request must both arrive within this time.
    std::chrono::milliseconds handshake_timeout{10'000};
    // Bounds one authenticated OPEN, including the server's route setup. For
    // CONNECT, expiry cancels the OPEN and replies with TTL expired (0x06). For
    // a UDP destination, expiry cancels the OPEN and starts the retry delay.
    std::chrono::milliseconds open_timeout{30'000};
    // Destinations one UDP association may use at once. Datagrams for another
    // destination are dropped until one of them closes.
    std::size_t max_udp_destinations{32U};
    // A UDP destination with no datagram in either direction for this long
    // closes and releases its stream.
    std::chrono::milliseconds udp_idle_timeout{60'000};
    // Datagrams to a UDP destination whose OPEN was refused, expired or ended
    // are dropped for this long before a new OPEN is tried.
    std::chrono::milliseconds udp_retry_delay{1'000};
};

// One loopback SOCKS5 listener offering only the no-authentication method.
//
// CONNECT becomes an authenticated byte-stream OPEN on the adapter's service.
// After the peer accepts it, the local socket and the stream are joined by the
// shared route bridge. When the adapter names a UDP service, UDP ASSOCIATE
// starts a NativeSocks5UdpAssociation that lasts as long as the client's TCP
// connection. Without one, UDP ASSOCIATE is refused as unsupported. BIND is
// always refused. A request made while no session is active is refused rather
// than queued.
//
// Creation, close and every callback run on the supplied single-runner
// context. The caller closes the adapter, calls finish() and drains. Bridged
// streams end with their session or either socket. on_stopped runs once after
// a listener failure that cannot be retried closes the adapter. Synchronous
// creation failure uses the returned status; explicit close does not notify.
class NativeSocks5Adapter final {
public:
    using Stopped = std::function<void(engine::Status)>;

    static engine::Result<std::shared_ptr<NativeSocks5Adapter>> create(
        std::shared_ptr<providers::AsioExecutionContext> context,
        const config::v1::Socks5Adapter& adapter,
        NativeSessionSource sessions,
        NativeSocks5Limits limits = {},
        Stopped on_stopped = {});

    NativeSocks5Adapter(const NativeSocks5Adapter&) = delete;
    NativeSocks5Adapter& operator=(const NativeSocks5Adapter&) = delete;
    ~NativeSocks5Adapter() noexcept;

    boost::asio::ip::tcp::endpoint local_endpoint() const noexcept;
    // Stops accepting and closes every connection not yet handed to the bridge,
    // including every UDP association.
    void close() noexcept;

private:
    struct State;
    explicit NativeSocks5Adapter(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::runtime
