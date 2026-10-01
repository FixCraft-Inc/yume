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
#include <optional>
#include <string>

#include "engine/status.hpp"
#include "providers/asio_execution_context.hpp"
#include "runtime/device_nat.hpp"
#include "runtime/native_session_source.hpp"

namespace yume::runtime {

struct DeviceBridgeOptions final {
    // A TUN descriptor that reads and writes whole IP packets without a
    // packet-information header. The bridge duplicates it and sets it
    // non-blocking, and the caller keeps and closes its own.
    int descriptor{-1};
    // 576 to 65535, and at least 1280 with an IPv6 pair.
    std::size_t mtu{1500U};
    // The byte-stream service one OPEN per TCP connection uses.
    std::string stream_service;
    // The packet service one OPEN per UDP destination uses. Empty drops UDP.
    std::string packet_service;
    // At least one family. A family without addresses is dropped.
    std::optional<DeviceAddressPair> ipv4;
    std::optional<DeviceAddressPair> ipv6;
    // TCP connections open at once, waiting for their stream or joined to
    // it. Accepting pauses at this count.
    std::size_t max_connections{1024U};
    // OPENs the bridge has in flight at once. A connection beyond that waits
    // for a free one, so a burst of connections never passes the session's
    // own bound for pending OPENs, which would refuse them.
    std::size_t max_pending_opens{48U};
    // Bounds a connection from its accept until its stream is joined: the
    // wait for an OPEN and the OPEN itself, including the server's route
    // setup.
    std::chrono::milliseconds open_timeout{30'000};
    // UDP destinations one local port and the whole device reach at once.
    std::size_t max_port_destinations{32U};
    std::size_t max_destinations{512U};
    std::chrono::milliseconds udp_idle_timeout{60'000};
    // How long datagrams to a destination are dropped after its OPEN was
    // refused, expired or ended, before a new OPEN is tried.
    std::chrono::milliseconds udp_retry_delay{1'000};
};

// Carries what enters a TUN device as streams and datagrams on a client's
// services, the way its SOCKS5 adapter carries a local application's
// connections (docs/ABI.md, "Device bridge").
//
// TCP is terminated by the host's kernel: DeviceNat rewrites each segment so
// the kernel accepts the application's connection on a listener bound to the
// device's address, and the bridge joins that socket to a byte-stream OPEN
// carrying the original destination, through the same route bridge the
// forward and SOCKS5 adapters use. The listener closes a peer the translator
// does not know, so another local process cannot open streams through it. A
// connection made while no session is active is reset at once, and one whose
// OPEN is refused or expires is closed.
//
// UDP follows the SOCKS5 UDP association's rules: every destination of a
// local port gets its own authenticated packet OPEN, datagrams waiting for
// their stream share one budget of 64 datagrams and 1 MiB with drop-newest,
// and a reply the device cannot take at once is dropped. Each OPEN names an
// address, never a host name.
//
// Name lookups are the exception to one OPEN per local port. A resolver
// would otherwise get a new OPEN for every query, since each comes from a
// new port, and every lookup would wait for it. All datagrams to port 53 of
// one address share one OPEN instead: the bridge gives each query a DNS
// identifier of its own, random as the application's was, and returns the
// reply to the port that asked with the identifier it used.
//
// Creation, close and every callback run on the supplied single-runner
// context. The caller closes the bridge, calls finish() and drains. Close
// ends joined connections too. on_stopped runs once when the device or a
// listener fails in a way that cannot be retried, after the bridge closed
// itself. An explicit close does not notify.
class DeviceBridge final {
public:
    using Stopped = std::function<void(engine::Status)>;

    // InvalidArgument for options outside their bounds or addresses the
    // listener cannot bind, which a device without that address causes.
    static engine::Result<std::shared_ptr<DeviceBridge>> create(
        std::shared_ptr<providers::AsioExecutionContext> context,
        const DeviceBridgeOptions& options, NativeSessionSource sessions,
        Stopped on_stopped = {}, NativeStreamOpener opener = {});

    DeviceBridge(const DeviceBridge&) = delete;
    DeviceBridge& operator=(const DeviceBridge&) = delete;
    ~DeviceBridge() noexcept;

    // Callable from any thread: what the bridge carries now.
    std::uint32_t tcp_connections() const noexcept;
    std::uint32_t udp_destinations() const noexcept;
    void close() noexcept;

private:
    struct State;
    explicit DeviceBridge(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::runtime
