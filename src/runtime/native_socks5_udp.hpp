/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <memory>
#include <string>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>

#include "engine/status.hpp"
#include "providers/asio_execution_context.hpp"
#include "runtime/native_socks5.hpp"

namespace yume::runtime {

// One SOCKS5 UDP association (RFC 1928, section 7) for one local client.
//
// A loopback relay socket receives the client's datagrams. Each destination
// gets its own authenticated packet OPEN on the configured UDP service, so the
// server checks the peer's identity grant and the service's configured
// destinations for UDP exactly as it does for CONNECT. Replies return to the
// client with that destination as their source. Only datagrams from the
// client's address, and from the port it announced or first used, are relayed.
//
// Backlogs follow the shared UDP queue policy. Datagrams waiting for their
// stream and replies waiting for the local socket each have their own budget
// of 64 datagrams and 1 MiB per association, and a full budget drops the
// newest datagram. Fragments and empty datagrams are dropped. A destination
// with no traffic for limits.udp_idle_timeout closes. Datagrams to a destination
// whose OPEN was refused, expired or ended are dropped for
// limits.udp_retry_delay before a new OPEN is tried.
//
// Creation, close and every callback run on the supplied single-runner
// context. The owner closes the association when the client's TCP connection
// ends, and the caller drains the context afterwards.
class NativeSocks5UdpAssociation final {
public:
    // relay_address must be a loopback address. A client port of zero accepts
    // the first valid datagram's source port and then only that port.
    static engine::Result<std::shared_ptr<NativeSocks5UdpAssociation>> create(
        std::shared_ptr<providers::AsioExecutionContext> context,
        std::string service,
        NativeSessionSource sessions,
        const NativeSocks5Limits& limits,
        const boost::asio::ip::address& relay_address,
        boost::asio::ip::udp::endpoint client);

    NativeSocks5UdpAssociation(const NativeSocks5UdpAssociation&) = delete;
    NativeSocks5UdpAssociation& operator=(const NativeSocks5UdpAssociation&) = delete;
    ~NativeSocks5UdpAssociation() noexcept;

    boost::asio::ip::udp::endpoint relay_endpoint() const noexcept;
    // Closes the relay socket and every destination stream and drops backlogs.
    void close() noexcept;

private:
    struct State;
    explicit NativeSocks5UdpAssociation(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::runtime
