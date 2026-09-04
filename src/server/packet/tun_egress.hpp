/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>

#include "core/security/crypto.hpp"
#include "server/config/config.hpp"

namespace yume::server {

struct PacketTunAssignment {
    std::uint32_t ipv4_be{0};
    std::string ipv4;
    std::uint32_t mtu{0};
    std::vector<std::string> dns_servers;
};

// True when the configuration names an IPv4 resolver for packet mode. There
// is deliberately no default: the resolver handed to every tunnelled client
// sees every hostname they look up, so the operator must name the party that
// gets to observe it.
bool packet_dns_configured(const ServerConfig& cfg) noexcept;

class PacketTunEgress {
public:
    using PacketHandler = std::function<void(crypto::Bytes)>;

    PacketTunEgress(boost::asio::io_context& io, ServerConfig cfg);
    ~PacketTunEgress();

    void start();
    void stop();
    bool active() const;

    std::optional<PacketTunAssignment> register_client(void* owner, PacketHandler handler);
    void unregister_client(void* owner, std::uint32_t ipv4_be);
    bool write_packets(std::uint32_t client_ipv4_be,
                       std::vector<crypto::Bytes> packets);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::server
