/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include "core/crypto.hpp"
#include "server/config/config.hpp"

namespace yume::server {

struct PacketTunAssignment {
    std::uint32_t ipv4_be{0};
    std::string ipv4;
    std::uint32_t mtu{0};
    std::vector<std::string> dns_servers;
};

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
    void write_packet(std::uint32_t client_ipv4_be, crypto::Bytes packet);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::server
