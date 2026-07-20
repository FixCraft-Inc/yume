/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <atomic>
#include <memory>
#include <string>

namespace yume::client::packet {

class PacketChannel;

// Attaches only to an operator-created TUN. It never changes addresses,
// routes, DNS, firewall rules, NAT, ownership, or persistence.
int run_packet_tun_adapter(const std::string& interface_name,
                           const std::shared_ptr<PacketChannel>& channel,
                           std::atomic<bool>& stop_requested,
                           std::string* error = nullptr);

}  // namespace yume::client::packet
