/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "client/packet/engine.hpp"

namespace yume::client {

class Tunnel;

namespace packet {

struct Assignment {
    std::string ipv4;
    std::uint32_t ipv4_be{0};
    std::uint32_t mtu{0};
    std::vector<std::string> dns_servers;
};

bool has_packet_bulk_capability(
    const std::vector<std::string>& server_capabilities) noexcept;
bool parse_packet_assignment(const std::string& payload,
                             Assignment* assignment,
                             std::string* error = nullptr);
bool validate_assigned_ipv4_packet(const Assignment& assignment,
                                   const Bytes& packet,
                                   bool outbound,
                                   std::string* error = nullptr);

class PacketChannel : public std::enable_shared_from_this<PacketChannel> {
public:
    static std::shared_ptr<PacketChannel> open(
        std::shared_ptr<Tunnel> tunnel,
        const std::vector<std::string>& server_capabilities,
        std::chrono::milliseconds timeout,
        std::string* error = nullptr);

    ~PacketChannel();
    PacketChannel(const PacketChannel&) = delete;
    PacketChannel& operator=(const PacketChannel&) = delete;

    const Assignment& assignment() const noexcept { return assignment_; }
    QueueResult write_packets(const std::vector<Bytes>& packets,
                              std::string* error = nullptr);
    QueueResult read_packets(std::size_t max_packets,
                             std::size_t max_bytes,
                             std::chrono::milliseconds timeout,
                             std::vector<Bytes>* packets,
                             std::size_t* required_first_bytes = nullptr);
    EngineStats stats() const;
    void close(const std::string& reason = "packet channel closed");

private:
    explicit PacketChannel(std::shared_ptr<Tunnel> tunnel);

    void on_data(const Bytes& payload);
    void stop_local(const std::string& reason);
    void sender_loop();

    std::shared_ptr<Tunnel> tunnel_;
    PacketBatchEngine engine_;
    Assignment assignment_;
    std::uint8_t stream_id_{0};
    std::atomic<bool> closed_{false};
    std::thread sender_;
};

}  // namespace packet
}  // namespace yume::client
