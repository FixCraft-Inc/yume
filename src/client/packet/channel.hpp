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
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "client/packet/engine.hpp"
#include "client/transport/runtime_lifetime.hpp"

namespace yume::client {

class Tunnel;

namespace packet {

struct PacketChannelTestPeer;

enum class OpenStatus {
    success,
    invalid_argument,
    not_running,
    capability_unavailable,
    timeout,
    peer_rejected,
    resource_exhausted,
    protocol_error,
};

struct OpenResult {
    OpenStatus status{OpenStatus::invalid_argument};
    std::string detail;
};

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
        std::string* error = nullptr,
        std::shared_ptr<RuntimeLifetimeGate> lifetime_gate = {},
        OpenResult* open_result = nullptr);

    ~PacketChannel();
    PacketChannel(const PacketChannel&) = delete;
    PacketChannel& operator=(const PacketChannel&) = delete;

    const Assignment& assignment() const noexcept { return assignment_; }
    QueueResult write_packets(const std::vector<Bytes>& packets,
                              std::string* error = nullptr);
    QueueResult write_packets(
        const std::vector<Bytes>& packets,
        std::chrono::milliseconds timeout,
        std::string* error = nullptr);
    QueueResult read_packets(std::size_t max_packets,
                             std::size_t max_bytes,
                             std::chrono::milliseconds timeout,
                             std::vector<Bytes>* packets,
                             std::size_t* required_first_bytes = nullptr);
    EngineStats stats() const;
    void close(const std::string& reason = "packet channel closed");

private:
    PacketChannel(std::shared_ptr<Tunnel> tunnel,
                  std::shared_ptr<RuntimeLifetimeGate> lifetime_gate);

    void on_data(const Bytes& payload,
                 runtime::InboundCredit inbound_credit);
    void stop_local(const std::string& reason);
    void sender_loop();
    template <typename WaitSend>
    static QueueResult wait_for_transport_capacity(
        Bytes* payload,
        WaitSend&& wait_send,
        const std::atomic<bool>& closed,
        std::string* error) {
        if (error) error->clear();
        if (!payload) {
            if (error) *error = "packet transport admission is unavailable";
            return QueueResult::invalid;
        }

        constexpr auto kAdmissionSlice = std::chrono::milliseconds{100};
        for (;;) {
            if (closed.load(std::memory_order_acquire)) {
                if (error) *error = "packet channel is stopping";
                return QueueResult::stopped;
            }

            // Tunnel::wait_send_data consumes the rvalue only after capacity
            // has been reserved. On timeout the encoded batch, including its
            // sequence, remains intact for the next bounded retry.
            const auto result = wait_send(
                std::move(*payload), kAdmissionSlice);
            switch (result) {
            case QueueResult::ok:
                return QueueResult::ok;
            case QueueResult::would_block:
            case QueueResult::timeout:
                continue;
            case QueueResult::stopped:
                if (error) *error = "packet transport stopped";
                return QueueResult::stopped;
            case QueueResult::invalid:
            case QueueResult::buffer_too_small:
                if (error) {
                    *error = "packet transport rejected packet payload";
                }
                return QueueResult::invalid;
            }
        }
    }

    // The connected-session runtime owns the tunnel and its executor. A
    // packet handle may outlive the client handle, so retaining the tunnel
    // here would also retain an object whose io_context has already gone
    // away. Every transport operation therefore takes a temporary lease.
    std::weak_ptr<Tunnel> tunnel_;
    std::shared_ptr<RuntimeLifetimeGate> lifetime_gate_;
    PacketBatchEngine engine_;
    Assignment assignment_;
    std::uint8_t stream_id_{0};
    std::atomic<bool> closed_{false};
    std::mutex sender_join_mu_;
    std::thread sender_;

    friend struct PacketChannelTestPeer;
};

}  // namespace packet
}  // namespace yume::client
