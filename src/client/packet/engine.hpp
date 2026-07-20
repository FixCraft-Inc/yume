/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

#include "core/protocol/packet_bulk.hpp"

namespace yume::client::packet {

using Bytes = std::vector<std::uint8_t>;

enum class QueueResult {
    ok,
    would_block,
    timeout,
    stopped,
    buffer_too_small,
    invalid,
};

struct EngineStats {
    std::uint64_t outbound_batches{0};
    std::uint64_t outbound_packets{0};
    std::uint64_t outbound_bytes{0};
    std::uint64_t inbound_batches{0};
    std::uint64_t inbound_packets{0};
    std::uint64_t inbound_bytes{0};
    std::size_t outbound_queue_packets{0};
    std::size_t outbound_queue_bytes{0};
    std::size_t inbound_queue_packets{0};
    std::size_t inbound_queue_bytes{0};
    bool stopped{false};
    std::string stop_reason;
};

class PacketBatchEngine {
public:
    static constexpr std::size_t kDefaultMaxQueuePackets = 1024;
    static constexpr std::size_t kDefaultMaxQueueBytes = 4U * 1024U * 1024U;

    struct Limits {
        std::size_t max_queue_packets{kDefaultMaxQueuePackets};
        std::size_t max_queue_bytes{kDefaultMaxQueueBytes};
    };

    PacketBatchEngine();
    explicit PacketBatchEngine(Limits limits);
    PacketBatchEngine(const PacketBatchEngine&) = delete;
    PacketBatchEngine& operator=(const PacketBatchEngine&) = delete;

    // Copies all packets before returning. The operation is all-or-none.
    QueueResult enqueue_outbound(const std::vector<Bytes>& packets,
                                 std::string* error = nullptr);

    // Coalesces up to 64 packets / 128 KiB and waits no longer than the
    // packet-bulk 2 ms flush delay after the first packet was enqueued.
    QueueResult take_outbound_payload(
        Bytes* payload,
        std::chrono::milliseconds timeout,
        std::string* error = nullptr);

    // Decodes one authenticated DATA payload and admits all packets or none.
    // Sequence zero is required first and every later sequence must be exact.
    QueueResult accept_inbound_payload(const Bytes& payload,
                                       std::string* error = nullptr);
    QueueResult accept_inbound_batch(protocol::packet_bulk::Batch batch,
                                     std::string* error = nullptr);

    // Returns complete packets only. If the first packet does not fit,
    // buffer_too_small is returned and it remains queued.
    QueueResult read_inbound(std::size_t max_packets,
                             std::size_t max_bytes,
                             std::chrono::milliseconds timeout,
                             std::vector<Bytes>* packets,
                             std::size_t* required_first_bytes = nullptr);

    void stop(std::string reason);
    EngineStats stats() const;

private:
    static void set_error(std::string* error, const std::string& value);
    bool can_admit_locked(std::size_t packets, std::size_t bytes,
                          std::size_t queued_packets,
                          std::size_t queued_bytes) const noexcept;

    Limits limits_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<Bytes> outbound_;
    std::deque<Bytes> inbound_;
    std::size_t outbound_bytes_{0};
    std::size_t inbound_bytes_{0};
    std::chrono::steady_clock::time_point outbound_first_queued_{};
    std::uint64_t next_outbound_sequence_{0};
    std::uint64_t next_inbound_sequence_{0};
    bool outbound_sequence_exhausted_{false};
    bool inbound_sequence_exhausted_{false};
    bool stopped_{false};
    std::string stop_reason_;
    EngineStats counters_;
};

}  // namespace yume::client::packet
