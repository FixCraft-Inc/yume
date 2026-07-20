/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/packet/engine.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace yume::client::packet {
namespace {

constexpr std::uint64_t kMaxSequence = 0x7FFF'FFFF'FFFF'FFFFull;

}  // namespace

PacketBatchEngine::PacketBatchEngine() : PacketBatchEngine(Limits{}) {}

PacketBatchEngine::PacketBatchEngine(Limits limits) : limits_(limits) {
    if (limits_.max_queue_packets == 0 || limits_.max_queue_bytes == 0) {
        throw std::invalid_argument("packet queue limits must be non-zero");
    }
}

void PacketBatchEngine::set_error(std::string* error, const std::string& value) {
    if (error) {
        *error = value;
    }
}

bool PacketBatchEngine::can_admit_locked(std::size_t packets,
                                         std::size_t bytes,
                                         std::size_t queued_packets,
                                         std::size_t queued_bytes) const noexcept {
    return packets <= limits_.max_queue_packets -
                          std::min(queued_packets, limits_.max_queue_packets) &&
           bytes <= limits_.max_queue_bytes -
                        std::min(queued_bytes, limits_.max_queue_bytes);
}

QueueResult PacketBatchEngine::enqueue_outbound(const std::vector<Bytes>& packets,
                                                std::string* error) {
    if (packets.empty()) {
        set_error(error, "packet write batch is empty");
        return QueueResult::invalid;
    }
    std::size_t bytes = 0;
    for (const auto& packet : packets) {
        if (packet.empty() || packet.size() > protocol::packet_bulk::kMaxPacketBytes) {
            set_error(error, "packet write contains an invalid packet size");
            return QueueResult::invalid;
        }
        if (bytes > std::numeric_limits<std::size_t>::max() - packet.size()) {
            set_error(error, "packet write size overflow");
            return QueueResult::invalid;
        }
        bytes += packet.size();
    }

    {
        std::lock_guard<std::mutex> lock(mu_);
        if (stopped_) {
            set_error(error, stop_reason_);
            return QueueResult::stopped;
        }
        if (!can_admit_locked(packets.size(), bytes,
                              outbound_.size(), outbound_bytes_)) {
            set_error(error, "packet outbound queue full");
            return QueueResult::would_block;
        }
        const bool was_empty = outbound_.empty();
        for (const auto& packet : packets) {
            outbound_.push_back(packet);
        }
        outbound_bytes_ += bytes;
        if (was_empty) {
            outbound_first_queued_ = std::chrono::steady_clock::now();
        }
    }
    cv_.notify_all();
    return QueueResult::ok;
}

QueueResult PacketBatchEngine::take_outbound_payload(
    Bytes* payload,
    std::chrono::milliseconds timeout,
    std::string* error) {
    if (!payload) {
        set_error(error, "packet payload output is null");
        return QueueResult::invalid;
    }
    const auto started = std::chrono::steady_clock::now();
    const auto deadline = started + timeout;
    std::unique_lock<std::mutex> lock(mu_);
    while (outbound_.empty() && !stopped_) {
        if (timeout.count() == 0) {
            return QueueResult::would_block;
        }
        if (!cv_.wait_until(lock, deadline, [&] {
                return stopped_ || !outbound_.empty();
            })) {
            return QueueResult::timeout;
        }
    }
    if (stopped_) {
        set_error(error, stop_reason_);
        return QueueResult::stopped;
    }
    if (outbound_sequence_exhausted_) {
        set_error(error, "packet outbound sequence exhausted");
        return QueueResult::stopped;
    }

    const auto flush_at = outbound_first_queued_ +
        std::chrono::microseconds(protocol::packet_bulk::kDefaultFlushDelayMicros);
    const auto effective_deadline = timeout.count() == 0
        ? started : std::min(deadline, flush_at);
    auto batch_ready = [&] {
        if (stopped_ || outbound_.size() >= protocol::packet_bulk::kMaxPacketsPerBatch) {
            return true;
        }
        std::size_t encoded = protocol::packet_bulk::kHeaderBytes;
        std::size_t count = 0;
        for (const auto& packet : outbound_) {
            if (!protocol::packet_bulk::can_append_packet(
                    encoded, count, packet.size())) {
                return true;
            }
            encoded += protocol::packet_bulk::kPacketLengthBytes + packet.size();
            if (++count >= protocol::packet_bulk::kMaxPacketsPerBatch) {
                return true;
            }
        }
        return std::chrono::steady_clock::now() >= flush_at;
    };
    if (!batch_ready() && timeout.count() > 0) {
        cv_.wait_until(lock, effective_deadline, batch_ready);
    }
    if (stopped_) {
        set_error(error, stop_reason_);
        return QueueResult::stopped;
    }

    protocol::packet_bulk::Batch batch;
    batch.sequence = next_outbound_sequence_;
    std::size_t encoded = protocol::packet_bulk::kHeaderBytes;
    while (!outbound_.empty() &&
           protocol::packet_bulk::can_append_packet(
               encoded, batch.packets.size(), outbound_.front().size())) {
        encoded += protocol::packet_bulk::kPacketLengthBytes +
                   outbound_.front().size();
        outbound_bytes_ -= outbound_.front().size();
        batch.packets.push_back(std::move(outbound_.front()));
        outbound_.pop_front();
    }
    if (!outbound_.empty()) {
        outbound_first_queued_ = std::chrono::steady_clock::now();
    }
    if (next_outbound_sequence_ == kMaxSequence) {
        outbound_sequence_exhausted_ = true;
    } else {
        ++next_outbound_sequence_;
    }
    counters_.outbound_batches += 1;
    counters_.outbound_packets += batch.packets.size();
    for (const auto& packet : batch.packets) {
        counters_.outbound_bytes += packet.size();
    }
    lock.unlock();

    try {
        *payload = protocol::packet_bulk::encode_batch(batch);
    } catch (const std::exception& ex) {
        stop(std::string("packet batch encode failed: ") + ex.what());
        set_error(error, ex.what());
        return QueueResult::stopped;
    }
    cv_.notify_all();
    return QueueResult::ok;
}

QueueResult PacketBatchEngine::accept_inbound_payload(const Bytes& payload,
                                                      std::string* error) {
    std::string decode_error;
    auto batch = protocol::packet_bulk::decode_batch(payload, &decode_error);
    if (!batch.has_value()) {
        set_error(error, decode_error);
        return QueueResult::invalid;
    }
    return accept_inbound_batch(std::move(*batch), error);
}

QueueResult PacketBatchEngine::accept_inbound_batch(
    protocol::packet_bulk::Batch batch,
    std::string* error) {
    std::size_t bytes = 0;
    for (const auto& packet : batch.packets) {
        bytes += packet.size();
    }

    {
        std::lock_guard<std::mutex> lock(mu_);
        if (stopped_) {
            set_error(error, stop_reason_);
            return QueueResult::stopped;
        }
        if (inbound_sequence_exhausted_ || batch.sequence != next_inbound_sequence_) {
            set_error(error, "packet inbound sequence mismatch");
            return QueueResult::invalid;
        }
        if (!can_admit_locked(batch.packets.size(), bytes,
                              inbound_.size(), inbound_bytes_)) {
            set_error(error, "packet inbound queue full");
            return QueueResult::would_block;
        }
        const std::size_t packet_count = batch.packets.size();
        for (auto& packet : batch.packets) {
            inbound_.push_back(std::move(packet));
        }
        inbound_bytes_ += bytes;
        if (next_inbound_sequence_ == kMaxSequence) {
            inbound_sequence_exhausted_ = true;
        } else {
            ++next_inbound_sequence_;
        }
        counters_.inbound_batches += 1;
        counters_.inbound_packets += packet_count;
        counters_.inbound_bytes += bytes;
    }
    cv_.notify_all();
    return QueueResult::ok;
}

QueueResult PacketBatchEngine::read_inbound(
    std::size_t max_packets,
    std::size_t max_bytes,
    std::chrono::milliseconds timeout,
    std::vector<Bytes>* packets,
    std::size_t* required_first_bytes) {
    if (!packets || max_packets == 0) {
        return QueueResult::invalid;
    }
    packets->clear();
    std::unique_lock<std::mutex> lock(mu_);
    if (inbound_.empty() && !stopped_) {
        if (timeout.count() == 0) {
            return QueueResult::would_block;
        }
        if (!cv_.wait_for(lock, timeout, [&] {
                return stopped_ || !inbound_.empty();
            })) {
            return QueueResult::timeout;
        }
    }
    if (inbound_.empty() && stopped_) {
        return QueueResult::stopped;
    }
    if (inbound_.front().size() > max_bytes) {
        if (required_first_bytes) {
            *required_first_bytes = inbound_.front().size();
        }
        return QueueResult::buffer_too_small;
    }

    std::size_t bytes = 0;
    while (!inbound_.empty() && packets->size() < max_packets &&
           inbound_.front().size() <= max_bytes - bytes) {
        bytes += inbound_.front().size();
        inbound_bytes_ -= inbound_.front().size();
        packets->push_back(std::move(inbound_.front()));
        inbound_.pop_front();
    }
    lock.unlock();
    cv_.notify_all();
    return QueueResult::ok;
}

void PacketBatchEngine::stop(std::string reason) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (stopped_) {
            return;
        }
        stopped_ = true;
        stop_reason_ = reason.empty() ? "packet engine stopped" : std::move(reason);
    }
    cv_.notify_all();
}

EngineStats PacketBatchEngine::stats() const {
    std::lock_guard<std::mutex> lock(mu_);
    EngineStats out = counters_;
    out.outbound_queue_packets = outbound_.size();
    out.outbound_queue_bytes = outbound_bytes_;
    out.inbound_queue_packets = inbound_.size();
    out.inbound_queue_bytes = inbound_bytes_;
    out.stopped = stopped_;
    out.stop_reason = stop_reason_;
    return out;
}

}  // namespace yume::client::packet
