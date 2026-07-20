/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * TransportCore outbound write path: frame queueing, encode + obfs padding, priority-ordered batched dispatch.
 * Extracted verbatim from client/transport/core.cpp. Same
 * yume::client::TransportCore class, no behavior change. Shared helpers
 * via client/transport/internal.hpp.
 */

#include "client/transport/core.hpp"
#include "client/transport/internal.hpp"

#include <algorithm>
#include <cstdio>
#include <thread>

#include "core/security/inner_crypto.hpp"

namespace yume::client {

using namespace detail;

namespace {

constexpr std::size_t kMaxOutstandingFrames = 512;
constexpr std::size_t kMaxOutstandingBytes = 16U * 1024U * 1024U;
constexpr std::size_t kReservedControlFrames = 64;
constexpr std::size_t kReservedControlBytes = 1U * 1024U * 1024U;
constexpr std::size_t kMaxOutstandingBulkFrames =
    kMaxOutstandingFrames - kReservedControlFrames;
constexpr std::size_t kMaxOutstandingBulkBytes =
    kMaxOutstandingBytes - kReservedControlBytes;

bool is_bulk_frame(const protocol::Frame& frame) noexcept {
    return frame.header.type == protocol::DATA;
}

}  // namespace

void TransportCore::mark_stream_ready_locked(uint8_t stream_id) {
    if (ready_priority_[stream_id] >= 0 || write_queues_[stream_id].empty()) {
        return;
    }
    const int priority = std::clamp(
        frame_write_priority(write_queues_[stream_id].front().frame), 0, 4);
    ready_priority_[stream_id] = static_cast<std::int8_t>(priority);
    ready_streams_[static_cast<std::size_t>(priority)].push_back(stream_id);
}

bool TransportCore::write_queues_empty_locked() const noexcept {
    return queued_frames_ == 0;
}

TransportCore::PendingWrite TransportCore::pop_stream_head_locked(uint8_t stream_id) {
    auto& queue = write_queues_[stream_id];
    PendingWrite write = std::move(queue.front());
    queue.pop_front();
    if (queued_frames_ > 0) {
        --queued_frames_;
    }
    mark_stream_ready_locked(stream_id);
    return write;
}

void TransportCore::release_write_reservation_locked(const PendingWrite& write) noexcept {
    if (write.bulk_reservation) {
        if (outstanding_bulk_frames_ > 0) {
            --outstanding_bulk_frames_;
        }
        outstanding_bulk_bytes_ = write.reserved_bytes <= outstanding_bulk_bytes_
            ? outstanding_bulk_bytes_ - write.reserved_bytes : 0;
    } else if (write.enqueue_order != 0 && outstanding_control_frames_ > 0) {
        --outstanding_control_frames_;
        outstanding_control_bytes_ =
            write.reserved_bytes <= outstanding_control_bytes_
            ? outstanding_control_bytes_ - write.reserved_bytes : 0;
    }
}

bool TransportCore::queue_frame(protocol::Frame frame, WriteCompletion handler,
                                bool already_protected) {
    bool dispatch = false;
    bool accepted = false;
    std::string rejection;
    const bool bulk = is_bulk_frame(frame);
    const std::size_t reserved_bytes = frame.payload.size();
    {
        std::scoped_lock lock(state_mu_, write_mu_);
        if (stopped_) {
            rejection = "transport stopped";
        } else if (bulk &&
                   (outstanding_bulk_frames_ >= kMaxOutstandingBulkFrames ||
                    frame.payload.size() >
                        kMaxOutstandingBulkBytes - outstanding_bulk_bytes_)) {
            rejection = "application write queue full";
        } else if (!bulk &&
                   (outstanding_control_frames_ >= kReservedControlFrames ||
                    frame.payload.size() >
                        kReservedControlBytes - outstanding_control_bytes_)) {
            rejection = "control write queue full";
        } else {
            const uint8_t stream_id = frame.header.stream_id;
            const bool was_empty = write_queues_[stream_id].empty();
            PendingWrite write{
                std::move(frame), std::move(handler), already_protected,
                bulk, reserved_bytes,
                ++next_enqueue_order_};
            if (bulk) {
                ++outstanding_bulk_frames_;
                outstanding_bulk_bytes_ += write.reserved_bytes;
            } else {
                ++outstanding_control_frames_;
                outstanding_control_bytes_ += write.reserved_bytes;
            }
            write_queues_[stream_id].push_back(std::move(write));
            ++queued_frames_;
            if (was_empty) {
                mark_stream_ready_locked(stream_id);
            }
            if (!write_in_flight_) {
                write_in_flight_ = true;
                dispatch = true;
            }
            accepted = true;
        }
    }
    if (!accepted && handler) {
        handler(false, 0, rejection);
    }
    if (!accepted && !bulk && rejection == "control write queue full") {
        request_transport_close(rejection);
    }
    if (dispatch) {
        dispatch_next_write();
    }
    return accepted;
}

std::shared_ptr<TransportCore::Bytes> TransportCore::encode_outgoing_frame(
    const protocol::Frame& frame, bool already_protected,
    std::uint64_t* seal_ns) {
    // Avoid copying the payload on the no-inner path: encode_frame and
    // encrypt_inner_payload both take const&, so the source frame's payload
    // can be passed through directly. Only the inner-encrypted path needs a
    // separate buffer to hold the AEAD output.
    protocol::Frame protected_frame;
    const protocol::Frame* effective_frame = &frame;
    bool use_legacy_inner = false;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        if (stopped_) {
            throw std::runtime_error("transport stopped");
        }
        if (ratchet_ && !already_protected) {
            const bool collect_timing = seal_ns != nullptr;
            const auto seal_started = collect_timing
                ? std::chrono::steady_clock::now()
                : std::chrono::steady_clock::time_point{};
            protected_frame = ratchet_->Seal(
                frame, std::chrono::steady_clock::now());
            if (collect_timing) {
                *seal_ns += static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::steady_clock::now() - seal_started).count());
            }
            effective_frame = &protected_frame;
        } else if (!ratchet_) {
            use_legacy_inner =
                (frame.header.flags & protocol::kFlagInnerEncrypted) != 0;
        }
    }
    const Bytes* eff_payload = &effective_frame->payload;
    Bytes encrypted;
    if (use_legacy_inner) {
        encrypted = encrypt_inner_payload(frame.header.type, frame.header.stream_id, frame.payload);
        eff_payload = &encrypted;
    }
    std::uint16_t pad_multiple = 0;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        pad_multiple = obfs_pad_multiple_;
    }
    return std::make_shared<Bytes>(protocol::encode_frame(
        static_cast<protocol::FrameType>(frame.header.type),
        frame.header.stream_id,
        effective_frame->header.flags,
        *eff_payload,
        pad_multiple));
}

void TransportCore::dispatch_next_write() {
    std::vector<PendingWrite> batch;
    auto encoded = std::make_shared<Bytes>();
    std::vector<std::size_t> encoded_sizes;
    WriteHandler writer;
    TimingHandler timing_handler;
    {
        std::lock_guard<std::mutex> state_lock(state_mu_);
        if (stopped_) {
            return;
        }
        writer = write_handler_;
        timing_handler = timing_handler_;
    }
    if (!writer) {
        request_transport_close("transport writer unavailable");
        return;
    }

    std::string selection_error;
    std::size_t total_bytes = 0;
    const bool collect_timing = static_cast<bool>(timing_handler);
    std::uint64_t selector_ns = 0;
    std::uint64_t seal_ns = 0;
    std::unordered_set<uint8_t> batch_streams;
    while (batch.size() < kMaxWriteBatchFrames) {
        std::optional<PendingWrite> selected;
        std::optional<protocol::Frame> rekey;
        const auto selector_started = collect_timing
            ? std::chrono::steady_clock::now()
            : std::chrono::steady_clock::time_point{};
        try {
            std::scoped_lock lock(state_mu_, write_mu_);
            if (stopped_) {
                write_in_flight_ = false;
                break;
            }
            if (write_queues_empty_locked()) {
                if (batch.empty()) {
                    write_in_flight_ = false;
                }
                break;
            }
            const bool ratchet_active = ratchet_ != nullptr;
            const bool rekey_blocked =
                ratchet_active && ratchet_->outbound_rekey_pending();
            const auto stream_id = select_next_write_locked(
                total_bytes, batch_streams, rekey_blocked);
            if (!stream_id.has_value()) {
                if (batch.empty()) {
                    write_in_flight_ = false;
                }
                break;
            }
            auto& head = write_queues_[*stream_id].front();
            if (ratchet_active && !head.already_protected &&
                ratchet_->ShouldStartRekey(
                    head.frame, std::chrono::steady_clock::now())) {
                rekey = ratchet_->BeginOutboundRekey(
                    std::chrono::steady_clock::now());
                if (!outbound_rekey_wait_started_.has_value()) {
                    outbound_rekey_wait_started_ =
                        std::chrono::steady_clock::now();
                }
                mark_stream_ready_locked(*stream_id);
            } else {
                selected = pop_stream_head_locked(*stream_id);
            }
        } catch (const std::exception& ex) {
            selection_error = ex.what();
            break;
        }
        if (collect_timing) {
            selector_ns += static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() - selector_started).count());
        }

        PendingWrite write;
        if (rekey.has_value()) {
            write.frame = std::move(*rekey);
            write.already_protected = true;
        } else if (selected.has_value()) {
            write = std::move(*selected);
        } else {
            break;
        }

        try {
            auto part = encode_outgoing_frame(
                write.frame, write.already_protected,
                collect_timing ? &seal_ns : nullptr);
            if (encoded->empty()) {
                encoded->reserve(std::min<std::size_t>(
                    kMaxWriteBatchBytes, part->size() + 64U * 1024U));
            }
            encoded_sizes.push_back(part->size());
            encoded->insert(encoded->end(), part->begin(), part->end());
            total_bytes += part->size();
            batch_streams.insert(write.frame.header.stream_id);
            batch.push_back(std::move(write));
            if (rekey.has_value() || total_bytes >= kMaxWriteBatchBytes) {
                break;
            }
        } catch (const std::exception& ex) {
            if (write.handler) {
                write.handler(false, 0, ex.what());
            }
            {
                std::lock_guard<std::mutex> write_lock(write_mu_);
                release_write_reservation_locked(write);
            }
            selection_error = ex.what();
            break;
        } catch (...) {
            if (write.handler) {
                write.handler(false, 0, "unknown error");
            }
            {
                std::lock_guard<std::mutex> write_lock(write_mu_);
                release_write_reservation_locked(write);
            }
            selection_error = "unknown error";
            break;
        }
    }
    if (!selection_error.empty()) {
        {
            std::lock_guard<std::mutex> write_lock(write_mu_);
            for (const auto& item : batch) {
                release_write_reservation_locked(item);
            }
            write_in_flight_ = false;
        }
        for (auto& item : batch) {
            if (item.handler) {
                item.handler(false, 0, selection_error);
            }
        }
        request_transport_close("rekey start failed: " + selection_error);
        return;
    }

    if (batch.empty()) {
        return;
    }

    if (collect_timing) {
        std::size_t queued_frames = 0;
        std::size_t bulk_frames = 0;
        std::size_t bulk_bytes = 0;
        std::size_t control_frames = 0;
        std::size_t control_bytes = 0;
        {
            std::lock_guard<std::mutex> write_lock(write_mu_);
            queued_frames = queued_frames_;
            bulk_frames = outstanding_bulk_frames_;
            bulk_bytes = outstanding_bulk_bytes_;
            control_frames = outstanding_control_frames_;
            control_bytes = outstanding_control_bytes_;
        }
        timing_handler(
            "client.transport", "write_batch",
            "frames=" + std::to_string(batch.size()) +
            " bytes=" + std::to_string(total_bytes) +
            " queued_frames=" + std::to_string(queued_frames) +
            " outstanding_bulk_frames=" + std::to_string(bulk_frames) +
            " outstanding_bulk_bytes=" + std::to_string(bulk_bytes) +
            " outstanding_control_frames=" +
                std::to_string(control_frames) +
            " outstanding_control_bytes=" +
                std::to_string(control_bytes) +
            " selector_us=" + std::to_string(selector_ns / 1000U) +
            " seal_us=" + std::to_string(seal_ns / 1000U));
    }

    writer(encoded, [this, batch = std::move(batch), encoded_sizes = std::move(encoded_sizes)](
                        bool ok,
                        std::size_t bytes,
                        const std::string& error) mutable {
        bool dispatch = false;
        const bool stopped = is_stopped();
        {
            std::lock_guard<std::mutex> write_lock(write_mu_);
            for (const auto& item : batch) {
                release_write_reservation_locked(item);
            }
            if (!ok || stopped || write_queues_empty_locked()) {
                write_in_flight_ = false;
            } else {
                write_in_flight_ = true;
                dispatch = true;
            }
        }
        for (std::size_t i = 0; i < batch.size(); ++i) {
            auto& item = batch[i];
            if (item.handler) {
                const bool completion_ok = ok && !stopped;
                const std::size_t item_bytes = completion_ok && i < encoded_sizes.size()
                    ? encoded_sizes[i] : bytes;
                item.handler(completion_ok, item_bytes,
                             stopped ? "transport stopped" : error);
            }
        }
        if (!ok) {
            request_transport_close("write failed: " + error);
            return;
        }
        if (dispatch) {
            dispatch_next_write();
        }
    });
}

void TransportCore::resume_writes_after_rekey() {
    bool dispatch = false;
    std::optional<std::uint64_t> rekey_wait_us;
    TimingHandler timing_handler;
    {
        std::scoped_lock lock(state_mu_, write_mu_);
        timing_handler = timing_handler_;
        if (outbound_rekey_wait_started_.has_value()) {
            rekey_wait_us = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() -
                    *outbound_rekey_wait_started_).count());
            outbound_rekey_wait_started_.reset();
        }
        if (!write_in_flight_ && !write_queues_empty_locked()) {
            write_in_flight_ = true;
            dispatch = true;
        }
    }
    if (rekey_wait_us.has_value() && timing_handler) {
        timing_handler("client.transport", "rekey_wait",
                       "us=" + std::to_string(*rekey_wait_us));
    }
    if (dispatch) dispatch_next_write();
}

}  // namespace yume::client
