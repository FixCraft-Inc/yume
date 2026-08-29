/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * TransportCore outbound write path: frame queueing, encode + obfs padding,
 * and priority-ordered batched dispatch.
 */

#include "outbound/core.hpp"
#include "outbound/internal.hpp"

#include <algorithm>
#include <cstdio>
#include <thread>

#include "core/security/inner_crypto.hpp"

namespace yume::outbound {

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

bool bulk_capacity_available(std::size_t payload_bytes,
                             std::size_t outstanding_frames,
                             std::size_t outstanding_bytes) noexcept {
    return outstanding_frames < kMaxOutstandingBulkFrames &&
           payload_bytes <= kMaxOutstandingBulkBytes &&
           outstanding_bytes <= kMaxOutstandingBulkBytes - payload_bytes;
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
    bool released = false;
    if (write.bulk_reservation) {
        if (outstanding_bulk_frames_ > 0) {
            --outstanding_bulk_frames_;
            released = true;
        }
        outstanding_bulk_bytes_ = write.reserved_bytes <= outstanding_bulk_bytes_
            ? outstanding_bulk_bytes_ - write.reserved_bytes : 0;
    } else if (write.enqueue_order != 0 && outstanding_control_frames_ > 0) {
        --outstanding_control_frames_;
        outstanding_control_bytes_ =
            write.reserved_bytes <= outstanding_control_bytes_
            ? outstanding_control_bytes_ - write.reserved_bytes : 0;
    }
    if (released) {
        write_capacity_cv_.notify_all();
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

TransportCore::DataWriteAdmission TransportCore::wait_send_data(
    uint8_t stream_id,
    Bytes&& data,
    std::chrono::milliseconds timeout,
    WriteCompletion handler) {
    if (timeout.count() < 0 || data.size() > kMaxOutstandingBulkBytes) {
        return DataWriteAdmission::invalid;
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        bool dispatch = false;
        bool stopped = false;
        bool accepted = false;
        ActivityHandler activity_handler;
        {
            std::scoped_lock lock(state_mu_, write_mu_);
            stopped = stopped_;
            if (!stopped && bulk_capacity_available(
                                data.size(), outstanding_bulk_frames_,
                                outstanding_bulk_bytes_)) {
                uint16_t flags = inner_key_.has_value()
                    ? protocol::kFlagInnerEncrypted : 0;
                if (!data.empty()) {
                    activity_handler = activity_handler_;
                }
                const std::size_t reserved_bytes = data.size();
                protocol::Frame frame{
                    {static_cast<uint32_t>(data.size()), protocol::DATA,
                     stream_id, flags},
                    std::move(data)};
                const bool was_empty = write_queues_[stream_id].empty();
                PendingWrite write{
                    std::move(frame), std::move(handler), false, true,
                    reserved_bytes, ++next_enqueue_order_};
                ++outstanding_bulk_frames_;
                outstanding_bulk_bytes_ += write.reserved_bytes;
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
        if (stopped) {
            return DataWriteAdmission::stopped;
        }
        if (accepted) {
            if (dispatch) dispatch_next_write();
            // Activity callbacks are advisory. An embedder callback must not
            // unwind across transport admission after ownership of the write
            // and its completion has transferred to the queue.
            if (activity_handler) {
                try {
                    activity_handler();
                } catch (...) {
                }
            }
            return DataWriteAdmission::accepted;
        }
        if (timeout == std::chrono::milliseconds::zero()) {
            return DataWriteAdmission::would_block;
        }

        std::unique_lock<std::mutex> lock(write_mu_);
        if (write_admission_stopped_) {
            return DataWriteAdmission::stopped;
        }
        if (bulk_capacity_available(data.size(), outstanding_bulk_frames_,
                                    outstanding_bulk_bytes_)) {
            continue;
        }
        const bool awakened = write_capacity_cv_.wait_until(
            lock, deadline, [&] {
                return write_admission_stopped_ ||
                       bulk_capacity_available(
                           data.size(), outstanding_bulk_frames_,
                           outstanding_bulk_bytes_);
            });
        if (!awakened) {
            return DataWriteAdmission::timeout;
        }
    }
}

std::shared_ptr<TransportCore::Bytes> TransportCore::encode_outgoing_frame(
    const protocol::Frame& frame, bool already_protected
#if YUME_ENABLE_DEV_DIAGNOSTICS
    , diagnostics::SampleAccumulator* seal_timing
#endif
) {
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
#if YUME_ENABLE_DEV_DIAGNOSTICS
            diagnostics::Stopwatch seal_timer(seal_timing != nullptr);
#endif
            protected_frame = ratchet_->Seal(
                frame, std::chrono::steady_clock::now());
#if YUME_ENABLE_DEV_DIAGNOSTICS
            if (seal_timing) seal_timing->record(seal_timer);
#endif
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

TransportCore::WriteSelection TransportCore::select_write_item_locked(
    std::size_t current_batch_bytes,
    const std::unordered_set<uint8_t>& batch_streams,
    bool collect_timing) {
#if !YUME_ENABLE_DEV_DIAGNOSTICS
    (void)collect_timing;
#endif
    if (stopped_) {
        write_in_flight_ = false;
        return {WriteSelectionStatus::Empty, std::nullopt};
    }
    if (write_queues_empty_locked()) {
        return {WriteSelectionStatus::Empty, std::nullopt};
    }

    const auto stream_id =
        select_next_write_locked(current_batch_bytes, batch_streams);
    if (!stream_id.has_value()) {
        return {WriteSelectionStatus::Empty, std::nullopt};
    }

    auto& head = write_queues_[*stream_id].front();
    const auto now = std::chrono::steady_clock::now();
    if (ratchet_ && !head.already_protected &&
        ratchet_->ApplicationWriteBlocked(head.frame, now)) {
#if YUME_ENABLE_DEV_DIAGNOSTICS
        if (collect_timing) {
            if (!outbound_application_blocked_) {
                outbound_application_block_wait_.start_if(true, now);
                outbound_application_blocked_ = true;
                ++ratchet_flow_stats_.application_block_count;
            }
            const std::size_t pending = ratchet_->outbound_rekeys_in_flight();
            const std::size_t prepared = ratchet_->prepared_outbound_epochs();
            ratchet_flow_stats_.max_pending_epochs = std::max(
                ratchet_flow_stats_.max_pending_epochs, pending);
            ratchet_flow_stats_.max_prepared_epochs = std::max(
                ratchet_flow_stats_.max_prepared_epochs, prepared);
            ratchet_flow_stats_.max_total_depth = std::max(
                ratchet_flow_stats_.max_total_depth, pending + prepared);
        }
#endif
        // Leave the application head queued until the ACK prepares the next
        // send epoch. Re-queueing its stream preserves the scheduler order.
        mark_stream_ready_locked(*stream_id);
        return {WriteSelectionStatus::Blocked, std::nullopt};
    }

    if (ratchet_ && !head.already_protected &&
        ratchet_->ShouldStartRekey(head.frame, now)) {
        PendingWrite rekey;
        rekey.frame = ratchet_->BeginOutboundRekey(now);
        rekey.already_protected = true;
#if YUME_ENABLE_DEV_DIAGNOSTICS
        outbound_rekey_wait_.start_if(collect_timing, now);
        if (collect_timing) {
            ++ratchet_flow_stats_.offer_count;
            const std::size_t pending = ratchet_->outbound_rekeys_in_flight();
            const std::size_t prepared = ratchet_->prepared_outbound_epochs();
            ratchet_flow_stats_.max_pending_epochs = std::max(
                ratchet_flow_stats_.max_pending_epochs, pending);
            ratchet_flow_stats_.max_prepared_epochs = std::max(
                ratchet_flow_stats_.max_prepared_epochs, prepared);
            ratchet_flow_stats_.max_total_depth = std::max(
                ratchet_flow_stats_.max_total_depth, pending + prepared);
        }
#endif
        mark_stream_ready_locked(*stream_id);
        return {WriteSelectionStatus::Selected, std::move(rekey)};
    }

    return {WriteSelectionStatus::Selected,
            pop_stream_head_locked(*stream_id)};
}

void TransportCore::fail_write_batch(std::vector<PendingWrite> batch,
                                     const std::string& error,
                                     const std::string& close_prefix) {
    {
        std::lock_guard<std::mutex> write_lock(write_mu_);
        for (const auto& item : batch) {
            release_write_reservation_locked(item);
        }
        write_in_flight_ = false;
    }
    for (auto& item : batch) {
        if (!item.handler) continue;
        try {
            item.handler(false, 0, error);
        } catch (...) {
            // Completion code is outside the scheduler trust boundary.
        }
    }
    request_transport_close(close_prefix + error);
}

void TransportCore::settle_write_batch(
    std::vector<PendingWrite> completed_batch,
    std::vector<std::size_t> completed_sizes,
    bool ok,
    std::size_t bytes,
    const std::string& error) {
    bool dispatch = false;
    const bool stopped = is_stopped();
    {
        std::lock_guard<std::mutex> write_lock(write_mu_);
        for (const auto& item : completed_batch) {
            release_write_reservation_locked(item);
        }
        if (!ok || stopped || write_queues_empty_locked()) {
            write_in_flight_ = false;
        } else {
            write_in_flight_ = true;
            dispatch = true;
        }
    }
    for (std::size_t i = 0; i < completed_batch.size(); ++i) {
        auto& item = completed_batch[i];
        if (!item.handler) continue;
        const bool completion_ok = ok && !stopped;
        const std::size_t item_bytes =
            completion_ok && i < completed_sizes.size()
                ? completed_sizes[i]
                : bytes;
        try {
            item.handler(completion_ok, item_bytes,
                         stopped ? "transport stopped" : error);
        } catch (...) {
            // Settle sibling writes even when an embedder callback fails.
        }
    }
    if (!ok) {
        request_transport_close("write failed: " + error);
    } else if (dispatch) {
        dispatch_next_write();
    }
}

void TransportCore::dispatch_next_write() {
    std::vector<PendingWrite> batch;
    auto encoded = std::make_shared<Bytes>();
    std::vector<std::size_t> encoded_sizes;
    WriteHandler writer;
#if YUME_ENABLE_DEV_DIAGNOSTICS
    TimingHandler timing_handler;
#endif
    {
        std::lock_guard<std::mutex> state_lock(state_mu_);
        if (stopped_) {
            return;
        }
        writer = write_handler_;
#if YUME_ENABLE_DEV_DIAGNOSTICS
        timing_handler = timing_handler_;
#endif
    }
    if (!writer) {
        request_transport_close("transport writer unavailable");
        return;
    }

    std::string selection_error;
    std::size_t total_bytes = 0;
#if YUME_ENABLE_DEV_DIAGNOSTICS
    const bool collect_timing = static_cast<bool>(timing_handler);
    diagnostics::SampleAccumulator selector_timing(collect_timing);
    diagnostics::SampleAccumulator seal_timing(collect_timing);
#endif
    std::unordered_set<uint8_t> batch_streams;
    while (batch.size() < kMaxWriteBatchFrames) {
#if YUME_ENABLE_DEV_DIAGNOSTICS
        diagnostics::Stopwatch selector_timer(collect_timing);
#endif
        WriteSelection selection;
        try {
            std::scoped_lock lock(state_mu_, write_mu_);
            selection = select_write_item_locked(
                total_bytes, batch_streams,
#if YUME_ENABLE_DEV_DIAGNOSTICS
                collect_timing
#else
                false
#endif
            );
            if (selection.status_ != WriteSelectionStatus::Selected &&
                batch.empty()) {
                write_in_flight_ = false;
            }
        } catch (const std::exception& ex) {
            selection_error = ex.what();
            break;
        }
#if YUME_ENABLE_DEV_DIAGNOSTICS
        selector_timing.record(selector_timer);
#endif

        if (selection.status_ != WriteSelectionStatus::Selected ||
            !selection.write_.has_value()) {
            break;
        }
        PendingWrite write = std::move(*selection.write_);

        try {
            auto part = encode_outgoing_frame(
                write.frame, write.already_protected
#if YUME_ENABLE_DEV_DIAGNOSTICS
                , collect_timing ? &seal_timing : nullptr
#endif
            );
            if (encoded->empty()) {
                encoded->reserve(std::min<std::size_t>(
                    kMaxWriteBatchBytes, part->size() + 64U * 1024U));
            }
            encoded_sizes.push_back(part->size());
            encoded->insert(encoded->end(), part->begin(), part->end());
            total_bytes += part->size();
            batch_streams.insert(write.frame.header.stream_id);
            batch.push_back(std::move(write));
            if (total_bytes >= kMaxWriteBatchBytes) {
                break;
            }
        } catch (const std::exception& ex) {
            {
                std::lock_guard<std::mutex> write_lock(write_mu_);
                release_write_reservation_locked(write);
            }
            if (write.handler) {
                try {
                    write.handler(false, 0, ex.what());
                } catch (...) {
                }
            }
            selection_error = ex.what();
            break;
        } catch (...) {
            {
                std::lock_guard<std::mutex> write_lock(write_mu_);
                release_write_reservation_locked(write);
            }
            if (write.handler) {
                try {
                    write.handler(false, 0, "unknown error");
                } catch (...) {
                }
            }
            selection_error = "unknown error";
            break;
        }
    }
    if (!selection_error.empty()) {
        fail_write_batch(std::move(batch), selection_error,
                         "rekey start failed: ");
        return;
    }

    if (batch.empty()) {
        return;
    }

#if YUME_ENABLE_DEV_DIAGNOSTICS
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
        const auto selector_sample = selector_timing.take_if(0, true);
        const auto seal_sample = seal_timing.take_if(0, true);
        YUME_TIMING_SINK(
            timing_handler, "client.transport", "write_batch",
            "frames=" + std::to_string(batch.size()) +
            " bytes=" + std::to_string(total_bytes) +
            " queued_frames=" + std::to_string(queued_frames) +
            " outstanding_bulk_frames=" + std::to_string(bulk_frames) +
            " outstanding_bulk_bytes=" + std::to_string(bulk_bytes) +
            " outstanding_control_frames=" +
                std::to_string(control_frames) +
            " outstanding_control_bytes=" +
                std::to_string(control_bytes) +
            " selector_us=" + std::to_string(
                selector_sample.has_value()
                    ? selector_sample->total_ns / 1000U : 0U) +
            " seal_us=" + std::to_string(
                seal_sample.has_value()
                    ? seal_sample->total_ns / 1000U : 0U));
    }
#endif

    std::shared_ptr<WriteCompletionState> completion_state;
    try {
        completion_state = std::make_shared<WriteCompletionState>();
    } catch (...) {
        settle_write_batch(
            std::move(batch), std::move(encoded_sizes), false, 0,
            "unable to allocate transport write completion state");
        return;
    }
    completion_state->batch_ = std::move(batch);
    completion_state->encoded_sizes_ = std::move(encoded_sizes);

    auto completion = [this, completion_state](
                          bool ok,
                          std::size_t bytes,
                          const std::string& error) mutable {
        std::vector<PendingWrite> owned_batch;
        std::vector<std::size_t> owned_sizes;
        {
            std::lock_guard<std::mutex> write_lock(write_mu_);
            if (completion_state->settled_) {
                return;
            }
            completion_state->settled_ = true;
            owned_batch = std::move(completion_state->batch_);
            owned_sizes = std::move(completion_state->encoded_sizes_);
        }
        settle_write_batch(std::move(owned_batch), std::move(owned_sizes),
                           ok, bytes, error);
    };

    try {
        writer(encoded, completion);
    } catch (const std::exception& ex) {
        completion(false, 0, ex.what());
    } catch (...) {
        completion(false, 0, "transport writer threw an unknown exception");
    }
}

void TransportCore::resume_writes_after_rekey() {
    bool dispatch = false;
#if YUME_ENABLE_DEV_DIAGNOSTICS
    std::optional<std::uint64_t> rekey_wait_us;
    TimingHandler timing_handler;
#endif
    {
        std::scoped_lock lock(state_mu_, write_mu_);
#if YUME_ENABLE_DEV_DIAGNOSTICS
        timing_handler = timing_handler_;
        rekey_wait_us = outbound_rekey_wait_.finish_us(
            std::chrono::steady_clock::now());
        if (timing_handler && ratchet_) {
            const std::size_t pending =
                ratchet_->outbound_rekeys_in_flight();
            const std::size_t prepared =
                ratchet_->prepared_outbound_epochs();
            ratchet_flow_stats_.max_pending_epochs = std::max(
                ratchet_flow_stats_.max_pending_epochs, pending);
            ratchet_flow_stats_.max_prepared_epochs = std::max(
                ratchet_flow_stats_.max_prepared_epochs, prepared);
            ratchet_flow_stats_.max_total_depth = std::max(
                ratchet_flow_stats_.max_total_depth, pending + prepared);
        }
        if (outbound_application_blocked_) {
            if (const auto elapsed =
                    outbound_application_block_wait_.finish_us(
                        std::chrono::steady_clock::now())) {
                ratchet_flow_stats_.application_block_us += *elapsed;
            }
            outbound_application_blocked_ = false;
        }
#endif
        if (!write_in_flight_ && !write_queues_empty_locked()) {
            write_in_flight_ = true;
            dispatch = true;
        }
    }
#if YUME_ENABLE_DEV_DIAGNOSTICS
    if (rekey_wait_us.has_value()) {
        YUME_TIMING_SINK(timing_handler, "client.transport", "rekey_wait",
                         "us=" + std::to_string(*rekey_wait_us));
    }
#endif
    if (dispatch) dispatch_next_write();
}

}  // namespace yume::outbound
