/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/runtime/service_stream.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>

namespace yume::runtime {

ServiceStream::ServiceStream(std::string service, std::string peer)
    : ServiceStream(std::move(service), std::move(peer), {}) {}

ServiceStream::ServiceStream(std::string service,
                             std::string peer,
                             ServicePeerInfo peer_info)
    : service_(std::move(service))
    , peer_(std::move(peer))
    , peer_info_(std::move(peer_info)) {
    if (peer_info_.service.empty()) {
        peer_info_.service = service_;
    }
    if (peer_info_.peer.empty()) {
        peer_info_.peer = peer_;
    }
    if (peer_info_.session_id.empty()) {
        peer_info_.session_id = peer_;
    }
}

ServiceStream::~ServiceStream() {
    close("stream destroyed");
}

const std::string& ServiceStream::service() const noexcept {
    return service_;
}

const std::string& ServiceStream::peer() const noexcept {
    return peer_;
}

ServicePeerInfo ServiceStream::peer_info() const {
    std::lock_guard<std::mutex> lock(mu_);
    return peer_info_;
}

void ServiceStream::set_callbacks(WriteCallback write_cb,
                                  CloseCallback close_cb,
                                  CloseCallback shutdown_write_cb,
                                  WriteWaitAllowedCallback write_wait_allowed_cb) {
    std::lock_guard<std::mutex> lock(mu_);
    write_cb_ = std::move(write_cb);
    close_cb_ = std::move(close_cb);
    shutdown_write_cb_ = std::move(shutdown_write_cb);
    write_wait_allowed_cb_ = std::move(write_wait_allowed_cb);
}

ServiceStream::WriteResult ServiceStream::write(
    const void* data,
    std::size_t size,
    std::uint32_t timeout_ms,
    std::string* error) {
    if (size > 0 && data == nullptr) {
        if (error) *error = "data is null";
        return WriteResult::Invalid;
    }
    if (size > kMaxServiceWriteBytes) {
        if (error) {
            *error = "service write exceeds the 256 KiB record limit";
        }
        return WriteResult::Invalid;
    }
    if (size == 0) {
        if (error) error->clear();
        return WriteResult::Accepted;
    }

    WriteCallback cb;
    WriteWaitAllowedCallback write_wait_allowed_cb;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (local_closed_ || remote_closed_) {
            if (error) *error = close_reason_.empty() ? "stream closed" : close_reason_;
            return WriteResult::Closed;
        }
        if (local_fin_sent_) {
            if (error) *error = "stream write side is shut down";
            return WriteResult::Closed;
        }
        cb = write_cb_;
        write_wait_allowed_cb = write_wait_allowed_cb_;
    }
    if (!cb) {
        if (error) *error = "stream is not connected";
        return WriteResult::Closed;
    }

    bool write_wait_allowed = true;
    if (write_wait_allowed_cb) {
        try {
            write_wait_allowed = write_wait_allowed_cb();
        } catch (...) {
            // Executor-affinity probes are advisory application code. Fail
            // closed to a nonblocking result if the caller cannot establish
            // that waiting here is safe.
            write_wait_allowed = false;
        }
    }

    const auto started = std::chrono::steady_clock::now();
    const auto deadline = started + std::chrono::milliseconds(timeout_ms);
    const auto outbound = outbound_state_;
    std::uint64_t write_token = 0;
    {
        std::unique_lock<std::mutex> lock(outbound->mutex);
        const auto available_or_closed = [&outbound] {
            return outbound->active_write == 0 || outbound->closed;
        };
        if (outbound->active_write != 0) {
            if (timeout_ms == 0 || !write_wait_allowed) {
                if (error) *error = "service write would block";
                return WriteResult::WouldBlock;
            }
            if (!outbound->cv.wait_until(lock, deadline,
                                         available_or_closed)) {
                if (error) *error = "service write deadline expired";
                return WriteResult::Timeout;
            }
        }
        if (outbound->closed) {
            if (error) {
                *error = outbound->close_reason.empty()
                    ? "stream closed" : outbound->close_reason;
            }
            return WriteResult::Closed;
        }
        if (timeout_ms != 0 &&
            std::chrono::steady_clock::now() >= deadline) {
            if (error) *error = "service write deadline expired";
            return WriteResult::Timeout;
        }
        if (outbound->next_write == std::numeric_limits<std::uint64_t>::max()) {
            outbound->closed = true;
            outbound->close_reason = "service write sequence exhausted";
            if (error) *error = outbound->close_reason;
            return WriteResult::Closed;
        }
        write_token = ++outbound->next_write;
        outbound->active_write = write_token;
    }

    Bytes payload;
    try {
        const auto* begin = static_cast<const std::uint8_t*>(data);
        payload.assign(begin, begin + size);
    } catch (...) {
        {
            std::lock_guard<std::mutex> lock(outbound->mutex);
            if (outbound->active_write == write_token) {
                outbound->active_write = 0;
            }
        }
        outbound->cv.notify_all();
        throw;
    }

    std::uint32_t remaining_ms = timeout_ms;
    if (timeout_ms != 0) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            {
                std::lock_guard<std::mutex> lock(outbound->mutex);
                if (outbound->active_write == write_token) {
                    outbound->active_write = 0;
                }
            }
            outbound->cv.notify_all();
            if (error) *error = "service write deadline expired";
            return WriteResult::Timeout;
        }
        const auto remaining = std::chrono::duration_cast<
            std::chrono::milliseconds>(deadline - now);
        if (remaining <= std::chrono::milliseconds::zero()) {
            {
                std::lock_guard<std::mutex> lock(outbound->mutex);
                if (outbound->active_write == write_token) {
                    outbound->active_write = 0;
                }
            }
            outbound->cv.notify_all();
            if (error) *error = "service write deadline expired";
            return WriteResult::Timeout;
        }
        remaining_ms = static_cast<std::uint32_t>(remaining.count());
    }

    auto completion = [outbound, write_token](bool ok, std::string reason) {
        {
            std::lock_guard<std::mutex> lock(outbound->mutex);
            if (outbound->active_write != write_token) {
                return;
            }
            outbound->active_write = 0;
            if (!ok) {
                outbound->closed = true;
                if (outbound->close_reason.empty()) {
                    outbound->close_reason = reason.empty()
                        ? "service transport write failed" : std::move(reason);
                }
            }
        }
        outbound->cv.notify_all();
    };

    WriteResult result = WriteResult::Failed;
    try {
        result = cb(std::move(payload), remaining_ms, completion, error);
    } catch (...) {
        completion(false, "service write callback threw");
        throw;
    }
    if (result != WriteResult::Accepted) {
        {
            std::lock_guard<std::mutex> lock(outbound->mutex);
            if (outbound->active_write == write_token) {
                outbound->active_write = 0;
            }
        }
        outbound->cv.notify_all();
    }
    return result;
}

bool ServiceStream::shutdown_write(std::string* error) {
    CloseCallback cb;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (local_closed_) {
            return true;
        }
        if (local_fin_sent_) {
            return true;
        }
        local_fin_sent_ = true;
        cb = shutdown_write_cb_;
    }
    if (!cb) {
        if (error) *error = "stream is not connected";
        return false;
    }
    cb("write side closed");
    return true;
}

void ServiceStream::close(std::string reason) {
    CloseCallback cb;
    std::string callback_reason;
    std::string outbound_reason;
    std::deque<InboundItem> discarded;
    InboundCredit discarded_current_credit;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (local_closed_) {
            return;
        }
        const bool notify_remote = !remote_closed_;
        local_closed_ = true;
        remote_closed_ = true;
        if (close_reason_.empty()) {
            close_reason_ = reason.empty() ? "stream closed" : std::move(reason);
        }
        outbound_reason = close_reason_;
        discarded.swap(incoming_);
        inbound_budget_.clear();
        current_.clear();
        current_offset_ = 0;
        discarded_current_credit = std::move(current_credit_);
        if (notify_remote) {
            cb = close_cb_;
            callback_reason = close_reason_;
        }
    }
    // Credit handlers may post work or inspect their owning stream. Release
    // only after dropping mu_ so close/error cleanup cannot self-deadlock.
    discarded_current_credit.release_now();
    discarded.clear();
    cv_.notify_all();
    {
        std::lock_guard<std::mutex> lock(outbound_state_->mutex);
        outbound_state_->closed = true;
        if (outbound_state_->close_reason.empty()) {
            outbound_state_->close_reason = std::move(outbound_reason);
        }
    }
    outbound_state_->cv.notify_all();
    if (cb) {
        cb(std::move(callback_reason));
    }
}

ServiceStream::ReadResult ServiceStream::read(void* out,
                                              std::size_t capacity,
                                              std::uint32_t timeout_ms,
                                              std::size_t* bytes_read,
                                              std::string* reason) {
    if (bytes_read) {
        *bytes_read = 0;
    }
    if (capacity > 0 && out == nullptr) {
        if (reason) *reason = "output buffer is null";
        return ReadResult::Closed;
    }

    InboundCredit consumed_credit;
    std::unique_lock<std::mutex> lock(mu_);
    auto has_data_or_closed = [this]() {
        return current_offset_ < current_.size() || !incoming_.empty() ||
               remote_fin_ || remote_closed_ || local_closed_;
    };
    if (!has_data_or_closed()) {
        if (timeout_ms == 0) {
            return ReadResult::Timeout;
        }
        if (!cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), has_data_or_closed)) {
            return ReadResult::Timeout;
        }
    }

    if (current_offset_ >= current_.size() && !incoming_.empty()) {
        auto item = std::move(incoming_.front());
        incoming_.pop_front();
        current_ = std::move(item.data);
        current_credit_ = std::move(item.credit);
        current_offset_ = 0;
    }

    if (current_offset_ < current_.size()) {
        const std::size_t n = std::min(capacity, current_.size() - current_offset_);
        if (n > 0) {
            std::memcpy(out, current_.data() + current_offset_, n);
            current_offset_ += n;
        }
        if (current_offset_ >= current_.size()) {
            inbound_budget_.record_dequeue(current_.size());
            current_.clear();
            current_offset_ = 0;
            consumed_credit = std::move(current_credit_);
        }
        if (bytes_read) {
            *bytes_read = n;
        }
        lock.unlock();
        consumed_credit.release_now();
        return ReadResult::Data;
    }

    if (remote_fin_) {
        if (reason) *reason = close_reason_;
        return ReadResult::Eof;
    }
    if (remote_closed_ || local_closed_) {
        if (reason) *reason = close_reason_;
        return ReadResult::Closed;
    }
    return ReadResult::Timeout;
}

bool ServiceStream::receive_data(Bytes data, std::string* error) {
    return receive_data(std::move(data), {}, error);
}

bool ServiceStream::receive_data(Bytes data,
                                 InboundCredit inbound_credit,
                                 std::string* error) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (local_closed_ || remote_closed_ || data.empty()) {
            return true;
        }
        const std::size_t bytes = data.size();
        if (!inbound_budget_.can_enqueue(bytes, error)) {
            return false;
        }
        incoming_.push_back(
            {std::move(data), std::move(inbound_credit)});
        inbound_budget_.record_enqueue(bytes);
    }
    cv_.notify_all();
    return true;
}

void ServiceStream::receive_fin(std::string reason) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (remote_closed_ || remote_fin_) {
            return;
        }
        remote_fin_ = true;
        if (close_reason_.empty()) {
            close_reason_ = std::move(reason);
        }
    }
    cv_.notify_all();
}

void ServiceStream::receive_close(std::string reason, bool discard_buffered) {
    std::deque<InboundItem> discarded;
    InboundCredit discarded_current_credit;
    std::string outbound_reason;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (remote_closed_) {
            return;
        }
        remote_closed_ = true;
        if (close_reason_.empty()) {
            close_reason_ = reason.empty() ? "remote closed" : std::move(reason);
        }
        outbound_reason = close_reason_;
        if (discard_buffered) {
            discarded.swap(incoming_);
            inbound_budget_.clear();
            current_.clear();
            current_offset_ = 0;
            discarded_current_credit = std::move(current_credit_);
        }
    }
    discarded_current_credit.release_now();
    discarded.clear();
    cv_.notify_all();
    {
        std::lock_guard<std::mutex> lock(outbound_state_->mutex);
        outbound_state_->closed = true;
        if (outbound_state_->close_reason.empty()) {
            outbound_state_->close_reason = std::move(outbound_reason);
        }
    }
    outbound_state_->cv.notify_all();
}

bool ServiceStream::closed() const {
    std::lock_guard<std::mutex> lock(mu_);
    return local_closed_ || remote_closed_;
}

ServiceStreamAdmissionGate::Permit
ServiceStreamAdmissionGate::try_acquire() {
    if (stopping_.load(std::memory_order_acquire)) {
        return {};
    }
    Permit permit(mutex_);
    if (stopping_.load(std::memory_order_acquire)) {
        return {};
    }
    return permit;
}

void ServiceStreamAdmissionGate::stop() noexcept {
    stopping_.store(true, std::memory_order_release);
    // Waiting for this mutex drains the one publication transaction that may
    // have linearized before the stop request became visible.
    std::lock_guard<std::mutex> lock(mutex_);
}

bool ServiceStreamAdmissionGate::stopping() const noexcept {
    return stopping_.load(std::memory_order_acquire);
}

ServiceWriteAdmissionQueue::ServiceWriteAdmissionQueue(
    std::size_t max_frames,
    std::size_t max_bytes)
    : max_frames_(max_frames)
    , max_bytes_(max_bytes) {
    if (max_frames_ == 0 || max_bytes_ == 0) {
        throw std::invalid_argument(
            "service write queue limits must be positive");
    }
}

bool ServiceWriteAdmissionQueue::capacity_available(
    std::size_t bytes) const noexcept {
    return outstanding_frames_ < max_frames_ &&
           bytes <= max_bytes_ &&
           outstanding_bytes_ <= max_bytes_ - bytes;
}

bool ServiceWriteAdmissionQueue::cancellation_requested(
    const Cancelled& cancelled) const noexcept {
    if (!cancelled) {
        return false;
    }
    try {
        return cancelled();
    } catch (...) {
        // A cancellation probe is advisory application code. Fail closed if
        // it cannot establish that the owning stream remains writable.
        return true;
    }
}

bool ServiceWriteAdmissionQueue::schedule_if_ready_locked() noexcept {
    if (stopped_ || in_flight_ || dispatch_scheduled_ || pending_.empty()) {
        return false;
    }
    dispatch_scheduled_ = true;
    return true;
}

ServiceWriteAdmissionQueue::AdmissionResult
ServiceWriteAdmissionQueue::enqueue(
    std::uint8_t stream_id,
    Bytes&& payload,
    std::chrono::milliseconds timeout,
    Completion completion,
    const Cancelled& cancelled,
    bool* needs_dispatch,
    std::string* reason) {
    if (needs_dispatch) {
        *needs_dispatch = false;
    }
    if (timeout.count() < 0 || payload.size() > kMaxServiceWriteBytes ||
        payload.size() > max_bytes_) {
        if (reason) *reason = "invalid service write admission request";
        return AdmissionResult::Invalid;
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::unique_lock<std::mutex> lock(mutex_);
    for (;;) {
        if (stopped_) {
            if (reason) {
                *reason = stop_reason_.empty()
                    ? "service write queue stopped" : stop_reason_;
            }
            return AdmissionResult::Stopped;
        }
        if (cancellation_requested(cancelled)) {
            if (reason) *reason = "service stream closed";
            return AdmissionResult::Stopped;
        }
        if (capacity_available(payload.size())) {
            // condition_variable::wait_until may report a satisfied predicate
            // after the deadline raced with a capacity release. Mutex
            // acquisition is part of admission too, so every positive
            // timeout keeps the original absolute deadline authoritative.
            if (timeout != std::chrono::milliseconds::zero() &&
                std::chrono::steady_clock::now() >= deadline) {
                if (reason) *reason = "service write deadline expired";
                return AdmissionResult::Timeout;
            }
            break;
        }
        if (timeout == std::chrono::milliseconds::zero()) {
            if (reason) *reason = "service write would block";
            return AdmissionResult::WouldBlock;
        }
        const bool awakened = capacity_cv_.wait_until(
            lock, deadline, [&] {
                return stopped_ || cancellation_requested(cancelled) ||
                       capacity_available(payload.size());
            });
        if (!awakened) {
            if (reason) *reason = "service write deadline expired";
            return AdmissionResult::Timeout;
        }
    }

    if (next_sequence_ == std::numeric_limits<std::uint64_t>::max()) {
        if (reason) {
            *reason = "service write admission sequence exhausted";
        }
        return AdmissionResult::Invalid;
    }

    const std::size_t bytes = payload.size();
    const std::uint64_t sequence = ++next_sequence_;
    pending_.push_back(
        {sequence, stream_id, std::move(payload), std::move(completion)});
    ++outstanding_frames_;
    outstanding_bytes_ += bytes;
    const bool schedule = schedule_if_ready_locked();
    if (needs_dispatch) {
        *needs_dispatch = schedule;
    }
    if (reason) reason->clear();
    return AdmissionResult::Accepted;
}

std::optional<ServiceWriteAdmissionQueue::Entry>
ServiceWriteAdmissionQueue::take_next() {
    std::lock_guard<std::mutex> lock(mutex_);
    dispatch_scheduled_ = false;
    if (stopped_ || in_flight_ || pending_.empty()) {
        return std::nullopt;
    }

    Entry entry = std::move(pending_.front());
    pending_.pop_front();
    in_flight_ = true;
    in_flight_sequence_ = entry.sequence;
    in_flight_bytes_ = entry.payload.size();
    return entry;
}

bool ServiceWriteAdmissionQueue::finish(
    std::uint64_t sequence,
    bool* needs_dispatch) noexcept {
    if (needs_dispatch) {
        *needs_dispatch = false;
    }
    bool schedule = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!in_flight_ || in_flight_sequence_ != sequence) {
            return false;
        }
        in_flight_ = false;
        in_flight_sequence_ = 0;
        if (outstanding_frames_ > 0) {
            --outstanding_frames_;
        }
        outstanding_bytes_ = in_flight_bytes_ <= outstanding_bytes_
            ? outstanding_bytes_ - in_flight_bytes_ : 0U;
        in_flight_bytes_ = 0;
        schedule = schedule_if_ready_locked();
    }
    capacity_cv_.notify_all();
    if (needs_dispatch) {
        *needs_dispatch = schedule;
    }
    return true;
}

void ServiceWriteAdmissionQueue::fail_entries(
    std::list<Entry> entries,
    const std::string& reason) noexcept {
    for (auto& entry : entries) {
        if (!entry.completion) {
            continue;
        }
        try {
            entry.completion(false, reason);
        } catch (...) {
            // Cancellation must settle every remaining entry even when an
            // embedder-owned completion misbehaves.
        }
    }
}

bool ServiceWriteAdmissionQueue::cancel_stream(
    std::uint8_t stream_id,
    std::string reason) noexcept {
    std::list<Entry> cancelled;
    bool schedule = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = pending_.begin(); it != pending_.end();) {
            if (it->stream_id != stream_id) {
                ++it;
                continue;
            }
            const std::size_t bytes = it->payload.size();
            auto current = it++;
            cancelled.splice(cancelled.end(), pending_, current);
            if (outstanding_frames_ > 0) {
                --outstanding_frames_;
            }
            outstanding_bytes_ = bytes <= outstanding_bytes_
                ? outstanding_bytes_ - bytes : 0U;
        }
        // Do not clear dispatch_scheduled_ here. The already-posted strand
        // handler still exists even when cancellation temporarily empties the
        // FIFO. Keeping its single wake token lets a later enqueue reuse that
        // handler instead of accumulating one stale post per cancel/re-enqueue
        // cycle before the strand gets CPU time.
        schedule = schedule_if_ready_locked();
    }
    capacity_cv_.notify_all();
    fail_entries(std::move(cancelled), reason);
    return schedule;
}

void ServiceWriteAdmissionQueue::stop(std::string reason) noexcept {
    std::list<Entry> abandoned;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopped_) {
            return;
        }
        stopped_ = true;
        if (reason.empty()) {
            try {
                reason = "service write queue stopped";
            } catch (...) {
            }
        }
        stop_reason_ = std::move(reason);
        dispatch_scheduled_ = false;
        abandoned.splice(abandoned.end(), pending_);
        for (const auto& entry : abandoned) {
            if (outstanding_frames_ > 0) {
                --outstanding_frames_;
            }
            const std::size_t bytes = entry.payload.size();
            outstanding_bytes_ = bytes <= outstanding_bytes_
                ? outstanding_bytes_ - bytes : 0U;
        }
    }
    capacity_cv_.notify_all();
    fail_entries(std::move(abandoned), stop_reason_);
}

void ServiceWriteAdmissionQueue::notify_waiters() noexcept {
    // Cancellation state is owned by the caller and may change without this
    // queue mutex. Briefly taking the mutex makes that external-state change
    // and the notification atomic with respect to enqueue()'s final predicate
    // check and transition into condition_variable::wait_until(). Without
    // this handshake, a notification can land after the predicate returned
    // false but before the waiter actually slept, delaying cancellation until
    // the write deadline.
    {
        std::lock_guard<std::mutex> lock(mutex_);
    }
    capacity_cv_.notify_all();
}

std::size_t ServiceWriteAdmissionQueue::outstanding_frames() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return outstanding_frames_;
}

std::size_t ServiceWriteAdmissionQueue::outstanding_bytes() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return outstanding_bytes_;
}

bool ServiceWriteAdmissionQueue::stopped() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return stopped_;
}

}  // namespace yume::runtime
