/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Session upstream-stream I/O and the client-facing write path:
 *   - upstream TCP read/write  (start/on_remote_read, *_remote_write,
 *                               shutdown/finish helpers)
 *   - upstream UDP read/write  (start/on_udp_read, *_udp_write)
 *   - egress pacing            (reserve_egress_delay)
 *   - frame write path         (async_write_frame, queue_frame_on_strand,
 *                               queue_encoded_write_on_strand, do_write,
 *                               inbound-read pause/resume backpressure)
 */

#include "server/session/session.hpp"
#include "server/runtime/manager.hpp"
#include "server/session/internal.hpp"
#include "server/session/write_policy.hpp"

namespace yume::server {

using namespace detail;

namespace {

// Short enough for the small-string buffer, so closing a session because an
// allocation failed does not need another allocation to succeed.
constexpr const char* kCarrierWriteFailed = "carrier failed";
constexpr const char* kFlushScheduleFailed = "flush failed";
constexpr const char* kWriteDispatchFailed = "write failed";

// Refusing a write and closing the session are two obligations, and the
// refusal runs first so the caller learns the outcome in order. A completion
// belongs to a stream owner outside this session, so it must not be able to
// take the close with it.
void settle_refusal(
    const std::function<void(const boost::system::error_code&, std::size_t)>&
        handler,
    const boost::system::error_code& ec) noexcept {
    if (!handler) return;
    try {
        handler(ec, 0);
    } catch (...) {
    }
}

}  // namespace

void Session::start_remote_read(uint8_t stream_id) {
    std::shared_ptr<RemoteStream> remote;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        remote = it->second;
        if (close_state_ != CloseState::Open) {
            remote->read_paused = true;
            return;
        }
        if (remote->read_in_flight) {
            return;
        }
        if (should_pause_inbound_reads_on_strand()) {
            remote->read_paused = true;
            return;
        }
        remote->read_paused = false;
        remote->read_in_flight = true;
    }

    auto self = shared_from_this();
    remote->socket.async_read_some(boost::asio::buffer(remote->read_buf),
                                   boost::asio::bind_executor(strand_,
                                                              [self, stream_id](const boost::system::error_code& ec, std::size_t bytes) {
                                                                  self->on_remote_read(stream_id, ec, bytes);
                                                              }));
}

void Session::on_remote_read(uint8_t stream_id, const boost::system::error_code& ec, std::size_t bytes) {
    std::shared_ptr<RemoteStream> remote;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        remote = it->second;
        remote->read_in_flight = false;
    }

    if (ec) {
        if (ec == boost::asio::error::eof) {
            bool send_fin = false;
            {
                std::lock_guard<std::mutex> lock(streams_mutex_);
                auto it = streams_.find(stream_id);
                if (it == streams_.end()) {
                    return;
                }
                if (!it->second->remote_fin_sent) {
                    it->second->remote_fin_sent = true;
                    send_fin = true;
                }
            }
            if (send_fin) {
                send_control_fin(stream_id, "remote closed");
            }
            finish_remote_stream_if_done(stream_id);
            return;
        }
        handle_close(stream_id, "remote read failed: " + ec.message());
        send_control_close(stream_id, "remote read failed");
        return;
    }
    remote->downstream_bytes += static_cast<std::uint64_t>(bytes);
    if (remote->first_downstream_ms == 0) {
        remote->first_downstream_ms = diagnostics::timing_now_ms();
        YUME_TIMING_LOG("server.stream",
                         "first_downstream",
                         "session=" + std::to_string(session_id_) +
                             " stream=" + std::to_string(stream_id) +
                             " proto=tcp ms=" +
                             std::to_string(remote->first_downstream_ms - remote->open_started_ms) +
                             " bytes=" + std::to_string(bytes));
    }

    crypto::Bytes payload(remote->read_buf.data(), remote->read_buf.data() + bytes);
    uint16_t flags = 0;

    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::DATA, stream_id, flags}, std::move(payload)};
    queue_frame_on_strand(frame);
    start_remote_read(stream_id);
}

void Session::start_udp_read(uint8_t stream_id) {
    std::shared_ptr<UdpStream> udp;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = udp_streams_.find(stream_id);
        if (it == udp_streams_.end()) {
            return;
        }
        udp = it->second;
        if (close_state_ != CloseState::Open) {
            udp->read_paused = true;
            return;
        }
        if (udp->read_in_flight) {
            return;
        }
        if (should_pause_inbound_reads_on_strand()) {
            udp->read_paused = true;
            return;
        }
        udp->read_paused = false;
        udp->read_in_flight = true;
    }

    auto self = shared_from_this();
    udp->socket.async_receive(boost::asio::buffer(udp->read_buf),
                              boost::asio::bind_executor(strand_,
                                                         [self, stream_id](const boost::system::error_code& ec, std::size_t bytes) {
                                                             self->on_udp_read(stream_id, ec, bytes);
                                                         }));
}

void Session::on_udp_read(uint8_t stream_id, const boost::system::error_code& ec, std::size_t bytes) {
    std::shared_ptr<UdpStream> udp;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = udp_streams_.find(stream_id);
        if (it == udp_streams_.end()) {
            return;
        }
        udp = it->second;
        udp->read_in_flight = false;
    }

    if (ec) {
        handle_close(stream_id, "udp remote closed");
        send_control_close(stream_id, "");
        return;
    }
    udp->downstream_bytes += static_cast<std::uint64_t>(bytes);
    if (udp->first_downstream_ms == 0) {
        udp->first_downstream_ms = diagnostics::timing_now_ms();
        YUME_TIMING_LOG("server.stream",
                         "first_downstream",
                         "session=" + std::to_string(session_id_) +
                             " stream=" + std::to_string(stream_id) +
                             " proto=udp ms=" +
                             std::to_string(udp->first_downstream_ms - udp->open_started_ms) +
                             " bytes=" + std::to_string(bytes));
    }

    crypto::Bytes payload(udp->read_buf.data(), udp->read_buf.data() + bytes);
    uint16_t flags = 0;

    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::DATA, stream_id, flags}, std::move(payload)};
    queue_frame_on_strand(frame);
    start_udp_read(stream_id);
}

void Session::enqueue_udp_write(uint8_t stream_id,
                                const crypto::Bytes& data,
                                runtime::InboundCredit inbound_credit) {
    std::shared_ptr<UdpStream> udp;
    bool should_write = false;
    std::string overflow_reason;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = udp_streams_.find(stream_id);
        if (it == udp_streams_.end()) {
            return;
        }
        udp = it->second;
        if (!udp->inbound_budget.can_enqueue(data.size(), &overflow_reason)) {
            udp.reset();
        } else {
            udp->write_queue.push_back(
                {data, std::move(inbound_credit)});
            udp->inbound_budget.record_enqueue(data.size());
            udp->upstream_bytes += static_cast<std::uint64_t>(data.size());
            if (udp->first_upstream_ms == 0) {
                udp->first_upstream_ms = diagnostics::timing_now_ms();
                YUME_TIMING_LOG("server.stream",
                                 "first_upstream",
                                 "session=" + std::to_string(session_id_) +
                                     " stream=" + std::to_string(stream_id) +
                                     " proto=udp ms=" +
                                     std::to_string(udp->first_upstream_ms - udp->open_started_ms) +
                                     " bytes=" + std::to_string(data.size()));
            }
            should_write = !udp->write_in_flight;
        }
    }
    if (!udp) {
        const std::string reason = "udp inbound queue overflow: " + overflow_reason;
        util::log_warn("session " + std::to_string(session_id_) + ": stream " +
                       std::to_string(stream_id) + " " + reason);
        handle_close(stream_id, reason);
        send_control_close(stream_id, reason);
        return;
    }
    if (should_write) {
        do_udp_write(stream_id);
    }
}

std::chrono::milliseconds Session::reserve_egress_delay(std::size_t bytes) const {
    if (!authenticated_ || !manager_ || bandwidth_fair_key_.empty() || bytes == 0) {
        return std::chrono::milliseconds(0);
    }
    return manager_->reserve_egress_write(bandwidth_fair_key_, bandwidth_weight_, bytes);
}

void Session::do_udp_write(uint8_t stream_id) {
    std::shared_ptr<UdpStream> udp;
    crypto::Bytes data_to_write;
    runtime::InboundCredit inbound_credit;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = udp_streams_.find(stream_id);
        if (it == udp_streams_.end()) {
            return;
        }
        udp = it->second;
        if (udp->write_queue.empty()) {
            udp->write_in_flight = false;
            return;
        }
        udp->write_in_flight = true;
        auto pending = std::move(udp->write_queue.front());
        udp->write_queue.pop_front();
        data_to_write = std::move(pending.data);
        inbound_credit = std::move(pending.credit);
    }
    auto buffer = std::make_shared<crypto::Bytes>(std::move(data_to_write));
    auto credit = std::make_shared<runtime::InboundCredit>(
        std::move(inbound_credit));
    auto self = shared_from_this();
    auto fire_write = [self, udp, buffer, credit, stream_id]() {
        udp->socket.async_send(
            boost::asio::buffer(*buffer),
            boost::asio::bind_executor(
                self->strand_,
                [self, udp, buffer, credit, stream_id](
                    const boost::system::error_code& ec, std::size_t) {
                    {
                        std::lock_guard<std::mutex> lock(self->streams_mutex_);
                        udp->inbound_budget.record_dequeue(buffer->size());
                    }
                    credit->release_now();
                    if (ec) {
                        self->handle_close(stream_id, "udp send failed");
                        self->send_control_close(stream_id, "");
                        return;
                    }
                    self->do_udp_write(stream_id);
                }));
    };
    const auto delay_ms = reserve_egress_delay(buffer->size());
    if (delay_ms.count() <= 0) {
        fire_write();
        return;
    }
    auto timer = std::make_shared<boost::asio::steady_timer>(strand_);
    timer->expires_after(delay_ms);
    timer->async_wait([timer, fire_write = std::move(fire_write)](const boost::system::error_code& ec) mutable {
        if (!ec) fire_write();
    });
}

void Session::enqueue_remote_write(uint8_t stream_id,
                                   const std::vector<uint8_t>& data,
                                   runtime::InboundCredit inbound_credit) {
    std::shared_ptr<RemoteStream> remote;
    bool should_write = false;
    std::string overflow_reason;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        remote = it->second;
        if (!remote->inbound_budget.can_enqueue(data.size(), &overflow_reason)) {
            remote.reset();
        } else {
            remote->write_queue.push_back(
                {data, std::move(inbound_credit)});
            remote->inbound_budget.record_enqueue(data.size());
            remote->upstream_bytes += static_cast<std::uint64_t>(data.size());
            if (remote->first_upstream_ms == 0) {
                remote->first_upstream_ms = diagnostics::timing_now_ms();
                YUME_TIMING_LOG("server.stream",
                                 "first_upstream",
                                 "session=" + std::to_string(session_id_) +
                                     " stream=" + std::to_string(stream_id) +
                                     " proto=tcp ms=" +
                                     std::to_string(remote->first_upstream_ms - remote->open_started_ms) +
                                     " bytes=" + std::to_string(data.size()));
            }
            should_write = !remote->write_in_flight;
        }
    }
    if (!remote) {
        const std::string reason = "tcp inbound queue overflow: " + overflow_reason;
        util::log_warn("session " + std::to_string(session_id_) + ": stream " +
                       std::to_string(stream_id) + " " + reason);
        handle_close(stream_id, reason);
        send_control_close(stream_id, reason);
        return;
    }
    if (should_write) {
        do_remote_write(stream_id);
    }
}

void Session::do_remote_write(uint8_t stream_id) {
    std::shared_ptr<RemoteStream> remote;
    std::vector<uint8_t> data_to_write;
    runtime::InboundCredit inbound_credit;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        remote = it->second;
        if (!remote->connected) {
            remote->write_in_flight = false;
            return;
        }
        if (remote->write_queue.empty()) {
            remote->write_in_flight = false;
            if (remote->write_shutdown_pending && !remote->write_shutdown_sent && remote->connected) {
                // Do the half-shutdown outside the mutex.
            } else {
                return;
            }
        }
        if (remote->write_queue.empty() && remote->write_shutdown_pending &&
            !remote->write_shutdown_sent && remote->connected) {
            // Nothing left to write from the client side; send FIN to the upstream TCP peer.
            remote->write_in_flight = false;
            remote->write_shutdown_sent = true;
            data_to_write.clear();
        } else if (remote->write_queue.empty()) {
            return;
        }
        if (!remote->write_queue.empty()) {
            remote->write_in_flight = true;
            auto pending = std::move(remote->write_queue.front());
            remote->write_queue.pop_front();
            data_to_write = std::move(pending.data);
            inbound_credit = std::move(pending.credit);
        }
    }

    if (data_to_write.empty()) {
        boost::system::error_code ec;
        remote->socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
        finish_remote_stream_if_done(stream_id);
        return;
    }

    auto buffer = std::make_shared<std::vector<uint8_t>>(std::move(data_to_write));
    auto credit = std::make_shared<runtime::InboundCredit>(
        std::move(inbound_credit));
    auto self = shared_from_this();
    auto fire_write = [self, remote, buffer, credit, stream_id]() {
        boost::asio::async_write(remote->socket, boost::asio::buffer(*buffer),
                                 boost::asio::bind_executor(self->strand_,
                                                            [self, remote, buffer, credit, stream_id](const boost::system::error_code& ec, std::size_t) {
                                                                {
                                                                    std::lock_guard<std::mutex> lock(self->streams_mutex_);
                                                                    remote->inbound_budget.record_dequeue(buffer->size());
                                                                }
                                                                credit->release_now();
                                                                if (ec) {
                                                                    self->handle_close(stream_id, "remote write failed");
                                                                    self->send_control_close(stream_id, "");
                                                                    return;
                                                                }
                                                                self->do_remote_write(stream_id);
                                                            }));
    };
    const auto delay_ms = reserve_egress_delay(buffer->size());
    if (delay_ms.count() <= 0) {
        fire_write();
        return;
    }
    auto timer = std::make_shared<boost::asio::steady_timer>(strand_);
    timer->expires_after(delay_ms);
    timer->async_wait([timer, fire_write = std::move(fire_write)](const boost::system::error_code& ec) mutable {
        if (!ec) fire_write();
    });
}

void Session::shutdown_remote_send_if_ready(uint8_t stream_id) {
    std::shared_ptr<RemoteStream> remote;
    bool shutdown_now = false;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        remote = it->second;
        if (remote->write_shutdown_pending && !remote->write_shutdown_sent &&
            !remote->write_in_flight && remote->write_queue.empty() && remote->connected) {
            remote->write_shutdown_sent = true;
            shutdown_now = true;
        }
    }
    if (!shutdown_now) {
        return;
    }
    boost::system::error_code ec;
    remote->socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    finish_remote_stream_if_done(stream_id);
}

void Session::finish_remote_stream_if_done(uint8_t stream_id) {
    bool done = false;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        const auto& remote = it->second;
        done = remote->client_fin_received && remote->remote_fin_sent &&
               remote->write_queue.empty() && !remote->write_in_flight;
    }
    if (done) {
        handle_close(stream_id, "tcp half-close complete");
    }
}

void Session::async_write_frame(const protocol::Frame& frame,
                                std::function<void(const boost::system::error_code&, std::size_t)> handler) {
    boost::asio::post(strand_, [self = shared_from_this(),
                                frame,
                                handler = std::move(handler)]() mutable {
        self->queue_frame_on_strand(frame, std::move(handler));
    });
}

void Session::queue_frame_on_strand(const protocol::Frame& frame,
                                    std::function<void(const boost::system::error_code&, std::size_t)> handler,
                                    bool already_protected) {
    protocol::Frame effective = frame;
    if (ratchet_) {
        try {
            const bool application =
                ratchet::SessionRatchet::IsApplicationFrame(frame.header.type);
            const auto now = std::chrono::steady_clock::now();
            if (application && ratchet_->ApplicationWriteBlocked(frame, now)) {
                if (ratchet_blocked_writes_.size() >= kMaxWriteQueueSize) {
                    settle_refusal(handler,
                                   boost::asio::error::no_buffer_space);
                    close_with_reason("ratchet application queue overrun");
                    return;
                }
                RatchetBlockedWrite blocked{frame, std::move(handler)};
                try {
                    ratchet_blocked_writes_.push_back(std::move(blocked));
                } catch (...) {
                    // Nothing was queued and `blocked` still owns the
                    // completion, so settle it once instead of dropping it.
                    settle_refusal(blocked.handler,
                                   boost::asio::error::no_buffer_space);
                    close_with_reason(
                        "ratchet application queue allocation failed");
                    return;
                }
#if YUME_ENABLE_DEV_DIAGNOSTICS
                if (YUME_TIMING_ENABLED()) {
                    if (!outbound_application_blocked_) {
                        outbound_application_block_wait_.start_if(true, now);
                        outbound_application_blocked_ = true;
                        ++ratchet_application_block_count_;
                    }
                    ratchet_max_blocked_writes_ = std::max(
                        ratchet_max_blocked_writes_,
                        ratchet_blocked_writes_.size());
                    const std::size_t pending =
                        ratchet_->outbound_rekeys_in_flight();
                    const std::size_t prepared =
                        ratchet_->prepared_outbound_epochs();
                    ratchet_max_pending_epochs_ = std::max(
                        ratchet_max_pending_epochs_, pending);
                    ratchet_max_prepared_epochs_ = std::max(
                        ratchet_max_prepared_epochs_, prepared);
                    ratchet_max_total_depth_ = std::max(
                        ratchet_max_total_depth_, pending + prepared);
                }
#endif
                return;
            }
            if (!already_protected && application &&
                ratchet_->ShouldStartRekey(frame, now)) {
                protocol::Frame init = ratchet_->BeginOutboundRekey(now);
#if YUME_ENABLE_DEV_DIAGNOSTICS
                outbound_rekey_wait_.start_if(YUME_TIMING_ENABLED(), now);
                if (YUME_TIMING_ENABLED()) {
                    ++ratchet_offer_count_;
                    const std::size_t pending =
                        ratchet_->outbound_rekeys_in_flight();
                    const std::size_t prepared =
                        ratchet_->prepared_outbound_epochs();
                    ratchet_max_pending_epochs_ = std::max(
                        ratchet_max_pending_epochs_, pending);
                    ratchet_max_prepared_epochs_ = std::max(
                        ratchet_max_prepared_epochs_, prepared);
                    ratchet_max_total_depth_ = std::max(
                        ratchet_max_total_depth_, pending + prepared);
                }
                // Preparation depth at each offer. `prepared` approaching the
                // negotiated window means the direction is pipelining; a
                // steady prepared=0 means it is advancing one epoch per round
                // trip and the window is the throughput ceiling.
                YUME_TIMING_LOG(
                    "server.ratchet", "offer",
                    "session=" + std::to_string(session_id_) +
                        " prepared=" +
                        std::to_string(ratchet_->prepared_outbound_epochs()) +
                        " in_flight=" +
                        std::to_string(ratchet_->outbound_rekeys_in_flight()));
#endif
                arm_ratchet_timeout_on_strand();
                // INIT must enter the ordered H2/TLS stream first. Re-process
                // the application frame immediately: it can use only the
                // remaining old-epoch allowance, otherwise it joins the same
                // bounded blocked queue used at the hard boundary.
                queue_frame_on_strand(init, {}, true);
                queue_frame_on_strand(frame, std::move(handler));
                return;
            }
            if (!already_protected) {
#if YUME_ENABLE_DEV_DIAGNOSTICS
                const bool collect_timing = YUME_TIMING_ENABLED();
                timing_seal_.set_active(collect_timing);
                diagnostics::Stopwatch seal_timer(collect_timing);
#endif
                effective = ratchet_->Seal(
                    frame, std::chrono::steady_clock::now());
#if YUME_ENABLE_DEV_DIAGNOSTICS
                timing_seal_.record(seal_timer);
                if (const auto sample = timing_seal_.take_if(64)) {
                    YUME_TIMING_LOG(
                        "server.transport", "ratchet_seal",
                        "session=" + std::to_string(session_id_) +
                        " frames=" + std::to_string(sample->count) +
                        " us=" + std::to_string(sample->total_ns / 1000U));
                }
#endif
            } else if (frame.header.type != protocol::REKEY_INIT &&
                       frame.header.type != protocol::REKEY_ACK) {
                throw std::runtime_error("unexpected pre-protected frame type");
            }
        } catch (const std::exception& ex) {
            settle_refusal(handler, boost::asio::error::fault);
            close_with_reason("ratchet seal failed: " + std::string(ex.what()));
            return;
        }
    }
    auto data = std::make_shared<std::vector<uint8_t>>(protocol::encode_frame(
        static_cast<protocol::FrameType>(effective.header.type),
        effective.header.stream_id,
        effective.header.flags,
        effective.payload,
        cfg_.obfs_pad_multiple));
    queue_encoded_write_on_strand(std::move(data),
                                  effective.header.type,
                                  effective.header.stream_id,
                                  effective.payload.size(),
                                  std::move(handler));
}

void Session::flush_ratchet_blocked_writes_on_strand() {
    // A newly prepared epoch can unblock queued writes while later offers are
    // still in flight, so this cannot wait for the whole window to drain.
    // Frames that are still blocked re-queue in order via queue_frame_on_strand.
    if (!ratchet_) return;
#if YUME_ENABLE_DEV_DIAGNOSTICS
    if (outbound_application_blocked_) {
        if (const auto elapsed = outbound_application_block_wait_.finish_us(
                std::chrono::steady_clock::now())) {
            ratchet_application_block_us_ += *elapsed;
        }
        outbound_application_blocked_ = false;
    }
#endif
    auto pending = std::move(ratchet_blocked_writes_);
    ratchet_blocked_writes_.clear();
    // Every entry in this batch owns a completion. If re-queueing one throws,
    // the remaining entries must still be settled rather than destroyed with
    // their callers still waiting.
    std::size_t index = 0;
    try {
        for (; index < pending.size(); ++index) {
            auto& write = pending[index];
            if (close_state_ != CloseState::Open) {
                settle_refusal(write.handler,
                               boost::asio::error::operation_aborted);
                continue;
            }
            queue_frame_on_strand(write.frame, std::move(write.handler));
        }
    } catch (...) {
        for (std::size_t rest = index; rest < pending.size(); ++rest) {
            settle_refusal(pending[rest].handler,
                           boost::asio::error::operation_aborted);
        }
        close_with_reason("ratchet application queue flush failed");
        return;
    }
    maybe_resume_inbound_reads_on_strand();
}

void Session::arm_ratchet_timeout_on_strand() {
    if (!ratchet_) return;
    const auto deadline = ratchet_->rekey_deadline();
    if (!deadline.has_value()) return;
    ratchet_timer_.expires_at(*deadline);
    auto self = shared_from_this();
    ratchet_timer_.async_wait(boost::asio::bind_executor(
        strand_, [self](const boost::system::error_code& ec) {
            if (ec || self->close_state_ != CloseState::Open || !self->ratchet_) {
                return;
            }
            if (self->ratchet_->rekey_timed_out(
                    std::chrono::steady_clock::now())) {
                self->close_with_reason("YUME 2.0 rekey timeout");
            }
        }));
}

void Session::close_carrier_write_failure() {
    // Describing the carrier's error needs an allocation that may be exactly
    // what failed. Closing the session is the part that must always happen,
    // so the detailed reason is best effort over a short fixed one.
    try {
        close_with_reason("v2 H2 carrier write failed: " +
                          v2_h2_carrier_->error());
        return;
    } catch (...) {
    }
    close_with_reason(kCarrierWriteFailed);
}

void Session::queue_encoded_write_on_strand(
    std::shared_ptr<std::vector<uint8_t>> data,
    uint8_t frame_type,
    uint8_t stream_id,
    std::size_t payload_size,
    std::function<void(const boost::system::error_code&, std::size_t)> handler) {
    if (v2_h2_tunnel_active_) {
        if (!v2_h2_carrier_ || close_state_ != CloseState::Open) {
            settle_refusal(handler, boost::asio::error::operation_aborted);
            return;
        }
        const std::size_t app_bytes = data ? data->size() : 0U;
        if (v2_h2_app_write_frames_ >= kMaxWriteQueueSize ||
            app_bytes > kH2AppWriteMaxBytes ||
            v2_h2_app_write_bytes_ > kH2AppWriteMaxBytes - app_bytes) {
            settle_refusal(handler, boost::asio::error::no_buffer_space);
            close_with_reason("v2 H2 application write queue overrun");
            return;
        }
        // Record the completion owner before the bytes reach the carrier.
        // Submitting first and only then recording would put application
        // bytes on the wire with no owner left to settle their completion.
        PendingWrite pending{std::move(data), frame_type, stream_id,
                             payload_size, std::move(handler)};
        try {
            v2_h2_pending_app_writes_.push_back(std::move(pending));
        } catch (...) {
            // push_back is strongly exception safe: nothing was submitted and
            // `pending` still owns its completion.
            settle_refusal(pending.handler,
                           boost::asio::error::no_buffer_space);
            close_with_reason(
                "v2 H2 application write queue allocation failed");
            return;
        }
        ++v2_h2_app_write_frames_;
        v2_h2_app_write_bytes_ += app_bytes;
        bool submitted_to_carrier = true;
        try {
            const auto& submitted = v2_h2_pending_app_writes_.back().data;
            submitted_to_carrier =
                !submitted || v2_h2_carrier_->SendBinary(*submitted);
        } catch (...) {
            // A throwing carrier submission is a carrier failure. Roll the
            // owner back and close rather than unwinding into the strand with
            // the completion still queued.
            submitted_to_carrier = false;
        }
        if (!submitted_to_carrier) {
            PendingWrite rolled_back =
                std::move(v2_h2_pending_app_writes_.back());
            v2_h2_pending_app_writes_.pop_back();
            --v2_h2_app_write_frames_;
            v2_h2_app_write_bytes_ =
                app_bytes <= v2_h2_app_write_bytes_
                    ? v2_h2_app_write_bytes_ - app_bytes : 0U;
            settle_refusal(rolled_back.handler, boost::asio::error::fault);
            close_carrier_write_failure();
            return;
        }
        try {
            schedule_v2_h2_wire_flush_on_strand();
        } catch (...) {
            // The bytes are with the carrier and their completion owner is
            // recorded, but nothing is left to flush them. Close so the
            // pending writes are settled instead of waiting forever.
            close_with_reason(kFlushScheduleFailed);
        }
        return;
    }
    enqueue_tls_write_on_strand(std::move(data), frame_type, stream_id,
                                payload_size, std::move(handler));
}

void Session::enqueue_tls_write_on_strand(
    std::shared_ptr<std::vector<uint8_t>> data,
    uint8_t frame_type,
    uint8_t stream_id,
    std::size_t payload_size,
    std::function<void(const boost::system::error_code&, std::size_t)> handler) {
    if (close_state_ != CloseState::Open) {
        settle_refusal(handler, boost::asio::error::operation_aborted);
        return;
    }

    if (write_queue_depth_ >= kMaxWriteQueueSize) {
        util::log_warn("session " + std::to_string(session_id_) +
                      ": write queue overflow (" + std::to_string(write_queue_depth_) +
                      " pending), closing to prevent SSL corruption");
        close_with_reason("write queue overrun - too many pending frames");
        settle_refusal(handler, boost::asio::error::operation_aborted);
        return;
    }

    const std::size_t queued_bytes = data ? data->size() : 0;
    PendingWrite pending{std::move(data), frame_type, stream_id, payload_size,
                         std::move(handler)};
    try {
        write_queues_[stream_id].push_back(std::move(pending));
    } catch (...) {
        // Nothing was queued and `pending` still owns the completion, so
        // settle it here rather than dropping it during unwind.
        settle_refusal(pending.handler,
                       boost::asio::error::no_buffer_space);
        close_with_reason("write queue allocation failed");
        return;
    }
    // Marking is allocation-free, so a queued frame always has a scheduler
    // entry and the enqueue needs no second rollback arm.
    mark_write_stream_ready_on_strand(stream_id);
    ++write_queued_frames_;
    write_queued_bytes_ += queued_bytes;
    write_queue_depth_++;
    if (!write_in_flight_) {
        do_write();
    }
}

bool Session::should_pause_inbound_reads_on_strand() const {
    return close_state_ != CloseState::Open ||
           ratchet_blocked_writes_.size() >= kWriteQueueHighWatermark ||
           write_queue_depth_ >= kWriteQueueHighWatermark ||
           v2_h2_app_write_frames_ >= kWriteQueueHighWatermark ||
           v2_h2_app_write_bytes_ >= kH2AppWriteHighWatermarkBytes;
}

void Session::maybe_resume_inbound_reads_on_strand() {
    if (close_state_ != CloseState::Open ||
        ratchet_blocked_writes_.size() > kWriteQueueLowWatermark ||
        write_queue_depth_ > kWriteQueueLowWatermark ||
        v2_h2_app_write_frames_ > kWriteQueueLowWatermark ||
        v2_h2_app_write_bytes_ > kH2AppWriteLowWatermarkBytes) {
        return;
    }

    std::vector<uint8_t> tcp_to_resume;
    std::vector<uint8_t> udp_to_resume;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        uint32_t budget = 0;
        if (write_queue_depth_ < kWriteQueueHighWatermark) {
            budget = kWriteQueueHighWatermark - write_queue_depth_;
        }
        if (budget == 0) {
            return;
        }

        for (const auto& [stream_id, remote] : streams_) {
            if (budget == 0) {
                break;
            }
            if (remote->read_paused && !remote->read_in_flight) {
                remote->read_paused = false;
                tcp_to_resume.push_back(stream_id);
                --budget;
            }
        }
        for (const auto& [stream_id, udp] : udp_streams_) {
            if (budget == 0) {
                break;
            }
            if (udp->read_paused && !udp->read_in_flight) {
                udp->read_paused = false;
                udp_to_resume.push_back(stream_id);
                --budget;
            }
        }
    }

    for (uint8_t stream_id : tcp_to_resume) {
        start_remote_read(stream_id);
    }
    for (uint8_t stream_id : udp_to_resume) {
        start_udp_read(stream_id);
    }
}

void Session::mark_write_stream_ready_on_strand(std::uint8_t stream_id) {
    if (write_ready_streams_.marked(stream_id) ||
        write_queues_[stream_id].empty()) {
        return;
    }
    const auto& head = write_queues_[stream_id].front();
    const int priority = std::clamp(
        frame_write_priority(head.frame_type, head.payload_size), 0,
        static_cast<int>(kWritePriorities) - 1);
    write_ready_streams_.mark(stream_id, static_cast<std::size_t>(priority));
}

Session::PendingWrite Session::pop_write_stream_head_on_strand(
    std::uint8_t stream_id) {
    auto& queue = write_queues_[stream_id];
    PendingWrite write = std::move(queue.front());
    queue.pop_front();
    if (write_queued_frames_ > 0) {
        --write_queued_frames_;
    }
    const std::size_t bytes = write.data ? write.data->size() : 0;
    write_queued_bytes_ = bytes <= write_queued_bytes_
        ? write_queued_bytes_ - bytes : 0;
    // Re-marking cannot fail, so the stream's remaining frames stay
    // schedulable without depending on a later enqueue to rescue them.
    mark_write_stream_ready_on_strand(stream_id);
    return write;
}

bool Session::write_queues_empty_on_strand() const noexcept {
    return write_queued_frames_ == 0;
}

std::optional<std::uint8_t> Session::select_next_write_on_strand(
    std::size_t current_batch_bytes,
    const std::unordered_set<uint8_t>& batch_streams) {
    auto select = [&](bool allow_already_selected_stream)
        -> std::optional<std::uint8_t> {
        for (std::size_t priority = 0; priority < kWritePriorities;
             ++priority) {
            // One pass per priority. rotate_front keeps a skipped stream in
            // its list, so the candidate count bounds the pass.
            const std::size_t candidates = write_ready_streams_.size(priority);
            for (std::size_t i = 0; i < candidates; ++i) {
                const auto head_id = write_ready_streams_.front(priority);
                if (!head_id.has_value()) break;
                const auto stream_id = *head_id;
                if (write_queues_[stream_id].empty()) {
                    write_ready_streams_.take_front(priority);
                    continue;
                }
                const auto& head = write_queues_[stream_id].front();
                const std::size_t estimated_size =
                    head.data ? head.data->size() : head.payload_size + 8U;
                const bool fits = current_batch_bytes == 0 ||
                    current_batch_bytes + estimated_size <= kMaxWriteBatchBytes;
                const bool new_stream = allow_already_selected_stream ||
                    batch_streams.count(stream_id) == 0;
                if (fits && new_stream) {
                    write_ready_streams_.take_front(priority);
                    return stream_id;
                }
                write_ready_streams_.rotate_front(priority);
            }
        }
        return std::nullopt;
    };

    auto stream_id = select(false);
    if (!stream_id.has_value()) {
        stream_id = select(true);
    }
    return stream_id;
}

void Session::settle_write_batch_on_strand(
    const std::shared_ptr<WriteBatchState>& batch_state,
    const boost::system::error_code& ec,
    std::size_t bytes) noexcept {
    // Own it locally first. Callers pass the session's own member, and this
    // clears that member below; without a copy the reset could free the state
    // while it is still being read. Copying a shared_ptr cannot throw.
    const std::shared_ptr<WriteBatchState> state = batch_state;
    // Every write in the batch has already left the queue, so this is the only
    // place left that can answer its caller. Exactly one of the write
    // completion, the delayed-write cancellation and the failure path below
    // reaches it.
    if (!state || state->settled) return;
    state->settled = true;
    if (in_flight_write_ == state) in_flight_write_.reset();
    auto batch = std::move(state->batch);
    const std::size_t count = batch.size();
    if (write_queue_depth_ >= count) {
        write_queue_depth_ -= static_cast<uint32_t>(count);
    } else {
        write_queue_depth_ = 0;
    }
    for (auto& item : batch) {
        if (!item.handler) continue;
        const std::size_t item_bytes = (!ec && item.data) ? item.data->size()
                                                          : bytes;
        try {
            item.handler(ec, item_bytes);
        } catch (...) {
            // A completion belongs to a stream owner outside this scheduler.
            // Its siblings still have to be settled.
        }
    }
}

void Session::fail_queued_writes_on_strand(
    const boost::system::error_code& ec) noexcept {
    // A dispatched batch whose completion never arrived is settled here too.
    // It has already left the queue, so nothing below would find it.
    settle_write_batch_on_strand(in_flight_write_, ec, 0);
    // Queued writes are dispatched only from a write completion, so once the
    // transport can no longer write, nothing will ever reach them again. This
    // is their last owner. Draining in place avoids the allocation a holding
    // container would need on a path that already failed.
    while (!write_queues_empty_on_strand()) {
        bool drained = false;
        for (std::size_t stream_id = 0; stream_id < write_queues_.size();
             ++stream_id) {
            auto& queue = write_queues_[stream_id];
            if (queue.empty()) continue;
            PendingWrite write = std::move(queue.front());
            queue.pop_front();
            drained = true;
            if (write_queued_frames_ > 0) --write_queued_frames_;
            const std::size_t bytes = write.data ? write.data->size() : 0;
            write_queued_bytes_ = bytes <= write_queued_bytes_
                ? write_queued_bytes_ - bytes : 0;
            if (write_queue_depth_ > 0) --write_queue_depth_;
            settle_refusal(write.handler, ec);
        }
        if (!drained) break;
    }
    write_queued_frames_ = 0;
    write_queued_bytes_ = 0;
    write_ready_streams_.reset();
}

void Session::do_write() noexcept {
    std::shared_ptr<WriteBatchState> state;
    try {
        // Keep shared ownership of entries already inserted into the batch
        // while dispatch assembles and submits the write.
        state = std::make_shared<WriteBatchState>();
        dispatch_write_batch_on_strand(state);
        return;
    } catch (...) {
        // Whatever dispatch had already popped is still owned by `state`.
    }
    write_in_flight_ = false;
    settle_write_batch_on_strand(state, boost::asio::error::no_buffer_space, 0);
    try {
        close_with_reason(kWriteDispatchFailed);
    } catch (...) {
    }
}

void Session::dispatch_write_batch_on_strand(
    const std::shared_ptr<WriteBatchState>& state) {
    if (write_queues_empty_on_strand()) {
        write_in_flight_ = false;
        if (close_state_ != CloseState::Open) {
            maybe_finish_close();
        }
        return;
    }
    write_in_flight_ = true;

    auto& batch = state->batch;
    std::size_t batch_count = 0;
    std::size_t total_bytes = 0;
#if YUME_ENABLE_DEV_DIAGNOSTICS
    diagnostics::Stopwatch selector_timer(YUME_TIMING_ENABLED());
#endif
    std::unordered_set<uint8_t> batch_streams;
    // Reserve both containers before the first pop. A write that has left the
    // queue but not yet reached the batch has no owner at all, so nothing
    // between the pop and the push may allocate. Reserving here instead can
    // only fail while the queue is still intact.
    batch.reserve(kMaxWriteBatchFrames);
    batch_streams.reserve(kMaxWriteBatchFrames);
    while (!write_queues_empty_on_strand() &&
           batch_count < kMaxWriteBatchFrames) {
        const auto stream_id =
            select_next_write_on_strand(total_bytes, batch_streams);
        if (!stream_id.has_value()) {
            break;
        }
        PendingWrite write = pop_write_stream_head_on_strand(*stream_id);
        const std::size_t write_bytes = write.data ? write.data->size() : 0;
        // Hand it to the owner first. push_back cannot allocate against the
        // reservation above, so the batch holds it before the set insert or
        // anything later can throw.
        batch.push_back(std::move(write));
        total_bytes += write_bytes;
        batch_streams.insert(*stream_id);
        ++batch_count;
    }
    if (batch_count == 0) {
        write_in_flight_ = false;
        return;
    }
    // From here the session owns the batch as well as do_write. A completion
    // that asio never delivers, because its own executor machinery failed,
    // destroys the handler and every reference it held; the session's
    // reference is what still answers those callers at terminal close.
    in_flight_write_ = state;
#if YUME_ENABLE_DEV_DIAGNOSTICS
    YUME_TIMING_LOG(
        "server.transport", "write_batch",
        "session=" + std::to_string(session_id_) +
        " frames=" + std::to_string(batch_count) +
        " bytes=" + std::to_string(total_bytes) +
        " queue_depth=" + std::to_string(write_queue_depth_) +
        " queued_frames=" + std::to_string(write_queued_frames_) +
        " queued_bytes=" + std::to_string(write_queued_bytes_) +
        " selector_us=" + std::to_string(selector_timer.elapsed_ns() / 1000U));
#endif

    std::shared_ptr<std::vector<uint8_t>> batch_data;
    if (batch_count == 1) {
        batch_data = batch.front().data;
    } else {
        batch_data = std::make_shared<std::vector<uint8_t>>();
        batch_data->reserve(total_bytes);
        for (const auto& item : batch) {
            if (item.data && !item.data->empty()) {
                batch_data->insert(batch_data->end(), item.data->begin(), item.data->end());
            }
        }
    }

    auto self = shared_from_this();
#if YUME_ENABLE_DEV_DIAGNOSTICS
    diagnostics::Stopwatch tls_write_timer(YUME_TIMING_ENABLED());
#endif
    auto on_complete = [self,
                        batch_data,
                        state
#if YUME_ENABLE_DEV_DIAGNOSTICS
                        , tls_write_timer
#endif
                       ](const boost::system::error_code& ec,
                                     std::size_t bytes) mutable {
        // Settle first. Everything after this allocates — diagnostics, read
        // resumption, the error message — and a throw there escapes into the
        // executor, so nothing that can fail may run while the batch is still
        // unanswered.
        self->settle_write_batch_on_strand(state, ec, bytes);
#if YUME_ENABLE_DEV_DIAGNOSTICS
        try {
            YUME_TIMING_LOG(
                "server.tls", "write",
                "session=" + std::to_string(self->session_id_) +
                " bytes=" + std::to_string(bytes) +
                " requested=" + std::to_string(batch_data->size()) +
                " us=" + std::to_string(tls_write_timer.elapsed_ns() / 1000U));
        } catch (...) {
            // Diagnostics never decide whether the session keeps running.
        }
#endif
        // This batch is no longer in flight whatever happened to it. Only the
        // success path below starts another, and it sets the flag again; a
        // failure that left it set would block the close from finishing until
        // the close deadline fired.
        self->write_in_flight_ = false;
        if (!ec) {
            try {
                self->maybe_resume_inbound_reads_on_strand();
            } catch (...) {
                // Resuming reads is best effort; the next dispatch below is
                // what keeps the queue moving.
            }
        }
        if (ec) {
            if (self->close_state_ != CloseState::Open && is_expected_close_ec(ec)) {
                self->shutdown_transport();
                return;
            }
            // No further dispatch happens after a failed write, so the
            // writes still queued behind this batch have no other owner.
            self->fail_queued_writes_on_strand(ec);
            // Building the description allocates. Closing is the obligation;
            // describing the cause is not allowed to prevent it.
            try {
                std::string error_msg =
                    "frame write failed: " + describe_error_code(ec);
                if (ec.category().name() == std::string("ssl") ||
                    ec == boost::asio::ssl::error::stream_truncated) {
                    error_msg = "SSL/TLS write error: " + error_msg +
                                " [client must reconnect]";
                }
                self->close_with_reason(error_msg);
            } catch (...) {
                self->close_with_reason(kWriteDispatchFailed);
            }
            return;
        }
        self->do_write();
    };

    auto fire_write = [self, batch_data, state,
                       on_complete = std::move(on_complete)]() mutable {
        try {
            boost::asio::async_write(
                self->stream_, boost::asio::buffer(*batch_data),
                boost::asio::bind_executor(self->strand_,
                                           std::move(on_complete)));
        } catch (...) {
            // The write never started, so nothing will complete it. Settle
            // the batch here and close instead of stalling the queue behind
            // a write_in_flight_ that no completion will ever clear.
            self->write_in_flight_ = false;
            self->settle_write_batch_on_strand(
                state, boost::asio::error::no_buffer_space, 0);
            try {
                self->close_with_reason(kWriteDispatchFailed);
            } catch (...) {
            }
        }
    };

    // Per-batch send-side jitter. Defers the actual async_write by a
    // uniform random 0..obfs_jitter_ms delay. Because do_write() is
    // strand-serialised and the next do_write() only fires from
    // on_complete, the delay propagates: each batch is offset
    // independently. This is what defeats the "every keepalive arrives
    // T ms after the last" ML feature. Opt-in via --obfs-jitter-ms; 0 =
    // no delay, no timer overhead.
    std::chrono::milliseconds delay_ms = reserve_egress_delay(batch_data ? batch_data->size() : 0);
    if (cfg_.obfs_jitter_ms > 0) {
        thread_local std::mt19937 jitter_rng{std::random_device{}()};
        std::uniform_int_distribution<std::uint32_t> dist(0, cfg_.obfs_jitter_ms);
        delay_ms += std::chrono::milliseconds(dist(jitter_rng));
    }
    if (delay_ms.count() <= 0) {
        fire_write();
        return;
    }
    // The delay timer belongs to the session so close can cancel it. A
    // cancelled or failed wait never starts the write, so it settles the
    // batch it was holding rather than destroying those completions. Only one
    // batch is ever delayed at a time: write_in_flight_ stays set until the
    // completion runs, and the next dispatch only starts from there.
    delayed_write_timer_.expires_after(delay_ms);
    delayed_write_timer_.async_wait(boost::asio::bind_executor(
        strand_,
        [self, state, fire_write = std::move(fire_write)](
            const boost::system::error_code& ec) mutable {
            if (!ec) {
                fire_write();
                return;
            }
            self->write_in_flight_ = false;
            self->settle_write_batch_on_strand(
                state, boost::asio::error::operation_aborted, 0);
            if (self->close_state_ == CloseState::Open) {
                // Still usable, so the queue behind this batch keeps its
                // ordinary dispatch.
                self->do_write();
                return;
            }
            // Closing. Dispatch only resumes from a write completion, and
            // this batch produced none, so the rest of the queue has no
            // other owner left.
            self->fail_queued_writes_on_strand(
                boost::asio::error::operation_aborted);
            self->maybe_finish_close();
        }));
}

}  // namespace yume::server
