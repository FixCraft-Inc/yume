/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * ----------------------------------------------------------------
 * Session upstream-stream I/O and the client-facing write path,
 * extracted verbatim from session.cpp:
 *   - upstream TCP read/write  (start/on_remote_read, *_remote_write,
 *                               shutdown/finish helpers)
 *   - upstream UDP read/write  (start/on_udp_read, *_udp_write)
 *   - egress pacing            (reserve_egress_delay)
 *   - frame write path         (async_write_frame, queue_frame_on_strand,
 *                               queue_encoded_write_on_strand, do_write,
 *                               inbound-read pause/resume backpressure)
 *
 * Same Session:: class, same wire output, no behavior change. Shared
 * helpers via server/session/internal.hpp.
 * ---------------------------------------------------------------- */

#include "server/session/session.hpp"
#include "server/runtime/manager.hpp"
#include "server/session/internal.hpp"

namespace yume::server {

using namespace detail;

namespace {

int frame_write_priority(uint8_t frame_type, std::size_t payload_size) {
    switch (frame_type) {
        case protocol::PING:
        case protocol::PONG:
        case protocol::CONTROL:
            return 0;
        case protocol::OPEN:
        case protocol::CLOSE:
        case protocol::RLISTEN:
        case protocol::ROPEN:
        case protocol::SOPEN:
        case protocol::EXEC:
            return 1;
        case protocol::DATA:
            return payload_size <= 4096 ? 2 : 3;
        default:
            return 4;
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
        remote->first_downstream_ms = util::now_ms();
        util::log_timing("server.stream",
                         "first_downstream",
                         "session=" + std::to_string(session_id_) +
                             " stream=" + std::to_string(stream_id) +
                             " proto=tcp ms=" +
                             std::to_string(remote->first_downstream_ms - remote->open_started_ms) +
                             " bytes=" + std::to_string(bytes));
    }

    crypto::Bytes payload(remote->read_buf.data(), remote->read_buf.data() + bytes);
    uint16_t flags = 0;
    if (inner_key_.has_value()) {
        payload = encrypt_inner_payload(protocol::DATA, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }

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
        udp->first_downstream_ms = util::now_ms();
        util::log_timing("server.stream",
                         "first_downstream",
                         "session=" + std::to_string(session_id_) +
                             " stream=" + std::to_string(stream_id) +
                             " proto=udp ms=" +
                             std::to_string(udp->first_downstream_ms - udp->open_started_ms) +
                             " bytes=" + std::to_string(bytes));
    }

    crypto::Bytes payload(udp->read_buf.data(), udp->read_buf.data() + bytes);
    uint16_t flags = 0;
    if (inner_key_.has_value()) {
        payload = encrypt_inner_payload(protocol::DATA, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }

    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::DATA, stream_id, flags}, std::move(payload)};
    queue_frame_on_strand(frame);
    start_udp_read(stream_id);
}

void Session::enqueue_udp_write(uint8_t stream_id, const crypto::Bytes& data) {
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
            udp->write_queue.push_back(data);
            udp->inbound_budget.record_enqueue(data.size());
            udp->upstream_bytes += static_cast<std::uint64_t>(data.size());
            if (udp->first_upstream_ms == 0) {
                udp->first_upstream_ms = util::now_ms();
                util::log_timing("server.stream",
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
    return manager_->reserve_egress_write(bandwidth_fair_key_, bandwidth_priority_, bytes);
}

void Session::do_udp_write(uint8_t stream_id) {
    std::shared_ptr<UdpStream> udp;
    crypto::Bytes data_to_write;
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
        const std::size_t queued_bytes = udp->write_queue.front().size();
        data_to_write = std::move(udp->write_queue.front());
        udp->write_queue.pop_front();
        udp->inbound_budget.record_dequeue(queued_bytes);
    }
    auto buffer = std::make_shared<crypto::Bytes>(std::move(data_to_write));
    auto self = shared_from_this();
    auto fire_write = [self, udp, buffer, stream_id]() {
        udp->socket.async_send(
            boost::asio::buffer(*buffer),
            boost::asio::bind_executor(
                self->strand_,
                [self, buffer, stream_id](const boost::system::error_code& ec, std::size_t) {
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

void Session::enqueue_remote_write(uint8_t stream_id, const std::vector<uint8_t>& data) {
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
            remote->write_queue.push_back(data);
            remote->inbound_budget.record_enqueue(data.size());
            remote->upstream_bytes += static_cast<std::uint64_t>(data.size());
            if (remote->first_upstream_ms == 0) {
                remote->first_upstream_ms = util::now_ms();
                util::log_timing("server.stream",
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
            const std::size_t queued_bytes = remote->write_queue.front().size();
            data_to_write = std::move(remote->write_queue.front());
            remote->write_queue.pop_front();
            remote->inbound_budget.record_dequeue(queued_bytes);
        }
    }

    if (data_to_write.empty()) {
        boost::system::error_code ec;
        remote->socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
        finish_remote_stream_if_done(stream_id);
        return;
    }

    auto buffer = std::make_shared<std::vector<uint8_t>>(std::move(data_to_write));
    auto self = shared_from_this();
    auto fire_write = [self, remote, buffer, stream_id]() {
        boost::asio::async_write(remote->socket, boost::asio::buffer(*buffer),
                                 boost::asio::bind_executor(self->strand_,
                                                            [self, buffer, stream_id](const boost::system::error_code& ec, std::size_t) {
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
            if (application && ratchet_->outbound_rekey_pending()) {
                if (ratchet_blocked_writes_.size() >= kMaxWriteQueueSize) {
                    if (handler) handler(boost::asio::error::no_buffer_space, 0);
                    close_with_reason("ratchet application queue overrun");
                    return;
                }
                ratchet_blocked_writes_.push_back(
                    {frame, std::move(handler)});
                return;
            }
            if (!already_protected && application &&
                ratchet_->ShouldStartRekey(
                    frame, std::chrono::steady_clock::now())) {
                protocol::Frame init = ratchet_->BeginOutboundRekey(
                    std::chrono::steady_clock::now());
                outbound_rekey_wait_started_ =
                    std::chrono::steady_clock::now();
                if (ratchet_blocked_writes_.size() >= kMaxWriteQueueSize) {
                    if (handler) handler(boost::asio::error::no_buffer_space, 0);
                    close_with_reason("ratchet application queue overrun");
                    return;
                }
                ratchet_blocked_writes_.push_back(
                    {frame, std::move(handler)});
                arm_ratchet_timeout_on_strand();
                queue_frame_on_strand(init, {}, true);
                return;
            }
            if (!already_protected) {
                const bool collect_timing = util::timing_enabled();
                const auto seal_started = collect_timing
                    ? std::chrono::steady_clock::now()
                    : std::chrono::steady_clock::time_point{};
                effective = ratchet_->Seal(
                    frame, std::chrono::steady_clock::now());
                if (collect_timing) {
                    timing_seal_ns_ += static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now() - seal_started).count());
                    ++timing_seal_frames_;
                }
                if (timing_seal_frames_ >= 64) {
                    if (util::timing_enabled()) {
                        util::log_timing(
                            "server.transport", "ratchet_seal",
                            "session=" + std::to_string(session_id_) +
                            " frames=" + std::to_string(timing_seal_frames_) +
                            " us=" + std::to_string(timing_seal_ns_ / 1000U));
                    }
                    timing_seal_ns_ = 0;
                    timing_seal_frames_ = 0;
                }
            } else if (frame.header.type != protocol::REKEY_INIT &&
                       frame.header.type != protocol::REKEY_ACK) {
                throw std::runtime_error("unexpected pre-protected frame type");
            }
        } catch (const std::exception& ex) {
            if (handler) handler(boost::asio::error::fault, 0);
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
    if (!ratchet_ || ratchet_->outbound_rekey_pending()) return;
    auto pending = std::move(ratchet_blocked_writes_);
    ratchet_blocked_writes_.clear();
    for (auto& write : pending) {
        if (close_state_ != CloseState::Open) {
            if (write.handler) {
                write.handler(boost::asio::error::operation_aborted, 0);
            }
            continue;
        }
        queue_frame_on_strand(write.frame, std::move(write.handler));
    }
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

void Session::queue_encoded_write_on_strand(
    std::shared_ptr<std::vector<uint8_t>> data,
    uint8_t frame_type,
    uint8_t stream_id,
    std::size_t payload_size,
    std::function<void(const boost::system::error_code&, std::size_t)> handler) {
    if (v2_h2_tunnel_active_) {
        if (!v2_h2_carrier_ || close_state_ != CloseState::Open) {
            if (handler) handler(boost::asio::error::operation_aborted, 0);
            return;
        }
        if (v2_h2_pending_app_writes_.size() >= kMaxWriteQueueSize) {
            if (handler) handler(boost::asio::error::no_buffer_space, 0);
            close_with_reason("v2 H2 application write queue overrun");
            return;
        }
        if (!v2_h2_carrier_->SendBinary(*data)) {
            if (handler) handler(boost::asio::error::fault, 0);
            close_with_reason("v2 H2 carrier write failed: " +
                              v2_h2_carrier_->error());
            return;
        }
        v2_h2_pending_app_writes_.push_back(
            {std::move(data), frame_type, stream_id, payload_size,
             std::move(handler)});
        flush_v2_h2_wire_on_strand();
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
        if (handler) {
            handler(boost::asio::error::operation_aborted, 0);
        }
        return;
    }

    if (write_queue_depth_ >= kMaxWriteQueueSize) {
        util::log_warn("session " + std::to_string(session_id_) +
                      ": write queue overflow (" + std::to_string(write_queue_depth_) +
                      " pending), closing to prevent SSL corruption");
        close_with_reason("write queue overrun - too many pending frames");
        if (handler) {
            handler(boost::asio::error::operation_aborted, 0);
        }
        return;
    }

    const bool was_empty = write_queues_[stream_id].empty();
    const std::size_t queued_bytes = data ? data->size() : 0;
    write_queues_[stream_id].push_back(
        {std::move(data), frame_type, stream_id, payload_size,
         std::move(handler)});
    ++write_queued_frames_;
    write_queued_bytes_ += queued_bytes;
    write_queue_depth_++;
    if (was_empty) {
        mark_write_stream_ready_on_strand(stream_id);
    }
    if (!write_in_flight_) {
        do_write();
    }
}

bool Session::should_pause_inbound_reads_on_strand() const {
    return close_state_ != CloseState::Open || write_queue_depth_ >= kWriteQueueHighWatermark;
}

void Session::maybe_resume_inbound_reads_on_strand() {
    if (close_state_ != CloseState::Open || write_queue_depth_ > kWriteQueueLowWatermark) {
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
    if (write_ready_priority_[stream_id] >= 0 ||
        write_queues_[stream_id].empty()) {
        return;
    }
    const auto& head = write_queues_[stream_id].front();
    const int priority = std::clamp(
        frame_write_priority(head.frame_type, head.payload_size), 0, 4);
    write_ready_priority_[stream_id] = static_cast<std::int8_t>(priority);
    write_ready_streams_[static_cast<std::size_t>(priority)].push_back(stream_id);
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
        for (std::size_t priority = 0;
             priority < write_ready_streams_.size(); ++priority) {
            auto& ready = write_ready_streams_[priority];
            const std::size_t candidates = ready.size();
            for (std::size_t i = 0; i < candidates; ++i) {
                const auto stream_id = ready.front();
                ready.pop_front();
                if (write_ready_priority_[stream_id] !=
                        static_cast<std::int8_t>(priority) ||
                    write_queues_[stream_id].empty()) {
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
                    write_ready_priority_[stream_id] = -1;
                    return stream_id;
                }
                ready.push_back(stream_id);
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

void Session::do_write() {
    if (write_queues_empty_on_strand()) {
        write_in_flight_ = false;
        if (close_state_ != CloseState::Open) {
            maybe_finish_close();
        }
        return;
    }
    write_in_flight_ = true;

    std::vector<PendingWrite> batch;
    std::size_t batch_count = 0;
    std::size_t total_bytes = 0;
    const bool collect_timing = util::timing_enabled();
    const auto selector_started = collect_timing
        ? std::chrono::steady_clock::now()
        : std::chrono::steady_clock::time_point{};
    std::unordered_set<uint8_t> batch_streams;
    while (!write_queues_empty_on_strand() &&
           batch_count < kMaxWriteBatchFrames) {
        const auto stream_id =
            select_next_write_on_strand(total_bytes, batch_streams);
        if (!stream_id.has_value()) {
            break;
        }
        PendingWrite write = pop_write_stream_head_on_strand(*stream_id);
        total_bytes += write.data ? write.data->size() : 0;
        batch_streams.insert(*stream_id);
        batch.push_back(std::move(write));
        ++batch_count;
    }
    if (batch_count == 0) {
        write_in_flight_ = false;
        return;
    }
    if (collect_timing) {
        const auto selector_us =
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - selector_started).count();
        util::log_timing(
            "server.transport", "write_batch",
            "session=" + std::to_string(session_id_) +
            " frames=" + std::to_string(batch_count) +
            " bytes=" + std::to_string(total_bytes) +
            " queue_depth=" + std::to_string(write_queue_depth_) +
            " queued_frames=" + std::to_string(write_queued_frames_) +
            " queued_bytes=" + std::to_string(write_queued_bytes_) +
            " selector_us=" + std::to_string(selector_us));
    }

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
    const auto tls_write_started = collect_timing
        ? std::chrono::steady_clock::now()
        : std::chrono::steady_clock::time_point{};
    auto on_complete = [self,
                        batch_data,
                        batch = std::move(batch),
                        batch_count,
                        tls_write_started,
                        collect_timing](const boost::system::error_code& ec,
                                     std::size_t bytes) mutable {
        if (collect_timing) {
            const auto tls_write_us =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - tls_write_started).count();
            util::log_timing(
                "server.tls", "write",
                "session=" + std::to_string(self->session_id_) +
                " bytes=" + std::to_string(bytes) +
                " requested=" + std::to_string(batch_data->size()) +
                " us=" + std::to_string(tls_write_us));
        }
        if (self->write_queue_depth_ >= batch_count) {
            self->write_queue_depth_ -= static_cast<uint32_t>(batch_count);
        } else {
            self->write_queue_depth_ = 0;
        }
        if (!ec) {
            self->maybe_resume_inbound_reads_on_strand();
        }
        for (auto& item : batch) {
            if (item.handler) {
                const std::size_t item_bytes = (!ec && item.data) ? item.data->size() : bytes;
                item.handler(ec, item_bytes);
            }
        }
        if (ec) {
            if (self->close_state_ != CloseState::Open && is_expected_close_ec(ec)) {
                self->shutdown_transport();
                return;
            }
            std::string error_msg = "frame write failed: " + describe_error_code(ec);
            if (ec.category().name() == std::string("ssl") ||
                ec == boost::asio::ssl::error::stream_truncated) {
                error_msg = "SSL/TLS write error: " + error_msg + " [client must reconnect]";
            }
            self->close_with_reason(error_msg);
            return;
        }
        self->do_write();
    };

    auto fire_write = [self, batch_data, on_complete = std::move(on_complete)]() mutable {
        boost::asio::async_write(self->stream_, boost::asio::buffer(*batch_data),
                                 boost::asio::bind_executor(self->strand_, std::move(on_complete)));
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
    auto timer = std::make_shared<boost::asio::steady_timer>(strand_);
    timer->expires_after(delay_ms);
    timer->async_wait([timer, fire_write = std::move(fire_write)](const boost::system::error_code& ec) mutable {
        if (!ec) fire_write();
    });
}

}  // namespace yume::server
