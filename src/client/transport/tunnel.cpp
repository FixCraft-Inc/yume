/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/transport/tunnel.hpp"

#include <chrono>
#include <limits>
#include <utility>

#include "client/proxy/forward.hpp"
#include "util.hpp"
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/write.hpp>

namespace yume::client {

Tunnel::Tunnel(ClientTransportStream&& stream,
               std::unique_ptr<obfs::H2Carrier> carrier,
               Bytes prefetched_carrier_bytes,
               std::unique_ptr<ratchet::SessionRatchet> ratchet)
    : stream_(std::move(stream))
    , strand_(stream_.get_executor())
    , carrier_(std::move(carrier))
    , prefetched_carrier_bytes_(std::move(prefetched_carrier_bytes)) {
    read_buf_.resize(util::relay_read_buf_size());
    // Not pinned: see the matching note in server/session/session.cpp. An
    // explicit SO_RCVBUF/SO_SNDBUF disables Linux window autotuning and caps
    // throughput far below the bandwidth-delay product on a delayed path.
    if (ratchet) core_.set_ratchet(std::move(ratchet));
#if YUME_ENABLE_DEV_DIAGNOSTICS
    if (YUME_TIMING_ENABLED()) {
        core_.set_timing_handler(
            [](const std::string& component,
               const std::string& event,
               const std::string& details) {
                YUME_TIMING_LOG(component, event, details);
            });
    }
#endif
    core_.set_write_handler([this](std::shared_ptr<Bytes> data, TransportCore::WriteCompletion completion) {
        auto self = shared_from_this();
        boost::asio::post(
            strand_,
            [self, data = std::move(data), completion = std::move(completion)]() mutable {
                if (self->closed_.load(std::memory_order_relaxed)) {
                    if (completion) {
                        completion(false, 0, "transport closed");
                    }
                    return;
                }
                if (self->carrier_) {
                    const std::size_t application_bytes = data->size();
                    if (!self->carrier_->SendBinary(*data)) {
                        if (completion) {
                            completion(false, 0, self->carrier_->error());
                        }
                        self->close_all("H2 carrier write failed: " +
                                        self->carrier_->error());
                        return;
                    }
                    self->carrier_completions_.push_back(
                        {std::move(completion), application_bytes});
                    self->flush_carrier_output();
                    return;
                }
                self->enqueue_wire_write(
                    std::move(data),
                    [completion = std::move(completion)](
                        const boost::system::error_code& ec,
                        std::size_t bytes) mutable {
                        if (completion) {
                            completion(!ec, bytes,
                                       ec ? ec.message() : std::string{});
                        }
                    });
            });
    });
    core_.set_close_transport_handler([this](const std::string& reason) {
        auto self = shared_from_this();
        boost::asio::post(self->strand_, [self, reason]() {
            self->close_all(reason);
        });
    });
    core_.set_server_stream_open_handler([this](uint8_t stream_id,
                                                const std::string& host,
                                                int port,
                                                std::string* reason) {
        if (!allow_server_streams_.load(std::memory_order_relaxed)) {
            if (reason) {
                *reason = "peer-initiated streams are disabled";
            }
            return false;
        }
        auto session = std::make_shared<ReverseForwardSession>(shared_from_this(), stream_id, host, port);
        if (!session->start()) {
            if (reason) {
                *reason = "stream id registration failed";
            }
            return false;
        }
        return true;
    });
}

void Tunnel::start() {
    if (carrier_) {
        std::weak_ptr<Tunnel> weak = weak_from_this();
        core_.set_inbound_credit_release_handler(
            [weak = std::move(weak)](std::size_t bytes) {
                if (auto self = weak.lock()) {
                    self->release_inbound_credit(bytes);
                }
            });
    }
    core_.start();
    if (!carrier_) {
        schedule_keepalive();
    } else if (!prefetched_carrier_bytes_.empty()) {
        core_.feed_tls_bytes(prefetched_carrier_bytes_.data(),
                             prefetched_carrier_bytes_.size(),
                             prefetched_carrier_bytes_.size());
        prefetched_carrier_bytes_.clear();
    }
    if (carrier_) schedule_ratchet_check();
    read_tls();
}

void Tunnel::set_inner_key(const Bytes& key) {
    core_.set_inner_key(key);
}

void Tunnel::set_obfs_shape(std::uint16_t pad_multiple, std::uint32_t jitter_ms_max) {
    core_.set_obfs_shape(pad_multiple, jitter_ms_max);
    obfs_jitter_ms_max_.store(jitter_ms_max, std::memory_order_relaxed);
}

void Tunnel::set_server_in_charge(bool enabled) {
    core_.set_server_in_charge(enabled);
}

void Tunnel::set_allow_exec(bool enabled) {
    if (enabled) {
        util::log_warn(
            "inbound remote command execution remains disabled because "
            "child-process shutdown is not bounded");
    }
    core_.set_allow_exec(false);
}

void Tunnel::set_allow_server_streams(bool allowed) {
    allow_server_streams_.store(allowed, std::memory_order_relaxed);
}

void Tunnel::set_reverse_handler(ReverseOpenHandler handler) {
    core_.set_reverse_handler(std::move(handler));
}

void Tunnel::set_close_handler(TunnelCloseHandler handler) {
    std::lock_guard<std::mutex> lock(close_handler_mu_);
    close_handler_ = std::move(handler);
}

void Tunnel::set_control_handler(ControlHandler handler) {
    core_.set_control_handler(std::move(handler));
}

void Tunnel::set_inbound_open_handler(InboundOpenHandler handler) {
    core_.set_inbound_open_handler(std::move(handler));
}

void Tunnel::set_activity_handler(ActivityHandler handler) {
    core_.set_activity_handler(std::move(handler));
}

boost::asio::any_io_executor Tunnel::get_executor() {
    return stream_.get_executor();
}

uint8_t Tunnel::reserve_stream_id() {
    return core_.reserve_stream_id();
}

bool Tunnel::register_stream(uint8_t stream_id,
                             DataHandler on_data,
                             CloseHandler on_close,
                             HalfCloseHandler on_half_close) {
    return core_.register_stream(stream_id, std::move(on_data),
                                 std::move(on_close),
                                 std::move(on_half_close));
}

void Tunnel::unregister_stream(uint8_t stream_id) {
    core_.unregister_stream(stream_id);
}

void Tunnel::retire_stream_id(uint8_t stream_id) {
    core_.retire_stream_id(stream_id);
}

void Tunnel::release_reserved_stream(uint8_t stream_id) {
    core_.release_reserved_stream(stream_id);
}

void Tunnel::open_stream(uint8_t stream_id,
                         const std::string& host,
                         int port,
                         OpenHandler handler,
                         const std::string& proto) {
    core_.open_stream(stream_id, host, port, std::move(handler), proto);
}

void Tunnel::open_relay_stream(uint8_t stream_id, const nlohmann::json& payload, OpenHandler handler) {
    core_.open_relay_stream(stream_id, payload, std::move(handler));
}

void Tunnel::request_remote_listen(uint8_t listen_id,
                                   const std::string& bind_host,
                                   int port,
                                   OpenHandler handler,
                                   bool reclaim,
                                   int min_port,
                                   int max_port) {
    core_.request_remote_listen(listen_id, bind_host, port, std::move(handler), reclaim, min_port, max_port);
}

void Tunnel::stop(const std::string& reason) {
    auto self = shared_from_this();
    boost::asio::post(strand_, [self, reason]() {
        self->close_all(reason);
    });
}

void Tunnel::cancel_runtime_operations(const std::string& reason) {
    auto close_callbacks = core_.shutdown();
    for (auto& callback : close_callbacks) {
        if (!callback) continue;
        try {
            callback(reason);
        } catch (...) {
            // Teardown must continue settling every registered operation even
            // when an embedder-provided close callback misbehaves.
        }
    }
}

void Tunnel::send_data(uint8_t stream_id, const Bytes& data) {
    core_.send_data(stream_id, data);
}

void Tunnel::send_data(uint8_t stream_id, Bytes&& data) {
    core_.send_data(stream_id, std::move(data));
}

void Tunnel::send_data(uint8_t stream_id,
                       Bytes&& data,
                       TransportCore::WriteCompletion completion) {
    core_.send_data(stream_id, std::move(data), std::move(completion));
}

bool Tunnel::try_send_data(uint8_t stream_id,
                           Bytes&& data,
                           TransportCore::WriteCompletion completion) {
    return core_.try_send_data(
        stream_id, std::move(data), std::move(completion));
}

TransportCore::DataWriteAdmission Tunnel::wait_send_data(
    uint8_t stream_id,
    Bytes&& data,
    std::chrono::milliseconds timeout,
    TransportCore::WriteCompletion completion) {
    return core_.wait_send_data(
        stream_id, std::move(data), timeout, std::move(completion));
}

void Tunnel::send_close(uint8_t stream_id, const std::string& reason) {
    core_.send_close(stream_id, reason);
}

void Tunnel::send_stream_fin(uint8_t stream_id, const std::string& reason) {
    core_.send_stream_fin(stream_id, reason);
}

void Tunnel::send_open_ack(uint8_t stream_id, bool ok, const std::string& reason) {
    core_.send_open_ack(stream_id, ok, reason);
}

void Tunnel::send_exec(uint8_t stream_id, const std::string& command) {
    core_.send_exec(stream_id, command);
}

void Tunnel::send_control_json(const nlohmann::json& json) {
    core_.send_control_json(json);
}

void Tunnel::read_tls() {
    auto self = shared_from_this();
    stream_.async_read_some(
        boost::asio::buffer(read_buf_),
        boost::asio::bind_executor(
            strand_,
            [self](const boost::system::error_code& ec, std::size_t bytes) {
                self->on_read_tls(ec, bytes);
            }));
}

void Tunnel::on_read_tls(const boost::system::error_code& ec, std::size_t bytes) {
    if (ec) {
        if (orderly_close_pending_) {
            // A transport EOF is not proof that the peer returned a valid
            // WebSocket CLOSE. Keep the terminal write alive until its
            // completion or the one bounded orderly-close timer fires.
            return;
        }
        close_all("read failed: " + ec.message());
        return;
    }
    if (bytes > 0) {
        bytes_in_.fetch_add(bytes, std::memory_order_relaxed);
        if (carrier_) {
            carrier_->Feed(read_buf_.data(), bytes);
            if (carrier_->failed()) {
                close_all("H2 carrier read failed: " + carrier_->error());
                return;
            }
            Bytes decoded = carrier_->TakeTunnelBytes();
            if (!decoded.empty()) {
                core_.feed_tls_bytes(
                    decoded.data(), decoded.size(), decoded.size());
            }
            flush_carrier_output();
            if (carrier_->carrier_closed()) {
                if (orderly_close_pending_) {
                    observe_orderly_peer_close();
                    return;
                }
                close_all("H2 carrier closed");
                return;
            }
        } else {
            core_.feed_tls_bytes(read_buf_.data(), bytes);
        }
    }
    if (!closed_.load(std::memory_order_relaxed)) {
        read_tls();
    }
}

void Tunnel::enqueue_wire_write(std::shared_ptr<Bytes> data,
                                WireCompletion completion) {
    if (!data || data->empty()) {
        if (completion) completion({}, 0);
        return;
    }
    wire_writes_.push_back({std::move(data), std::move(completion)});
    if (!wire_write_active_) start_wire_write();
}

void Tunnel::start_wire_write() {
    if (wire_write_active_ || wire_writes_.empty() ||
        closed_.load(std::memory_order_relaxed)) {
        return;
    }
    wire_write_active_ = true;
    auto self = shared_from_this();
    auto data = wire_writes_.front().data;
#if YUME_ENABLE_DEV_DIAGNOSTICS
    diagnostics::Stopwatch write_timer(YUME_TIMING_ENABLED());
#endif
    boost::asio::async_write(
        stream_, boost::asio::buffer(*data),
        boost::asio::bind_executor(
            strand_, [self, data
#if YUME_ENABLE_DEV_DIAGNOSTICS
                      , write_timer
#endif
                     ](const boost::system::error_code& ec,
                                  std::size_t bytes) {
                self->wire_write_active_ = false;
                if (!ec && bytes > 0) {
                    self->bytes_out_.fetch_add(bytes,
                                               std::memory_order_relaxed);
                }
#if YUME_ENABLE_DEV_DIAGNOSTICS
                YUME_TIMING_LOG(
                    "client.tls", "write",
                    "bytes=" + std::to_string(bytes) +
                    " requested=" + std::to_string(data->size()) +
                    " us=" + std::to_string(write_timer.elapsed_ns() / 1000U));
#endif
                WireCompletion completion;
                if (!self->wire_writes_.empty()) {
                    completion = std::move(self->wire_writes_.front().completion);
                    self->wire_writes_.pop_front();
                }
                if (completion) completion(ec, bytes);
                if (ec) {
                    self->complete_carrier_writes(
                        self->carrier_completions_.size(), false, ec.message());
                    self->close_all("write failed: " + ec.message());
                    return;
                }
                self->start_wire_write();
            }));
}

void Tunnel::flush_carrier_output() {
    if (!carrier_ || carrier_->failed()) return;
    Bytes output = carrier_->TakeOutbound();
    if (output.empty()) return;
    const std::size_t completion_count =
        carrier_->queued_output_bytes() == 0 ? carrier_completions_.size() : 0;
    auto data = std::make_shared<Bytes>(std::move(output));
    auto self = shared_from_this();
    enqueue_wire_write(
        std::move(data),
        [self, completion_count](const boost::system::error_code& ec,
                                 std::size_t) {
            self->complete_carrier_writes(
                completion_count, !ec, ec ? ec.message() : std::string{});
        });
}

void Tunnel::complete_carrier_writes(std::size_t count,
                                     bool ok,
                                     const std::string& error) {
    count = std::min(count, carrier_completions_.size());
    while (count-- > 0) {
        CarrierCompletion pending = std::move(carrier_completions_.front());
        carrier_completions_.pop_front();
        if (pending.completion) {
            pending.completion(ok, ok ? pending.application_bytes : 0, error);
        }
    }
}

void Tunnel::release_inbound_credit(std::size_t bytes) {
    if (bytes == 0U) {
        return;
    }
    if (!strand_.running_in_this_thread()) {
        boost::asio::post(
            strand_, [self = shared_from_this(), bytes]() {
                self->release_inbound_credit(bytes);
            });
        return;
    }
    if (!carrier_ || closed_.load(std::memory_order_relaxed) ||
        inbound_credit_release_failed_) {
        return;
    }
    if (bytes > std::numeric_limits<std::size_t>::max() -
                    pending_inbound_credit_bytes_) {
        inbound_credit_release_failed_ = true;
        close_all("H2 receive-credit release overflow");
        return;
    }
    pending_inbound_credit_bytes_ += bytes;
    if (inbound_credit_release_scheduled_) {
        return;
    }
    inbound_credit_release_scheduled_ = true;
    boost::asio::post(strand_, [self = shared_from_this()] {
        self->flush_inbound_credit_on_strand();
    });
}

void Tunnel::flush_inbound_credit_on_strand() {
    if (!inbound_credit_release_scheduled_) {
        return;
    }
    inbound_credit_release_scheduled_ = false;
    const std::size_t bytes =
        std::exchange(pending_inbound_credit_bytes_, 0U);
    if (bytes == 0U || !carrier_ ||
        closed_.load(std::memory_order_relaxed) ||
        inbound_credit_release_failed_) {
        return;
    }
    if (!carrier_->ConsumeTunnelBytes(bytes)) {
        inbound_credit_release_failed_ = true;
        close_all("H2 receive-credit release failed: " + carrier_->error());
        return;
    }
    flush_carrier_output();
}

void Tunnel::observe_orderly_peer_close() {
    if (!orderly_close_pending_) return;
    orderly_close_peer_closed_ = true;
    if (orderly_close_write_complete_) {
        finish_close(orderly_close_reason_);
    }
}

void Tunnel::record_orderly_close_wire_result(bool completed) noexcept {
    if (orderly_close_wire_result_recorded_) return;
    orderly_close_wire_result_recorded_ = true;
    if (carrier_) carrier_->RecordCloseWireResult(completed);
}

void Tunnel::complete_orderly_close_write(
        const boost::system::error_code& error,
        std::size_t written,
        std::size_t expected) {
    if (!orderly_close_pending_) return;
    const bool complete = !error && written == expected;
    if (!error && written != 0) {
        bytes_out_.fetch_add(written, std::memory_order_relaxed);
    }
    record_orderly_close_wire_result(complete);
    orderly_close_write_complete_ = complete;
    wire_write_active_ = false;
    if (!complete || orderly_close_peer_closed_) {
        finish_close(orderly_close_reason_);
        return;
    }
    start_wire_write();
}

void Tunnel::handle_orderly_close_timeout(
        const boost::system::error_code& error) {
    if (error || !orderly_close_pending_) return;
    // If the terminal write itself did not complete within the bounded close
    // window, the wire observation must fail closed. A completed write keeps
    // its truthful result even when the peer never returns a CLOSE.
    if (!orderly_close_write_complete_) {
        record_orderly_close_wire_result(false);
    }
    finish_close(orderly_close_reason_);
}

void Tunnel::close_all(const std::string& reason) {
    if (closed_.load(std::memory_order_relaxed) || orderly_close_pending_) {
        return;
    }

    // Evidence capture keeps the read side alive briefly after the terminal
    // write so the peer's WebSocket CLOSE can be observed. The bounded timer
    // prevents an unresponsive peer from delaying shutdown indefinitely.
    if (carrier_ && carrier_->capture_observer_active() &&
        reason != "interrupt" && !wire_write_active_ &&
        wire_writes_.empty()) {
        orderly_close_pending_ = true;
        orderly_close_write_complete_ = false;
        orderly_close_peer_closed_ = carrier_->carrier_closed();
        orderly_close_wire_result_recorded_ = false;
        orderly_close_reason_ = reason;
        auto self = shared_from_this();
        close_timer_.expires_after(std::chrono::milliseconds(750));
        close_timer_.async_wait(boost::asio::bind_executor(
            strand_, [self](const boost::system::error_code& timer_error) {
                self->handle_orderly_close_timeout(timer_error);
            }));
        carrier_->GracefulClose();
        Bytes close_wire = carrier_->TakeOutbound();
        if (!close_wire.empty() && !carrier_->failed()) {
            auto data = std::make_shared<Bytes>(std::move(close_wire));
            // Serialize any H2 reply produced by the read path behind this
            // terminal write. The peer can schedule its response before our
            // completion handler runs even though it has received the bytes.
            wire_write_active_ = true;
            boost::asio::async_write(
                stream_, boost::asio::buffer(*data),
                boost::asio::bind_executor(
                    strand_, [self, data](
                        const boost::system::error_code& write_error,
                        std::size_t written) {
                        self->complete_orderly_close_write(
                            write_error, written, data->size());
                    }));
            return;
        }
        record_orderly_close_wire_result(false);
        finish_close(reason);
        return;
    }

    // Preserve the ordinary production close path when no evidence observer
    // is attached. Existing callers may stop their io_context immediately
    // after posting stop(), so this small terminal write remains synchronous.
    if (carrier_ && !carrier_->capture_observer_active() &&
        reason != "interrupt" && !wire_write_active_ &&
        wire_writes_.empty()) {
        carrier_->GracefulClose();
        Bytes close_wire = carrier_->TakeOutbound();
        if (!close_wire.empty() && !carrier_->failed()) {
            boost::system::error_code close_write_ec;
            const std::size_t written = boost::asio::write(
                stream_, boost::asio::buffer(close_wire), close_write_ec);
            if (!close_write_ec) {
                bytes_out_.fetch_add(written, std::memory_order_relaxed);
            }
        }
    }

    finish_close(reason);
}

void Tunnel::finish_close(const std::string& reason) {
    if (closed_.exchange(true, std::memory_order_relaxed)) return;
    if (orderly_close_pending_ && !orderly_close_wire_result_recorded_) {
        record_orderly_close_wire_result(false);
    }
    orderly_close_pending_ = false;
    close_timer_.cancel();

#if YUME_ENABLE_DEV_DIAGNOSTICS
    if (carrier_ && YUME_TIMING_ENABLED()) {
        const auto stats = carrier_->stats();
        YUME_TIMING_LOG(
            "client.carrier", "summary",
            obfs::FormatH2CarrierStats(stats));
    }
    if (YUME_TIMING_ENABLED()) {
        const auto stats = core_.ratchet_flow_stats();
        YUME_TIMING_LOG(
            "client.ratchet", "summary",
            "offers=" + std::to_string(stats.offer_count) +
            " application_blocks=" +
                std::to_string(stats.application_block_count) +
            " application_block_us=" +
                std::to_string(stats.application_block_us) +
            " max_pending=" +
                std::to_string(stats.max_pending_epochs) +
            " max_prepared=" +
                std::to_string(stats.max_prepared_epochs) +
            " max_depth=" + std::to_string(stats.max_total_depth));
    }
#endif

    auto close_callbacks = core_.shutdown();
    TunnelCloseHandler close_handler;
    {
        std::lock_guard<std::mutex> lock(close_handler_mu_);
        close_handler = std::move(close_handler_);
    }

    if (reason == "interrupt" || reason == "server closed" || reason == "server shutdown") {
        util::log_info("tunnel closed: " + reason);
    } else {
        util::log_warn("tunnel closed: " + reason);
    }
    keepalive_timer_.cancel();
    ratchet_timer_.cancel();
    complete_carrier_writes(carrier_completions_.size(), false, reason);
    const auto aborted = boost::asio::error::operation_aborted;
    for (auto& write : wire_writes_) {
        if (write.completion) write.completion(aborted, 0);
    }
    wire_writes_.clear();
    if (close_handler) {
        close_handler(reason);
    }
    for (auto& callback : close_callbacks) {
        callback(reason);
    }

    if (reason == "interrupt") {
        stream_.cancel_and_close();
        return;
    }
    stream_.shutdown_and_close();
}

void Tunnel::schedule_keepalive() {
    keepalive_timer_.expires_after(std::chrono::seconds(15));
    auto self = shared_from_this();
    keepalive_timer_.async_wait(boost::asio::bind_executor(
        strand_,
        [self](const boost::system::error_code& ec) {
            if (ec || self->closed_.load(std::memory_order_relaxed)) {
                return;
            }
            std::string close_reason;
            if (!self->core_.handle_keepalive_tick(std::chrono::steady_clock::now(), &close_reason)) {
                self->close_all(close_reason);
                return;
            }
            self->schedule_keepalive();
        }));
}

void Tunnel::schedule_ratchet_check() {
    ratchet_timer_.expires_after(std::chrono::milliseconds(250));
    auto self = shared_from_this();
    ratchet_timer_.async_wait(boost::asio::bind_executor(
        strand_, [self](const boost::system::error_code& ec) {
            if (ec || self->closed_.load(std::memory_order_relaxed)) return;
            if (self->core_.rekey_timed_out(std::chrono::steady_clock::now())) {
                self->close_all("YUME 2.0 rekey timeout");
                return;
            }
            self->schedule_ratchet_check();
        }));
}

}  // namespace yume::client
