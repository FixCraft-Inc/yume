/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/transport/tunnel.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <thread>

#include "client/proxy/forward.hpp"
#include "util.hpp"

namespace yume::client {

namespace {
constexpr int kSocketBufferBytes = 2 * 1024 * 1024;
}

Tunnel::Tunnel(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>&& stream,
               std::unique_ptr<obfs::H2Carrier> carrier,
               Bytes prefetched_carrier_bytes,
               std::unique_ptr<ratchet::SessionRatchet> ratchet)
    : stream_(std::move(stream))
    , strand_(stream_.get_executor())
    , carrier_(std::move(carrier))
    , prefetched_carrier_bytes_(std::move(prefetched_carrier_bytes)) {
    read_buf_.resize(util::relay_read_buf_size());
    boost::system::error_code recvbuf_ec;
    stream_.lowest_layer().set_option(boost::asio::socket_base::receive_buffer_size(kSocketBufferBytes), recvbuf_ec);
    boost::system::error_code sendbuf_ec;
    stream_.lowest_layer().set_option(boost::asio::socket_base::send_buffer_size(kSocketBufferBytes), sendbuf_ec);
    if (ratchet) core_.set_ratchet(std::move(ratchet));
    if (util::timing_enabled()) {
        core_.set_timing_handler(
            [](const std::string& component,
               const std::string& event,
               const std::string& details) {
                util::log_timing(component, event, details);
            });
    }
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
                                                std::string*) {
        auto session = std::make_shared<ReverseForwardSession>(shared_from_this(), stream_id, host, port);
        session->start();
        return true;
    });
    core_.set_exec_handler([this](uint8_t stream_id, const std::string& command) {
        start_exec(stream_id, command);
    });
}

void Tunnel::start() {
    core_.start();
    if (!carrier_) {
        schedule_keepalive();
    } else if (!prefetched_carrier_bytes_.empty()) {
        core_.feed_tls_bytes(prefetched_carrier_bytes_.data(),
                             prefetched_carrier_bytes_.size());
        prefetched_carrier_bytes_.clear();
    }
    if (carrier_) schedule_ratchet_check();
    read_tls();
}

void Tunnel::set_inner_key(const Bytes& key) {
    core_.set_inner_key(key);
}

void Tunnel::set_hop(bool enabled, std::uint32_t interval_ms, std::int64_t offset_ms) {
    core_.set_hop(enabled, interval_ms, offset_ms);
}

void Tunnel::set_obfs_shape(std::uint16_t pad_multiple, std::uint32_t jitter_ms_max) {
    core_.set_obfs_shape(pad_multiple, jitter_ms_max);
    obfs_jitter_ms_max_.store(jitter_ms_max, std::memory_order_relaxed);
}

void Tunnel::set_server_in_charge(bool enabled) {
    core_.set_server_in_charge(enabled);
}

void Tunnel::set_allow_exec(bool enabled) {
    core_.set_allow_exec(enabled);
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

void Tunnel::register_stream(uint8_t stream_id,
                             DataHandler on_data,
                             CloseHandler on_close,
                             HalfCloseHandler on_half_close) {
    core_.register_stream(stream_id, std::move(on_data), std::move(on_close), std::move(on_half_close));
}

void Tunnel::unregister_stream(uint8_t stream_id) {
    core_.unregister_stream(stream_id);
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
                core_.feed_tls_bytes(decoded.data(), decoded.size());
            }
            flush_carrier_output();
            if (carrier_->carrier_closed()) {
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
    const bool collect_timing = util::timing_enabled();
    const auto write_started = collect_timing
        ? std::chrono::steady_clock::now()
        : std::chrono::steady_clock::time_point{};
    boost::asio::async_write(
        stream_, boost::asio::buffer(*data),
        boost::asio::bind_executor(
            strand_, [self, data, write_started, collect_timing](const boost::system::error_code& ec,
                                  std::size_t bytes) {
                self->wire_write_active_ = false;
                if (!ec && bytes > 0) {
                    self->bytes_out_.fetch_add(bytes,
                                               std::memory_order_relaxed);
                }
                if (collect_timing) {
                    const auto elapsed_us =
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - write_started).count();
                    util::log_timing(
                        "client.tls", "write",
                        "bytes=" + std::to_string(bytes) +
                        " requested=" + std::to_string(data->size()) +
                        " us=" + std::to_string(elapsed_us));
                }
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

void Tunnel::start_exec(uint8_t stream_id, std::string command) {
    std::uint32_t active = active_execs_.load(std::memory_order_relaxed);
    while (active < kMaxConcurrentExecs &&
           !active_execs_.compare_exchange_weak(
               active, active + 1,
               std::memory_order_acq_rel,
               std::memory_order_relaxed)) {
    }
    if (active >= kMaxConcurrentExecs) {
        send_data(stream_id, Bytes({'E', 'X', 'E', 'C', ' ', 'b', 'u', 's', 'y'}));
        send_close(stream_id, "exec concurrency limit reached");
        core_.release_reserved_stream(stream_id);
        return;
    }

    auto self = shared_from_this();
    std::thread([self, stream_id, command = std::move(command)]() {
        struct ExecSlotGuard {
            Tunnel* tunnel;
            ~ExecSlotGuard() {
                tunnel->active_execs_.fetch_sub(1, std::memory_order_acq_rel);
            }
        } slot{self.get()};
#if defined(_WIN32)
        std::string exec_cmd = "cmd /C " + command;
        FILE* pipe = _popen(exec_cmd.c_str(), "r");
#else
        std::string exec_cmd = command + " 2>&1";
        FILE* pipe = popen(exec_cmd.c_str(), "r");
#endif
        if (!pipe) {
            self->send_data(stream_id, Bytes({'E', 'X', 'E', 'C', ' ', 'f', 'a', 'i', 'l', 'e', 'd'}));
            self->send_close(stream_id, "exec failed");
            self->core_.release_reserved_stream(stream_id);
            return;
        }
        std::array<char, 4096> buf{};
        while (true) {
            size_t n = std::fread(buf.data(), 1, buf.size(), pipe);
            if (n > 0) {
                Bytes out(reinterpret_cast<uint8_t*>(buf.data()),
                          reinterpret_cast<uint8_t*>(buf.data()) + n);
                self->send_data(stream_id, out);
            }
            if (n < buf.size()) {
                break;
            }
        }
#if defined(_WIN32)
        _pclose(pipe);
#else
        pclose(pipe);
#endif
        self->send_close(stream_id, "exec done");
        self->core_.release_reserved_stream(stream_id);
    }).detach();
}

void Tunnel::close_all(const std::string& reason) {
    if (closed_.exchange(true, std::memory_order_relaxed)) {
        return;
    }

    // For an orderly locally initiated close, emit the captured Chrome H2
    // PING, masked WebSocket CLOSE, and GOAWAY before TLS close_notify. This is
    // a small terminal write and is only attempted after the normal output
    // queue has drained; error/interrupt paths still close immediately.
    if (carrier_ && reason != "interrupt" && !wire_write_active_ &&
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

    if (carrier_ && util::timing_enabled()) {
        const auto stats = carrier_->stats();
        util::log_timing(
            "client.carrier", "summary",
            "h2_feed_calls=" + std::to_string(stats.h2_feed_calls) +
            " h2_feed_bytes=" + std::to_string(stats.h2_feed_bytes) +
            " h2_feed_us=" + std::to_string(stats.h2_feed_ns / 1000U) +
            " h2_flush_calls=" + std::to_string(stats.h2_flush_calls) +
            " h2_flush_bytes=" + std::to_string(stats.h2_flush_bytes) +
            " h2_flush_us=" + std::to_string(stats.h2_flush_ns / 1000U) +
            " websocket_encode_bytes=" +
                std::to_string(stats.websocket_encode_bytes) +
            " websocket_encode_us=" +
                std::to_string(stats.websocket_encode_ns / 1000U) +
            " websocket_decode_bytes=" +
                std::to_string(stats.websocket_decode_bytes) +
            " websocket_decode_us=" +
                std::to_string(stats.websocket_decode_ns / 1000U));
    }

    auto close_callbacks = core_.shutdown();
    TunnelCloseHandler close_handler;
    {
        std::lock_guard<std::mutex> lock(close_handler_mu_);
        close_handler = close_handler_;
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

    boost::system::error_code ec;
    if (reason == "interrupt") {
        stream_.lowest_layer().cancel(ec);
        stream_.lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        stream_.lowest_layer().close(ec);
        return;
    }
    stream_.shutdown(ec);
    stream_.lowest_layer().close(ec);
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
