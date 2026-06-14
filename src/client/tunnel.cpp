/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/tunnel.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <random>
#include <thread>

#include "client/forward.hpp"
#include "util.hpp"

namespace yume::client {

namespace {
constexpr int kSocketBufferBytes = 2 * 1024 * 1024;
}

Tunnel::Tunnel(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>&& stream)
    : stream_(std::move(stream))
    , strand_(stream_.get_executor()) {
    read_buf_.resize(util::relay_read_buf_size());
    boost::system::error_code recvbuf_ec;
    stream_.lowest_layer().set_option(boost::asio::socket_base::receive_buffer_size(kSocketBufferBytes), recvbuf_ec);
    boost::system::error_code sendbuf_ec;
    stream_.lowest_layer().set_option(boost::asio::socket_base::send_buffer_size(kSocketBufferBytes), sendbuf_ec);
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
                auto write_data = std::move(data);
                auto write_handler = boost::asio::bind_executor(
                    self->strand_,
                    [self, write_data, completion = std::move(completion)](
                        const boost::system::error_code& ec,
                        std::size_t bytes) mutable {
                        if (!ec && bytes > 0) {
                            self->bytes_out_.fetch_add(bytes,
                                std::memory_order_relaxed);
                        }
                        if (completion) {
                            completion(!ec, bytes, ec ? ec.message() : std::string{});
                        }
                    });
                auto fire = [self, write_data, write_handler = std::move(write_handler)]() mutable {
                    boost::asio::async_write(
                        self->stream_,
                        boost::asio::buffer(*write_data),
                        std::move(write_handler));
                };
                // Per-batch send-side jitter. The strand serialises
                // dispatches, so a delay on batch N delays the write
                // strand's next batch by the same amount — breaks the
                // tight inter-arrival ML signature without losing
                // payload ordering. 0 = bypass entirely.
                const std::uint32_t jitter_max =
                    self->obfs_jitter_ms_max_.load(std::memory_order_relaxed);
                if (jitter_max == 0) {
                    fire();
                    return;
                }
                thread_local std::mt19937 jitter_rng{std::random_device{}()};
                std::uniform_int_distribution<std::uint32_t> dist(0, jitter_max);
                const auto delay = std::chrono::milliseconds(dist(jitter_rng));
                auto timer = std::make_shared<boost::asio::steady_timer>(self->strand_);
                timer->expires_after(delay);
                timer->async_wait([timer, fire = std::move(fire)](const boost::system::error_code& ec) mutable {
                    if (!ec) fire();
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
    schedule_keepalive();
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
                                   int port,
                                   OpenHandler handler,
                                   bool reclaim,
                                   int min_port,
                                   int max_port) {
    core_.request_remote_listen(listen_id, port, std::move(handler), reclaim, min_port, max_port);
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
        core_.feed_tls_bytes(read_buf_.data(), bytes);
    }
    if (!closed_.load(std::memory_order_relaxed)) {
        read_tls();
    }
}

void Tunnel::start_exec(uint8_t stream_id, std::string command) {
    auto self = shared_from_this();
    std::thread([self, stream_id, command = std::move(command)]() {
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
    if (close_handler) {
        close_handler(reason);
    }
    for (auto& callback : close_callbacks) {
        callback(reason);
    }

    boost::system::error_code ec;
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

}  // namespace yume::client
