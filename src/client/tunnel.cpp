/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/tunnel.hpp"

#include <array>
#include <cstdio>
#include <ctime>
#include <thread>

#include "client/forward.hpp"
#include "core/obfs_h2.hpp"
#include "core/obfs_signal.hpp"
#include "util.hpp"

namespace yume::client {

Tunnel::Tunnel(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>&& stream)
    : stream_(std::move(stream))
    , strand_(stream_.get_executor()) {
    core_.set_write_handler([this](std::shared_ptr<Bytes> data, TransportCore::WriteCompletion completion) {
        auto self = shared_from_this();
        boost::asio::post(
            strand_,
            [self, data = std::move(data), completion = std::move(completion)]() mutable {
                if (self->closed_) {
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
                        (void)self;
                        if (completion) {
                            completion(!ec, bytes, ec ? ec.message() : std::string{});
                        }
                    });
                boost::asio::async_write(
                    self->stream_,
                    boost::asio::buffer(*write_data),
                    std::move(write_handler));
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
    if (h2_carrier_enabled_) {
        send_h2_client_handshake_then_start();
    } else {
        read_tls();
    }
}

void Tunnel::enable_h2_carrier(const std::string& sni,
                               const std::string& secret,
                               const std::string& user_agent) {
    h2_carrier_enabled_ = true;
    h2_sni_ = sni;
    h2_secret_ = secret;
    h2_user_agent_ = user_agent.empty()
        ? std::string("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36")
        : user_agent;
}

void Tunnel::send_h2_client_handshake_then_start() {
    crypto::Bytes signal = obfs::derive_signal_key(h2_secret_);
    std::int64_t hour = static_cast<std::int64_t>(std::time(nullptr)) / 3600;
    std::string token = obfs::derive_path_token(signal, h2_sni_, hour);
    std::string nonce = obfs::random_nonce_hex();
    std::string path = obfs::build_path(token, nonce);
    crypto::Bytes hello = obfs::encode_client_handshake(h2_sni_, path, h2_user_agent_);
    h2_decoder_ = std::make_unique<obfs::H2InboundDecoder>(false);
    auto buf = std::make_shared<std::vector<uint8_t>>(hello.begin(), hello.end());
    auto self = shared_from_this();
    boost::asio::async_write(stream_, boost::asio::buffer(*buf),
                             boost::asio::bind_executor(strand_,
                                                        [self, buf](const boost::system::error_code& ec, std::size_t) {
                                                            if (ec) {
                                                                self->close_all("h2 carrier client write failed: " + ec.message());
                                                                return;
                                                            }
                                                            self->read_tls();
                                                        }));
}

void Tunnel::set_inner_key(const Bytes& key) {
    core_.set_inner_key(key);
}

void Tunnel::set_hop(bool enabled, std::uint32_t interval_ms, std::int64_t offset_ms) {
    core_.set_hop(enabled, interval_ms, offset_ms);
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

void Tunnel::register_stream(uint8_t stream_id, DataHandler on_data, CloseHandler on_close) {
    core_.register_stream(stream_id, std::move(on_data), std::move(on_close));
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

void Tunnel::send_close(uint8_t stream_id, const std::string& reason) {
    core_.send_close(stream_id, reason);
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
        if (h2_carrier_enabled_ && !h2_handshake_done_ && h2_decoder_) {
            h2_decoder_->feed(read_buf_.data(), bytes);
            if (h2_decoder_->failed()) {
                close_all("h2 carrier server response decode failed: " + h2_decoder_->error());
                return;
            }
            auto replies = h2_decoder_->take_outbound_replies();
            if (!replies.empty()) {
                auto buf = std::make_shared<std::vector<uint8_t>>(std::move(replies));
                auto self = shared_from_this();
                boost::asio::async_write(stream_, boost::asio::buffer(*buf),
                                         boost::asio::bind_executor(strand_,
                                                                    [self, buf](const boost::system::error_code&, std::size_t) {}));
            }
            if (h2_decoder_->headers_seen()) {
                std::vector<uint8_t> leftover;
                h2_decoder_->drain_inbound_buffer(&leftover);
                h2_handshake_done_ = true;
                h2_decoder_.reset();
                if (!leftover.empty()) {
                    core_.feed_tls_bytes(leftover.data(), leftover.size());
                }
            }
        } else {
            core_.feed_tls_bytes(read_buf_.data(), bytes);
        }
    }
    if (!closed_) {
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
    if (closed_) {
        return;
    }
    closed_ = true;

    auto close_callbacks = core_.shutdown();
    TunnelCloseHandler close_handler;
    {
        std::lock_guard<std::mutex> lock(close_handler_mu_);
        close_handler = close_handler_;
    }

    util::log_warn("tunnel closed: " + reason);
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
            if (ec || self->closed_) {
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
