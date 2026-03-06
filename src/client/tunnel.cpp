/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/tunnel.hpp"

#include <cstdio>
#include <nlohmann/json.hpp>
#include <thread>

#include "client/forward.hpp"
#include "core/inner_crypto.hpp"
#include "core/protocol.hpp"
#include "util.hpp"

namespace yume::client {

namespace {
std::string payload_to_string(const std::vector<uint8_t>& payload) {
    return std::string(payload.begin(), payload.end());
}
}  // namespace

Tunnel::Tunnel(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>&& stream)
    : stream_(std::move(stream))
    , strand_(stream_.get_executor()) {}

void Tunnel::start() {
    last_pong_ = std::chrono::steady_clock::now();
    schedule_keepalive();
    read_header();
}

void Tunnel::set_inner_key(const Bytes& key) {
    inner_key_ = key;
}

void Tunnel::set_hop(bool enabled, std::uint32_t interval_ms, std::int64_t offset_ms) {
    hop_enabled_ = enabled;
    hop_interval_ms_ = interval_ms;
    hop_offset_ms_ = offset_ms;
}

void Tunnel::set_server_in_charge(bool enabled) {
    server_in_charge_ = enabled;
}

void Tunnel::set_allow_exec(bool enabled) {
    allow_exec_ = enabled;
}

void Tunnel::set_reverse_handler(ReverseOpenHandler handler) {
    reverse_handler_ = std::move(handler);
}

void Tunnel::set_close_handler(TunnelCloseHandler handler) {
    close_handler_ = std::move(handler);
}

boost::asio::any_io_executor Tunnel::get_executor() {
    return stream_.get_executor();
}

uint8_t Tunnel::reserve_stream_id() {
    for (int i = 0; i < 255; ++i) {
        uint8_t candidate = next_stream_id_++;
        if (candidate == 0) {
            candidate = next_stream_id_++;
        }
        if (streams_.find(candidate) == streams_.end() &&
            pending_open_.find(candidate) == pending_open_.end() &&
            pending_rlisten_.find(candidate) == pending_rlisten_.end() &&
            control_exec_.find(candidate) == control_exec_.end()) {
            return candidate;
        }
    }
    return 0;
}

void Tunnel::register_stream(uint8_t stream_id, DataHandler on_data, CloseHandler on_close) {
    streams_[stream_id] = StreamCallbacks{std::move(on_data), std::move(on_close)};
}

void Tunnel::unregister_stream(uint8_t stream_id) {
    streams_.erase(stream_id);
    pending_open_.erase(stream_id);
}

void Tunnel::open_stream(uint8_t stream_id, const std::string& host, int port, OpenHandler handler,
                         const std::string& proto) {
    nlohmann::json json{{"host", host}, {"port", port}, {"proto", proto}};
    const std::string payload_str = json.dump();
    Bytes payload(payload_str.begin(), payload_str.end());
    uint16_t flags = 0;
    if (inner_key_.has_value()) {
        payload = encrypt_inner_payload(protocol::OPEN, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }

    pending_open_[stream_id] = std::move(handler);
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::OPEN, stream_id, flags}, payload};
    async_write_frame(frame);
}

void Tunnel::request_remote_listen(uint8_t listen_id,
                                   int port,
                                   OpenHandler handler,
                                   bool reclaim,
                                   int min_port,
                                   int max_port) {
    nlohmann::json json{{"port", port}, {"reclaim", reclaim}};
    if (min_port > 0) {
        json["min_port"] = min_port;
    }
    if (max_port > 0) {
        json["max_port"] = max_port;
    }
    std::string payload_str = json.dump();
    Bytes payload(payload_str.begin(), payload_str.end());
    uint16_t flags = 0;
    if (inner_key_.has_value()) {
        payload = encrypt_inner_payload(protocol::RLISTEN, listen_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }
    pending_rlisten_[listen_id] = std::move(handler);
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::RLISTEN, listen_id, flags}, payload};
    async_write_frame(frame);
}

void Tunnel::send_data(uint8_t stream_id, const Bytes& data) {
    Bytes payload = data;
    uint16_t flags = 0;
    if (inner_key_.has_value()) {
        payload = encrypt_inner_payload(protocol::DATA, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::DATA, stream_id, flags}, payload};
    async_write_frame(frame);
}

void Tunnel::send_close(uint8_t stream_id, const std::string& reason) {
    Bytes payload(reason.begin(), reason.end());
    uint16_t flags = 0;
    if (inner_key_.has_value()) {
        payload = encrypt_inner_payload(protocol::CLOSE, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::CLOSE, stream_id, flags}, payload};
    async_write_frame(frame);
}

void Tunnel::send_open_ack(uint8_t stream_id, bool ok, const std::string& reason) {
    Bytes payload(reason.begin(), reason.end());
    uint16_t flags = ok ? protocol::kFlagOpenOk : 0;
    if (inner_key_.has_value()) {
        payload = encrypt_inner_payload(protocol::OPEN, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::OPEN, stream_id, flags}, payload};
    async_write_frame(frame);
}

void Tunnel::send_exec(uint8_t stream_id, const std::string& command) {
    Bytes payload(command.begin(), command.end());
    uint16_t flags = 0;
    if (inner_key_.has_value()) {
        payload = encrypt_inner_payload(protocol::EXEC, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::EXEC, stream_id, flags}, payload};
    async_write_frame(frame);
}

void Tunnel::read_header() {
    auto self = shared_from_this();
    boost::asio::async_read(stream_, boost::asio::buffer(header_buf_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec, std::size_t bytes) {
                                                           self->on_read_header(ec, bytes);
                                                       }));
}

void Tunnel::on_read_header(const boost::system::error_code& ec, std::size_t) {
    if (ec) {
        close_all("read header failed: " + ec.message());
        return;
    }

    uint32_t len = (static_cast<uint32_t>(header_buf_[0]) << 24) |
                   (static_cast<uint32_t>(header_buf_[1]) << 16) |
                   (static_cast<uint32_t>(header_buf_[2]) << 8) |
                   (static_cast<uint32_t>(header_buf_[3]));

    current_header_.len = len;
    current_header_.type = header_buf_[4];
    current_header_.stream_id = header_buf_[5];
    current_header_.flags = static_cast<uint16_t>(header_buf_[6] << 8) |
                            static_cast<uint16_t>(header_buf_[7]);

    payload_buf_.assign(len, 0);
    if (len == 0) {
        protocol::Frame frame{current_header_, {}};
        handle_frame(frame);
        return;
    }

    auto self = shared_from_this();
    boost::asio::async_read(stream_, boost::asio::buffer(payload_buf_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& e, std::size_t bytes) {
                                                           self->on_read_payload(e, bytes);
                                                       }));
}

void Tunnel::on_read_payload(const boost::system::error_code& ec, std::size_t) {
    if (ec) {
        close_all("read payload failed: " + ec.message());
        return;
    }

    protocol::Frame frame{current_header_, payload_buf_};
    handle_frame(frame);
}

void Tunnel::handle_frame(const protocol::Frame& frame) {
    const uint8_t stream_id = frame.header.stream_id;
    Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        Bytes decrypted;
        if (!decrypt_inner_payload(frame.header.type, stream_id, frame.payload, &decrypted)) {
            close_all("decrypt failed");
            return;
        }
        payload = std::move(decrypted);
    }
    switch (frame.header.type) {
        case protocol::OPEN: {
            auto it_listen = pending_rlisten_.find(stream_id);
            if (it_listen != pending_rlisten_.end()) {
                auto handler = std::move(it_listen->second);
                pending_rlisten_.erase(it_listen);
                if (frame.header.flags & protocol::kFlagOpenOk) {
                    handler(true, "");
                } else {
                    handler(false, payload_to_string(payload));
                }
                break;
            }
            auto it = pending_open_.find(stream_id);
            if (it != pending_open_.end()) {
                auto handler = std::move(it->second);
                pending_open_.erase(it);
                if (frame.header.flags & protocol::kFlagOpenOk) {
                    handler(true, "");
                } else {
                    handler(false, payload_to_string(payload));
                }
            }
            break;
        }
        case protocol::ROPEN: {
            if (reverse_handler_) {
                try {
                    auto json = nlohmann::json::parse(payload_to_string(payload));
                    uint8_t listen_id = static_cast<uint8_t>(json.value("listen_id", 0));
                    if (listen_id != 0) {
                        reverse_handler_(listen_id, stream_id);
                    }
                } catch (...) {
                }
            }
            break;
        }
        case protocol::SOPEN: {
            if (!server_in_charge_) {
                send_open_ack(stream_id, false, "server control disabled");
                break;
            }
            try {
                auto json = nlohmann::json::parse(payload_to_string(payload));
                std::string host = json.value("host", "");
                int port = json.value("port", 0);
                std::string proto = json.value("proto", "tcp");
                if (host.empty() || port <= 0) {
                    send_open_ack(stream_id, false, "invalid control target");
                    break;
                }
                if (proto != "tcp") {
                    send_open_ack(stream_id, false, "unsupported control proto");
                    break;
                }
                auto session = std::make_shared<ReverseForwardSession>(shared_from_this(), stream_id, host, port);
                control_sessions_[stream_id] = session;
                session->start();
            } catch (...) {
                send_open_ack(stream_id, false, "invalid control payload");
            }
            break;
        }
        case protocol::DATA: {
            auto it = streams_.find(stream_id);
            if (it != streams_.end() && it->second.on_data) {
                it->second.on_data(payload);
            }
            break;
        }
        case protocol::EXEC: {
            if (!allow_exec_) {
                send_data(stream_id, Bytes({'E', 'X', 'E', 'C', ' ', 'd', 'e', 'n', 'i', 'e', 'd'}));
                send_close(stream_id, "exec denied");
                break;
            }
            if (streams_.find(stream_id) != streams_.end() ||
                pending_open_.find(stream_id) != pending_open_.end() ||
                pending_rlisten_.find(stream_id) != pending_rlisten_.end() ||
                control_exec_.find(stream_id) != control_exec_.end()) {
                send_close(stream_id, "exec stream id in use");
                break;
            }
            control_exec_.insert(stream_id);
            std::string cmd(payload.begin(), payload.end());
            auto self = shared_from_this();
            std::thread([self, stream_id, cmd]() {
#if defined(_WIN32)
                std::string exec_cmd = "cmd /C " + cmd;
                FILE* pipe = _popen(exec_cmd.c_str(), "r");
#else
                std::string exec_cmd = cmd + " 2>&1";
                FILE* pipe = popen(exec_cmd.c_str(), "r");
#endif
                if (!pipe) {
                    self->send_data(stream_id, Bytes({'E', 'X', 'E', 'C', ' ', 'f', 'a', 'i', 'l', 'e', 'd'}));
                    self->send_close(stream_id, "exec failed");
                    boost::asio::post(self->strand_, [self, stream_id]() { self->control_exec_.erase(stream_id); });
                    return;
                }
                std::array<char, 4096> buf{};
                while (true) {
                    size_t n = std::fread(buf.data(), 1, buf.size(), pipe);
                    if (n > 0) {
                        Tunnel::Bytes out(reinterpret_cast<uint8_t*>(buf.data()),
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
                boost::asio::post(self->strand_, [self, stream_id]() { self->control_exec_.erase(stream_id); });
            }).detach();
            break;
        }
        case protocol::CLOSE: {
            auto it = streams_.find(stream_id);
            if (it != streams_.end()) {
                if (it->second.on_close) {
                    it->second.on_close();
                }
                streams_.erase(it);
            }
            pending_open_.erase(stream_id);
            pending_rlisten_.erase(stream_id);
            control_sessions_.erase(stream_id);
            control_exec_.erase(stream_id);
            break;
        }
        case protocol::PING: {
            protocol::Frame pong{{0, protocol::PONG, 0, 0}, {}};
            async_write_frame(pong);
            break;
        }
        case protocol::PONG: {
            last_pong_ = std::chrono::steady_clock::now();
            break;
        }
        default:
            break;
    }

    read_header();
}

Tunnel::Bytes Tunnel::encrypt_inner_payload(uint8_t frame_type, uint8_t stream_id, const Bytes& input) {
    if (!inner_key_.has_value()) {
        return input;
    }
    if (!hop_enabled_ || hop_interval_ms_ == 0) {
        return inner::encrypt_payload(*inner_key_, frame_type, stream_id, input);
    }
    std::uint64_t hop_id = current_hop_id();
    Bytes hop_key = inner::derive_hop_key(*inner_key_, hop_id);
    return inner::encrypt_payload(hop_key, frame_type, stream_id, input);
}

bool Tunnel::decrypt_inner_payload(uint8_t frame_type, uint8_t stream_id, const Bytes& input, Bytes* output) {
    if (!output) {
        return false;
    }
    if (!inner_key_.has_value()) {
        *output = input;
        return true;
    }
    try {
        if (!hop_enabled_ || hop_interval_ms_ == 0) {
            *output = inner::decrypt_payload(*inner_key_, frame_type, stream_id, input);
            return true;
        }
        std::uint64_t hop_id = current_hop_id();
        std::uint64_t candidates[3] = {hop_id, hop_id > 0 ? hop_id - 1 : hop_id, hop_id + 1};
        for (std::size_t i = 0; i < 3; ++i) {
            std::uint64_t id = candidates[i];
            if (i == 1 && hop_id == 0) {
                continue;
            }
            Bytes hop_key = inner::derive_hop_key(*inner_key_, id);
            try {
                *output = inner::decrypt_payload(hop_key, frame_type, stream_id, input);
                return true;
            } catch (...) {
            }
        }
    } catch (...) {
    }
    return false;
}

std::uint64_t Tunnel::current_hop_id() const {
    if (!hop_enabled_ || hop_interval_ms_ == 0) {
        return 0;
    }
    return inner::hop_id_from_time_ms(util::now_ms(), hop_interval_ms_, hop_offset_ms_);
}

void Tunnel::async_write_frame(const protocol::Frame& frame,
                               std::function<void(const boost::system::error_code&, std::size_t)> handler) {
    auto data = std::make_shared<std::vector<uint8_t>>(protocol::encode_frame(
        static_cast<protocol::FrameType>(frame.header.type),
        frame.header.stream_id,
        frame.header.flags,
        frame.payload));

    boost::asio::post(strand_, [self = shared_from_this(), data, handler = std::move(handler)]() mutable {
        self->write_queue_.push_back({data, std::move(handler)});
        if (!self->write_in_flight_) {
            self->do_write();
        }
    });
}

void Tunnel::do_write() {
    if (write_queue_.empty()) {
        write_in_flight_ = false;
        return;
    }
    write_in_flight_ = true;

    auto& item = write_queue_.front();
    auto self = shared_from_this();
    boost::asio::async_write(stream_, boost::asio::buffer(*item.data),
                             boost::asio::bind_executor(strand_,
                                                        [self](const boost::system::error_code& ec, std::size_t bytes) {
                                                            auto item = std::move(self->write_queue_.front());
                                                            self->write_queue_.pop_front();
                                                            if (item.handler) {
                                                                item.handler(ec, bytes);
                                                            }
                                                            if (ec) {
                                                                self->close_all("write failed: " + ec.message());
                                                                return;
                                                            }
                                                            self->do_write();
                                                        }));
}

void Tunnel::close_all(const std::string& reason) {
    if (closed_) {
        return;
    }
    closed_ = true;
    util::log_warn("tunnel closed: " + reason);
    boost::system::error_code ec;
    keepalive_timer_.cancel();
    if (close_handler_) {
        close_handler_(reason);
    }
    for (auto& entry : streams_) {
        if (entry.second.on_close) {
            entry.second.on_close();
        }
    }
    streams_.clear();
    pending_open_.clear();
    pending_rlisten_.clear();
    control_sessions_.clear();
    control_exec_.clear();

    stream_.shutdown(ec);
    stream_.lowest_layer().close(ec);
}

void Tunnel::schedule_keepalive() {
    keepalive_timer_.expires_after(std::chrono::seconds(15));
    auto self = shared_from_this();
    keepalive_timer_.async_wait(boost::asio::bind_executor(
        strand_,
        [self](const boost::system::error_code& ec) {
            if (ec) {
                return;
            }
            auto now = std::chrono::steady_clock::now();
            if (now - self->last_pong_ > std::chrono::seconds(60)) {
                self->close_all("keepalive timeout");
                return;
            }
            protocol::Frame ping{{0, protocol::PING, 0, 0}, {}};
            self->async_write_frame(ping);
            self->schedule_keepalive();
        }));
}

}  // namespace yume::client
