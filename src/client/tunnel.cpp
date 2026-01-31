/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/tunnel.hpp"

#include <nlohmann/json.hpp>

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
    read_header();
}

void Tunnel::set_inner_key(const Bytes& key) {
    inner_key_ = key;
}

void Tunnel::set_reverse_handler(ReverseOpenHandler handler) {
    reverse_handler_ = std::move(handler);
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
        if (streams_.find(candidate) == streams_.end() && pending_open_.find(candidate) == pending_open_.end()) {
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

void Tunnel::open_stream(uint8_t stream_id, const std::string& host, int port, OpenHandler handler) {
    nlohmann::json json{{"host", host}, {"port", port}, {"proto", "tcp"}};
    const std::string payload_str = json.dump();
    Bytes payload(payload_str.begin(), payload_str.end());
    uint16_t flags = 0;
    if (inner_key_.has_value()) {
        payload = inner::encrypt_payload(*inner_key_, protocol::OPEN, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }

    pending_open_[stream_id] = std::move(handler);
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::OPEN, stream_id, flags}, payload};
    async_write_frame(frame);
}

void Tunnel::request_remote_listen(uint8_t listen_id, int port, OpenHandler handler) {
    nlohmann::json json{{"port", port}};
    std::string payload_str = json.dump();
    Bytes payload(payload_str.begin(), payload_str.end());
    uint16_t flags = 0;
    if (inner_key_.has_value()) {
        payload = inner::encrypt_payload(*inner_key_, protocol::RLISTEN, listen_id, payload);
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
        payload = inner::encrypt_payload(*inner_key_, protocol::DATA, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::DATA, stream_id, flags}, payload};
    async_write_frame(frame);
}

void Tunnel::send_close(uint8_t stream_id, const std::string& reason) {
    Bytes payload(reason.begin(), reason.end());
    uint16_t flags = 0;
    if (inner_key_.has_value()) {
        payload = inner::encrypt_payload(*inner_key_, protocol::CLOSE, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::CLOSE, stream_id, flags}, payload};
    async_write_frame(frame);
}

void Tunnel::send_open_ack(uint8_t stream_id, bool ok, const std::string& reason) {
    Bytes payload(reason.begin(), reason.end());
    uint16_t flags = ok ? protocol::kFlagOpenOk : 0;
    if (inner_key_.has_value()) {
        payload = inner::encrypt_payload(*inner_key_, protocol::OPEN, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::OPEN, stream_id, flags}, payload};
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
        close_all("read header failed");
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
        close_all("read payload failed");
        return;
    }

    protocol::Frame frame{current_header_, payload_buf_};
    handle_frame(frame);
}

void Tunnel::handle_frame(const protocol::Frame& frame) {
    const uint8_t stream_id = frame.header.stream_id;
    Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        try {
            payload = inner::decrypt_payload(*inner_key_, frame.header.type, stream_id, frame.payload);
        } catch (const std::exception& ex) {
            close_all(std::string("decrypt failed: ") + ex.what());
            return;
        }
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
        case protocol::DATA: {
            auto it = streams_.find(stream_id);
            if (it != streams_.end() && it->second.on_data) {
                it->second.on_data(payload);
            }
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
            break;
        }
        default:
            break;
    }

    read_header();
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
                                                                self->close_all("write failed");
                                                                return;
                                                            }
                                                            self->do_write();
                                                        }));
}

void Tunnel::close_all(const std::string& reason) {
    util::log_warn("tunnel closed: " + reason);
    for (auto& entry : streams_) {
        if (entry.second.on_close) {
            entry.second.on_close();
        }
    }
    streams_.clear();
    pending_open_.clear();

    boost::system::error_code ec;
    stream_.shutdown(ec);
    stream_.lowest_layer().close(ec);
}

}  // namespace yume::client
