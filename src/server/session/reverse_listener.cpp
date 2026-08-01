/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/session.hpp"
#include "server/runtime/manager.hpp"
#include "server/session/internal.hpp"

namespace yume::server {

using namespace detail;

void Session::handle_rlisten(const protocol::Frame& frame) {
    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() &&
        (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        crypto::Bytes decrypted;
        if (decrypt_inner_payload(
                frame.header.type,
                frame.header.stream_id,
                frame.payload,
                &decrypted)) {
            payload = std::move(decrypted);
        } else {
            send_open_reply(
                frame.header.stream_id, false, "RLISTEN decrypt failed");
            return;
        }
    }
    std::string payload_str(payload.begin(), payload.end());
    int listen_port = 0;
    std::string bind_host;
    bool reclaim = false;
    int min_port = 0;
    int max_port = 0;
    try {
        auto json = nlohmann::json::parse(payload_str);
        listen_port = json.value("port", 0);
        bind_host = json.value("bind_host", std::string{});
        reclaim = json.value("reclaim", false);
        min_port = json.value("min_port", 0);
        max_port = json.value("max_port", 0);
    } catch (...) {
        send_open_reply(
            frame.header.stream_id, false, "invalid RLISTEN payload");
        return;
    }
    const bool auto_select_port =
        (listen_port <= 0) && (min_port > 0) && (max_port > 0);
    if (!auto_select_port) {
        if (listen_port <= 0) {
            send_open_reply(
                frame.header.stream_id, false, "invalid listen port");
            return;
        }
        if (listen_port < cfg_.reverse_port_min ||
            listen_port > cfg_.reverse_port_max) {
            send_open_reply(
                frame.header.stream_id,
                false,
                "listen port must be " +
                    std::to_string(cfg_.reverse_port_min) + "-" +
                    std::to_string(cfg_.reverse_port_max));
            return;
        }
    } else {
        if (min_port > max_port) {
            std::swap(min_port, max_port);
        }
        min_port = std::max(min_port, cfg_.reverse_port_min);
        max_port = std::min(max_port, cfg_.reverse_port_max);
        if (min_port > max_port) {
            min_port = cfg_.reverse_port_min;
            max_port = cfg_.reverse_port_max;
        }
    }
    if (reverse_listeners_.find(frame.header.stream_id) !=
        reverse_listeners_.end()) {
        send_open_reply(
            frame.header.stream_id, false, "listener exists");
        return;
    }

    boost::asio::ip::address bind_address;
    bool has_bind_address = false;
    if (!bind_host.empty()) {
        boost::system::error_code ec;
        bind_address = boost::asio::ip::make_address(bind_host, ec);
        if (ec) {
            send_open_reply(
                frame.header.stream_id,
                false,
                "bind address must be an IP literal");
            return;
        }
        has_bind_address = true;
    }

    bool reclaimed = false;
    std::string bind_error;
    auto try_bind_listener =
        [&](int candidate_port,
            std::shared_ptr<boost::asio::ip::tcp::acceptor>* out_acceptor)
        -> bool {
        if (reclaim && manager_) {
            reclaimed =
                manager_->reclaim_reverse_listener(candidate_port, this);
        }
        auto candidate =
            std::make_shared<boost::asio::ip::tcp::acceptor>(
                stream_.get_executor());
        boost::system::error_code ec;
        boost::asio::ip::tcp::endpoint ep =
            has_bind_address
                ? boost::asio::ip::tcp::endpoint(
                      bind_address,
                      static_cast<unsigned short>(candidate_port))
                : boost::asio::ip::tcp::endpoint(
                      boost::asio::ip::tcp::v4(),
                      static_cast<unsigned short>(candidate_port));
        candidate->open(ep.protocol(), ec);
        if (ec) {
            bind_error = "listen failed: " + ec.message();
            return false;
        }
        candidate->set_option(
            boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
        candidate->bind(ep, ec);
        if (ec == boost::asio::error::address_in_use && reclaim &&
            manager_ && !reclaimed) {
            if (manager_->reclaim_reverse_listener(
                    candidate_port, this)) {
                ec.clear();
                candidate->bind(ep, ec);
            }
        }
        if (ec) {
            bind_error = "bind failed: " + ec.message();
            return false;
        }
        candidate->listen(
            boost::asio::socket_base::max_listen_connections, ec);
        if (ec) {
            bind_error = "listen failed: " + ec.message();
            return false;
        }
        *out_acceptor = std::move(candidate);
        return true;
    };

    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor;
    if (auto_select_port) {
        const int range_size = max_port - min_port + 1;
        const int start_port = random_int_inclusive(min_port, max_port);
        bool found_port = false;
        for (int offset = 0; offset < range_size; ++offset) {
            const int candidate =
                min_port +
                ((start_port - min_port + offset) % range_size);
            if (try_bind_listener(candidate, &acceptor)) {
                listen_port = candidate;
                found_port = true;
                break;
            }
        }
        if (!found_port) {
            send_open_reply(
                frame.header.stream_id,
                false,
                "no available listen port in range " +
                    std::to_string(min_port) + "-" +
                    std::to_string(max_port));
            return;
        }
    } else if (!try_bind_listener(listen_port, &acceptor)) {
        send_open_reply(frame.header.stream_id, false, bind_error);
        return;
    }
    reverse_listeners_[frame.header.stream_id] = acceptor;
    reverse_listener_ports_[frame.header.stream_id] = listen_port;
    reverse_port_streams_[listen_port] = frame.header.stream_id;
    if (manager_) {
        manager_->register_reverse_listener(
            listen_port, shared_from_this());
    }
    send_open_reply(
        frame.header.stream_id, true, std::to_string(listen_port));

    auto self = shared_from_this();
    auto do_accept = std::make_shared<std::function<void()>>();
    *do_accept =
        [self,
         acceptor,
         listen_id = frame.header.stream_id,
         do_accept]() {
            acceptor->async_accept(boost::asio::bind_executor(
                self->strand_,
                [self, acceptor, listen_id, do_accept](
                    const boost::system::error_code& ec2,
                    boost::asio::ip::tcp::socket socket) {
                    if (!ec2) {
                        const uint8_t stream_id =
                            self->reserve_stream_id();
                        if (stream_id == 0) {
                            boost::system::error_code close_ec;
                            socket.close(close_ec);
                        } else {
                            auto remote =
                                std::make_shared<RemoteStream>(
                                    self->stream_.get_executor());
                            remote->socket = std::move(socket);
                            remote->open_started_ms = util::now_ms();
                            remote->connected = true;
                            boost::system::error_code keep_ec;
                            remote->socket.set_option(
                                boost::asio::socket_base::keep_alive(
                                    true),
                                keep_ec);
                            boost::system::error_code nodelay_ec;
                            remote->socket.set_option(
                                boost::asio::ip::tcp::no_delay(true),
                                nodelay_ec);
                            boost::system::error_code recvbuf_ec;
                            remote->socket.set_option(
                                boost::asio::socket_base::
                                    receive_buffer_size(
                                        kSocketBufferBytes),
                                recvbuf_ec);
                            boost::system::error_code sendbuf_ec;
                            remote->socket.set_option(
                                boost::asio::socket_base::
                                    send_buffer_size(
                                        kSocketBufferBytes),
                                sendbuf_ec);
                            {
                                std::lock_guard<std::mutex> lock(
                                    self->streams_mutex_);
                                self->streams_[stream_id] = remote;
                            }
                            self->pending_reverse_.insert(stream_id);
                            remote->open_timer =
                                std::make_unique<
                                    boost::asio::steady_timer>(
                                    self->strand_);
                            remote->open_timer->expires_after(
                                std::chrono::milliseconds(
                                    kReverseAcceptTimeoutMs));
                            remote->open_timer->async_wait(
                                boost::asio::bind_executor(
                                    self->strand_,
                                    [self, stream_id](
                                        const boost::system::
                                            error_code& timer_ec) {
                                        if (timer_ec ||
                                            self->close_state_ !=
                                                CloseState::Open) {
                                            return;
                                        }
                                        if (self->pending_reverse_.erase(
                                                stream_id) == 0) {
                                            return;
                                        }
                                        util::log_warn(
                                            "session " +
                                            std::to_string(
                                                self->session_id_) +
                                            ": reverse open timeout for "
                                            "stream " +
                                            std::to_string(stream_id));
                                        self->send_control_close(
                                            stream_id,
                                            "reverse open timeout");
                                        self->handle_close(
                                            stream_id,
                                            "reverse open timeout");
                                    }));

                            nlohmann::json json{
                                {"listen_id", listen_id}};
                            std::string payload_str = json.dump();
                            std::vector<uint8_t> notify_payload(
                                payload_str.begin(), payload_str.end());
                            uint16_t flags = 0;
                            if (self->inner_key_.has_value()) {
                                notify_payload =
                                    self->encrypt_inner_payload(
                                        protocol::ROPEN,
                                        stream_id,
                                        notify_payload);
                                flags |=
                                    protocol::kFlagInnerEncrypted;
                            }
                            protocol::Frame notify{
                                {static_cast<uint32_t>(
                                     notify_payload.size()),
                                 protocol::ROPEN,
                                 stream_id,
                                 flags},
                                notify_payload};
                            self->async_write_frame(notify);
                        }
                    }
                    (*do_accept)();
                }));
        };
    (*do_accept)();
}

}  // namespace yume::server
