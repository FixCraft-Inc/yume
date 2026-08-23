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

    arm_reverse_accept(frame.header.stream_id, acceptor);
}

bool Session::reverse_listener_is_active(
    uint8_t listen_id,
    const std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor) {
    if (close_state_ != CloseState::Open || !acceptor ||
        !acceptor->is_open()) {
        return false;
    }
    std::lock_guard<std::mutex> lock(streams_mutex_);
    const auto it = reverse_listeners_.find(listen_id);
    return it != reverse_listeners_.end() && it->second == acceptor;
}

void Session::arm_reverse_accept(
    uint8_t listen_id,
    const std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor) {
    if (!reverse_listener_is_active(listen_id, acceptor)) return;
    acceptor->async_accept(boost::asio::bind_executor(
        strand_,
        [weak = weak_from_this(), acceptor, listen_id](
            const boost::system::error_code& error,
            boost::asio::ip::tcp::socket socket) mutable {
            if (auto self = weak.lock()) {
                self->on_reverse_accept(
                    listen_id, acceptor, error, std::move(socket));
            } else {
                boost::system::error_code ignored;
                socket.close(ignored);
            }
        }));
}

void Session::on_reverse_accept(
    uint8_t listen_id,
    const std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor,
    const boost::system::error_code& error,
    boost::asio::ip::tcp::socket socket) {
    if (error) {
        if (error == boost::asio::error::connection_aborted &&
            reverse_listener_is_active(listen_id, acceptor)) {
            arm_reverse_accept(listen_id, acceptor);
        } else if (error != boost::asio::error::operation_aborted &&
                   reverse_listener_is_active(listen_id, acceptor)) {
            const std::string reason =
                "reverse listener accept failed: " + error.message();
            util::log_warn("session " + std::to_string(session_id_) +
                           ": " + reason);
            send_control_close(listen_id, reason);
            handle_close(listen_id, reason);
        }
        return;
    }
    if (!reverse_listener_is_active(listen_id, acceptor)) {
        boost::system::error_code ignored;
        socket.close(ignored);
        return;
    }

    auto stream_reservation = reserve_stream_id();
    if (!stream_reservation) {
        boost::system::error_code ignored;
        socket.close(ignored);
        arm_reverse_accept(listen_id, acceptor);
        return;
    }
    const uint8_t stream_id = stream_reservation.stream_id();

    auto remote =
        std::make_shared<RemoteStream>(stream_.get_executor());
    remote->socket = std::move(socket);
    remote->open_started_ms = diagnostics::timing_now_ms();
    remote->connected = true;
    boost::system::error_code keep_error;
    remote->socket.set_option(
        boost::asio::socket_base::keep_alive(true), keep_error);
    boost::system::error_code nodelay_error;
    remote->socket.set_option(
        boost::asio::ip::tcp::no_delay(true), nodelay_error);
    // Buffers remain kernel-autotuned; see session.cpp.
    bool stream_inserted = false;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        stream_inserted = streams_.try_emplace(stream_id, remote).second;
    }
    if (!stream_inserted) {
        boost::system::error_code ignored;
        remote->socket.close(ignored);
        arm_reverse_accept(listen_id, acceptor);
        return;
    }
    pending_reverse_.insert(stream_id);
    remote->open_timer =
        std::make_unique<boost::asio::steady_timer>(strand_);
    remote->open_timer->expires_after(
        std::chrono::milliseconds(kReverseAcceptTimeoutMs));
    remote->open_timer->async_wait(boost::asio::bind_executor(
        strand_,
        [self = shared_from_this(), stream_id](
            const boost::system::error_code& timer_error) {
            if (timer_error || self->close_state_ != CloseState::Open) {
                return;
            }
            if (self->pending_reverse_.erase(stream_id) == 0) return;
            util::log_warn(
                "session " + std::to_string(self->session_id_) +
                ": reverse open timeout for stream " +
                std::to_string(stream_id));
            self->send_control_close(stream_id, "reverse open timeout");
            self->handle_close(stream_id, "reverse open timeout");
        }));

    nlohmann::json json{{"listen_id", listen_id}};
    const std::string payload_text = json.dump();
    std::vector<uint8_t> notify_payload(
        payload_text.begin(), payload_text.end());
    uint16_t flags = 0;
    if (inner_key_.has_value()) {
        notify_payload = encrypt_inner_payload(
            protocol::ROPEN, stream_id, notify_payload);
        flags |= protocol::kFlagInnerEncrypted;
    }
    protocol::Frame notify{
        {static_cast<uint32_t>(notify_payload.size()),
         protocol::ROPEN, stream_id, flags},
        std::move(notify_payload)};
    async_write_frame(notify);
    arm_reverse_accept(listen_id, acceptor);
}

}  // namespace yume::server
