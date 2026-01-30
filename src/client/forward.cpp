/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/forward.hpp"

#include "util.hpp"

namespace yume::client {

ForwardSession::ForwardSession(boost::asio::ip::tcp::socket socket,
                               std::shared_ptr<Tunnel> tunnel,
                               std::string target_host,
                               int target_port)
    : socket_(std::move(socket))
    , tunnel_(std::move(tunnel))
    , strand_(socket_.get_executor())
    , target_host_(std::move(target_host))
    , target_port_(target_port) {}

void ForwardSession::start() {
    start_tunnel();
}

void ForwardSession::start_tunnel() {
    stream_id_ = tunnel_->reserve_stream_id();
    if (stream_id_ == 0) {
        util::log_warn("forward: no stream ids available");
        close();
        return;
    }

    tunnel_->register_stream(
        stream_id_,
        [self = shared_from_this()](const Tunnel::Bytes& data) { self->deliver_from_tunnel(data); },
        [self = shared_from_this()]() { self->close_from_tunnel(); });

    tunnel_->open_stream(stream_id_, target_host_, target_port_,
                         [self = shared_from_this()](bool ok, const std::string& reason) {
                             if (!ok) {
                                 util::log_warn("forward open failed: " + reason);
                                 self->close();
                                 return;
                             }
                             self->open_confirmed_ = true;
                             self->start_client_read();
                         });
}

void ForwardSession::start_client_read() {
    auto self = shared_from_this();
    socket_.async_read_some(boost::asio::buffer(read_buf_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec, std::size_t bytes) {
                                                           self->on_client_read(ec, bytes);
                                                       }));
}

void ForwardSession::on_client_read(const boost::system::error_code& ec, std::size_t bytes) {
    if (ec) {
        close();
        return;
    }

    Tunnel::Bytes payload(read_buf_.data(), read_buf_.data() + bytes);
    tunnel_->send_data(stream_id_, payload);
    start_client_read();
}

void ForwardSession::deliver_from_tunnel(const Tunnel::Bytes& data) {
    auto self = shared_from_this();
    boost::asio::post(strand_, [self, data]() {
        auto buf = std::make_shared<std::vector<uint8_t>>(data.begin(), data.end());
        self->enqueue_write(buf);
    });
}

void ForwardSession::close_from_tunnel() {
    auto self = shared_from_this();
    boost::asio::post(strand_, [self]() { self->close(); });
}

void ForwardSession::enqueue_write(std::shared_ptr<std::vector<uint8_t>> data) {
    boost::asio::post(strand_, [self = shared_from_this(), data = std::move(data)]() mutable {
        self->write_queue_.push_back(std::move(data));
        if (!self->write_in_flight_) {
            self->do_write();
        }
    });
}

void ForwardSession::do_write() {
    if (write_queue_.empty()) {
        write_in_flight_ = false;
        return;
    }
    write_in_flight_ = true;

    auto data = std::move(write_queue_.front());
    write_queue_.pop_front();

    auto self = shared_from_this();
    boost::asio::async_write(socket_, boost::asio::buffer(*data),
                             boost::asio::bind_executor(strand_,
                                                        [self, data](const boost::system::error_code& ec, std::size_t) {
                                                            if (ec) {
                                                                self->close();
                                                                return;
                                                            }
                                                            self->do_write();
                                                        }));
}

void ForwardSession::close() {
    if (stream_id_ != 0) {
        tunnel_->send_close(stream_id_, "client closed");
        tunnel_->unregister_stream(stream_id_);
        stream_id_ = 0;
    }

    boost::system::error_code ec;
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    socket_.close(ec);
}

ForwardServer::ForwardServer(boost::asio::io_context& io,
                             int listen_port,
                             std::string target_host,
                             int target_port,
                             std::shared_ptr<Tunnel> tunnel)
    : acceptor_(io)
    , target_host_(std::move(target_host))
    , target_port_(target_port)
    , tunnel_(std::move(tunnel)) {
    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), listen_port);
    acceptor_.open(ep.protocol());
    acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    acceptor_.bind(ep);
    acceptor_.listen();
}

void ForwardServer::start() {
    do_accept();
}

void ForwardServer::do_accept() {
    acceptor_.async_accept([this](const boost::system::error_code& ec, boost::asio::ip::tcp::socket socket) {
        if (!ec) {
            auto session = std::make_shared<ForwardSession>(std::move(socket), tunnel_, target_host_, target_port_);
            session->start();
        } else {
            util::log_warn(std::string("forward accept failed: ") + ec.message());
        }
        do_accept();
    });
}

}  // namespace yume::client
