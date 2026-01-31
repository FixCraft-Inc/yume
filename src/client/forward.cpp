/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/forward.hpp"

#include "util.hpp"

namespace yume::client {

namespace {
bool is_private_ipv4(const boost::asio::ip::address_v4& addr) {
    const auto bytes = addr.to_bytes();
    const uint8_t a = bytes[0];
    const uint8_t b = bytes[1];
    if (a == 10) return true;
    if (a == 127) return true;
    if (a == 0) return true;
    if (a == 169 && b == 254) return true;
    if (a == 172 && (b >= 16 && b <= 31)) return true;
    if (a == 192 && b == 168) return true;
    return false;
}

bool is_private_ipv6(const boost::asio::ip::address_v6& addr) {
    if (addr.is_loopback() || addr.is_unspecified()) {
        return true;
    }
    const auto bytes = addr.to_bytes();
    if ((bytes[0] & 0xFE) == 0xFC) { // fc00::/7
        return true;
    }
    if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80) { // fe80::/10
        return true;
    }
    if (addr.is_v4_mapped()) {
        return is_private_ipv4(addr.to_v4());
    }
    return false;
}

bool is_private_address(const boost::asio::ip::address& addr) {
    if (addr.is_v4()) return is_private_ipv4(addr.to_v4());
    if (addr.is_v6()) return true;
    return false;
}

bool is_blocked_literal(const std::string& host) {
    if (host == "localhost" || host == "localhost.localdomain") {
        return true;
    }
    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(host, ec);
    if (!ec) {
        return is_private_address(addr);
    }
    return false;
}
}  // namespace

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

bool ForwardServer::is_local_target() const {
    return is_blocked_literal(target_host_);
}

void ForwardServer::do_accept() {
    acceptor_.async_accept([this](const boost::system::error_code& ec, boost::asio::ip::tcp::socket socket) {
        if (!ec) {
            if (is_local_target()) {
                auto session = std::make_shared<LocalForwardSession>(std::move(socket), target_host_, target_port_);
                session->start();
            } else {
                auto session = std::make_shared<ForwardSession>(std::move(socket), tunnel_, target_host_, target_port_);
                session->start();
            }
        } else {
            util::log_warn(std::string("forward accept failed: ") + ec.message());
        }
        do_accept();
    });
}

LocalForwardSession::LocalForwardSession(boost::asio::ip::tcp::socket socket,
                                         std::string target_host,
                                         int target_port)
    : socket_(std::move(socket))
    , remote_(socket_.get_executor())
    , resolver_(socket_.get_executor())
    , strand_(socket_.get_executor())
    , target_host_(std::move(target_host))
    , target_port_(target_port) {}

void LocalForwardSession::start() {
    start_connect();
}

void LocalForwardSession::start_connect() {
    auto self = shared_from_this();
    resolver_.async_resolve(boost::asio::ip::tcp::v4(), target_host_, std::to_string(target_port_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec,
                                                              const boost::asio::ip::tcp::resolver::results_type& results) {
                                                           if (ec) {
                                                               util::log_warn("local forward resolve failed: " + ec.message());
                                                               self->close();
                                                               return;
                                                           }
                                                           boost::asio::async_connect(self->remote_, results,
                                                                                      boost::asio::bind_executor(self->strand_,
                                                                                                                 [self](const boost::system::error_code& ec2,
                                                                                                                        const boost::asio::ip::tcp::endpoint&) {
                                                                                                                     if (ec2) {
                                                                                                                         util::log_warn("local forward connect failed: " + ec2.message());
                                                                                                                         self->close();
                                                                                                                         return;
                                                                                                                     }
                                                                                                                     self->start_client_read();
                                                                                                                     self->start_remote_read();
                                                                                                                 }));
                                                       }));
}

void LocalForwardSession::start_client_read() {
    auto self = shared_from_this();
    socket_.async_read_some(boost::asio::buffer(client_buf_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec, std::size_t bytes) {
                                                           self->on_client_read(ec, bytes);
                                                       }));
}

void LocalForwardSession::start_remote_read() {
    auto self = shared_from_this();
    remote_.async_read_some(boost::asio::buffer(remote_buf_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec, std::size_t bytes) {
                                                           self->on_remote_read(ec, bytes);
                                                       }));
}

void LocalForwardSession::on_client_read(const boost::system::error_code& ec, std::size_t bytes) {
    if (ec) {
        close();
        return;
    }
    auto self = shared_from_this();
    boost::asio::async_write(remote_, boost::asio::buffer(client_buf_.data(), bytes),
                             boost::asio::bind_executor(strand_,
                                                        [self](const boost::system::error_code& ec2, std::size_t) {
                                                            if (ec2) {
                                                                self->close();
                                                                return;
                                                            }
                                                            self->start_client_read();
                                                        }));
}

void LocalForwardSession::on_remote_read(const boost::system::error_code& ec, std::size_t bytes) {
    if (ec) {
        close();
        return;
    }
    auto self = shared_from_this();
    boost::asio::async_write(socket_, boost::asio::buffer(remote_buf_.data(), bytes),
                             boost::asio::bind_executor(strand_,
                                                        [self](const boost::system::error_code& ec2, std::size_t) {
                                                            if (ec2) {
                                                                self->close();
                                                                return;
                                                            }
                                                            self->start_remote_read();
                                                        }));
}

void LocalForwardSession::close() {
    boost::system::error_code ec;
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    socket_.close(ec);
    remote_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    remote_.close(ec);
}

ReverseForwardSession::ReverseForwardSession(std::shared_ptr<Tunnel> tunnel,
                                             uint8_t stream_id,
                                             std::string target_host,
                                             int target_port)
    : tunnel_(std::move(tunnel))
    , stream_id_(stream_id)
    , local_(tunnel_->get_executor())
    , resolver_(tunnel_->get_executor())
    , strand_(tunnel_->get_executor())
    , target_host_(std::move(target_host))
    , target_port_(target_port) {}

void ReverseForwardSession::start() {
    tunnel_->register_stream(
        stream_id_,
        [self = shared_from_this()](const Tunnel::Bytes& data) { self->deliver_from_tunnel(data); },
        [self = shared_from_this()]() { self->close_from_tunnel(); });
    start_connect();
}

void ReverseForwardSession::start_connect() {
    auto self = shared_from_this();
    resolver_.async_resolve(boost::asio::ip::tcp::v4(), target_host_, std::to_string(target_port_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec,
                                                              const boost::asio::ip::tcp::resolver::results_type& results) {
                                                           if (ec) {
                                                               self->tunnel_->send_open_ack(self->stream_id_, false, "local resolve failed");
                                                               self->close();
                                                               return;
                                                           }
                                                           boost::asio::async_connect(self->local_, results,
                                                                                      boost::asio::bind_executor(self->strand_,
                                                                                                                 [self](const boost::system::error_code& ec2,
                                                                                                                        const boost::asio::ip::tcp::endpoint&) {
                                                                                                                     if (ec2) {
                                                                                                                         self->tunnel_->send_open_ack(self->stream_id_, false, "local connect failed");
                                                                                                                         self->close();
                                                                                                                         return;
                                                                                                                     }
                                                                                                                     self->open_confirmed_ = true;
                                                                                                                     self->tunnel_->send_open_ack(self->stream_id_, true, "");
                                                                                                                     self->start_local_read();
                                                                                                                 }));
                                                       }));
}

void ReverseForwardSession::start_local_read() {
    auto self = shared_from_this();
    local_.async_read_some(boost::asio::buffer(read_buf_),
                           boost::asio::bind_executor(strand_,
                                                      [self](const boost::system::error_code& ec, std::size_t bytes) {
                                                          self->on_local_read(ec, bytes);
                                                      }));
}

void ReverseForwardSession::on_local_read(const boost::system::error_code& ec, std::size_t bytes) {
    if (ec) {
        close();
        return;
    }
    Tunnel::Bytes payload(read_buf_.data(), read_buf_.data() + bytes);
    tunnel_->send_data(stream_id_, payload);
    start_local_read();
}

void ReverseForwardSession::deliver_from_tunnel(const Tunnel::Bytes& data) {
    auto self = shared_from_this();
    boost::asio::post(strand_, [self, data]() {
        if (!self->open_confirmed_) {
            return;
        }
        boost::asio::async_write(self->local_, boost::asio::buffer(data),
                                 boost::asio::bind_executor(self->strand_,
                                                            [self](const boost::system::error_code& ec, std::size_t) {
                                                                if (ec) {
                                                                    self->close();
                                                                }
                                                            }));
    });
}

void ReverseForwardSession::close_from_tunnel() {
    auto self = shared_from_this();
    boost::asio::post(strand_, [self]() { self->close(); });
}

void ReverseForwardSession::close() {
    if (stream_id_ != 0) {
        tunnel_->send_close(stream_id_, "reverse closed");
        tunnel_->unregister_stream(stream_id_);
        stream_id_ = 0;
    }
    boost::system::error_code ec;
    local_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    local_.close(ec);
}

}  // namespace yume::client
