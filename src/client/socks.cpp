/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/socks.hpp"

#include <algorithm>
#include <limits>

#include "util.hpp"

namespace yume::client {

namespace {
constexpr uint8_t kVersion5 = 0x05;
constexpr uint8_t kMethodNoAuth = 0x00;
constexpr uint8_t kReplySuccess = 0x00;
constexpr uint8_t kReplyGeneralFailure = 0x01;
constexpr uint8_t kReplyCommandNotSupported = 0x07;
constexpr uint8_t kReplyAddrNotSupported = 0x08;
constexpr uint8_t kCmdConnect = 0x01;
constexpr uint8_t kCmdUdpAssociate = 0x03;
constexpr uint8_t kAtypV4 = 0x01;
constexpr uint8_t kAtypDomain = 0x03;
constexpr uint8_t kAtypV6 = 0x04;

std::vector<uint8_t> make_reply(uint8_t reply_code) {
    std::vector<uint8_t> resp(10, 0);
    resp[0] = kVersion5;
    resp[1] = reply_code;
    resp[2] = 0x00;
    resp[3] = 0x01;  // IPv4
    // BND.ADDR and BND.PORT left zero
    return resp;
}

std::vector<uint8_t> make_reply(uint8_t reply_code, const boost::asio::ip::udp::endpoint& ep) {
    std::vector<uint8_t> resp(10, 0);
    resp[0] = kVersion5;
    resp[1] = reply_code;
    resp[2] = 0x00;
    resp[3] = kAtypV4;
    auto bytes = ep.address().to_v4().to_bytes();
    resp[4] = bytes[0];
    resp[5] = bytes[1];
    resp[6] = bytes[2];
    resp[7] = bytes[3];
    resp[8] = static_cast<uint8_t>((ep.port() >> 8) & 0xFF);
    resp[9] = static_cast<uint8_t>(ep.port() & 0xFF);
    return resp;
}

std::string udp_assoc_key(const std::string& host, int port) {
    return host + "|" + std::to_string(port);
}
}  // namespace

SocksSession::SocksSession(boost::asio::ip::tcp::socket socket, std::shared_ptr<Tunnel> tunnel, bool allow_udp)
    : socket_(std::move(socket))
    , tunnel_(std::move(tunnel))
    , strand_(socket_.get_executor())
    , allow_udp_(allow_udp)
    , udp_socket_(socket_.get_executor()) {}

void SocksSession::start() {
    read_greeting();
}

void SocksSession::read_greeting() {
    auto self = shared_from_this();
    boost::asio::async_read(socket_, boost::asio::buffer(greeting_hdr_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec, std::size_t bytes) {
                                                           self->on_read_greeting(ec, bytes);
                                                       }));
}

void SocksSession::on_read_greeting(const boost::system::error_code& ec, std::size_t) {
    if (ec) {
        close();
        return;
    }
    if (greeting_hdr_[0] != kVersion5) {
        close();
        return;
    }

    const uint8_t nmethods = greeting_hdr_[1];
    if (nmethods == 0) {
        close();
        return;
    }

    methods_.assign(nmethods, 0);
    auto self = shared_from_this();
    boost::asio::async_read(socket_, boost::asio::buffer(methods_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& e, std::size_t bytes) {
                                                           self->on_read_methods(e, bytes);
                                                       }));
}

void SocksSession::on_read_methods(const boost::system::error_code& ec, std::size_t) {
    if (ec) {
        close();
        return;
    }

    bool supports_no_auth = false;
    for (uint8_t method : methods_) {
        if (method == kMethodNoAuth) {
            supports_no_auth = true;
            break;
        }
    }

    std::array<uint8_t, 2> reply{0x05, static_cast<uint8_t>(supports_no_auth ? kMethodNoAuth : 0xFF)};
    auto data = std::make_shared<std::vector<uint8_t>>(reply.begin(), reply.end());
    enqueue_write(data, [self = shared_from_this(), supports_no_auth]() {
        if (supports_no_auth) {
            self->read_request_header();
        } else {
            self->close();
        }
    });
}

void SocksSession::read_request_header() {
    auto self = shared_from_this();
    boost::asio::async_read(socket_, boost::asio::buffer(request_hdr_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec, std::size_t bytes) {
                                                           self->on_read_request_header(ec, bytes);
                                                       }));
}

void SocksSession::on_read_request_header(const boost::system::error_code& ec, std::size_t) {
    if (ec) {
        close();
        return;
    }

    if (request_hdr_[0] != kVersion5) {
        close();
        return;
    }

    const uint8_t cmd = request_hdr_[1];
    const uint8_t atyp = request_hdr_[3];

    if (cmd != kCmdConnect && cmd != kCmdUdpAssociate) {
        send_reply(kReplyCommandNotSupported, [self = shared_from_this()]() { self->close(); });
        return;
    }
    if (cmd == kCmdUdpAssociate && !allow_udp_) {
        send_reply(kReplyCommandNotSupported, [self = shared_from_this()]() { self->close(); });
        return;
    }

    pending_cmd_ = cmd;
    read_request_address(atyp);
}

void SocksSession::read_request_address(uint8_t atyp) {
    size_t len = 0;
    if (atyp == kAtypV4) {
        len = 4;
    } else if (atyp == kAtypDomain) {
        len = 1;  // domain length byte
        awaiting_domain_len_ = true;
    } else if (atyp == kAtypV6) {
        len = 16;
    } else {
        send_reply(kReplyAddrNotSupported, [self = shared_from_this()]() { self->close(); });
        return;
    }

    addr_buf_.assign(len, 0);
    auto self = shared_from_this();
    boost::asio::async_read(socket_, boost::asio::buffer(addr_buf_),
                            boost::asio::bind_executor(strand_,
                                                       [self, atyp](const boost::system::error_code& ec, std::size_t bytes) {
                                                           self->on_read_request_address(atyp, ec, bytes);
                                                       }));
}

void SocksSession::on_read_request_address(uint8_t atyp, const boost::system::error_code& ec, std::size_t) {
    if (ec) {
        close();
        return;
    }

    if (atyp == kAtypDomain && awaiting_domain_len_) {
        awaiting_domain_len_ = false;
        const uint8_t domain_len = addr_buf_.empty() ? 0 : addr_buf_[0];
        if (domain_len == 0) {
            send_reply(kReplyAddrNotSupported, [self = shared_from_this()]() { self->close(); });
            return;
        }
        addr_buf_.assign(domain_len, 0);
        auto self = shared_from_this();
        boost::asio::async_read(socket_, boost::asio::buffer(addr_buf_),
                                boost::asio::bind_executor(strand_,
                                                           [self](const boost::system::error_code& e, std::size_t bytes) {
                                                               self->on_read_request_address(kAtypDomain, e, bytes);
                                                           }));
        return;
    }

    if (atyp == kAtypV4) {
        boost::asio::ip::address_v4::bytes_type bytes{};
        std::copy_n(addr_buf_.begin(), 4, bytes.begin());
        target_host_ = boost::asio::ip::address_v4(bytes).to_string();
    } else if (atyp == kAtypV6) {
        send_reply(kReplyAddrNotSupported, [self = shared_from_this()]() { self->close(); });
        return;
    } else if (atyp == kAtypDomain) {
        target_host_.assign(addr_buf_.begin(), addr_buf_.end());
    }

    auto self = shared_from_this();
    boost::asio::async_read(socket_, boost::asio::buffer(port_buf_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& e, std::size_t bytes) {
                                                           self->on_read_request_port(e, bytes);
                                                       }));
}

void SocksSession::on_read_request_port(const boost::system::error_code& ec, std::size_t) {
    if (ec) {
        close();
        return;
    }

    target_port_ = static_cast<int>((port_buf_[0] << 8) | port_buf_[1]);
    if (target_host_.empty() || target_port_ <= 0) {
        send_reply(kReplyGeneralFailure, [self = shared_from_this()]() { self->close(); });
        return;
    }
    if (pending_cmd_ == kCmdUdpAssociate) {
        start_udp_associate();
        return;
    }
    start_tunnel();
}

void SocksSession::send_reply(uint8_t reply, std::function<void()> on_done) {
    auto resp = std::make_shared<std::vector<uint8_t>>(make_reply(reply));
    enqueue_write(resp, std::move(on_done));
}

void SocksSession::start_tunnel() {
    stream_id_ = tunnel_->reserve_stream_id();
    if (stream_id_ == 0) {
        send_reply(kReplyGeneralFailure, [self = shared_from_this()]() { self->close(); });
        return;
    }

    tunnel_->register_stream(
        stream_id_,
        [self = shared_from_this()](const Tunnel::Bytes& data) { self->deliver_from_tunnel(data); },
        [self = shared_from_this()]() { self->close_from_tunnel(); });

    tunnel_->open_stream(stream_id_, target_host_, target_port_,
                         [self = shared_from_this()](bool ok, const std::string& reason) {
                             if (!ok) {
                                 util::log_warn("SOCKS open failed: " + reason);
                                 self->send_reply(kReplyGeneralFailure, [self]() { self->close(); });
                                 return;
                             }
                             self->open_confirmed_ = true;
                             self->send_reply(kReplySuccess, [self]() { self->start_client_read(); });
                         });
}

void SocksSession::start_udp_associate() {
    if (udp_active_) {
        send_reply(kReplyGeneralFailure, [self = shared_from_this()]() { self->close(); });
        return;
    }

    boost::system::error_code ec;
    boost::asio::ip::udp::endpoint ep(boost::asio::ip::address_v4::loopback(), 0);
    udp_socket_.open(ep.protocol(), ec);
    if (!ec) {
        udp_socket_.bind(ep, ec);
    }
    if (ec) {
        send_reply(kReplyGeneralFailure, [self = shared_from_this()]() { self->close(); });
        return;
    }

    udp_active_ = true;
    udp_client_endpoint_ = boost::asio::ip::udp::endpoint(socket_.remote_endpoint().address(), 0);

    auto resp = std::make_shared<std::vector<uint8_t>>(make_reply(kReplySuccess, udp_socket_.local_endpoint()));
    enqueue_write(resp, [self = shared_from_this()]() { self->start_udp_read(); });
}

void SocksSession::start_udp_read() {
    if (!udp_active_) {
        return;
    }
    auto self = shared_from_this();
    udp_socket_.async_receive_from(boost::asio::buffer(udp_buf_), udp_sender_,
                                   boost::asio::bind_executor(strand_,
                                                              [self](const boost::system::error_code& ec, std::size_t bytes) {
                                                                  self->on_udp_read(ec, bytes);
                                                              }));
}

void SocksSession::on_udp_read(const boost::system::error_code& ec, std::size_t bytes) {
    if (ec) {
        close();
        return;
    }
    if (bytes < 4) {
        start_udp_read();
        return;
    }
    if (udp_client_endpoint_.address().is_unspecified()) {
        udp_client_endpoint_ = udp_sender_;
    } else if (udp_sender_.address() != udp_client_endpoint_.address()) {
        start_udp_read();
        return;
    } else if (udp_client_endpoint_.port() == 0) {
        udp_client_endpoint_.port(udp_sender_.port());
    }

    const auto* buf = udp_buf_.data();
    if (buf[0] != 0x00 || buf[1] != 0x00 || buf[2] != 0x00) {
        start_udp_read();
        return;
    }

    uint8_t atyp = buf[3];
    size_t idx = 4;
    std::string host;
    if (atyp == kAtypV4) {
        if (bytes < idx + 4 + 2) {
            start_udp_read();
            return;
        }
        boost::asio::ip::address_v4::bytes_type addr_bytes{};
        std::copy_n(buf + idx, 4, addr_bytes.begin());
        host = boost::asio::ip::address_v4(addr_bytes).to_string();
        idx += 4;
    } else if (atyp == kAtypDomain) {
        if (bytes < idx + 1) {
            start_udp_read();
            return;
        }
        uint8_t len = buf[idx++];
        if (bytes < idx + len + 2) {
            start_udp_read();
            return;
        }
        host.assign(reinterpret_cast<const char*>(buf + idx), len);
        idx += len;
    } else if (atyp == kAtypV6) {
        start_udp_read();
        return;
    } else {
        start_udp_read();
        return;
    }

    if (bytes < idx + 2) {
        start_udp_read();
        return;
    }
    int port = static_cast<int>((buf[idx] << 8) | buf[idx + 1]);
    idx += 2;
    if (host.empty() || port <= 0) {
        start_udp_read();
        return;
    }

    Tunnel::Bytes payload(buf + idx, buf + bytes);
    std::string key = udp_assoc_key(host, port);
    auto it = udp_assoc_.find(key);
    if (it == udp_assoc_.end()) {
        uint8_t stream_id = tunnel_->reserve_stream_id();
        if (stream_id == 0) {
            start_udp_read();
            return;
        }
        auto assoc = std::make_shared<UdpAssoc>();
        assoc->host = host;
        assoc->port = port;
        assoc->stream_id = stream_id;
        udp_assoc_[key] = assoc;
        udp_assoc_by_stream_[stream_id] = assoc;

        tunnel_->register_stream(
            stream_id,
            [self = shared_from_this(), stream_id](const Tunnel::Bytes& data) { self->deliver_udp(stream_id, data); },
            [self = shared_from_this(), stream_id]() { self->close_udp_assoc(stream_id, "remote closed"); });
        tunnel_->open_stream(stream_id, host, port,
                             [self = shared_from_this(), stream_id](bool ok, const std::string& reason) {
                                 auto it_assoc = self->udp_assoc_by_stream_.find(stream_id);
                                 if (it_assoc == self->udp_assoc_by_stream_.end()) {
                                     return;
                                 }
                                 auto assoc = it_assoc->second;
                                 if (!ok) {
                                     self->close_udp_assoc(stream_id, "open failed: " + reason);
                                     return;
                                 }
                                 assoc->open_confirmed = true;
                                 while (!assoc->pending.empty()) {
                                     self->tunnel_->send_data(stream_id, assoc->pending.front());
                                     assoc->pending.pop_front();
                                 }
                             },
                             "udp");
        it = udp_assoc_.find(key);
    }

    auto assoc = it->second;
    if (assoc->open_confirmed) {
        tunnel_->send_data(assoc->stream_id, payload);
    } else {
        assoc->pending.push_back(std::move(payload));
    }

    start_udp_read();
}

void SocksSession::deliver_udp(uint8_t stream_id, const Tunnel::Bytes& data) {
    auto it = udp_assoc_by_stream_.find(stream_id);
    if (it == udp_assoc_by_stream_.end() || !udp_active_) {
        return;
    }
    if (udp_client_endpoint_.address().is_unspecified() || udp_client_endpoint_.port() == 0) {
        return;
    }
    auto assoc = it->second;
    std::vector<uint8_t> resp;
    auto add_size = [](size_t a, size_t b, size_t& out) {
        if (a > std::numeric_limits<size_t>::max() - b) {
            return false;
        }
        out = a + b;
        return true;
    };
    size_t reserve = 0;
    if (!add_size(4, assoc->host.size(), reserve) ||
        !add_size(reserve, data.size(), reserve) ||
        !add_size(reserve, 8, reserve)) {
        return;
    }
    if (reserve > resp.max_size()) {
        return;
    }
    resp.reserve(reserve);
    resp.push_back(0x00);
    resp.push_back(0x00);
    resp.push_back(0x00);

    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(assoc->host, ec);
    if (!ec && addr.is_v4()) {
        resp.push_back(kAtypV4);
        auto bytes = addr.to_v4().to_bytes();
        resp.insert(resp.end(), bytes.begin(), bytes.end());
    } else {
        resp.push_back(kAtypDomain);
        if (assoc->host.size() > 255) {
            return;
        }
        resp.push_back(static_cast<uint8_t>(assoc->host.size()));
        resp.insert(resp.end(), assoc->host.begin(), assoc->host.end());
    }
    resp.push_back(static_cast<uint8_t>((assoc->port >> 8) & 0xFF));
    resp.push_back(static_cast<uint8_t>(assoc->port & 0xFF));
    resp.insert(resp.end(), data.begin(), data.end());

    auto buffer = std::make_shared<std::vector<uint8_t>>(std::move(resp));
    auto self = shared_from_this();
    udp_socket_.async_send_to(boost::asio::buffer(*buffer), udp_client_endpoint_,
                              boost::asio::bind_executor(strand_,
                                                         [self, buffer](const boost::system::error_code&, std::size_t) {}));
}

void SocksSession::close_udp_assoc(uint8_t stream_id, const std::string&) {
    auto it = udp_assoc_by_stream_.find(stream_id);
    if (it == udp_assoc_by_stream_.end()) {
        return;
    }
    auto assoc = it->second;
    udp_assoc_by_stream_.erase(it);
    udp_assoc_.erase(udp_assoc_key(assoc->host, assoc->port));
    tunnel_->unregister_stream(stream_id);
}

void SocksSession::start_client_read() {
    auto self = shared_from_this();
    socket_.async_read_some(boost::asio::buffer(read_buf_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec, std::size_t bytes) {
                                                           self->on_client_read(ec, bytes);
                                                       }));
}

void SocksSession::on_client_read(const boost::system::error_code& ec, std::size_t bytes) {
    if (ec) {
        close();
        return;
    }

    Tunnel::Bytes payload(read_buf_.data(), read_buf_.data() + bytes);
    tunnel_->send_data(stream_id_, payload);
    start_client_read();
}

void SocksSession::deliver_from_tunnel(const Tunnel::Bytes& data) {
    auto self = shared_from_this();
    boost::asio::post(strand_, [self, data]() {
        auto buf = std::make_shared<std::vector<uint8_t>>(data.begin(), data.end());
        self->enqueue_write(buf);
    });
}

void SocksSession::close_from_tunnel() {
    auto self = shared_from_this();
    boost::asio::post(strand_, [self]() { self->close(); });
}

void SocksSession::enqueue_write(std::shared_ptr<std::vector<uint8_t>> data, std::function<void()> on_done) {
    boost::asio::post(strand_, [self = shared_from_this(), data = std::move(data), on_done = std::move(on_done)]() mutable {
        self->write_queue_.emplace_back(std::move(data), std::move(on_done));
        if (!self->write_in_flight_) {
            self->do_write();
        }
    });
}

void SocksSession::do_write() {
    if (write_queue_.empty()) {
        write_in_flight_ = false;
        return;
    }
    write_in_flight_ = true;

    auto item = std::move(write_queue_.front());
    write_queue_.pop_front();
    auto data = item.first;
    auto done = std::move(item.second);

    auto self = shared_from_this();
    boost::asio::async_write(socket_, boost::asio::buffer(*data),
                             boost::asio::bind_executor(strand_,
                                                        [self, data, done = std::move(done)](const boost::system::error_code& ec, std::size_t) mutable {
                                                            if (done) {
                                                                done();
                                                            }
                                                            if (ec) {
                                                                self->close();
                                                                return;
                                                            }
                                                            self->do_write();
                                                        }));
}

void SocksSession::close() {
    if (stream_id_ != 0) {
        tunnel_->send_close(stream_id_, "client closed");
        tunnel_->unregister_stream(stream_id_);
        stream_id_ = 0;
    }
    for (auto& entry : udp_assoc_by_stream_) {
        tunnel_->send_close(entry.first, "udp associate closed");
        tunnel_->unregister_stream(entry.first);
    }
    udp_assoc_by_stream_.clear();
    udp_assoc_.clear();
    if (udp_active_) {
        boost::system::error_code ec;
        udp_socket_.close(ec);
        udp_active_ = false;
    }

    boost::system::error_code ec;
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    socket_.close(ec);
}

SocksServer::SocksServer(boost::asio::io_context& io, int port, std::shared_ptr<Tunnel> tunnel, bool allow_udp)
    : acceptor_(io)
    , tunnel_(std::move(tunnel))
    , allow_udp_(allow_udp) {
    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), port);
    acceptor_.open(ep.protocol());
    acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    acceptor_.bind(ep);
    acceptor_.listen();
}

void SocksServer::start() {
    do_accept();
}

int SocksServer::port() const {
    boost::system::error_code ec;
    auto ep = acceptor_.local_endpoint(ec);
    if (ec) {
        return 0;
    }
    return static_cast<int>(ep.port());
}

void SocksServer::do_accept() {
    acceptor_.async_accept([this](const boost::system::error_code& ec, boost::asio::ip::tcp::socket socket) {
        if (!ec) {
            auto session = std::make_shared<SocksSession>(std::move(socket), tunnel_, allow_udp_);
            session->start();
        } else {
            util::log_warn(std::string("SOCKS accept failed: ") + ec.message());
        }
        do_accept();
    });
}

}  // namespace yume::client
