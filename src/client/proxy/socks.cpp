/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/proxy/socks.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

#include "client/transport/tunnel_pool.hpp"
#include "util.hpp"

namespace yume::client {

namespace {
constexpr uint8_t kVersion5 = 0x05;
constexpr uint8_t kMethodNoAuth = 0x00;
constexpr uint8_t kReplySuccess         = 0x00;
constexpr uint8_t kReplyGeneralFailure  = 0x01;
constexpr uint8_t kReplyNetworkUnreach  = 0x03;
constexpr uint8_t kReplyHostUnreach     = 0x04;
constexpr uint8_t kReplyConnRefused     = 0x05;
constexpr uint8_t kReplyCommandNotSupported = 0x07;
constexpr uint8_t kReplyAddrNotSupported = 0x08;
constexpr uint8_t kCmdConnect = 0x01;
constexpr uint8_t kCmdUdpAssociate = 0x03;
constexpr uint8_t kAtypV4 = 0x01;
constexpr uint8_t kAtypDomain = 0x03;
constexpr uint8_t kAtypV6 = 0x04;
constexpr int kSocketBufferBytes = 2 * 1024 * 1024;

void validate_listen_port(int port) {
    if (port < 0 || port > 65535) {
        throw std::runtime_error("SOCKS listen port must be 0..65535");
    }
}

boost::asio::ip::tcp::endpoint make_tcp_listen_endpoint(const std::string& bind_host, int port) {
    validate_listen_port(port);
    if (bind_host.empty()) {
        return {boost::asio::ip::tcp::v4(), static_cast<unsigned short>(port)};
    }
    boost::system::error_code ec;
    auto address = boost::asio::ip::make_address(bind_host, ec);
    if (ec) {
        throw std::runtime_error("invalid SOCKS bind address '" + bind_host + "': " + ec.message());
    }
    return {address, static_cast<unsigned short>(port)};
}

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

// Map a free-text server-side OPEN failure reason to the best-fitting
// RFC 1928 §6 REP code. The server doesn't currently emit a structured
// error class, so we substring-match on the canonical phrases. Falling
// back to general-failure (0x01) is always safe; the more specific
// codes just let well-behaved clients (browsers, curl) report a more
// useful error to the user instead of "SOCKS5 general failure".
uint8_t reason_to_rep(const std::string& reason) {
    auto contains = [&](const char* needle) { return reason.find(needle) != std::string::npos; };
    if (contains("blocked"))                              return 0x02;  // not allowed by ruleset
    if (contains("resolve failed") || contains("resolve timeout") ||
        contains("DNS"))                                  return 0x04;  // host unreachable (DNS class)
    if (contains("network unreachable"))                  return 0x03;
    if (contains("Connection refused") ||
        contains("connection refused"))                   return 0x05;
    if (contains("connect timeout") || contains("Host unreachable") ||
        contains("host unreachable"))                     return 0x04;
    return 0x01;  // general failure
}

bool noisy_open_failure(const std::string& reason) {
    return reason.find("resolve failed") != std::string::npos ||
           reason.find("resolve timeout") != std::string::npos ||
           reason.find("connect timeout") != std::string::npos;
}
}  // namespace

SocksSession::SocksSession(boost::asio::ip::tcp::socket socket,
                           std::shared_ptr<Tunnel> tunnel,
                           bool allow_udp,
                           std::shared_ptr<TunnelPool> pool)
    : socket_(std::move(socket))
    , tunnel_(std::move(tunnel))
    , pool_(std::move(pool))
    , strand_(socket_.get_executor())
    , allow_udp_(allow_udp)
    , udp_socket_(socket_.get_executor()) {
    read_buf_.resize(util::relay_read_buf_size());
    boost::system::error_code ec;
    socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec);
    boost::system::error_code recvbuf_ec;
    socket_.set_option(boost::asio::socket_base::receive_buffer_size(kSocketBufferBytes), recvbuf_ec);
    boost::system::error_code sendbuf_ec;
    socket_.set_option(boost::asio::socket_base::send_buffer_size(kSocketBufferBytes), sendbuf_ec);
}

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
        // Pre-fix this branch refused IPv6 with kReplyAddrNotSupported,
        // which broke any site whose Happy-Eyeballs AAAA was tried
        // first by the client (Chromium, curl, ...). The client would
        // then either fall back to IPv4 (slow) or fail outright; some
        // clients fall back to a direct connection on SOCKS failure,
        // which is an IP leak. The tunnel takes host as a string, so
        // we can forward the IPv6 literal verbatim — the server-side
        // resolver / connect path already handles v6 endpoints when
        // YUME_RESOLVE_FAMILY=any (see session.cpp).
        boost::asio::ip::address_v6::bytes_type bytes{};
        std::copy_n(addr_buf_.begin(), 16, bytes.begin());
        target_host_ = boost::asio::ip::address_v6(bytes).to_string();
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
    opened_started_ms_ = util::now_ms();
    YUME_TIMING_LOG("client.socks",
                     "open_start",
                     "stream=" + std::to_string(stream_id_) +
                         " target=" + target_host_ + ":" + std::to_string(target_port_));

    tunnel_->register_stream(
        stream_id_,
        [self = shared_from_this()](const Tunnel::Bytes& data) { self->deliver_from_tunnel(data); },
        [self = shared_from_this()](const std::string&) { self->close_from_tunnel(); },
        [self = shared_from_this()](const std::string& reason) { self->remote_fin_from_tunnel(reason); });

    // RFC 1928 §6: REP must be sent AFTER the upstream connection
    // either succeeds or fails — with the right code in either case.
    // Pre-fix this sent REP=succeeded the moment open_stream was
    // *initiated*, then closed the SOCKS socket if the server-side
    // connect later failed. From the browser's POV that looked like
    // a connection that succeeded and then died mid-request — which
    // some browsers respond to by retrying directly (an IP leak),
    // others by spinning until timeout (the "websites won't load
    // properly" symptom). Now we wait for the open_stream callback
    // and reply with the right REP code (or a specific failure code
    // mapped from the server's reason string via reason_to_rep).
    tunnel_->open_stream(stream_id_, target_host_, target_port_,
                         [self = shared_from_this()](bool ok, const std::string& reason) {
                             // Consumed only by the timing log, which compiles
                             // out entirely in production builds.
                             [[maybe_unused]] const int64_t elapsed =
                                 self->opened_started_ms_ > 0
                                     ? (util::now_ms() - self->opened_started_ms_)
                                     : 0;
                             YUME_TIMING_LOG("client.socks",
                                              "open_done",
                                              "stream=" + std::to_string(self->stream_id_) +
                                                  " ok=" + std::string(ok ? "1" : "0") +
                                                  " ms=" + std::to_string(elapsed) +
                                                  " target=" + self->target_host_ + ":" +
                                                  std::to_string(self->target_port_) +
                                                  (reason.empty() ? std::string{} : " reason=" + reason));
                             if (!ok) {
                                 const uint8_t rep = reason_to_rep(reason);
                                 const std::string message = "SOCKS open failed (REP=0x" +
                                     std::to_string(rep) + "): " + reason;
                                 if (noisy_open_failure(reason)) {
                                     util::log_info_rate_limited("socks-open-noisy-failure", message, 30000);
                                 } else {
                                     util::log_warn(message);
                                 }
                                 self->send_reply(rep,
                                     [self]() { self->close(); });
                                 return;
                             }
                             self->open_confirmed_ = true;
                             self->send_reply(kReplySuccess,
                                 [self]() { self->start_client_read(); });
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
        if (bytes < idx + 16 + 2) {
            start_udp_read();
            return;
        }
        boost::asio::ip::address_v6::bytes_type addr_bytes{};
        std::copy_n(buf + idx, 16, addr_bytes.begin());
        host = boost::asio::ip::address_v6(addr_bytes).to_string();
        idx += 16;
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
            [self = shared_from_this(), stream_id](const std::string& reason) {
                self->close_udp_assoc(stream_id, reason.empty() ? "remote closed" : reason);
            });
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
        if (ec == boost::asio::error::eof) {
            send_client_fin();
            return;
        }
        close();
        return;
    }

    Tunnel::Bytes payload(read_buf_.data(), read_buf_.data() + bytes);
    upload_bytes_ += static_cast<std::uint64_t>(bytes);
    if (first_upload_ms_ == 0) {
        first_upload_ms_ = util::now_ms();
        [[maybe_unused]] const int64_t open_to_first =
            opened_started_ms_ > 0 ? (first_upload_ms_ - opened_started_ms_) : 0;
        YUME_TIMING_LOG("client.socks",
                         "first_upload",
                         "stream=" + std::to_string(stream_id_) +
                             " ms=" + std::to_string(open_to_first) +
                             " bytes=" + std::to_string(bytes));
    }
    tunnel_->send_data(stream_id_, std::move(payload));
    start_client_read();
}

void SocksSession::send_client_fin() {
    if (closed_ || local_fin_sent_) {
        return;
    }
    local_fin_sent_ = true;
    if (stream_id_ != 0) {
        tunnel_->send_stream_fin(stream_id_, "client upload finished");
    }
    maybe_finish_cleanly();
}

void SocksSession::deliver_from_tunnel(const Tunnel::Bytes& data) {
    auto self = shared_from_this();
    auto buf = std::make_shared<std::vector<uint8_t>>(data.begin(), data.end());
    boost::asio::post(strand_, [self, buf = std::move(buf)]() mutable {
        if (self->closed_) {
            return;
        }
        self->download_bytes_ += static_cast<std::uint64_t>(buf->size());
        if (self->first_download_ms_ == 0) {
            self->first_download_ms_ = util::now_ms();
            [[maybe_unused]] const int64_t open_to_first =
                self->opened_started_ms_ > 0
                    ? (self->first_download_ms_ - self->opened_started_ms_)
                    : 0;
            YUME_TIMING_LOG("client.socks",
                             "first_download",
                             "stream=" + std::to_string(self->stream_id_) +
                                 " ms=" + std::to_string(open_to_first) +
                                 " bytes=" + std::to_string(buf->size()));
        }
        self->write_queue_.emplace_back(std::move(buf), std::function<void()>{});
        if (!self->write_in_flight_) {
            self->do_write();
        }
    });
}

void SocksSession::close_from_tunnel() {
    auto self = shared_from_this();
    boost::asio::post(strand_, [self]() { self->close(); });
}

void SocksSession::remote_fin_from_tunnel(const std::string&) {
    auto self = shared_from_this();
    boost::asio::post(strand_, [self]() {
        if (self->closed_ || self->remote_fin_received_) {
            return;
        }
        self->remote_fin_received_ = true;
        self->request_socket_send_shutdown();
        self->maybe_finish_cleanly();
    });
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
        request_socket_send_shutdown();
        maybe_finish_cleanly();
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

void SocksSession::request_socket_send_shutdown() {
    if (!remote_fin_received_ || socket_send_shutdown_done_) {
        return;
    }
    socket_send_shutdown_pending_ = true;
    if (write_in_flight_ || !write_queue_.empty()) {
        return;
    }
    boost::system::error_code ec;
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    socket_send_shutdown_done_ = true;
    socket_send_shutdown_pending_ = false;
}

void SocksSession::maybe_finish_cleanly() {
    if (closed_ || !local_fin_sent_ || !remote_fin_received_ ||
        write_in_flight_ || !write_queue_.empty()) {
        return;
    }
    closed_ = true;
    log_summary_once();
    if (stream_id_ != 0) {
        tunnel_->unregister_stream(stream_id_);
        stream_id_ = 0;
    }
    release_pool_session();
    boost::system::error_code ec;
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    socket_.close(ec);
}

void SocksSession::release_pool_session() {
    if (pool_ && !pool_session_released_) {
        pool_session_released_ = true;
        pool_->release_session(tunnel_);
    }
}

void SocksSession::log_summary_once() {
    if (!close_summary_logged_ && (opened_started_ms_ > 0 || upload_bytes_ > 0 || download_bytes_ > 0)) {
        close_summary_logged_ = true;
        [[maybe_unused]] const int64_t elapsed =
            opened_started_ms_ > 0 ? (util::now_ms() - opened_started_ms_) : 0;
        YUME_TIMING_LOG("client.socks",
                         "stream_summary",
                         "stream=" + std::to_string(stream_id_) +
                             " ms=" + std::to_string(elapsed) +
                             " up=" + std::to_string(upload_bytes_) +
                             " down=" + std::to_string(download_bytes_) +
                             " target=" + target_host_ + ":" + std::to_string(target_port_));
    }
}

void SocksSession::close() {
    if (closed_) {
        return;
    }
    closed_ = true;
    log_summary_once();
    if (stream_id_ != 0) {
        tunnel_->send_close(stream_id_, "client closed");
        tunnel_->unregister_stream(stream_id_);
        stream_id_ = 0;
    }
    release_pool_session();
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
    : SocksServer(io, std::string{}, port, std::move(tunnel), allow_udp) {}

SocksServer::SocksServer(boost::asio::io_context& io,
                         std::string bind_host,
                         int port,
                         std::shared_ptr<Tunnel> tunnel,
                         bool allow_udp)
    : acceptor_(io)
    , tunnel_(std::move(tunnel))
    , allow_udp_(allow_udp) {
    auto ep = make_tcp_listen_endpoint(bind_host, port);
    acceptor_.open(ep.protocol());
    acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    acceptor_.bind(ep);
    acceptor_.listen();
}

SocksServer::SocksServer(boost::asio::io_context& io,
                         int port,
                         std::shared_ptr<TunnelPool> pool,
                         bool allow_udp)
    : SocksServer(io, std::string{}, port, std::move(pool), allow_udp) {}

SocksServer::SocksServer(boost::asio::io_context& io,
                         std::string bind_host,
                         int port,
                         std::shared_ptr<TunnelPool> pool,
                         bool allow_udp)
    : acceptor_(io)
    , pool_(std::move(pool))
    , allow_udp_(allow_udp) {
    auto ep = make_tcp_listen_endpoint(bind_host, port);
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

std::shared_ptr<Tunnel> SocksServer::pick_tunnel_for_new_session() {
    if (pool_) {
        return pool_->pick_for_session();
    }
    return tunnel_;
}

void SocksServer::do_accept() {
    acceptor_.async_accept([this](const boost::system::error_code& ec, boost::asio::ip::tcp::socket socket) {
        if (!ec) {
            auto picked = pick_tunnel_for_new_session();
            if (!picked) {
                util::log_warn("SOCKS accept: no live tunnel available; dropping client");
            } else {
                auto session = std::make_shared<SocksSession>(
                    std::move(socket),
                    std::move(picked),
                    allow_udp_,
                    pool_);
                session->start();
            }
        } else {
            util::log_warn(std::string("SOCKS accept failed: ") + ec.message());
        }
        do_accept();
    });
}

}  // namespace yume::client
