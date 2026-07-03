/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/host/extra_listeners.hpp"

#include "server/host/host_routes.hpp"
#include "server/host/http_proxy.hpp"
#include "server/host/socket_util.hpp"
#include "server/runtime/manager.hpp"
#include "core/app_codec/codec.hpp"
#include "core/stealth/obfs.hpp"
#include "util.hpp"

#include <array>
#include <cctype>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>

namespace yume::server {
namespace {

constexpr std::size_t kMaxSmtpCommandLine = 1024;

class TlsTerminateBridge : public std::enable_shared_from_this<TlsTerminateBridge> {
public:
    TlsTerminateBridge(boost::asio::ip::tcp::socket client,
                       boost::asio::ssl::context& ssl_ctx,
                       std::string backend_host,
                       int backend_port,
                       Manager* manager)
        : client_stream_(std::move(client), ssl_ctx)
        , backend_host_(std::move(backend_host))
        , backend_port_(backend_port)
        , manager_(manager)
        , timer_(client_stream_.get_executor()) {}

    void start() {
        arm_timeout(std::chrono::seconds(10));
        auto self = shared_from_this();
        client_stream_.async_handshake(boost::asio::ssl::stream_base::server,
                                       [self](const boost::system::error_code& ec) {
                                           self->cancel_timeout();
                                           if (ec) {
                                               self->close_client();
                                               return;
                                           }
                                           if (yume::obfs::selected_alpn(self->client_stream_.native_handle()) == "h2") {
                                               self->close_client();
                                               return;
                                           }
                                           self->read_http_request();
                                       });
    }

private:
    void read_http_request() {
        arm_timeout(std::chrono::seconds(10));
        auto self = shared_from_this();
        boost::asio::async_read_until(
            client_stream_,
            boost::asio::dynamic_buffer(request_, yume::app_codec::kMaxHttpHeaderBytes + 1),
            "\r\n\r\n",
            [self](const boost::system::error_code& ec, std::size_t) {
                self->cancel_timeout();
                if (ec || self->request_.size() > yume::app_codec::kMaxHttpHeaderBytes) {
                    self->close_client();
                    return;
                }
                if (self->request_.rfind("PRI * HT", 0) == 0) {
                    self->close_client();
                    return;
                }
                host::start_http_reverse_proxy(std::move(self->client_stream_),
                                               std::move(self->request_),
                                               self->backend_host_,
                                               self->backend_port_,
                                               self->manager_);
            });
    }

    void arm_timeout(std::chrono::steady_clock::duration duration) {
        auto self = shared_from_this();
        timer_.expires_after(duration);
        timer_.async_wait([self](const boost::system::error_code& ec) {
            if (!ec) {
                self->close_client();
            }
        });
    }

    void cancel_timeout() {
        timer_.cancel();
    }

    void close_client() {
        boost::system::error_code ec;
        timer_.cancel();
        client_stream_.lowest_layer().close(ec);
    }

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> client_stream_;
    std::string backend_host_;
    int backend_port_{0};
    Manager* manager_{nullptr};
    std::string request_;
    boost::asio::steady_timer timer_;
};

class SmtpStartTlsBridge : public std::enable_shared_from_this<SmtpStartTlsBridge> {
public:
    SmtpStartTlsBridge(boost::asio::ip::tcp::socket client,
                       boost::asio::ssl::context& ssl_ctx,
                       std::string backend_host,
                       int backend_port)
        : client_stream_(std::move(client), ssl_ctx)
        , backend_host_(std::move(backend_host))
        , backend_port_(backend_port)
        , backend_socket_(client_stream_.get_executor())
        , timer_(client_stream_.get_executor()) {}

    void start() {
        auto self = shared_from_this();
        auto banner = std::make_shared<std::string>("220 yume.local ESMTP ready\r\n");
        boost::asio::async_write(
            client_stream_.next_layer(),
            boost::asio::buffer(*banner),
            [self, banner](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    return;
                }
                self->read_client_line();
            });
    }

private:
    void read_client_line() {
        arm_timeout(std::chrono::seconds(30));
        auto self = shared_from_this();
        boost::asio::async_read_until(
            client_stream_.next_layer(),
            boost::asio::dynamic_buffer(client_buf_, kMaxSmtpCommandLine + 2),
            "\r\n",
            [self](const boost::system::error_code& ec, std::size_t) {
                self->cancel_timeout();
                if (ec || self->client_buf_.size() > kMaxSmtpCommandLine + 2) {
                    self->close_client();
                    return;
                }
                std::string line = self->client_buf_;
                self->client_buf_.clear();
                std::string upper = line;
                for (char& c : upper) {
                    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                }
                if (upper.rfind("STARTTLS", 0) == 0) {
                    auto reply = std::make_shared<std::string>("220 Ready to start TLS\r\n");
                    boost::asio::async_write(
                        self->client_stream_.next_layer(),
                        boost::asio::buffer(*reply),
                        [self, reply](const boost::system::error_code& wec, std::size_t) {
                            if (wec) {
                                return;
                            }
                            self->arm_timeout(std::chrono::seconds(10));
                            self->client_stream_.async_handshake(
                                boost::asio::ssl::stream_base::server,
                                [self](const boost::system::error_code& hec) {
                                    self->cancel_timeout();
                                    if (hec) {
                                        return;
                                    }
                                    self->connect_backend();
                                });
                        });
                    return;
                }
                if (upper.rfind("QUIT", 0) == 0) {
                    auto reply = std::make_shared<std::string>("221 Bye\r\n");
                    boost::asio::async_write(
                        self->client_stream_.next_layer(),
                        boost::asio::buffer(*reply),
                        [self, reply](const boost::system::error_code&, std::size_t) {});
                    return;
                }
                auto reply = std::make_shared<std::string>("502 Command not implemented\r\n");
                boost::asio::async_write(
                    self->client_stream_.next_layer(),
                    boost::asio::buffer(*reply),
                    [self, reply](const boost::system::error_code&, std::size_t) { self->read_client_line(); });
            });
    }

    void connect_backend() {
        boost::system::error_code addr_ec;
        const auto address = boost::asio::ip::make_address(backend_host_, addr_ec);
        if (addr_ec || backend_port_ < 1 || backend_port_ > 65535) {
            yume::util::log_warn("smtp shield backend address invalid: " + backend_host_);
            return;
        }
        arm_timeout(std::chrono::seconds(10));
        auto self = shared_from_this();
        backend_socket_.async_connect(
            boost::asio::ip::tcp::endpoint(address, static_cast<unsigned short>(backend_port_)),
            [self](const boost::system::error_code& ec) {
                self->cancel_timeout();
                if (ec) {
                    yume::util::log_warn("smtp shield backend connect failed: " + ec.message());
                    return;
                }
                self->relay_client_to_backend();
                self->relay_backend_to_client();
            });
    }

    void arm_timeout(std::chrono::steady_clock::duration duration) {
        auto self = shared_from_this();
        timer_.expires_after(duration);
        timer_.async_wait([self](const boost::system::error_code& ec) {
            if (!ec) {
                self->close_client();
            }
        });
    }

    void cancel_timeout() {
        timer_.cancel();
    }

    void close_client() {
        boost::system::error_code ec;
        timer_.cancel();
        backend_socket_.close(ec);
        client_stream_.lowest_layer().close(ec);
    }

    void relay_client_to_backend() {
        auto self = shared_from_this();
        client_stream_.async_read_some(
            boost::asio::buffer(read_client_),
            [self](const boost::system::error_code& ec, std::size_t n) {
                if (ec) {
                    return;
                }
                boost::asio::async_write(
                    self->backend_socket_,
                    boost::asio::buffer(self->read_client_.data(), n),
                    [self](const boost::system::error_code& wec, std::size_t) {
                        if (wec) {
                            return;
                        }
                        self->relay_client_to_backend();
                    });
            });
    }

    void relay_backend_to_client() {
        auto self = shared_from_this();
        backend_socket_.async_read_some(
            boost::asio::buffer(read_backend_),
            [self](const boost::system::error_code& ec, std::size_t n) {
                if (ec) {
                    return;
                }
                boost::asio::async_write(
                    self->client_stream_,
                    boost::asio::buffer(self->read_backend_.data(), n),
                    [self](const boost::system::error_code& wec, std::size_t) {
                        if (wec) {
                            return;
                        }
                        self->relay_backend_to_client();
                    });
            });
    }

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> client_stream_;
    std::string backend_host_;
    int backend_port_{0};
    boost::asio::ip::tcp::socket backend_socket_;
    std::string client_buf_;
    std::array<char, 8192> read_client_{};
    std::array<char, 8192> read_backend_{};
    boost::asio::steady_timer timer_;
};

class TcpPassthroughBridge : public std::enable_shared_from_this<TcpPassthroughBridge> {
public:
    TcpPassthroughBridge(boost::asio::ip::tcp::socket client,
                         std::string backend_host,
                         int backend_port)
        : client_(std::move(client))
        , backend_host_(std::move(backend_host))
        , backend_port_(backend_port)
        , backend_(client_.get_executor())
        , timer_(client_.get_executor()) {}

    void start() {
        boost::system::error_code addr_ec;
        const auto address = boost::asio::ip::make_address(backend_host_, addr_ec);
        if (addr_ec || backend_port_ < 1 || backend_port_ > 65535) {
            yume::util::log_warn("tcp passthrough backend address invalid: " + backend_host_);
            boost::system::error_code close_ec;
            client_.close(close_ec);
            return;
        }
        arm_timeout(std::chrono::seconds(10));
        auto self = shared_from_this();
        backend_.async_connect(
            boost::asio::ip::tcp::endpoint(address, static_cast<unsigned short>(backend_port_)),
            [self](const boost::system::error_code& ec) {
                self->cancel_timeout();
                if (ec) {
                    yume::util::log_warn("tcp passthrough backend connect failed: " + ec.message());
                    boost::system::error_code close_ec;
                    self->client_.close(close_ec);
                    return;
                }
                self->relay_client_to_backend();
                self->relay_backend_to_client();
            });
    }

private:
    void arm_timeout(std::chrono::steady_clock::duration duration) {
        auto self = shared_from_this();
        timer_.expires_after(duration);
        timer_.async_wait([self](const boost::system::error_code& ec) {
            if (!ec) {
                self->close_both();
            }
        });
    }

    void cancel_timeout() {
        timer_.cancel();
    }

    void close_both() {
        boost::system::error_code ec;
        timer_.cancel();
        backend_.close(ec);
        client_.close(ec);
    }

    void relay_client_to_backend() {
        auto self = shared_from_this();
        client_.async_read_some(
            boost::asio::buffer(client_buf_),
            [self](const boost::system::error_code& ec, std::size_t n) {
                if (ec) {
                    boost::system::error_code shutdown_ec;
                    self->backend_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, shutdown_ec);
                    return;
                }
                boost::asio::async_write(
                    self->backend_,
                    boost::asio::buffer(self->client_buf_.data(), n),
                    [self](const boost::system::error_code& wec, std::size_t) {
                        if (wec) {
                            return;
                        }
                        self->relay_client_to_backend();
                    });
            });
    }

    void relay_backend_to_client() {
        auto self = shared_from_this();
        backend_.async_read_some(
            boost::asio::buffer(backend_buf_),
            [self](const boost::system::error_code& ec, std::size_t n) {
                if (ec) {
                    boost::system::error_code shutdown_ec;
                    self->client_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, shutdown_ec);
                    return;
                }
                boost::asio::async_write(
                    self->client_,
                    boost::asio::buffer(self->backend_buf_.data(), n),
                    [self](const boost::system::error_code& wec, std::size_t) {
                        if (wec) {
                            return;
                        }
                        self->relay_backend_to_client();
                    });
            });
    }

    boost::asio::ip::tcp::socket client_;
    std::string backend_host_;
    int backend_port_{0};
    boost::asio::ip::tcp::socket backend_;
    std::array<char, 16384> client_buf_{};
    std::array<char, 16384> backend_buf_{};
    boost::asio::steady_timer timer_;
};

}  // namespace

ExtraListeners::ExtraListeners(boost::asio::io_context& io,
                               boost::asio::ssl::context& ssl_ctx,
                               const ServerConfig& cfg,
                               Manager* manager)
    : io_(io), ssl_ctx_(ssl_ctx), cfg_(cfg), manager_(manager) {}

ExtraListeners::~ExtraListeners() {
    stop();
}

void ExtraListeners::start() {
    for (const auto& spec : cfg_.extra_listeners) {
        start_listener(spec);
    }
}

void ExtraListeners::stop() {
    if (stopped_) {
        return;
    }
    stopped_ = true;
    for (auto& listener : listeners_) {
        boost::system::error_code ec;
        listener->acceptor->close(ec);
    }
    listeners_.clear();
}

void ExtraListeners::start_listener(const host::ListenerSpec& spec) {
    if (spec.bind_port < 1 || spec.bind_port > 65535) {
        throw std::runtime_error("extra listener bind port out of range");
    }
    auto entry = std::make_shared<PlainListener>();
    entry->spec = spec;
    entry->acceptor = std::make_unique<boost::asio::ip::tcp::acceptor>(io_);
    boost::asio::ip::tcp::endpoint ep;
    if (spec.bind_address.empty()) {
        ep = boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(),
                                            static_cast<unsigned short>(spec.bind_port));
    } else {
        boost::system::error_code addr_ec;
        const auto address = boost::asio::ip::make_address(spec.bind_address, addr_ec);
        if (addr_ec) {
            throw std::runtime_error("extra listener invalid bind address: " + spec.bind_address);
        }
        ep = boost::asio::ip::tcp::endpoint(address, static_cast<unsigned short>(spec.bind_port));
    }
    boost::system::error_code ec;
    entry->acceptor->open(ep.protocol(), ec);
    if (ec) {
        throw std::runtime_error("extra listener open failed: " + ec.message());
    }
    entry->acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    entry->acceptor->bind(ep, ec);
    if (ec) {
        throw std::runtime_error("extra listener bind failed: " + ec.message());
    }
    entry->acceptor->listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) {
        throw std::runtime_error("extra listener listen failed: " + ec.message());
    }
    yume::util::log_info("extra listener on " + ep.address().to_string() + ":" +
                         std::to_string(ep.port()) + " mode=" +
                         host::to_string(spec.mode));
    listeners_.push_back(entry);
    do_accept_plain(entry);
}

void ExtraListeners::do_accept_plain(std::shared_ptr<PlainListener> listener) {
    if (stopped_ || !listener->acceptor->is_open()) {
        return;
    }
    listener->acceptor->async_accept([this, listener](const boost::system::error_code& ec,
                                                      boost::asio::ip::tcp::socket socket) {
        if (!ec) {
            if (manager_ && !manager_->admit_plain_client(socket)) {
                boost::system::error_code close_ec;
                socket.close(close_ec);
            } else {
                handle_plain_connection(listener->spec, std::move(socket));
            }
        }
        if (!stopped_ && listener->acceptor->is_open()) {
            do_accept_plain(listener);
        }
    });
}

void ExtraListeners::handle_plain_connection(host::ListenerSpec spec, boost::asio::ip::tcp::socket socket) {
    auto backend = host::parse_loopback_backend(spec.backend);
    if (!backend.has_value()) {
        host::close_socket(cfg_.client_deny_action, socket);
        return;
    }
    if (spec.mode == host::ListenerMode::TcpPassthrough) {
        std::make_shared<TcpPassthroughBridge>(std::move(socket), backend->first, backend->second)->start();
        return;
    }
    if (spec.mode == host::ListenerMode::StartTlsMail) {
        std::make_shared<SmtpStartTlsBridge>(std::move(socket), ssl_ctx_, backend->first, backend->second)
            ->start();
        return;
    }
    if (spec.mode == host::ListenerMode::TlsTerminate) {
        std::make_shared<TlsTerminateBridge>(std::move(socket),
                                             ssl_ctx_,
                                             backend->first,
                                             backend->second,
                                             manager_)
            ->start();
        return;
    }
    host::close_socket(cfg_.client_deny_action, socket);
}

}  // namespace yume::server
