/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/host/http_proxy.hpp"

#include <array>
#include <chrono>
#include <memory>
#include <string>

#include "server/runtime/manager.hpp"
#include "util.hpp"

namespace yume::server::host {
namespace {

class HttpReverseProxy : public std::enable_shared_from_this<HttpReverseProxy> {
public:
    HttpReverseProxy(boost::asio::ssl::stream<boost::asio::ip::tcp::socket> client_stream,
                     std::string initial_request,
                     std::string backend_host,
                     int backend_port,
                     Manager* manager)
        : client_stream_(std::move(client_stream))
        , initial_request_(std::move(initial_request))
        , backend_host_(std::move(backend_host))
        , backend_port_(backend_port)
        , backend_socket_(client_stream_.get_executor())
        , connect_timer_(client_stream_.get_executor()) {
        (void)manager;
    }

    void start() {
        boost::system::error_code addr_ec;
        const auto address = boost::asio::ip::make_address(backend_host_, addr_ec);
        if (addr_ec || backend_port_ < 1 || backend_port_ > 65535) {
            yume::util::log_warn("host http proxy backend address invalid: " + backend_host_);
            boost::system::error_code close_ec;
            client_stream_.lowest_layer().close(close_ec);
            return;
        }
        arm_connect_timeout();
        auto self = shared_from_this();
        backend_socket_.async_connect(
            boost::asio::ip::tcp::endpoint(address, static_cast<unsigned short>(backend_port_)),
            [self](const boost::system::error_code& ec) {
                self->connect_timer_.cancel();
                if (ec) {
                    yume::util::log_warn("host http proxy backend connect failed: " + ec.message());
                    boost::system::error_code close_ec;
                    self->client_stream_.lowest_layer().close(close_ec);
                    return;
                }
                self->on_backend_connected();
            });
    }

private:
    void arm_connect_timeout() {
        auto self = shared_from_this();
        connect_timer_.expires_after(std::chrono::seconds(10));
        connect_timer_.async_wait([self](const boost::system::error_code& ec) {
            if (!ec) {
                self->close_both("backend connect timed out");
            }
        });
    }

    void on_backend_connected() {
        auto self = shared_from_this();
        boost::asio::async_write(
            backend_socket_,
            boost::asio::buffer(initial_request_),
            [self](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    self->close_both("backend write failed: " + ec.message());
                    return;
                }
                self->pump_client_to_backend();
                self->pump_backend_to_client();
            });
    }

    void pump_client_to_backend() {
        auto self = shared_from_this();
        client_stream_.async_read_some(
            boost::asio::buffer(client_buf_),
            [self](const boost::system::error_code& ec, std::size_t n) {
                if (ec) {
                    boost::system::error_code shutdown_ec;
                    self->backend_socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, shutdown_ec);
                    return;
                }
                boost::asio::async_write(
                    self->backend_socket_,
                    boost::asio::buffer(self->client_buf_.data(), n),
                    [self](const boost::system::error_code& wec, std::size_t) {
                        if (wec) {
                            self->close_both("backend relay failed");
                            return;
                        }
                        self->pump_client_to_backend();
                    });
            });
    }

    void pump_backend_to_client() {
        auto self = shared_from_this();
        backend_socket_.async_read_some(
            boost::asio::buffer(backend_buf_),
            [self](const boost::system::error_code& ec, std::size_t n) {
                if (ec) {
                    self->client_stream_.async_shutdown(
                        [self](const boost::system::error_code&) {
                            boost::system::error_code close_ec;
                            self->client_stream_.lowest_layer().close(close_ec);
                        });
                    return;
                }
                auto data = std::make_shared<std::string>(self->backend_buf_.data(), n);
                boost::asio::async_write(
                    self->client_stream_,
                    boost::asio::buffer(*data),
                    [self, data](const boost::system::error_code& wec, std::size_t) {
                        if (wec) {
                            self->close_both("client relay failed");
                            return;
                        }
                        self->pump_backend_to_client();
                    });
            });
    }

    void close_both(const std::string& reason) {
        (void)reason;
        boost::system::error_code ec;
        connect_timer_.cancel();
        backend_socket_.close(ec);
        client_stream_.lowest_layer().close(ec);
    }

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> client_stream_;
    std::string initial_request_;
    std::string backend_host_;
    int backend_port_{0};
    boost::asio::ip::tcp::socket backend_socket_;
    boost::asio::steady_timer connect_timer_;
    std::array<char, 16384> client_buf_{};
    std::array<char, 16384> backend_buf_{};
};

}  // namespace

void start_http_reverse_proxy(boost::asio::ssl::stream<boost::asio::ip::tcp::socket> client_stream,
                              std::string initial_request,
                              const std::string& backend_host,
                              int backend_port,
                              Manager* manager) {
    auto proxy = std::make_shared<HttpReverseProxy>(
        std::move(client_stream), std::move(initial_request), backend_host, backend_port, manager);
    proxy->start();
}

}  // namespace yume::server::host
