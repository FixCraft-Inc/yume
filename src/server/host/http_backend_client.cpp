/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/host/http_backend_client.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include <algorithm>
#include <cctype>
#include <memory>
#include <stdexcept>

namespace yume::server::host {
namespace {

namespace beast = boost::beast;
namespace http = beast::http;
using tcp = boost::asio::ip::tcp;

bool HopByHop(std::string_view name) {
    return name == "connection" || name == "keep-alive" ||
           name == "proxy-authenticate" || name == "proxy-authorization" ||
           name == "te" || name == "trailer" || name == "transfer-encoding" ||
           name == "upgrade";
}

std::size_t RequestHeaderBytes(const http::request<http::empty_body>& request) {
    // Count the serialized HTTP/1.1 request line and fields before handing the
    // request to Beast. This keeps the configured bound independent of any
    // internal buffer representation.
    std::size_t bytes = request.method_string().size() + 1U +
                        request.target().size() + sizeof(" HTTP/1.1\r\n") - 1U;
    for (const auto& field : request.base()) {
        bytes += field.name_string().size() + sizeof(": ") - 1U +
                 field.value().size() + sizeof("\r\n") - 1U;
    }
    return bytes + sizeof("\r\n") - 1U;
}

class Fetch : public std::enable_shared_from_this<Fetch> {
public:
    Fetch(boost::asio::any_io_executor executor,
          std::string ip, int port, std::string method, std::string target,
          BackendHttpLimits limits, BackendFetchHandler handler)
        : stream_(executor), ip_(std::move(ip)), port_(port),
          method_(std::move(method)), target_(std::move(target)),
          limits_(limits), handler_(std::move(handler)) {}

    void Start() {
        boost::system::error_code ec;
        const auto address = boost::asio::ip::make_address(ip_, ec);
        if (ec || !address.is_loopback() || port_ < 1 || port_ > 65535) {
            return Finish("backend is not a valid loopback IP endpoint");
        }
        if ((method_ != "GET" && method_ != "HEAD") || target_.empty() ||
            target_.front() != '/' || target_.size() > 8192 ||
            target_.find('\r') != std::string::npos ||
            target_.find('\n') != std::string::npos) {
            return Finish("invalid backend method or target");
        }
        request_.method(method_ == "GET" ? http::verb::get : http::verb::head);
        request_.target(target_);
        request_.version(11);
        request_.set(http::field::host, ip_ + ":" + std::to_string(port_));
        request_.set(http::field::user_agent, "yumed/2.0 cover-proxy");
        request_.set(http::field::accept, "*/*");
        request_.set(http::field::connection, "close");
        if (RequestHeaderBytes(request_) > limits_.request_headers) {
            return Finish("backend request headers exceed 32 KiB");
        }
        parser_.header_limit(limits_.response_headers);
        parser_.body_limit(limits_.response_body);
        if (method_ == "HEAD") parser_.skip(true);
        stream_.expires_after(limits_.connect_timeout);
        stream_.async_connect(tcp::endpoint(address, static_cast<unsigned short>(port_)),
            [self = shared_from_this()](const boost::system::error_code& connect_ec) {
                self->OnConnect(connect_ec);
            });
    }

private:
    void OnConnect(const boost::system::error_code& ec) {
        if (ec) return Finish("backend connect failed: " + ec.message());
        stream_.expires_after(limits_.response_timeout);
        http::async_write(stream_, request_,
            [self = shared_from_this()](const boost::system::error_code& write_ec,
                                        std::size_t) {
                self->OnWrite(write_ec);
            });
    }

    void OnWrite(const boost::system::error_code& ec) {
        if (ec) return Finish("backend request failed: " + ec.message());
        http::async_read(stream_, buffer_, parser_,
            [self = shared_from_this()](const boost::system::error_code& read_ec,
                                        std::size_t) {
                self->OnRead(read_ec);
            });
    }

    void OnRead(const boost::system::error_code& ec) {
        if (ec && ec != http::error::end_of_stream) {
            return Finish("backend response failed: " + ec.message());
        }
        auto message = parser_.release();
        BackendHttpResponse response;
        response.status = message.result_int();
        std::size_t header_bytes = 0;
        for (const auto& field : message.base()) {
            std::string name(field.name_string());
            std::transform(name.begin(), name.end(), name.begin(),
                           [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
            if (HopByHop(name)) continue;
            std::string value(field.value());
            // A HEAD response has no body, but its Content-Length describes
            // the corresponding GET representation. Preserve that value
            // instead of replacing it with the zero-byte parser body below.
            if (name == "content-length") {
                if (method_ == "HEAD") {
                    response.headers.emplace_back(std::move(name),
                                                  std::move(value));
                }
                continue;
            }
            if (name.size() + value.size() > limits_.response_headers -
                    std::min(limits_.response_headers, header_bytes)) {
                return Finish("backend response headers exceed 64 KiB");
            }
            header_bytes += name.size() + value.size();
            response.headers.emplace_back(std::move(name), std::move(value));
        }
        response.body = std::move(message.body());
        if (method_ != "HEAD") {
            response.headers.emplace_back("content-length",
                                          std::to_string(response.body.size()));
        }
        Finish({}, std::move(response));
    }

    void Finish(std::string error, BackendHttpResponse response = {}) {
        if (!handler_) return;
        boost::system::error_code ignored;
        stream_.socket().shutdown(tcp::socket::shutdown_both, ignored);
        stream_.socket().close(ignored);
        auto handler = std::move(handler_);
        handler(std::move(error), std::move(response));
    }

    beast::tcp_stream stream_;
    beast::flat_buffer buffer_;
    http::request<http::empty_body> request_;
    http::response_parser<http::vector_body<std::uint8_t>> parser_;
    std::string ip_;
    int port_;
    std::string method_;
    std::string target_;
    BackendHttpLimits limits_;
    BackendFetchHandler handler_;
};

}  // namespace

void fetch_loopback_http(boost::asio::any_io_executor executor,
                         std::string loopback_ip, int port,
                         std::string method, std::string target,
                         BackendHttpLimits limits, BackendFetchHandler handler) {
    std::make_shared<Fetch>(executor, std::move(loopback_ip), port,
                            std::move(method), std::move(target), limits,
                            std::move(handler))->Start();
}

bool probe_loopback_http(const std::string& loopback_ip, int port,
                         std::string* error, BackendHttpLimits limits) {
    boost::asio::io_context io;
    bool success = false;
    std::string result_error = "backend health probe did not complete";
    fetch_loopback_http(io.get_executor(), loopback_ip, port, "HEAD", "/", limits,
        [&](std::string fetch_error, BackendHttpResponse response) {
            result_error = std::move(fetch_error);
            success = result_error.empty() && response.status >= 200 && response.status < 500;
            if (!success && result_error.empty()) {
                result_error = "backend health probe returned HTTP " +
                               std::to_string(response.status);
            }
        });
    io.run();
    if (error) *error = std::move(result_error);
    return success;
}

}  // namespace yume::server::host
