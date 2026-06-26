/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/codec/monero_rpc.hpp"

#include <algorithm>
#include <array>
#include <istream>
#include <stdexcept>

#include <nlohmann/json.hpp>

#include "util.hpp"

namespace yume::client::codec {
namespace {

constexpr int kSocketBufferBytes = 512 * 1024;
constexpr auto kLocalReadTimeout = std::chrono::seconds(10);
constexpr auto kCodecResponseTimeout = std::chrono::seconds(60);

void tune_socket(boost::asio::ip::tcp::socket& socket) {
    boost::system::error_code ec;
    socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);
    socket.set_option(boost::asio::socket_base::receive_buffer_size(kSocketBufferBytes), ec);
    socket.set_option(boost::asio::socket_base::send_buffer_size(kSocketBufferBytes), ec);
}

app_codec::HttpResponse make_error_response(int status, const std::string& message) {
    app_codec::HttpResponse response;
    response.status_code = status;
    switch (status) {
        case 400: response.reason = "Bad Request"; break;
        case 403: response.reason = "Forbidden"; break;
        case 408: response.reason = "Request Timeout"; break;
        case 413: response.reason = "Payload Too Large"; break;
        case 502: response.reason = "Bad Gateway"; break;
        case 504: response.reason = "Gateway Timeout"; break;
        default: response.reason = "Codec Error"; break;
    }
    const std::string body = nlohmann::json{{"error", message}}.dump() + "\n";
    response.headers.push_back({"Content-Type", "application/json"});
    response.body.assign(body.begin(), body.end());
    return response;
}

class MoneroRpcCodecSession : public std::enable_shared_from_this<MoneroRpcCodecSession> {
public:
    MoneroRpcCodecSession(boost::asio::ip::tcp::socket socket,
                          std::shared_ptr<Tunnel> tunnel)
        : socket_(std::move(socket))
        , tunnel_(std::move(tunnel))
        , strand_(socket_.get_executor())
        , timer_(socket_.get_executor())
        , request_buf_(app_codec::kMaxHttpHeaderBytes + 1) {
        tune_socket(socket_);
    }

    void start() {
        read_headers();
    }

private:
    void arm_deadline(std::chrono::steady_clock::duration timeout, std::string reason) {
        timer_.expires_after(timeout);
        auto self = shared_from_this();
        timer_.async_wait(boost::asio::bind_executor(
            strand_,
            [self, reason = std::move(reason)](const boost::system::error_code& ec) {
                if (ec || self->closed_) {
                    return;
                }
                self->fail_local(504, reason);
            }));
    }

    void read_headers() {
        arm_deadline(kLocalReadTimeout, "Monero RPC request timed out");
        auto self = shared_from_this();
        boost::asio::async_read_until(
            socket_,
            request_buf_,
            "\r\n\r\n",
            boost::asio::bind_executor(
                strand_,
                [self](const boost::system::error_code& ec, std::size_t bytes) {
                    self->on_headers(ec, bytes);
                }));
    }

    void on_headers(const boost::system::error_code& ec, std::size_t bytes) {
        if (closed_) {
            return;
        }
        if (ec) {
            close();
            return;
        }
        if (bytes > app_codec::kMaxHttpHeaderBytes) {
            fail_local(413, "HTTP headers too large");
            return;
        }

        std::istream input(&request_buf_);
        std::string header_text(bytes, '\0');
        input.read(header_text.data(), static_cast<std::streamsize>(bytes));

        std::string parse_error;
        if (!app_codec::parse_http_request_head(header_text, &request_, &parse_error)) {
            fail_local(400, parse_error.empty() ? "invalid HTTP request" : parse_error);
            return;
        }
        if (app_codec::has_transfer_encoding_chunked(request_.headers)) {
            fail_local(400, "chunked requests are not supported by this codec");
            return;
        }
        std::string length_error;
        const auto content_len = app_codec::content_length(request_.headers, &length_error).value_or(0);
        if (!length_error.empty()) {
            fail_local(400, length_error);
            return;
        }
        if (content_len > app_codec::kMoneroRpcMaxRequestBody) {
            fail_local(413, "Monero RPC request body too large");
            return;
        }

        request_.body.resize(content_len);
        const std::size_t buffered = std::min<std::size_t>(request_buf_.size(), content_len);
        if (buffered > 0) {
            input.read(reinterpret_cast<char*>(request_.body.data()),
                       static_cast<std::streamsize>(buffered));
        }
        if (buffered >= content_len) {
            process_request();
            return;
        }
        auto self = shared_from_this();
        boost::asio::async_read(
            socket_,
            boost::asio::buffer(request_.body.data() + buffered, content_len - buffered),
            boost::asio::bind_executor(
                strand_,
                [self](const boost::system::error_code& body_ec, std::size_t) {
                    if (body_ec) {
                        self->close();
                        return;
                    }
                    self->process_request();
                }));
    }

    void process_request() {
        std::string deny_reason;
        if (!app_codec::validate_monero_rpc_request(request_, &deny_reason)) {
            fail_local(403, deny_reason.empty() ? "Monero RPC request denied" : deny_reason);
            return;
        }

        stream_id_ = tunnel_->reserve_stream_id();
        if (stream_id_ == 0) {
            fail_local(502, "no Yume stream ids available");
            return;
        }
        tunnel_->register_stream(
            stream_id_,
            [self = shared_from_this()](const Tunnel::Bytes& data) {
                boost::asio::post(self->strand_, [self, data]() {
                    self->on_codec_data(data);
                });
            },
            [self = shared_from_this()](const std::string& reason) {
                boost::asio::post(self->strand_, [self, reason]() {
                    self->on_codec_close(reason);
                });
            });

        nlohmann::json open_json{
            {"proto", std::string(app_codec::kOpenProto)},
            {"codec", std::string(app_codec::kMoneroRpcCodecId)},
        };
        tunnel_->open_relay_stream(
            stream_id_,
            open_json,
            [self = shared_from_this()](bool ok, const std::string& reason) {
                boost::asio::post(self->strand_, [self, ok, reason]() {
                    self->on_open_result(ok, reason);
                });
            });
        arm_deadline(kCodecResponseTimeout, "Monero RPC codec open timed out");
    }

    void on_open_result(bool ok, const std::string& reason) {
        if (closed_) {
            return;
        }
        if (!ok) {
            fail_local(502, reason.empty() ? "Monero RPC codec open failed" : reason);
            return;
        }
        util::log_info("monero-rpc codec: forwarding " + request_.method +
                       " " + request_.path +
                       " body_bytes=" + std::to_string(request_.body.size()));
        tunnel_->send_data(stream_id_, app_codec::encode_request(request_));
        arm_deadline(kCodecResponseTimeout, "Monero RPC backend timed out");
    }

    void on_codec_data(const Tunnel::Bytes& data) {
        if (closed_ || responded_) {
            return;
        }
        app_codec::Envelope envelope;
        std::string error;
        if (!app_codec::decode_envelope(data, app_codec::kMoneroRpcMaxResponseBody, &envelope, &error)) {
            fail_local(502, error.empty() ? "invalid codec response" : error);
            return;
        }
        if (envelope.kind == app_codec::EnvelopeKind::Error) {
            fail_local(envelope.error_status, envelope.error_message);
            return;
        }
        if (envelope.kind != app_codec::EnvelopeKind::Response) {
            fail_local(502, "unexpected codec frame");
            return;
        }
        responded_ = true;
        write_http_response(app_codec::build_client_http_response(envelope.response));
    }

    void on_codec_close(const std::string& reason) {
        if (closed_ || responded_) {
            close();
            return;
        }
        fail_local(502, reason.empty() ? "Monero RPC codec closed" : reason);
    }

    void fail_local(int status, const std::string& message) {
        if (closed_ || responded_) {
            close();
            return;
        }
        util::log_warn("monero-rpc codec: " + message);
        responded_ = true;
        write_http_response(app_codec::build_client_http_response(
            make_error_response(status, message)));
    }

    void write_http_response(std::string response) {
        timer_.cancel();
        auto data = std::make_shared<std::string>(std::move(response));
        auto self = shared_from_this();
        boost::asio::async_write(
            socket_,
            boost::asio::buffer(*data),
            boost::asio::bind_executor(
                strand_,
                [self, data](const boost::system::error_code&, std::size_t) {
                    self->close();
                }));
    }

    void close() {
        if (closed_) {
            return;
        }
        closed_ = true;
        timer_.cancel();
        if (stream_id_ != 0) {
            tunnel_->send_close(stream_id_, "monero-rpc local session closed");
            tunnel_->unregister_stream(stream_id_);
            stream_id_ = 0;
        }
        boost::system::error_code ec;
        socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        socket_.close(ec);
    }

    boost::asio::ip::tcp::socket socket_;
    std::shared_ptr<Tunnel> tunnel_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;
    boost::asio::steady_timer timer_;
    boost::asio::streambuf request_buf_;
    app_codec::HttpRequest request_;
    std::uint8_t stream_id_{0};
    bool responded_{false};
    bool closed_{false};
};

}  // namespace

MoneroRpcCodecServer::MoneroRpcCodecServer(boost::asio::io_context& io,
                                           app_codec::Endpoint listen,
                                           std::shared_ptr<Tunnel> tunnel)
    : acceptor_(io)
    , listen_(std::move(listen))
    , tunnel_(std::move(tunnel)) {
    if (!app_codec::is_loopback_host_literal(listen_.host)) {
        throw std::runtime_error("monero-rpc codec listener must be a loopback IP literal");
    }
    boost::system::error_code ec;
    const auto addr = boost::asio::ip::make_address(listen_.host, ec);
    if (ec) {
        throw std::runtime_error("monero-rpc codec listen address invalid: " + ec.message());
    }
    boost::asio::ip::tcp::endpoint endpoint(addr, static_cast<unsigned short>(listen_.port));
    acceptor_.open(endpoint.protocol(), ec);
    if (ec) {
        throw std::runtime_error("monero-rpc codec listen open failed: " + ec.message());
    }
    acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    acceptor_.bind(endpoint, ec);
    if (ec) {
        throw std::runtime_error("monero-rpc codec listen bind failed: " + ec.message());
    }
    acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) {
        throw std::runtime_error("monero-rpc codec listen failed: " + ec.message());
    }
}

void MoneroRpcCodecServer::start() {
    util::log_info("monero-rpc codec listening on " + listen_.host + ":" +
                   std::to_string(listen_.port));
    do_accept();
}

void MoneroRpcCodecServer::do_accept() {
    acceptor_.async_accept([this](const boost::system::error_code& ec,
                                  boost::asio::ip::tcp::socket socket) {
        if (!ec) {
            std::make_shared<MoneroRpcCodecSession>(std::move(socket), tunnel_)->start();
        } else {
            util::log_warn("monero-rpc codec accept failed: " + ec.message());
        }
        do_accept();
    });
}

}  // namespace yume::client::codec
