/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/session.hpp"

#include <algorithm>
#include <istream>
#include <new>

#include "core/app_codec/builtin/monero_rpc.hpp"
#include "core/app_codec/codec.hpp"
#include "server/session/internal.hpp"

namespace yume::server {

using namespace detail;

namespace {
constexpr auto kCodecBackendTimeout = std::chrono::milliseconds(30000);
constexpr std::size_t kMaxCodecStreamsPerSession = 8;
constexpr std::size_t kCodecResponseBudgetBytes = 32U * 1024U * 1024U;

// Maps a codec to the config fields that spell its backend override. Codecs may
// name their own flags on the product surface, so this is the single place that
// translation happens; dispatch below stays descriptor-driven. A codec without
// an entry uses its descriptor's default endpoint.
app_codec::Endpoint resolve_codec_backend(const ServerConfig& cfg,
                                          const app_codec::CodecDescriptor& descriptor) {
    if (descriptor.id == std::string(app_codec::builtin::kMoneroRpcCodecId)) {
        return app_codec::Endpoint{cfg.monero_rpc_backend_host,
                                   cfg.monero_rpc_backend_port};
    }
    return descriptor.default_endpoint;
}

}  // namespace

std::shared_ptr<Session::CodecStream> Session::find_codec_stream(uint8_t stream_id) {
    std::lock_guard<std::mutex> lock(streams_mutex_);
    auto it = codec_streams_.find(stream_id);
    if (it == codec_streams_.end()) {
        return nullptr;
    }
    return it->second;
}

bool Session::handle_codec_open(uint8_t stream_id, const nlohmann::json& json) {
    const std::string codec_id = app_codec::canonical_codec_id(json.value("codec", ""));
    auto descriptor = app_codec::builtin_codec(codec_id);
    if (!descriptor.has_value()) {
        send_open_reply(stream_id, false, "unsupported application codec");
        return true;
    }
    if (!app_codec::contains_codec(cfg_.allowed_codecs, codec_id) ||
        session_allowed_codecs_.count(codec_id) == 0) {
        send_open_reply(stream_id, false, descriptor->id + " codec not permitted");
        return true;
    }

    const app_codec::Endpoint backend = resolve_codec_backend(cfg_, *descriptor);
    if (descriptor->require_loopback_backend &&
        !app_codec::is_loopback_host_literal(backend.host)) {
        send_open_reply(stream_id, false, descriptor->id + " backend must be a loopback IP literal");
        return true;
    }
    if (backend.port < 1 || backend.port > 65535) {
        send_open_reply(stream_id, false, descriptor->id + " backend port invalid");
        return true;
    }

    auto codec = std::make_shared<CodecStream>(stream_.get_executor());
    codec->codec_id = descriptor->id;
    codec->backend_host = backend.host;
    codec->backend_port = backend.port;
    codec->open_started_ms = util::now_ms();
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        if (codec_streams_.find(stream_id) != codec_streams_.end()) {
            send_open_reply(stream_id, false, "codec stream already exists");
            return true;
        }
        if (codec_streams_.size() >= kMaxCodecStreamsPerSession) {
            send_open_reply(stream_id, false, "too many concurrent codec streams");
            return true;
        }
        codec_streams_[stream_id] = codec;
    }

    util::log_info("session " + std::to_string(session_id_) +
                   ": OPEN app codec stream " + std::to_string(stream_id) +
                   " codec=" + codec->codec_id + " backend=" + codec->backend_host +
                   ":" + std::to_string(codec->backend_port));
    send_open_reply(stream_id, true, "");
    return true;
}

bool Session::handle_codec_data(uint8_t stream_id, const crypto::Bytes& payload) {
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        if (codec_streams_.find(stream_id) == codec_streams_.end()) {
            return false;
        }
    }
    start_codec_backend(stream_id, payload);
    return true;
}

bool Session::handle_codec_close(uint8_t stream_id,
                                 [[maybe_unused]] const std::string& reason) {
    std::shared_ptr<CodecStream> codec;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = codec_streams_.find(stream_id);
        if (it == codec_streams_.end()) {
            return false;
        }
        codec = it->second;
        codec_response_bytes_ -=
            std::min(codec_response_bytes_, codec->response_reserved_bytes);
        codec->response_reserved_bytes = 0;
        codec_streams_.erase(it);
    }

    if (codec && !codec->close_summary_logged) {
        codec->close_summary_logged = true;
        [[maybe_unused]] const int64_t elapsed =
            codec->open_started_ms > 0 ? (util::now_ms() - codec->open_started_ms) : 0;
        YUME_TIMING_LOG("server.stream",
                         "summary",
                         "session=" + std::to_string(session_id_) +
                             " stream=" + std::to_string(stream_id) +
                             " proto=app-codec codec=" + codec->codec_id +
                             " ms=" + std::to_string(elapsed) +
                             " upstream=" + std::to_string(codec->upstream_bytes) +
                             " downstream=" + std::to_string(codec->downstream_bytes) +
                             " backend=" + codec->backend_host + ":" + std::to_string(codec->backend_port) +
                             " reason=" + reason);
    }
    if (codec) {
        boost::system::error_code ec;
        codec->timer.cancel();
        codec->socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        codec->socket.close(ec);
    }
    return true;
}

void Session::send_codec_error(uint8_t stream_id, int http_status, const std::string& message) {
    std::string codec_id = "app-codec";
    if (auto codec = find_codec_stream(stream_id)) {
        codec_id = codec->codec_id;
    }
    util::log_warn("session " + std::to_string(session_id_) +
                   ": " + codec_id + " stream " + std::to_string(stream_id) +
                   ": " + message);
    send_control_frame(protocol::DATA, stream_id, app_codec::encode_error(http_status, message));
    send_control_close(stream_id, message);
}

void Session::start_codec_backend(uint8_t stream_id, const crypto::Bytes& payload) {
    std::shared_ptr<CodecStream> codec = find_codec_stream(stream_id);
    if (!codec) {
        return;
    }
    if (!codec->request_bytes.empty() || codec->response_sent) {
        send_codec_error(stream_id, 400, "codec stream accepts one request");
        handle_codec_close(stream_id, "duplicate codec request");
        return;
    }

    auto descriptor = app_codec::builtin_codec(codec->codec_id);
    if (!descriptor.has_value()) {
        send_codec_error(stream_id, 400, "unsupported codec handler");
        handle_codec_close(stream_id, "unsupported codec handler");
        return;
    }

    app_codec::Envelope envelope;
    std::string decode_error;
    if (!app_codec::decode_envelope(payload, descriptor->max_request_body, &envelope, &decode_error) ||
        envelope.kind != app_codec::EnvelopeKind::Request) {
        send_codec_error(stream_id, 400, decode_error.empty() ? "invalid codec request" : decode_error);
        handle_codec_close(stream_id, "invalid codec request");
        return;
    }
    // Fail-closed: a codec that ships no request policy admits nothing.
    std::string deny_reason;
    if (descriptor->validate_request == nullptr ||
        !descriptor->validate_request(envelope.request, &deny_reason)) {
        send_codec_error(stream_id, 403,
                         deny_reason.empty() ? descriptor->display_name + " request denied"
                                             : deny_reason);
        handle_codec_close(stream_id, "codec request denied");
        return;
    }

    app_codec::Endpoint backend{codec->backend_host, codec->backend_port};
    std::string request_error;
    const auto http_request = app_codec::build_backend_http_request(
        envelope.request, backend, &request_error);
    if (!http_request.has_value()) {
        send_codec_error(stream_id, 400, request_error.empty() ? "invalid codec request" : request_error);
        handle_codec_close(stream_id, "invalid codec request reconstruction");
        return;
    }
    codec->request_bytes.assign(http_request->begin(), http_request->end());
    codec->upstream_bytes = envelope.request.body.size();
    codec->request_started_ms = util::now_ms();

    boost::system::error_code addr_ec;
    const auto backend_addr = boost::asio::ip::make_address(codec->backend_host, addr_ec);
    if (addr_ec || !backend_addr.is_loopback()) {
        send_codec_error(stream_id, 502, "Monero RPC backend address invalid");
        handle_codec_close(stream_id, "invalid codec backend");
        return;
    }
    boost::asio::ip::tcp::endpoint endpoint(backend_addr, static_cast<unsigned short>(codec->backend_port));
    boost::system::error_code open_ec;
    codec->socket.open(endpoint.protocol(), open_ec);
    if (open_ec) {
        send_codec_error(stream_id, 502, "Monero RPC backend socket open failed");
        handle_codec_close(stream_id, "backend socket open failed");
        return;
    }

    arm_codec_timer(stream_id, kCodecBackendTimeout, "Monero RPC backend connect timeout");
    auto self = shared_from_this();
    codec->socket.async_connect(endpoint,
                                boost::asio::bind_executor(
                                    strand_,
                                    [self, stream_id, codec](const boost::system::error_code& ec) {
                                        (void)codec;
                                        self->on_codec_backend_connect(stream_id, ec);
                                    }));
}

void Session::on_codec_backend_connect(uint8_t stream_id, const boost::system::error_code& ec) {
    std::shared_ptr<CodecStream> codec = find_codec_stream(stream_id);
    if (!codec) {
        return;
    }
    if (ec) {
        send_codec_error(stream_id, 502, "Monero RPC backend connect failed");
        handle_codec_close(stream_id, "backend connect failed: " + ec.message());
        return;
    }

    arm_codec_timer(stream_id, kCodecBackendTimeout, "Monero RPC backend write timeout");
    auto buffer = std::make_shared<std::vector<uint8_t>>(codec->request_bytes);
    auto self = shared_from_this();
    boost::asio::async_write(
        codec->socket,
        boost::asio::buffer(*buffer),
        boost::asio::bind_executor(
            strand_,
            [self, stream_id, codec, buffer](const boost::system::error_code& write_ec, std::size_t bytes) {
                (void)codec;
                self->on_codec_backend_write(stream_id, write_ec, bytes);
            }));
}

void Session::on_codec_backend_write(uint8_t stream_id,
                                     const boost::system::error_code& ec,
                                     std::size_t) {
    std::shared_ptr<CodecStream> codec = find_codec_stream(stream_id);
    if (!codec) {
        return;
    }
    if (ec) {
        send_codec_error(stream_id, 502, "Monero RPC backend write failed");
        handle_codec_close(stream_id, "backend write failed: " + ec.message());
        return;
    }

    arm_codec_timer(stream_id, kCodecBackendTimeout, "Monero RPC backend response timeout");
    auto self = shared_from_this();
    boost::asio::async_read_until(
        codec->socket,
        codec->response_buf,
        "\r\n\r\n",
        boost::asio::bind_executor(
            strand_,
            [self, stream_id, codec](const boost::system::error_code& read_ec, std::size_t bytes) {
                (void)codec;
                self->on_codec_backend_headers(stream_id, read_ec, bytes);
            }));
}

void Session::on_codec_backend_headers(uint8_t stream_id,
                                       const boost::system::error_code& ec,
                                       std::size_t bytes) {
    std::shared_ptr<CodecStream> codec = find_codec_stream(stream_id);
    if (!codec) {
        return;
    }
    if (ec == boost::asio::error::not_found ||
        codec->response_buf.size() > app_codec::kMaxHttpHeaderBytes) {
        send_codec_error(stream_id, 502, "Monero RPC backend headers too large");
        handle_codec_close(stream_id, "backend headers exceeded limit");
        return;
    }
    if (ec) {
        send_codec_error(stream_id, 502, "Monero RPC backend did not return HTTP");
        handle_codec_close(stream_id, "backend header read failed: " + ec.message());
        return;
    }
    if (bytes > app_codec::kMaxHttpHeaderBytes) {
        send_codec_error(stream_id, 502, "Monero RPC backend headers too large");
        handle_codec_close(stream_id, "backend headers too large");
        return;
    }

    std::istream input(&codec->response_buf);
    std::string header_text(bytes, '\0');
    input.read(header_text.data(), static_cast<std::streamsize>(bytes));

    app_codec::HttpResponse response;
    std::string parse_error;
    if (!app_codec::parse_http_response_head(header_text, &response, &parse_error)) {
        send_codec_error(stream_id, 502, parse_error.empty() ? "invalid backend HTTP response" : parse_error);
        handle_codec_close(stream_id, "invalid backend response");
        return;
    }
    if (app_codec::has_transfer_encoding_chunked(response.headers)) {
        send_codec_error(stream_id, 502, "chunked backend responses are not supported by this codec");
        handle_codec_close(stream_id, "chunked backend response");
        return;
    }
    std::string length_error;
    const auto content_len = app_codec::content_length(response.headers, &length_error).value_or(0);
    if (!length_error.empty()) {
        send_codec_error(stream_id, 502, length_error);
        handle_codec_close(stream_id, "invalid backend content length");
        return;
    }
    const std::size_t max_response_body = app_codec::builtin_codec(codec->codec_id)
        .value_or(app_codec::CodecDescriptor{})
        .max_response_body;
    if (content_len > max_response_body) {
        send_codec_error(stream_id, 502, "Monero RPC backend response too large");
        handle_codec_close(stream_id, "backend response too large");
        return;
    }
    bool response_budget_available = false;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        if (codec_response_bytes_ <= kCodecResponseBudgetBytes &&
            content_len <= kCodecResponseBudgetBytes - codec_response_bytes_) {
            codec_response_bytes_ += content_len;
            codec->response_reserved_bytes = content_len;
            response_budget_available = true;
        }
    }
    if (!response_budget_available) {
        send_codec_error(stream_id, 503, "codec response budget exhausted");
        handle_codec_close(stream_id, "codec response budget exhausted");
        return;
    }
    codec->response_status = response.status_code;
    try {
        codec->response_body.resize(content_len);
    } catch (const std::bad_alloc&) {
        send_codec_error(stream_id, 503, "codec response allocation failed");
        handle_codec_close(stream_id, "codec response allocation failed");
        return;
    }
    const std::size_t buffered = std::min<std::size_t>(codec->response_buf.size(), content_len);
    if (buffered > 0) {
        input.read(reinterpret_cast<char*>(codec->response_body.data()),
                   static_cast<std::streamsize>(buffered));
    }
    codec->downstream_bytes = content_len;

    // Store parsed response headers by reusing request_bytes as a compact
    // metadata scratch is too brittle; keep the response object alive by
    // encoding once the body is complete.
    if (buffered >= content_len) {
        codec->timer.cancel();
        response.body = codec->response_body;
        codec->response_sent = true;
        send_control_frame(protocol::DATA, stream_id, app_codec::encode_response(response));
        send_control_close(stream_id, "monero-rpc response complete");
        handle_codec_close(stream_id, "monero-rpc response complete");
        return;
    }

    auto response_holder = std::make_shared<app_codec::HttpResponse>(std::move(response));
    auto self = shared_from_this();
    boost::asio::async_read(
        codec->socket,
        boost::asio::buffer(codec->response_body.data() + buffered, content_len - buffered),
        boost::asio::bind_executor(
            strand_,
            [self, stream_id, codec, response_holder](const boost::system::error_code& body_ec, std::size_t bytes_read) {
                (void)codec;
                std::shared_ptr<CodecStream> body_codec = self->find_codec_stream(stream_id);
                if (!body_codec) {
                    return;
                }
                if (!body_ec) {
                    response_holder->body = body_codec->response_body;
                    body_codec->response_sent = true;
                    body_codec->timer.cancel();
                    self->send_control_frame(protocol::DATA, stream_id, app_codec::encode_response(*response_holder));
                    self->send_control_close(stream_id, "monero-rpc response complete");
                    self->handle_codec_close(stream_id, "monero-rpc response complete");
                    return;
                }
                self->on_codec_backend_body(stream_id, body_ec, bytes_read);
            }));
}

void Session::on_codec_backend_body(uint8_t stream_id,
                                    const boost::system::error_code& ec,
                                    std::size_t) {
    if (ec) {
        send_codec_error(stream_id, 502, "Monero RPC backend body read failed");
        handle_codec_close(stream_id, "backend body read failed: " + ec.message());
    }
}

void Session::arm_codec_timer(uint8_t stream_id,
                              std::chrono::milliseconds timeout,
                              std::string reason) {
    std::shared_ptr<CodecStream> codec = find_codec_stream(stream_id);
    if (!codec) {
        return;
    }
    codec->timer.expires_after(timeout);
    auto self = shared_from_this();
    codec->timer.async_wait(boost::asio::bind_executor(
        strand_,
        [self, stream_id, codec, reason = std::move(reason)](const boost::system::error_code& ec) {
            (void)codec;
            if (ec) {
                return;
            }
            self->send_codec_error(stream_id, 504, reason);
            self->handle_codec_close(stream_id, reason);
        }));
}

}  // namespace yume::server
