/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/stealth/h2_carrier.hpp"

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <cstring>
#include <deque>
#include <iterator>
#include <limits>
#include <map>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

#include "core/stealth/websocket_codec.hpp"

namespace yume::obfs {
namespace {

constexpr std::size_t kMaxRequestHeaders = 32U * 1024U;
constexpr std::size_t kMaxResponseHeaders = 64U * 1024U;
constexpr std::size_t kMaxResponseBody = 8U * 1024U * 1024U;
constexpr std::size_t kMaxQueuedOutput = 32U * 1024U * 1024U;
constexpr std::size_t kChromeWebSocketMessageBytes = 16U * 1024U;
constexpr std::int32_t kAuthenticatedReceiveWindow = 2 * 1024 * 1024;
constexpr std::string_view kDefaultUserAgent =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36";

nghttp2_nv Nv(std::string& name, std::string& value) {
    return nghttp2_nv{
        reinterpret_cast<std::uint8_t*>(name.data()),
        reinterpret_cast<std::uint8_t*>(value.data()),
        name.size(), value.size(), NGHTTP2_NV_FLAG_NONE};
}

std::vector<nghttp2_nv> MakeNva(H2Headers& headers) {
    std::vector<nghttp2_nv> out;
    out.reserve(headers.size());
    for (auto& [name, value] : headers) out.push_back(Nv(name, value));
    return out;
}

std::string HeaderValue(const H2Headers& headers, std::string_view wanted) {
    for (const auto& [name, value] : headers) {
        if (name == wanted) return value;
    }
    return {};
}

bool IsHopByHop(std::string_view name) {
    return name == "connection" || name == "keep-alive" ||
           name == "proxy-authenticate" || name == "proxy-authorization" ||
           name == "te" || name == "trailer" || name == "transfer-encoding" ||
           name == "upgrade";
}

std::string NodeDateHeader() {
    const std::time_t now = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now());
    std::tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    char text[40]{};
    if (std::strftime(text, sizeof(text), "%a, %d %b %Y %H:%M:%S GMT", &utc) == 0) {
        throw std::runtime_error("failed to format HTTP date");
    }
    return text;
}

}  // namespace

class H2Carrier::Impl {
public:
    explicit Impl(H2CarrierRole role)
        : role_(role),
          websocket_(role == H2CarrierRole::Client ? WebSocketRole::Client
                                                   : WebSocketRole::Server) {
        nghttp2_session_callbacks* callbacks = nullptr;
        Check(nghttp2_session_callbacks_new(&callbacks), "allocate callbacks");
        callbacks_.reset(callbacks);
        nghttp2_session_callbacks_set_on_begin_headers_callback(
            callbacks, &Impl::OnBeginHeaders);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, &Impl::OnHeader);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &Impl::OnFrameRecv);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
            callbacks, &Impl::OnDataChunk);
        nghttp2_session_callbacks_set_on_stream_close_callback(
            callbacks, &Impl::OnStreamClose);

        nghttp2_session* session = nullptr;
        const int rv = role_ == H2CarrierRole::Client
            ? nghttp2_session_client_new(&session, callbacks, this)
            : nghttp2_session_server_new(&session, callbacks, this);
        Check(rv, "create HTTP/2 session");
        session_.reset(session);

        if (role_ == H2CarrierRole::Server) {
            const nghttp2_settings_entry settings[] = {
                {NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1},
            };
            Check(nghttp2_submit_settings(session_.get(), NGHTTP2_FLAG_NONE,
                                          settings, std::size(settings)),
                  "submit server SETTINGS");
        }
    }

    bool StartClient(std::string authority, std::string user_agent) {
        if (role_ != H2CarrierRole::Client || client_started_ || authority.empty()) {
            return Fail("invalid client HTTP/2 start");
        }
        authority_ = std::move(authority);
        user_agent_ = user_agent.empty() ? std::string(kDefaultUserAgent)
                                        : std::move(user_agent);
        // Chrome 150.0.7871.114, Debian 13 golden capture order and values.
        const nghttp2_settings_entry settings[] = {
            {NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 65536},
            {NGHTTP2_SETTINGS_ENABLE_PUSH, 0},
            {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 6U * 1024U * 1024U},
            {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, 256U * 1024U},
        };
        if (!CheckBool(nghttp2_submit_settings(session_.get(), NGHTTP2_FLAG_NONE,
                                               settings, std::size(settings)),
                       "submit client SETTINGS")) {
            return false;
        }
        if (!CheckBool(nghttp2_submit_window_update(
                           session_.get(), NGHTTP2_FLAG_NONE, 0, 15663105),
                       "submit Chrome connection WINDOW_UPDATE")) {
            return false;
        }
        H2Headers headers{
            {":method", "GET"},
            {":authority", authority_},
            {":scheme", "https"},
            {":path", "/"},
            {"sec-ch-ua", "\"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"150\", \"Google Chrome\";v=\"150\""},
            {"sec-ch-ua-mobile", "?0"},
            {"sec-ch-ua-platform", "\"Linux\""},
            {"upgrade-insecure-requests", "1"},
            {"user-agent", user_agent_},
            {"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
            {"sec-fetch-site", "none"},
            {"sec-fetch-mode", "navigate"},
            {"sec-fetch-user", "?1"},
            {"sec-fetch-dest", "document"},
            {"accept-encoding", "gzip, deflate, br, zstd"},
            {"accept-language", "en-US,en;q=0.9"},
            {"priority", "u=0, i"},
        };
        auto nva = MakeNva(headers);
        nghttp2_priority_spec priority{};
        nghttp2_priority_spec_init(&priority, 0, 256, 1);
        priming_stream_id_ = nghttp2_submit_request2(
            session_.get(), &priority, nva.data(), nva.size(), nullptr, nullptr);
        if (priming_stream_id_ < 0) {
            return FailNghttp2("submit priming GET", priming_stream_id_);
        }
        client_started_ = true;
        Flush();
        return !failed();
    }

    bool SubmitExtendedConnect(std::string path,
                               const H2Headers& additional_headers) {
        if (role_ != H2CarrierRole::Client || !priming_complete_ ||
            !peer_connect_enabled_ || carrier_stream_id_ >= 0 || path.empty()) {
            return Fail("extended CONNECT submitted before priming/support");
        }
        H2Headers headers{
            {":method", "CONNECT"},
            {":authority", authority_},
            {":scheme", "https"},
            {":path", std::move(path)},
            {":protocol", "websocket"},
            {"pragma", "no-cache"},
            {"cache-control", "no-cache"},
            {"user-agent", user_agent_},
            {"origin", "https://" + authority_},
            {"sec-websocket-version", "13"},
            {"accept-encoding", "gzip, deflate, br, zstd"},
            {"accept-language", "en-US,en;q=0.9"},
            {"sec-websocket-extensions", "permessage-deflate; client_max_window_bits"},
        };
        for (const auto& header : additional_headers) {
            if (header.first.empty() || header.first.front() == ':' ||
                IsHopByHop(header.first)) {
                return Fail("invalid extended CONNECT header");
            }
            headers.push_back(header);
        }
        nghttp2_data_provider2 provider{};
        provider.source.ptr = this;
        provider.read_callback = &Impl::ReadData;
        auto nva = MakeNva(headers);
        nghttp2_priority_spec priority{};
        nghttp2_priority_spec_init(&priority, 0, 147, 1);
        const auto stream_id = nghttp2_submit_request2(
            session_.get(), &priority, nva.data(), nva.size(), &provider, nullptr);
        if (stream_id < 0) return FailNghttp2("submit extended CONNECT", stream_id);
        carrier_stream_id_ = stream_id;
        outbound_streams_.emplace(stream_id, OutboundStream{false});
        Flush();
        return !failed();
    }

    std::vector<H2Request> TakeRequests() {
        std::vector<H2Request> out;
        out.swap(requests_);
        return out;
    }

    bool RespondHttp(std::int32_t stream_id, unsigned status,
                     const H2Headers& input_headers, H2Bytes body,
                     bool head_request) {
        if (role_ != H2CarrierRole::Server || status < 100 || status > 599 ||
            body.size() > kMaxResponseBody || responded_streams_.count(stream_id) != 0) {
            return Fail("invalid or duplicate HTTP/2 response");
        }
        H2Headers headers{{":status", std::to_string(status)}};
        std::size_t header_bytes = headers.front().second.size() + 7;
        bool content_length_seen = false;
        for (const auto& [name, value] : input_headers) {
            if (name.empty() || name.front() == ':' || IsHopByHop(name)) continue;
            if (header_bytes > kMaxResponseHeaders - std::min(kMaxResponseHeaders, name.size() + value.size())) {
                return Fail("HTTP/2 response headers exceed 64 KiB");
            }
            header_bytes += name.size() + value.size();
            if (name == "content-length") content_length_seen = true;
            headers.emplace_back(name, value);
        }
        if (!content_length_seen) {
            headers.emplace_back("content-length", std::to_string(body.size()));
        }
        auto nva = MakeNva(headers);
        int rv = 0;
        if (head_request || body.empty()) {
            rv = nghttp2_submit_response2(session_.get(), stream_id,
                                           nva.data(), nva.size(), nullptr);
        } else {
            OutboundStream state{true};
            state.queued_bytes = body.size();
            state.chunks.push_back(std::move(body));
            outbound_streams_.emplace(stream_id, std::move(state));
            nghttp2_data_provider2 provider{};
            provider.source.ptr = this;
            provider.read_callback = &Impl::ReadData;
            rv = nghttp2_submit_response2(session_.get(), stream_id,
                                          nva.data(), nva.size(), &provider);
        }
        if (!CheckBool(rv, "submit HTTP/2 response")) return false;
        responded_streams_.insert(stream_id);
        Flush();
        return !failed();
    }

    bool AcceptCarrier(std::int32_t stream_id,
                       const H2Headers& response_headers) {
        if (role_ != H2CarrierRole::Server || carrier_stream_id_ >= 0 ||
            responded_streams_.count(stream_id) != 0) {
            return Fail("invalid carrier acceptance");
        }
        H2Headers headers{{":status", "200"}};
        for (const auto& [name, value] : response_headers) {
            if (name.empty() || name.front() == ':' || IsHopByHop(name)) {
                return Fail("invalid carrier response header");
            }
            headers.emplace_back(name, value);
        }
        if (HeaderValue(headers, "date").empty()) {
            headers.emplace_back("date", NodeDateHeader());
        }
        outbound_streams_.emplace(stream_id, OutboundStream{false});
        nghttp2_data_provider2 provider{};
        provider.source.ptr = this;
        provider.read_callback = &Impl::ReadData;
        auto nva = MakeNva(headers);
        if (!CheckBool(nghttp2_submit_response2(session_.get(), stream_id,
                                                nva.data(), nva.size(), &provider),
                       "accept extended CONNECT")) {
            outbound_streams_.erase(stream_id);
            return false;
        }
        responded_streams_.insert(stream_id);
        carrier_stream_id_ = stream_id;
        carrier_active_ = true;
        Flush();
        return !failed();
    }

    bool EnableAuthenticatedReceiveWindow() {
        if (role_ != H2CarrierRole::Server || !carrier_active_ ||
            carrier_stream_id_ < 0 || carrier_closed_ || failed()) {
            return Fail(
                "authenticated receive window requires an active server carrier");
        }
        if (authenticated_receive_window_enabled_) return true;
        if (!CheckBool(nghttp2_session_set_local_window_size(
                           session_.get(), NGHTTP2_FLAG_NONE, 0,
                           kAuthenticatedReceiveWindow),
                       "expand authenticated HTTP/2 connection receive window") ||
            !CheckBool(nghttp2_session_set_local_window_size(
                           session_.get(), NGHTTP2_FLAG_NONE,
                           carrier_stream_id_, kAuthenticatedReceiveWindow),
                       "expand authenticated HTTP/2 stream receive window")) {
            return false;
        }
        authenticated_receive_window_enabled_ = true;
        Flush();
        return !failed();
    }

    bool RejectCarrier(std::int32_t stream_id, unsigned status,
                       const H2Headers& headers, H2Bytes body) {
        return RespondHttp(stream_id, status, headers, std::move(body), false);
    }

    void Feed(const std::uint8_t* data, std::size_t size) {
        if (failed() || size == 0) return;
#if YUME_ENABLE_DEV_DIAGNOSTICS
        diagnostics::Stopwatch feed_timer(collect_timing_);
#endif
        const auto rv = nghttp2_session_mem_recv2(session_.get(), data, size);
#if YUME_ENABLE_DEV_DIAGNOSTICS
        stats_.h2_feed_calls += 1;
        stats_.h2_feed_bytes += size;
        if (collect_timing_) {
            stats_.h2_feed_ns += feed_timer.elapsed_ns();
        }
#endif
        if (rv < 0) {
            FailNghttp2("receive HTTP/2 bytes", static_cast<int>(rv));
            return;
        }
        if (static_cast<std::size_t>(rv) != size) {
            Fail("libnghttp2 did not consume the complete TLS plaintext chunk");
            return;
        }
        Flush();
    }

    H2Bytes TakeOutbound() {
        Flush();
        H2Bytes out;
        out.swap(serialized_output_);
        return out;
    }

    bool SendBinary(const std::uint8_t* data, std::size_t size) {
        if (!carrier_active_ || carrier_closed_ || failed()) {
            return Fail("carrier is not active");
        }
        try {
#if YUME_ENABLE_DEV_DIAGNOSTICS
            diagnostics::Stopwatch encode_timer(collect_timing_);
#endif
            H2Bytes wire;
            std::size_t offset = 0;
            while (offset < size) {
                const std::size_t chunk = std::min(
                    kChromeWebSocketMessageBytes, size - offset);
                H2Bytes frame;
                // The captured Node fixture fragments its first complete
                // 16-KiB server binary message into 8-KiB binary/continuation
                // frames. Smaller authentication/control messages are left
                // intact and do not consume this one-time profile behavior.
                if (role_ == H2CarrierRole::Server &&
                    !server_fragment_fixture_sent_ &&
                    chunk == kChromeWebSocketMessageBytes) {
                    frame = websocket_.EncodeBinaryFragmented(
                        data + offset, chunk, chunk / 2);
                    server_fragment_fixture_sent_ = true;
                } else {
                    frame = websocket_.EncodeBinary(data + offset, chunk);
                }
                if (frame.size() > kMaxQueuedOutput -
                        std::min(kMaxQueuedOutput, wire.size())) {
                    return Fail("encoded WebSocket output exceeded 32 MiB");
                }
                wire.insert(wire.end(), frame.begin(), frame.end());
                offset += chunk;
            }
            if (size == 0) wire = websocket_.EncodeBinary(data, 0);
#if YUME_ENABLE_DEV_DIAGNOSTICS
            stats_.websocket_encode_bytes += size;
            if (collect_timing_) {
                stats_.websocket_encode_ns += encode_timer.elapsed_ns();
            }
#endif
            return QueueStreamBytes(carrier_stream_id_, std::move(wire));
        } catch (const std::exception& ex) {
            return Fail(std::string("encode WebSocket binary: ") + ex.what());
        }
    }

    H2Bytes TakeTunnelBytes() {
        H2Bytes out;
        out.swap(tunnel_bytes_);
        return out;
    }

    void GracefulClose(std::uint16_t websocket_code) {
        if (failed() || graceful_close_started_) return;
        graceful_close_started_ = true;
        if (carrier_active_ && !carrier_closed_) {
            try {
                // The Chrome 150 active-WebSocket close fixture sends one H2
                // PING immediately before the masked WebSocket CLOSE. It does
                // not show a periodic idle keepalive cadence. The server only
                // acknowledges this PING; it does not originate a matching one.
                if (role_ == H2CarrierRole::Client) {
                    const std::uint8_t opaque[8] = {0, 0, 0, 0, 0, 0, 0, 1};
                    Check(nghttp2_submit_ping(session_.get(), NGHTTP2_FLAG_NONE,
                                              opaque),
                          "submit captured close PING");
                }
                QueueStreamBytes(carrier_stream_id_, websocket_.EncodeClose(websocket_code));
            } catch (const std::exception& ex) {
                Fail(std::string("encode WebSocket close: ") + ex.what());
                return;
            }
        }
        nghttp2_submit_goaway(session_.get(), NGHTTP2_FLAG_NONE,
                              nghttp2_session_get_last_proc_stream_id(session_.get()),
                              NGHTTP2_NO_ERROR, nullptr, 0);
        Flush();
    }

    bool priming_complete() const noexcept { return priming_complete_; }
    bool peer_extended_connect_enabled() const noexcept { return peer_connect_enabled_; }
    bool carrier_active() const noexcept { return carrier_active_; }
    bool carrier_closed() const noexcept { return carrier_closed_; }
    std::int32_t carrier_stream_id() const noexcept { return carrier_stream_id_; }
    std::size_t queued_output_bytes() const noexcept {
        std::size_t total = serialized_output_.size();
        for (const auto& [_, stream] : outbound_streams_) total += stream.queued_bytes;
        return total;
    }
#if YUME_ENABLE_DEV_DIAGNOSTICS
    H2CarrierStats stats() const noexcept { return stats_; }
    void set_timing_enabled(bool enabled) noexcept { collect_timing_ = enabled; }
#endif
    bool failed() const noexcept { return !error_.empty(); }
    const std::string& error() const noexcept { return error_; }

private:
    struct SessionDeleter {
        void operator()(nghttp2_session* value) const { nghttp2_session_del(value); }
    };
    struct CallbacksDeleter {
        void operator()(nghttp2_session_callbacks* value) const {
            nghttp2_session_callbacks_del(value);
        }
    };
    struct OutboundStream {
        bool finish_when_empty{false};
        std::deque<H2Bytes> chunks;
        std::size_t front_offset{0};
        std::size_t queued_bytes{0};
    };

    static int OnBeginHeaders(nghttp2_session*, const nghttp2_frame* frame,
                              void* user_data) noexcept {
        auto& self = *static_cast<Impl*>(user_data);
        if (frame->hd.type == NGHTTP2_HEADERS) {
            self.incoming_headers_[frame->hd.stream_id].clear();
            self.incoming_header_bytes_[frame->hd.stream_id] = 0;
        }
        return 0;
    }

    static int OnHeader(nghttp2_session*, const nghttp2_frame* frame,
                        const std::uint8_t* name, std::size_t namelen,
                        const std::uint8_t* value, std::size_t valuelen,
                        std::uint8_t, void* user_data) noexcept {
        auto& self = *static_cast<Impl*>(user_data);
        try {
            const std::size_t cap = self.role_ == H2CarrierRole::Server
                ? kMaxRequestHeaders : kMaxResponseHeaders;
            auto& used = self.incoming_header_bytes_[frame->hd.stream_id];
            if (namelen > cap || valuelen > cap - std::min(cap, namelen) ||
                used > cap - namelen - valuelen) {
                self.Fail("HTTP/2 header block exceeds configured cap");
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            used += namelen + valuelen;
            self.incoming_headers_[frame->hd.stream_id].emplace_back(
                std::string(reinterpret_cast<const char*>(name), namelen),
                std::string(reinterpret_cast<const char*>(value), valuelen));
            return 0;
        } catch (...) {
            self.Fail("exception while retaining HTTP/2 header");
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }

    static int OnFrameRecv(nghttp2_session*, const nghttp2_frame* frame,
                           void* user_data) noexcept {
        auto& self = *static_cast<Impl*>(user_data);
        try {
            self.HandleFrame(*frame);
            return self.failed() ? NGHTTP2_ERR_CALLBACK_FAILURE : 0;
        } catch (const std::exception& ex) {
            self.Fail(std::string("HTTP/2 frame callback: ") + ex.what());
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        } catch (...) {
            self.Fail("unknown HTTP/2 frame callback exception");
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }

    static int OnDataChunk(nghttp2_session*, std::uint8_t,
                           std::int32_t stream_id, const std::uint8_t* data,
                           std::size_t len, void* user_data) noexcept {
        auto& self = *static_cast<Impl*>(user_data);
        try {
            self.HandleData(stream_id, data, len);
            return self.failed() ? NGHTTP2_ERR_CALLBACK_FAILURE : 0;
        } catch (const std::exception& ex) {
            self.Fail(std::string("HTTP/2 DATA callback: ") + ex.what());
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        } catch (...) {
            self.Fail("unknown HTTP/2 DATA callback exception");
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }

    static int OnStreamClose(nghttp2_session*, std::int32_t stream_id,
                             std::uint32_t, void* user_data) noexcept {
        auto& self = *static_cast<Impl*>(user_data);
        try {
            if (stream_id == self.priming_stream_id_) {
                if (self.priming_status_ < 200 || self.priming_status_ >= 400) {
                    self.Fail("Chrome priming GET was rejected");
                } else {
                    self.SubmitClientAssets();
                }
            } else if (stream_id == self.css_stream_id_) {
                self.css_complete_ = self.css_status_ >= 200 && self.css_status_ < 400;
            } else if (stream_id == self.js_stream_id_) {
                self.js_complete_ = self.js_status_ >= 200 && self.js_status_ < 400;
            }
            if ((stream_id == self.css_stream_id_ || stream_id == self.js_stream_id_) &&
                ((!self.css_complete_ && self.css_status_ >= 400) ||
                 (!self.js_complete_ && self.js_status_ >= 400))) {
                self.Fail("Chrome priming asset was rejected");
            }
            self.priming_complete_ = self.css_complete_ && self.js_complete_;
            if (stream_id == self.carrier_stream_id_) {
                self.carrier_closed_ = true;
                self.carrier_active_ = false;
            }
            self.outbound_streams_.erase(stream_id);
            self.incoming_headers_.erase(stream_id);
            self.incoming_header_bytes_.erase(stream_id);
            return self.failed() ? NGHTTP2_ERR_CALLBACK_FAILURE : 0;
        } catch (const std::exception& ex) {
            self.Fail(std::string("HTTP/2 stream-close callback: ") + ex.what());
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        } catch (...) {
            self.Fail("unknown HTTP/2 stream-close callback exception");
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }

    static nghttp2_ssize ReadData(nghttp2_session*, std::int32_t stream_id,
                                  std::uint8_t* buf, std::size_t length,
                                  std::uint32_t* data_flags,
                                  nghttp2_data_source*, void* user_data) noexcept {
        auto& self = *static_cast<Impl*>(user_data);
        auto it = self.outbound_streams_.find(stream_id);
        if (it == self.outbound_streams_.end()) {
            self.Fail("missing HTTP/2 outbound stream state");
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        auto& stream = it->second;
        if (stream.chunks.empty()) {
            if (stream.finish_when_empty) {
                *data_flags |= NGHTTP2_DATA_FLAG_EOF;
                return 0;
            }
            return NGHTTP2_ERR_DEFERRED;
        }
        auto& front = stream.chunks.front();
        const std::size_t available = front.size() - stream.front_offset;
        const std::size_t count = std::min(length, available);
        std::memcpy(buf, front.data() + stream.front_offset, count);
        stream.front_offset += count;
        stream.queued_bytes -= count;
        if (stream.front_offset == front.size()) {
            stream.chunks.pop_front();
            stream.front_offset = 0;
        }
        if (stream.chunks.empty() && stream.finish_when_empty) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        }
        return static_cast<nghttp2_ssize>(count);
    }

    void HandleFrame(const nghttp2_frame& frame) {
        if (frame.hd.type == NGHTTP2_SETTINGS &&
            (frame.hd.flags & NGHTTP2_FLAG_ACK) == 0) {
            for (std::size_t i = 0; i < frame.settings.niv; ++i) {
                const auto& entry = frame.settings.iv[i];
                if (entry.settings_id == NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL &&
                    entry.value == 1) {
                    peer_connect_enabled_ = true;
                }
            }
            return;
        }
        if (frame.hd.type != NGHTTP2_HEADERS) return;

        auto it = incoming_headers_.find(frame.hd.stream_id);
        if (it == incoming_headers_.end()) return;
        H2Headers headers = std::move(it->second);
        incoming_headers_.erase(it);
        incoming_header_bytes_.erase(frame.hd.stream_id);

        if (role_ == H2CarrierRole::Server &&
            frame.headers.cat == NGHTTP2_HCAT_REQUEST) {
            H2Request request;
            request.stream_id = frame.hd.stream_id;
            request.method = HeaderValue(headers, ":method");
            request.path = HeaderValue(headers, ":path");
            request.authority = HeaderValue(headers, ":authority");
            request.protocol = HeaderValue(headers, ":protocol");
            request.headers = std::move(headers);
            if (request.method.empty() || request.authority.empty()) {
                Fail("HTTP/2 request is missing method or authority");
                return;
            }
            requests_.push_back(std::move(request));
            return;
        }
        if (role_ == H2CarrierRole::Client &&
            frame.headers.cat == NGHTTP2_HCAT_RESPONSE) {
            unsigned status = 0;
            const std::string text = HeaderValue(headers, ":status");
            if (text.size() == 3 &&
                std::all_of(text.begin(), text.end(), [](unsigned char ch) {
                    return std::isdigit(ch) != 0;
                })) {
                status = static_cast<unsigned>((text[0] - '0') * 100 +
                                               (text[1] - '0') * 10 +
                                               (text[2] - '0'));
            }
            if (frame.hd.stream_id == priming_stream_id_) {
                priming_status_ = status;
            } else if (frame.hd.stream_id == css_stream_id_) {
                css_status_ = status;
            } else if (frame.hd.stream_id == js_stream_id_) {
                js_status_ = status;
            } else if (frame.hd.stream_id == carrier_stream_id_) {
                if (status == 200) {
                    carrier_active_ = true;
                } else {
                    carrier_closed_ = true;
                }
            }
        }
    }

    void HandleData(std::int32_t stream_id, const std::uint8_t* data,
                    std::size_t len) {
        if (stream_id != carrier_stream_id_) {
            if (role_ == H2CarrierRole::Client &&
                (stream_id == priming_stream_id_ || stream_id == css_stream_id_ ||
                 stream_id == js_stream_id_)) {
                priming_body_bytes_ += len;
                if (priming_body_bytes_ > kMaxResponseBody) {
                    Fail("priming response body exceeds 8 MiB");
                }
            }
            return;
        }
        // A rejected extended CONNECT is an ordinary HTTP response on the
        // attempted stream. Its Node-shaped body is cover content, not a
        // WebSocket frame, and must never reach the tunnel parser.
        if (!carrier_active_) {
            priming_body_bytes_ += len;
            if (priming_body_bytes_ > kMaxResponseBody) {
                Fail("cover rejection body exceeds 8 MiB");
            }
            return;
        }
#if YUME_ENABLE_DEV_DIAGNOSTICS
        diagnostics::Stopwatch decode_timer(collect_timing_);
#endif
        websocket_.Feed(data, len);
        if (websocket_.failed()) {
            Fail("WebSocket carrier: " + websocket_.error());
            return;
        }
        auto decoded = websocket_.TakeDecoded();
#if YUME_ENABLE_DEV_DIAGNOSTICS
        stats_.websocket_decode_bytes += len;
        if (collect_timing_) {
            stats_.websocket_decode_ns += decode_timer.elapsed_ns();
        }
#endif
        if (decoded.size() > kMaxQueuedOutput - std::min(kMaxQueuedOutput, tunnel_bytes_.size())) {
            Fail("decoded tunnel input queue exceeded 32 MiB");
            return;
        }
        if (tunnel_bytes_.empty()) {
            tunnel_bytes_ = std::move(decoded);
        } else {
            tunnel_bytes_.insert(tunnel_bytes_.end(), decoded.begin(), decoded.end());
        }
        auto replies = websocket_.TakeWireReplies();
        if (!replies.empty()) QueueStreamBytes(stream_id, std::move(replies));
        if (role_ == H2CarrierRole::Server && !server_active_ping_sent_ &&
            !decoded.empty()) {
            static constexpr std::uint8_t kFixturePing[] = {
                'f', 'i', 'x', 't', 'u', 'r', 'e', '-', 'p', 'i', 'n', 'g'};
            QueueStreamBytes(
                stream_id,
                websocket_.EncodePing(kFixturePing, std::size(kFixturePing)));
            server_active_ping_sent_ = true;
        }
        if (websocket_.closed()) carrier_closed_ = true;
    }

    bool QueueStreamBytes(std::int32_t stream_id, H2Bytes bytes) {
        auto it = outbound_streams_.find(stream_id);
        if (it == outbound_streams_.end()) return Fail("unknown HTTP/2 output stream");
        if (bytes.size() > kMaxQueuedOutput - std::min(kMaxQueuedOutput, queued_output_bytes())) {
            return Fail("HTTP/2 output queue exceeded 32 MiB");
        }
        it->second.queued_bytes += bytes.size();
        it->second.chunks.push_back(std::move(bytes));
        const int rv = nghttp2_session_resume_data(session_.get(), stream_id);
        if (rv != 0 && rv != NGHTTP2_ERR_INVALID_ARGUMENT) {
            return FailNghttp2("resume HTTP/2 DATA", rv);
        }
        Flush();
        return !failed();
    }

    void SubmitClientAssets() {
        if (role_ != H2CarrierRole::Client || css_stream_id_ >= 0 ||
            js_stream_id_ >= 0) {
            throw std::runtime_error("duplicate Chrome priming asset submission");
        }
        H2Headers css_headers{
            {":method", "GET"}, {":authority", authority_},
            {":scheme", "https"}, {":path", "/assets/site.css"},
            {"sec-ch-ua-platform", "\"Linux\""},
            {"user-agent", user_agent_},
            {"sec-ch-ua", "\"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"150\", \"Google Chrome\";v=\"150\""},
            {"sec-ch-ua-mobile", "?0"}, {"accept", "text/css,*/*;q=0.1"},
            {"sec-fetch-site", "same-origin"}, {"sec-fetch-mode", "no-cors"},
            {"sec-fetch-dest", "style"}, {"referer", "https://" + authority_ + "/"},
            {"accept-encoding", "gzip, deflate, br, zstd"},
            {"accept-language", "en-US,en;q=0.9"}, {"priority", "u=0"}};
        auto css_nva = MakeNva(css_headers);
        nghttp2_priority_spec css_priority{};
        nghttp2_priority_spec_init(&css_priority, 0, 256, 1);
        css_stream_id_ = nghttp2_submit_request2(
            session_.get(), &css_priority, css_nva.data(), css_nva.size(),
            nullptr, nullptr);
        if (css_stream_id_ < 0) {
            throw std::runtime_error("submit Chrome CSS request: " +
                                     std::string(nghttp2_strerror(css_stream_id_)));
        }

        H2Headers js_headers{
            {":method", "GET"}, {":authority", authority_},
            {":scheme", "https"}, {":path", "/assets/site.js"},
            {"sec-ch-ua-platform", "\"Linux\""},
            {"user-agent", user_agent_},
            {"sec-ch-ua", "\"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"150\", \"Google Chrome\";v=\"150\""},
            {"sec-ch-ua-mobile", "?0"}, {"accept", "*/*"},
            {"sec-fetch-site", "same-origin"}, {"sec-fetch-mode", "no-cors"},
            {"sec-fetch-dest", "script"}, {"referer", "https://" + authority_ + "/"},
            {"accept-encoding", "gzip, deflate, br, zstd"},
            {"accept-language", "en-US,en;q=0.9"}};
        auto js_nva = MakeNva(js_headers);
        nghttp2_priority_spec js_priority{};
        nghttp2_priority_spec_init(&js_priority, css_stream_id_, 147, 1);
        js_stream_id_ = nghttp2_submit_request2(
            session_.get(), &js_priority, js_nva.data(), js_nva.size(),
            nullptr, nullptr);
        if (js_stream_id_ < 0) {
            throw std::runtime_error("submit Chrome JS request: " +
                                     std::string(nghttp2_strerror(js_stream_id_)));
        }
        Flush();
    }

    void Flush() {
        if (failed()) return;
#if YUME_ENABLE_DEV_DIAGNOSTICS
        diagnostics::Stopwatch flush_timer(collect_timing_);
        std::size_t flushed_bytes = 0;
#endif
        while (true) {
            const std::uint8_t* data = nullptr;
            const auto length = nghttp2_session_mem_send2(session_.get(), &data);
            if (length < 0) {
                FailNghttp2("serialize HTTP/2 output", static_cast<int>(length));
                break;
            }
            if (length == 0) break;
            const auto count = static_cast<std::size_t>(length);
            if (count > kMaxQueuedOutput - std::min(kMaxQueuedOutput, serialized_output_.size())) {
                Fail("serialized HTTP/2 output exceeded 32 MiB");
                break;
            }
            serialized_output_.insert(serialized_output_.end(), data, data + count);
#if YUME_ENABLE_DEV_DIAGNOSTICS
            flushed_bytes += count;
#endif
        }
#if YUME_ENABLE_DEV_DIAGNOSTICS
        stats_.h2_flush_calls += 1;
        stats_.h2_flush_bytes += flushed_bytes;
        if (collect_timing_) {
            stats_.h2_flush_ns += flush_timer.elapsed_ns();
        }
#endif
    }

    void Check(int rv, const char* operation) {
        if (rv < 0) throw std::runtime_error(
            std::string(operation) + ": " + nghttp2_strerror(rv));
    }
    bool CheckBool(int rv, const char* operation) {
        return rv < 0 ? FailNghttp2(operation, rv) : true;
    }
    bool FailNghttp2(std::string operation, int rv) {
        return Fail(std::move(operation) + ": " + nghttp2_strerror(rv));
    }
    bool Fail(std::string reason) {
        if (error_.empty()) error_ = std::move(reason);
        return false;
    }

    H2CarrierRole role_;
    WebSocketCodec websocket_;
#if YUME_ENABLE_DEV_DIAGNOSTICS
    H2CarrierStats stats_;
    bool collect_timing_{false};
#endif
    std::unique_ptr<nghttp2_session_callbacks, CallbacksDeleter> callbacks_;
    std::unique_ptr<nghttp2_session, SessionDeleter> session_;
    std::unordered_map<std::int32_t, H2Headers> incoming_headers_;
    std::unordered_map<std::int32_t, std::size_t> incoming_header_bytes_;
    std::unordered_map<std::int32_t, OutboundStream> outbound_streams_;
    std::unordered_set<std::int32_t> responded_streams_;
    std::vector<H2Request> requests_;
    H2Bytes serialized_output_;
    H2Bytes tunnel_bytes_;
    std::string authority_;
    std::string user_agent_;
    std::string error_;
    std::int32_t priming_stream_id_{-1};
    std::int32_t css_stream_id_{-1};
    std::int32_t js_stream_id_{-1};
    std::int32_t carrier_stream_id_{-1};
    unsigned priming_status_{0};
    unsigned css_status_{0};
    unsigned js_status_{0};
    std::size_t priming_body_bytes_{0};
    bool css_complete_{false};
    bool js_complete_{false};
    bool client_started_{false};
    bool priming_complete_{false};
    bool peer_connect_enabled_{false};
    bool carrier_active_{false};
    bool carrier_closed_{false};
    bool authenticated_receive_window_enabled_{false};
    bool graceful_close_started_{false};
    bool server_fragment_fixture_sent_{false};
    bool server_active_ping_sent_{false};
};

H2Carrier::H2Carrier(H2CarrierRole role) : impl_(std::make_unique<Impl>(role)) {}
H2Carrier::H2Carrier(H2Carrier&&) noexcept = default;
H2Carrier& H2Carrier::operator=(H2Carrier&&) noexcept = default;
H2Carrier::~H2Carrier() = default;
#if YUME_ENABLE_DEV_DIAGNOSTICS
void H2Carrier::set_timing_enabled(bool enabled) noexcept {
    impl_->set_timing_enabled(enabled);
}
#endif

bool H2Carrier::StartClient(std::string authority, std::string user_agent) {
    return impl_->StartClient(std::move(authority), std::move(user_agent));
}
bool H2Carrier::SubmitExtendedConnect(std::string path,
                                      const H2Headers& additional_headers) {
    return impl_->SubmitExtendedConnect(std::move(path), additional_headers);
}
std::vector<H2Request> H2Carrier::TakeRequests() { return impl_->TakeRequests(); }
bool H2Carrier::RespondHttp(std::int32_t stream_id, unsigned status,
                            const H2Headers& headers, H2Bytes body,
                            bool head_request) {
    return impl_->RespondHttp(stream_id, status, headers, std::move(body), head_request);
}
bool H2Carrier::AcceptCarrier(std::int32_t stream_id,
                              const H2Headers& response_headers) {
    return impl_->AcceptCarrier(stream_id, response_headers);
}
bool H2Carrier::EnableAuthenticatedReceiveWindow() {
    return impl_->EnableAuthenticatedReceiveWindow();
}
bool H2Carrier::RejectCarrier(std::int32_t stream_id, unsigned status,
                              const H2Headers& headers, H2Bytes body) {
    return impl_->RejectCarrier(stream_id, status, headers, std::move(body));
}
void H2Carrier::Feed(const std::uint8_t* data, std::size_t size) {
    impl_->Feed(data, size);
}
H2Bytes H2Carrier::TakeOutbound() { return impl_->TakeOutbound(); }
bool H2Carrier::SendBinary(const std::uint8_t* data, std::size_t size) {
    return impl_->SendBinary(data, size);
}
H2Bytes H2Carrier::TakeTunnelBytes() { return impl_->TakeTunnelBytes(); }
bool H2Carrier::priming_complete() const noexcept { return impl_->priming_complete(); }
bool H2Carrier::peer_extended_connect_enabled() const noexcept {
    return impl_->peer_extended_connect_enabled();
}
bool H2Carrier::carrier_active() const noexcept { return impl_->carrier_active(); }
bool H2Carrier::carrier_closed() const noexcept { return impl_->carrier_closed(); }
std::int32_t H2Carrier::carrier_stream_id() const noexcept {
    return impl_->carrier_stream_id();
}
std::size_t H2Carrier::queued_output_bytes() const noexcept {
    return impl_->queued_output_bytes();
}
#if YUME_ENABLE_DEV_DIAGNOSTICS
H2CarrierStats H2Carrier::stats() const noexcept { return impl_->stats(); }
#endif
void H2Carrier::GracefulClose(std::uint16_t websocket_code) {
    impl_->GracefulClose(websocket_code);
}
bool H2Carrier::failed() const noexcept { return impl_->failed(); }
const std::string& H2Carrier::error() const noexcept { return impl_->error(); }

}  // namespace yume::obfs
