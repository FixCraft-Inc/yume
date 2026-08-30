/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/stealth/h2_carrier.hpp"

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <ctime>
#include <cstring>
#include <deque>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#include "core/stealth/h2_wire_profile.hpp"
#include "core/stealth/websocket_codec.hpp"

namespace yume::obfs {
namespace {

constexpr std::size_t kMaxRequestHeaders = 32U * 1024U;
constexpr std::size_t kMaxResponseHeaders = 64U * 1024U;
constexpr std::size_t kMaxResponseBody = 8U * 1024U * 1024U;
constexpr std::size_t kMaxQueuedOutput = 32U * 1024U * 1024U;
constexpr std::size_t kMaxPendingServerRequests = 64U;
constexpr std::size_t kMaxPendingServerStreamCloses = 256U;
// Receive window advertised on the carrier once the peer is authenticated.
//
// This is the binding constraint on inbound throughput at WAN latency, not the
// ratchet and not TCP: a window of W delivers at most W/RTT, so 2 MiB capped a
// 60 ms path near 280 Mbit/s while the kernel's autotuned TCP window had
// already grown to ~3.9 MB (545 Mbit/s) underneath it. 8 MiB is approximately
// one bandwidth-delay product for a 1 Gbit/s path at 60 ms (7.5 MB). It does
// not guarantee uninterrupted 1 Gbit/s delivery: nghttp2 normally sends a
// WINDOW_UPDATE after roughly half the window is consumed, so the remaining
// credit must also cover the update's return trip.
//
// The WINDOW_UPDATE increment is TLS-encrypted and its frame remains 13 bytes,
// so the magnitude is not directly visible. A larger receive window can still
// change externally observable burst and timing geometry, and therefore needs
// separate capture and classifier evidence.
//
// Why not larger. Server receive credit is now returned explicitly after
// WebSocket framing is handled and tunnel payload drains downstream, so a fast
// peer stalls at this bounded window instead of filling application queues.
// Increasing it would still enlarge retained protocol/parser state and change
// WINDOW_UPDATE timing; that belongs with separate WAN and classifier evidence.
// See docs/IMPLEMENTATION_STATUS.md, "Performance and network qualification".
constexpr std::int32_t kAuthenticatedReceiveWindow = 8 * 1024 * 1024;

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
    explicit Impl(H2CarrierRole role,
                  std::shared_ptr<OuterCarrierTrace> outer_trace)
        : role_(role),
          websocket_(role == H2CarrierRole::Client ? WebSocketRole::Client
                                                   : WebSocketRole::Server,
                     cover_profile::active().websocket_message_bytes),
          outer_trace_(std::move(outer_trace)),
          inbound_preface_pending_(role == H2CarrierRole::Server) {
        if (outer_trace_) {
            websocket_.set_inbound_frame_observer(
                &Impl::OnWebSocketFrame, this);
        }
        nghttp2_session_callbacks* callbacks = nullptr;
        Check(nghttp2_session_callbacks_new(&callbacks), "allocate callbacks");
        callbacks_.reset(callbacks);
        nghttp2_session_callbacks_set_on_begin_headers_callback(
            callbacks, &Impl::OnBeginHeaders);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, &Impl::OnHeader);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &Impl::OnFrameRecv);
#if YUME_ENABLE_DEV_DIAGNOSTICS
        nghttp2_session_callbacks_set_on_frame_send_callback(
            callbacks, &Impl::OnFrameSend);
#endif
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
            callbacks, &Impl::OnDataChunk);
        nghttp2_session_callbacks_set_on_stream_close_callback(
            callbacks, &Impl::OnStreamClose);

        nghttp2_option* raw_option = nullptr;
        Check(nghttp2_option_new(&raw_option),
              "allocate HTTP/2 receive-credit options");
        const std::unique_ptr<nghttp2_option, decltype(&nghttp2_option_del)>
            option(raw_option, &nghttp2_option_del);
        nghttp2_option_set_no_auto_window_update(option.get(), 1);

        nghttp2_session* session = nullptr;
        const int rv = role_ == H2CarrierRole::Client
            ? nghttp2_session_client_new2(
                  &session, callbacks, this, option.get())
            : nghttp2_session_server_new2(
                  &session, callbacks, this, option.get());
        Check(rv, "create HTTP/2 session");
        session_.reset(session);

        if (role_ == H2CarrierRole::Server) {
            const auto& profile =
                cover_profile::active();
            std::vector<nghttp2_settings_entry> settings;
            settings.reserve(profile.server_settings.size());
            for (const auto& setting : profile.server_settings) {
                settings.push_back({
                    static_cast<std::int32_t>(setting.id), setting.value});
            }
            Check(nghttp2_submit_settings(session_.get(), NGHTTP2_FLAG_NONE,
                                          settings.data(), settings.size()),
                  "submit server SETTINGS");
        }
    }

    bool StartClient(std::string authority) {
        if (role_ != H2CarrierRole::Client || client_started_ || authority.empty()) {
            return Fail("invalid client HTTP/2 start");
        }
        authority_ = std::move(authority);
        const auto& profile = cover_profile::active();
        std::vector<nghttp2_settings_entry> settings;
        settings.reserve(profile.client_settings.size());
        for (const auto& setting : profile.client_settings) {
            settings.push_back({
                static_cast<std::int32_t>(setting.id), setting.value});
        }
        if (!CheckBool(nghttp2_submit_settings(session_.get(), NGHTTP2_FLAG_NONE,
                                               settings.data(), settings.size()),
                       "submit client SETTINGS")) {
            return false;
        }
        if (!CheckBool(nghttp2_submit_window_update(
                           session_.get(), NGHTTP2_FLAG_NONE, 0,
                           profile.connection_window_update),
                       "submit Chrome connection WINDOW_UPDATE")) {
            return false;
        }
        H2Headers headers =
            profile.render_headers(profile.priming_request, authority_);
        auto nva = MakeNva(headers);
        nghttp2_priority_spec priority{};
        nghttp2_priority_spec_init(
            &priority,
            profile.priming_request.priority.parent_stream_id,
            profile.priming_request.priority.weight,
            profile.priming_request.priority.exclusive ? 1 : 0);
        priming_stream_id_ = nghttp2_submit_request2(
            session_.get(), &priority, nva.data(), nva.size(), nullptr, nullptr);
        if (priming_stream_id_ < 0) {
            return FailNghttp2("submit priming GET", priming_stream_id_);
        }
        if (!wire_profile_.QueuePriority(
                priming_stream_id_, profile.priming_request.priority,
                error_)) {
            return false;
        }
        QueueTraceHeaders(priming_stream_id_, headers);
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
        const auto& profile = cover_profile::active();
        H2Headers headers =
            profile.render_headers(profile.extended_connect, authority_, path);
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
        nghttp2_priority_spec_init(
            &priority,
            profile.extended_connect.priority.parent_stream_id,
            profile.extended_connect.priority.weight,
            profile.extended_connect.priority.exclusive ? 1 : 0);
        const auto stream_id = nghttp2_submit_request2(
            session_.get(), &priority, nva.data(), nva.size(), &provider, nullptr);
        if (stream_id < 0) return FailNghttp2("submit extended CONNECT", stream_id);
        carrier_stream_id_ = stream_id;
        outbound_streams_.emplace(stream_id, OutboundStream{false});
        if (!wire_profile_.QueuePriority(
                stream_id, profile.extended_connect.priority, error_)) {
            return false;
        }
        QueueTraceHeaders(stream_id, headers, path);
        Flush();
        return !failed();
    }

    std::vector<H2Request> TakeRequests() {
        std::vector<H2Request> out;
        out.swap(requests_);
        return out;
    }

    std::vector<H2StreamClose> TakeStreamCloses() {
        std::vector<H2StreamClose> out;
        out.swap(stream_closes_);
        return out;
    }

    bool RefuseStream(std::int32_t stream_id) {
        if (role_ != H2CarrierRole::Server || stream_id <= 0 || failed()) {
            return Fail("invalid HTTP/2 stream refusal");
        }
        if (!CheckBool(nghttp2_submit_rst_stream(
                           session_.get(), NGHTTP2_FLAG_NONE, stream_id,
                           NGHTTP2_REFUSED_STREAM),
                       "refuse saturated HTTP/2 stream")) {
            return false;
        }
        Flush();
        return !failed();
    }

    bool RespondHttp(std::int32_t stream_id, unsigned status,
                     const H2Headers& input_headers, H2Bytes body,
                     bool head_request) {
        if (role_ != H2CarrierRole::Server || status < 100 || status > 599 ||
            body.size() > kMaxResponseBody ||
            body.size() > kMaxQueuedOutput -
                std::min(kMaxQueuedOutput, queued_output_bytes()) ||
            responded_streams_.count(stream_id) != 0) {
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
            if (!outbound_streams_.emplace(stream_id, std::move(state)).second) {
                return Fail("duplicate HTTP/2 output stream state");
            }
            nghttp2_data_provider2 provider{};
            provider.source.ptr = this;
            provider.read_callback = &Impl::ReadData;
            rv = nghttp2_submit_response2(session_.get(), stream_id,
                                          nva.data(), nva.size(), &provider);
        }
        if (!CheckBool(rv, "submit HTTP/2 response")) {
            outbound_streams_.erase(stream_id);
            return false;
        }
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
        ObserveInboundH2Wire(data, size);
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
#if YUME_ENABLE_DEV_DIAGNOSTICS
        ObserveFlowControlStats();
#endif
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
                    cover_profile::active()
                        .websocket_message_bytes,
                        size - offset);
                H2Bytes frame;
                // The captured Node fixture fragments its first complete
                // 16-KiB server binary message into 8-KiB binary/continuation
                // frames. Smaller authentication/control messages are left
                // intact and do not consume this one-time profile behavior.
                if (role_ == H2CarrierRole::Server &&
                    !server_fragment_fixture_sent_ &&
                    chunk == cover_profile::active()
                                 .websocket_message_bytes) {
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
        if (unconsumed_tunnel_bytes_ >
                received_unconsumed_carrier_bytes_ ||
            tunnel_bytes_.size() >
                received_unconsumed_carrier_bytes_ -
                    unconsumed_tunnel_bytes_) {
            Fail("HTTP/2 tunnel receive-credit ledger mismatch");
            return {};
        }
        unconsumed_tunnel_bytes_ += tunnel_bytes_.size();
#if YUME_ENABLE_DEV_DIAGNOSTICS
        if (collect_timing_) {
            stats_.max_unconsumed_tunnel_bytes = std::max<std::uint64_t>(
                stats_.max_unconsumed_tunnel_bytes,
                unconsumed_tunnel_bytes_);
        }
#endif
        H2Bytes out;
        out.swap(tunnel_bytes_);
        return out;
    }

    bool ConsumeTunnelBytes(std::size_t size) {
        if (size > unconsumed_tunnel_bytes_) {
            return Fail("HTTP/2 tunnel receive-credit over-consumption");
        }
        if (size == 0) return !failed();
        if (!ConsumeCarrierBytes(size)) return false;
        unconsumed_tunnel_bytes_ -= size;
        Flush();
        return !failed();
    }

    std::size_t unconsumed_tunnel_bytes() const noexcept {
        return unconsumed_tunnel_bytes_;
    }

    void GracefulClose(std::uint16_t websocket_code) {
        if (failed() || graceful_close_started_) return;
        graceful_close_started_ = true;
        if (carrier_active_ && !carrier_closed_) {
            try {
                // The Chrome 151 active-WebSocket close fixture sends one H2
                // PING immediately before the masked WebSocket CLOSE. It does
                // not show a periodic idle keepalive cadence. The server only
                // acknowledges this PING; it does not originate a matching one.
                if (role_ == H2CarrierRole::Client) {
                    const std::uint8_t opaque[8] = {0, 0, 0, 0, 0, 0, 0, 1};
                    Check(nghttp2_submit_ping(session_.get(), NGHTTP2_FLAG_NONE,
                                              opaque),
                          "submit captured close PING");
                }
                QueueStreamBytes(
                    carrier_stream_id_, websocket_.EncodeClose(websocket_code));
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

    void RecordCloseWireResult(bool completed) noexcept {
        if (!outer_trace_) return;
        OuterCarrierEvent event;
        event.kind = OuterCarrierEventKind::CloseWire;
        event.direction = OuterCarrierDirection::Sent;
        event.stream_class = OuterCarrierStreamClass::Carrier;
        event.completed = completed;
        outer_trace_->Record(std::move(event));
    }

    bool capture_observer_active() const noexcept {
        return static_cast<bool>(outer_trace_);
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
    H2CarrierStats stats() const noexcept {
        H2CarrierStats result = stats_;
        if (collect_timing_ && remote_window_stall_started_.has_value()) {
            result.remote_window_stall_ns += static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() -
                    *remote_window_stall_started_).count());
        }
        return result;
    }
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
        std::deque<H2Bytes> chunks{};
        std::size_t front_offset{0};
        std::size_t queued_bytes{0};
    };

    struct PendingTraceHeaders {
        std::vector<OuterCarrierHeader> headers;
    };

    static std::uint32_t ReadBe24(const std::uint8_t* data) noexcept {
        return (static_cast<std::uint32_t>(data[0]) << 16U) |
               (static_cast<std::uint32_t>(data[1]) << 8U) |
               static_cast<std::uint32_t>(data[2]);
    }

    static std::uint32_t ReadBe32(const std::uint8_t* data) noexcept {
        return (static_cast<std::uint32_t>(data[0]) << 24U) |
               (static_cast<std::uint32_t>(data[1]) << 16U) |
               (static_cast<std::uint32_t>(data[2]) << 8U) |
               static_cast<std::uint32_t>(data[3]);
    }

    OuterCarrierStreamClass ClassifyStream(
        std::int32_t stream_id) const noexcept {
        if (stream_id == 0) return OuterCarrierStreamClass::Connection;
        if (stream_id == priming_stream_id_) {
            return OuterCarrierStreamClass::Priming;
        }
        if (stream_id == css_stream_id_) {
            return OuterCarrierStreamClass::AssetCss;
        }
        if (stream_id == js_stream_id_) {
            return OuterCarrierStreamClass::AssetJs;
        }
        if (stream_id == carrier_stream_id_) {
            return OuterCarrierStreamClass::Carrier;
        }
        return OuterCarrierStreamClass::Other;
    }

    bool IsPinnedRequestHeader(
        std::string_view name, std::string_view value) const {
        const auto& profile = cover_profile::active();
        auto contains = [&](const cover_profile::RequestTemplate& request,
                            std::string_view path = {}) {
            const auto headers = profile.render_headers(
                request, "capture.invalid", path);
            return std::any_of(
                headers.begin(), headers.end(), [&](const auto& header) {
                    return header.first == name && header.second == value;
                });
        };
        if (contains(profile.priming_request) ||
            contains(profile.extended_connect, "/capture")) {
            return true;
        }
        return std::any_of(
            profile.assets.begin(), profile.assets.end(),
            [&](const auto& asset) { return contains(asset.request); });
    }

    std::string SafeHeaderName(
        std::string_view name, std::string_view value,
        OuterCarrierDirection direction) const {
        if (name.empty() || name.size() > 64 ||
            !std::all_of(name.begin(), name.end(), [](unsigned char ch) {
                return (ch >= 'a' && ch <= 'z') ||
                       (ch >= '0' && ch <= '9') || ch == ':' || ch == '-';
            })) {
            return "<invalid-header>";
        }
        if (name == "authorization" || name == "proxy-authorization" ||
            name == "cookie" || name == "set-cookie" ||
            name == "sec-websocket-key") {
            return "<sensitive-header>";
        }
        if (direction == OuterCarrierDirection::Received) {
            return name == ":status" || name == "date"
                ? std::string(name)
                : "<unrecognized-header>";
        }
        if (name != ":authority" && name != ":path" && name != "origin" &&
            name != "referer" && !IsPinnedRequestHeader(name, value)) {
            return "<unrecognized-header>";
        }
        return std::string(name);
    }

    std::string SafeHeaderValue(
        std::string_view name, std::string_view value,
        OuterCarrierStreamClass stream_class,
        OuterCarrierDirection direction,
        std::string_view expected_carrier_path = {}) const {
        if (name == "authorization" || name == "proxy-authorization" ||
            name == "cookie" || name == "set-cookie" ||
            name == "sec-websocket-key") {
            return "<redacted>";
        }
        if (name == ":authority") {
            return value == authority_
                ? "<cover-authority>" : "<unexpected-authority>";
        }
        if (name == "origin") {
            return value == "https://" + authority_
                ? "https://<cover-authority>" : "<unexpected-origin>";
        }
        if (name == "referer") {
            return value == "https://" + authority_ + "/"
                ? "https://<cover-authority>/" : "<unexpected-referer>";
        }
        if (name == "date") {
            const bool date_shape = value.size() == 29 && value[3] == ',' &&
                value[4] == ' ' && value[7] == ' ' && value[11] == ' ' &&
                value[16] == ' ' && value[19] == ':' && value[22] == ':' &&
                value.substr(25) == " GMT";
            return date_shape ? "<runtime-date>" : "<unexpected-date>";
        }
        if (name == ":path") {
            std::string_view expected;
            switch (stream_class) {
                case OuterCarrierStreamClass::Priming: expected = "/"; break;
                case OuterCarrierStreamClass::AssetCss:
                    expected = cover_profile::active().assets[0].path;
                    break;
                case OuterCarrierStreamClass::AssetJs:
                    expected = cover_profile::active().assets[1].path;
                    break;
                case OuterCarrierStreamClass::Carrier:
                    return !expected_carrier_path.empty() &&
                            value == expected_carrier_path
                        ? "<authenticated-carrier-path>"
                        : "<unexpected-carrier-path>";
                default: return "<unexpected-path>";
            }
            return value == expected
                ? std::string(expected) : "<unexpected-path>";
        }
        if (direction == OuterCarrierDirection::Received) {
            if (name == ":status" && value.size() == 3 &&
                std::all_of(value.begin(), value.end(), [](unsigned char ch) {
                    return std::isdigit(ch) != 0;
                })) {
                return std::string(value);
            }
            return "<redacted>";
        }
        if (value.size() <= 1024 && IsPinnedRequestHeader(name, value)) {
            return std::string(value);
        }
        return "<redacted>";
    }

    std::vector<OuterCarrierHeader> SanitizeHeaders(
        const H2Headers& headers, OuterCarrierStreamClass stream_class,
        OuterCarrierDirection direction,
        std::string_view expected_carrier_path = {}) const {
        std::vector<OuterCarrierHeader> sanitized;
        sanitized.reserve(headers.size());
        for (const auto& [name, value] : headers) {
            sanitized.push_back({
                SafeHeaderName(name, value, direction),
                SafeHeaderValue(name, value, stream_class, direction,
                                expected_carrier_path)});
        }
        return sanitized;
    }

    void QueueTraceHeaders(std::int32_t stream_id,
                           const H2Headers& headers,
                           std::string_view expected_carrier_path = {}) noexcept {
        if (!outer_trace_ || outer_trace_->truncated()) return;
        try {
            PendingTraceHeaders pending;
            pending.headers = SanitizeHeaders(
                headers, ClassifyStream(stream_id),
                OuterCarrierDirection::Sent, expected_carrier_path);
            const auto [_, inserted] = pending_trace_headers_.emplace(
                stream_id, std::move(pending));
            if (!inserted) outer_trace_->MarkTruncated();
        } catch (...) {
            outer_trace_->MarkTruncated();
        }
    }

    void RecordH2Frame(
        OuterCarrierDirection direction,
        OuterCarrierStreamClass stream_class,
        std::int32_t stream_id,
        std::uint8_t type, std::uint8_t flags, std::uint32_t length,
        std::vector<OuterCarrierSetting> settings = {},
        std::vector<OuterCarrierHeader> headers = {},
        std::uint32_t value = 0, std::uint32_t error_code = 0,
        bool priority_present = false, bool priority_exclusive = false,
        std::int32_t priority_parent = 0,
        std::int32_t priority_weight = 0,
        std::uint64_t ping_id = 0) noexcept {
        if (!outer_trace_) return;
        OuterCarrierEvent event;
        event.kind = OuterCarrierEventKind::H2Frame;
        event.direction = direction;
        event.stream_class = stream_class;
        event.h2_stream_id = stream_id;
        event.h2_type = type;
        event.flags = flags;
        event.length = length;
        event.value = value;
        event.error_code = error_code;
        event.settings = std::move(settings);
        event.headers = std::move(headers);
        event.priority_present = priority_present;
        event.priority_exclusive = priority_exclusive;
        event.priority_parent_stream_id = priority_parent;
        event.priority_weight = priority_weight;
        event.ping_id = ping_id;
        outer_trace_->Record(std::move(event));
    }

    std::uint64_t CorrelateH2Ping(
        OuterCarrierDirection direction, std::uint8_t flags,
        const std::uint8_t* payload, std::uint32_t length) noexcept {
        if (length != 8 || !payload) return 0;
        const bool ack = (flags & NGHTTP2_FLAG_ACK) != 0;
        auto equals = [&](const std::array<std::uint8_t, 8>& value) {
            return std::equal(value.begin(), value.end(), payload);
        };
        if (direction == OuterCarrierDirection::Sent) {
            if (ack) {
                return last_received_ping_valid_ &&
                        equals(last_received_ping_opaque_)
                    ? last_received_ping_id_ : 0;
            }
            std::copy_n(payload, 8, last_sent_ping_opaque_.begin());
            last_sent_ping_valid_ = true;
            last_sent_ping_id_ = next_ping_id_++;
            return last_sent_ping_id_;
        }
        if (ack) {
            return last_sent_ping_valid_ && equals(last_sent_ping_opaque_)
                ? last_sent_ping_id_ : 0;
        }
        std::copy_n(payload, 8, last_received_ping_opaque_.begin());
        last_received_ping_valid_ = true;
        last_received_ping_id_ = next_ping_id_++;
        return last_received_ping_id_;
    }

    void ObserveOutboundH2Wire(const std::uint8_t* data,
                               std::size_t size) noexcept {
        if (!outer_trace_ || size == 0) return;
        try {
            static constexpr std::string_view kClientPreface =
                "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            std::size_t offset = 0;
            std::uint8_t previous_type = 0xffU;
            std::uint8_t previous_flags = 0;
            if (size >= kClientPreface.size() &&
                std::equal(kClientPreface.begin(), kClientPreface.end(), data)) {
                offset = kClientPreface.size();
            }
            while (offset < size) {
                if (size - offset < 9) {
                    outer_trace_->MarkTruncated();
                    return;
                }
                const std::uint8_t* header = data + offset;
                const std::uint32_t length = ReadBe24(header);
                if (static_cast<std::size_t>(length) > size - offset - 9) {
                    outer_trace_->MarkTruncated();
                    return;
                }
                const std::uint8_t type = header[3];
                const std::uint8_t flags = header[4];
                const std::int32_t stream_id = static_cast<std::int32_t>(
                    ReadBe32(header + 5) & 0x7fffffffU);
                const std::uint8_t* payload = header + 9;
                const bool carrier_data_preceded_by_ping =
                    type == NGHTTP2_DATA &&
                    ClassifyStream(stream_id) ==
                        OuterCarrierStreamClass::Carrier &&
                    previous_type == NGHTTP2_PING &&
                    (previous_flags & NGHTTP2_FLAG_ACK) == 0;
                std::vector<OuterCarrierSetting> settings;
                std::vector<OuterCarrierHeader> headers;
                std::uint32_t value = 0;
                std::uint32_t error_code = 0;
                bool priority_present = false;
                bool priority_exclusive = false;
                std::int32_t priority_parent = 0;
                std::int32_t priority_weight = 0;
                std::uint64_t ping_id = 0;

                if (type == NGHTTP2_SETTINGS &&
                    (flags & NGHTTP2_FLAG_ACK) == 0) {
                    if (length % 6 != 0) {
                        outer_trace_->MarkTruncated();
                        return;
                    }
                    settings.reserve(length / 6);
                    for (std::size_t index = 0; index < length; index += 6) {
                        settings.push_back({
                            static_cast<std::uint32_t>(
                                (payload[index] << 8U) | payload[index + 1]),
                            ReadBe32(payload + index + 2)});
                    }
                } else if (type == NGHTTP2_WINDOW_UPDATE && length == 4) {
                    value = ReadBe32(payload) & 0x7fffffffU;
                } else if (type == NGHTTP2_GOAWAY && length >= 8) {
                    error_code = ReadBe32(payload + 4);
                } else if (type == NGHTTP2_PING) {
                    ping_id = CorrelateH2Ping(
                        OuterCarrierDirection::Sent, flags, payload, length);
                } else if (type == NGHTTP2_HEADERS) {
                    auto pending = pending_trace_headers_.find(stream_id);
                    if (pending != pending_trace_headers_.end()) {
                        headers = std::move(pending->second.headers);
                        pending_trace_headers_.erase(pending);
                    }
                    std::size_t priority_offset = 0;
                    if ((flags & NGHTTP2_FLAG_PADDED) != 0) {
                        priority_offset = 1;
                    }
                    if ((flags & NGHTTP2_FLAG_PRIORITY) != 0 &&
                        length >= priority_offset + 5) {
                        const std::uint32_t dependency =
                            ReadBe32(payload + priority_offset);
                        priority_present = true;
                        priority_exclusive =
                            (dependency & 0x80000000U) != 0;
                        priority_parent = static_cast<std::int32_t>(
                            dependency & 0x7fffffffU);
                        priority_weight =
                            static_cast<std::int32_t>(
                                payload[priority_offset + 4]) + 1;
                    }
                }
                RecordH2Frame(
                    OuterCarrierDirection::Sent, ClassifyStream(stream_id),
                    stream_id, type, flags, length, std::move(settings),
                    std::move(headers), value, error_code, priority_present,
                    priority_exclusive, priority_parent, priority_weight,
                    ping_id);
                if (type == NGHTTP2_DATA &&
                    ClassifyStream(stream_id) ==
                        OuterCarrierStreamClass::Carrier) {
                    const std::uint8_t* websocket_payload = payload;
                    std::size_t websocket_size = length;
                    if ((flags & NGHTTP2_FLAG_PADDED) != 0) {
                        if (length == 0 || payload[0] >= length) {
                            outer_trace_->MarkTruncated();
                            return;
                        }
                        websocket_payload = payload + 1;
                        websocket_size = length - 1 - payload[0];
                    }
                    ObserveOutboundWebSocketBytes(
                        websocket_payload, websocket_size,
                        carrier_data_preceded_by_ping);
                }
                previous_type = type;
                previous_flags = flags;
                offset += 9 + length;
            }
        } catch (...) {
            outer_trace_->MarkTruncated();
        }
    }

    void CompleteInboundH2Frame() noexcept {
        try {
            std::uint32_t value = 0;
            std::uint32_t error_code = 0;
            bool priority_present = false;
            bool priority_exclusive = false;
            std::int32_t priority_parent = 0;
            std::int32_t priority_weight = 0;
            std::uint64_t ping_id = 0;
            if (inbound_frame_type_ == NGHTTP2_WINDOW_UPDATE &&
                inbound_frame_length_ == 4 && inbound_control_used_ == 4) {
                value = ReadBe32(inbound_control_prefix_.data()) & 0x7fffffffU;
            } else if (inbound_frame_type_ == NGHTTP2_GOAWAY &&
                       inbound_frame_length_ >= 8 &&
                       inbound_control_used_ == 8) {
                error_code = ReadBe32(inbound_control_prefix_.data() + 4);
            } else if (inbound_frame_type_ == NGHTTP2_PING) {
                ping_id = CorrelateH2Ping(
                    OuterCarrierDirection::Received, inbound_frame_flags_,
                    inbound_control_prefix_.data(), inbound_frame_length_);
            } else if (inbound_frame_type_ == NGHTTP2_HEADERS) {
                const std::size_t priority_offset =
                    (inbound_frame_flags_ & NGHTTP2_FLAG_PADDED) != 0 ? 1 : 0;
                if ((inbound_frame_flags_ & NGHTTP2_FLAG_PRIORITY) != 0 &&
                    inbound_frame_length_ >= priority_offset + 5 &&
                    inbound_control_used_ >= priority_offset + 5) {
                    const std::uint32_t dependency = ReadBe32(
                        inbound_control_prefix_.data() + priority_offset);
                    priority_present = true;
                    priority_exclusive =
                        (dependency & 0x80000000U) != 0;
                    priority_parent = static_cast<std::int32_t>(
                        dependency & 0x7fffffffU);
                    priority_weight = static_cast<std::int32_t>(
                        inbound_control_prefix_[priority_offset + 4]) + 1;
                }
            }
            RecordH2Frame(
                OuterCarrierDirection::Received,
                ClassifyStream(inbound_frame_stream_id_),
                inbound_frame_stream_id_, inbound_frame_type_,
                inbound_frame_flags_, inbound_frame_length_,
                std::move(inbound_frame_settings_), {}, value, error_code,
                priority_present, priority_exclusive, priority_parent,
                priority_weight, ping_id);
        } catch (...) {
            outer_trace_->MarkTruncated();
        }
        inbound_frame_header_used_ = 0;
        inbound_frame_length_ = 0;
        inbound_frame_remaining_ = 0;
        inbound_control_used_ = 0;
        inbound_setting_used_ = 0;
        inbound_frame_settings_.clear();
    }

    void ObserveInboundH2Wire(
        const std::uint8_t* data, std::size_t size) noexcept {
        if (!outer_trace_ || size == 0 || outer_trace_->truncated()) return;
        static constexpr std::uint32_t kMaxObservedFrameBytes =
            1024U * 1024U;
        static constexpr std::size_t kMaxObservedSettings = 64;
        static constexpr std::string_view kClientPreface =
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        try {
            std::size_t offset = 0;
            while (inbound_preface_pending_ && offset < size) {
                if (data[offset] != static_cast<std::uint8_t>(
                        kClientPreface[inbound_preface_used_])) {
                    outer_trace_->MarkTruncated();
                    return;
                }
                ++offset;
                if (++inbound_preface_used_ == kClientPreface.size()) {
                    inbound_preface_pending_ = false;
                }
            }
            while (offset < size && !outer_trace_->truncated()) {
                if (inbound_frame_header_used_ < inbound_frame_header_.size()) {
                    const std::size_t count = std::min(
                        inbound_frame_header_.size() -
                            inbound_frame_header_used_,
                        size - offset);
                    std::copy_n(
                        data + offset, count,
                        inbound_frame_header_.begin() +
                            static_cast<std::ptrdiff_t>(
                                inbound_frame_header_used_));
                    inbound_frame_header_used_ += count;
                    offset += count;
                    if (inbound_frame_header_used_ <
                        inbound_frame_header_.size()) {
                        return;
                    }
                    inbound_frame_length_ = ReadBe24(
                        inbound_frame_header_.data());
                    if (inbound_frame_length_ > kMaxObservedFrameBytes) {
                        outer_trace_->MarkTruncated();
                        return;
                    }
                    inbound_frame_type_ = inbound_frame_header_[3];
                    inbound_frame_flags_ = inbound_frame_header_[4];
                    inbound_frame_stream_id_ = static_cast<std::int32_t>(
                        ReadBe32(inbound_frame_header_.data() + 5) &
                        0x7fffffffU);
                    inbound_frame_remaining_ = inbound_frame_length_;
                    inbound_control_prefix_.fill(0);
                    inbound_control_used_ = 0;
                    inbound_setting_used_ = 0;
                    inbound_frame_settings_.clear();
                    if (inbound_frame_type_ == NGHTTP2_SETTINGS &&
                        (inbound_frame_flags_ & NGHTTP2_FLAG_ACK) == 0) {
                        if (inbound_frame_length_ % 6 != 0 ||
                            inbound_frame_length_ / 6 >
                                kMaxObservedSettings) {
                            outer_trace_->MarkTruncated();
                            return;
                        }
                        inbound_frame_settings_.reserve(
                            inbound_frame_length_ / 6);
                    }
                    if (inbound_frame_remaining_ == 0) {
                        CompleteInboundH2Frame();
                        continue;
                    }
                }

                const std::size_t count = std::min<std::size_t>(
                    inbound_frame_remaining_, size - offset);
                if (inbound_frame_type_ == NGHTTP2_SETTINGS &&
                    (inbound_frame_flags_ & NGHTTP2_FLAG_ACK) == 0) {
                    for (std::size_t index = 0; index < count; ++index) {
                        inbound_setting_entry_[inbound_setting_used_++] =
                            data[offset + index];
                        if (inbound_setting_used_ ==
                            inbound_setting_entry_.size()) {
                            inbound_frame_settings_.push_back({
                                static_cast<std::uint32_t>(
                                    (inbound_setting_entry_[0] << 8U) |
                                    inbound_setting_entry_[1]),
                                ReadBe32(
                                    inbound_setting_entry_.data() + 2)});
                            inbound_setting_used_ = 0;
                        }
                    }
                } else if (
                    inbound_frame_type_ == NGHTTP2_WINDOW_UPDATE ||
                    inbound_frame_type_ == NGHTTP2_GOAWAY ||
                    inbound_frame_type_ == NGHTTP2_PING ||
                    (inbound_frame_type_ == NGHTTP2_HEADERS &&
                     (inbound_frame_flags_ & NGHTTP2_FLAG_PRIORITY) != 0)) {
                    std::size_t retained_limit =
                        inbound_control_prefix_.size();
                    if (inbound_frame_type_ == NGHTTP2_WINDOW_UPDATE) {
                        retained_limit = 4;
                    } else if (inbound_frame_type_ == NGHTTP2_HEADERS) {
                        retained_limit =
                            ((inbound_frame_flags_ & NGHTTP2_FLAG_PADDED) != 0
                                 ? 1U
                                 : 0U) + 5U;
                    }
                    const std::size_t retained = std::min(
                        count, retained_limit -
                            std::min(retained_limit, inbound_control_used_));
                    std::copy_n(
                        data + offset, retained,
                        inbound_control_prefix_.begin() +
                            static_cast<std::ptrdiff_t>(
                                inbound_control_used_));
                    inbound_control_used_ += retained;
                }
                offset += count;
                inbound_frame_remaining_ -=
                    static_cast<std::uint32_t>(count);
                if (inbound_frame_remaining_ == 0) {
                    if (inbound_setting_used_ != 0) {
                        outer_trace_->MarkTruncated();
                        return;
                    }
                    CompleteInboundH2Frame();
                }
            }
        } catch (...) {
            outer_trace_->MarkTruncated();
        }
    }

    void RecordOutboundWebSocketFrame(
        const WebSocketFrameMetadata& frame,
        bool carrier_data_preceded_by_ping) noexcept {
        if (!outer_trace_) return;
        OuterCarrierEvent event;
        event.kind = OuterCarrierEventKind::WebSocketFrame;
        event.direction = OuterCarrierDirection::Sent;
        event.stream_class = OuterCarrierStreamClass::Carrier;
        event.websocket_opcode = frame.opcode;
        event.websocket_final = frame.final;
        event.websocket_masked = frame.masked;
        event.websocket_payload_bytes = frame.payload_bytes;
        event.h2_ping_immediately_before =
            frame.opcode == 0x8 && carrier_data_preceded_by_ping;
        outer_trace_->Record(std::move(event));
    }

    bool CarrierWindowBlocked() const noexcept {
        if (carrier_stream_id_ <= 0) return false;
        const auto stream = outbound_streams_.find(carrier_stream_id_);
        if (stream == outbound_streams_.end() ||
            stream->second.queued_bytes == 0) {
            return false;
        }
        const std::int32_t stream_window =
            nghttp2_session_get_stream_remote_window_size(
                session_.get(), carrier_stream_id_);
        const std::int32_t connection_window =
            nghttp2_session_get_remote_window_size(session_.get());
        return stream_window <= 0 || connection_window <= 0;
    }

    void ObserveCarrierWindowState() noexcept {
#if YUME_ENABLE_DEV_DIAGNOSTICS
        if (!outer_trace_ && !collect_timing_) return;
#else
        if (!outer_trace_) return;
#endif
        const bool blocked = CarrierWindowBlocked();
        if (blocked == carrier_window_stalled_) return;
#if YUME_ENABLE_DEV_DIAGNOSTICS
        if (collect_timing_) {
            const auto now = std::chrono::steady_clock::now();
            if (blocked) {
                ++stats_.remote_window_stall_count;
                remote_window_stall_started_ = now;
            } else if (remote_window_stall_started_.has_value()) {
                stats_.remote_window_stall_ns += static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        now - *remote_window_stall_started_).count());
                remote_window_stall_started_.reset();
            }
        }
#endif
        if (outer_trace_) {
            OuterCarrierEvent event;
            event.kind = blocked
                ? OuterCarrierEventKind::FlowWindowStalled
                : OuterCarrierEventKind::FlowWindowRecovered;
            event.direction = OuterCarrierDirection::Sent;
            event.stream_class = OuterCarrierStreamClass::Carrier;
            outer_trace_->Record(std::move(event));
        }
        carrier_window_stalled_ = blocked;
    }

    enum class OutboundWebSocketParseState : std::uint8_t {
        First,
        Second,
        ExtendedLength,
        Mask,
        Payload,
    };

    void CompleteOutboundWebSocketFrame() noexcept {
        RecordOutboundWebSocketFrame(
            outbound_websocket_frame_,
            outbound_websocket_current_h2_ping_before_);
        outbound_websocket_state_ = OutboundWebSocketParseState::First;
        outbound_websocket_extended_bytes_ = 0;
        outbound_websocket_mask_bytes_ = 0;
        outbound_websocket_payload_remaining_ = 0;
        outbound_websocket_frame_ = {};
        outbound_websocket_current_h2_ping_before_ = false;
    }

    void AdvanceOutboundWebSocketAfterLength() noexcept {
        outbound_websocket_mask_bytes_ =
            outbound_websocket_frame_.masked ? 4 : 0;
        if (outbound_websocket_mask_bytes_ != 0) {
            outbound_websocket_state_ = OutboundWebSocketParseState::Mask;
        } else if (outbound_websocket_payload_remaining_ != 0) {
            outbound_websocket_state_ = OutboundWebSocketParseState::Payload;
        } else {
            CompleteOutboundWebSocketFrame();
        }
    }

    void ObserveOutboundWebSocketBytes(
        const std::uint8_t* data, std::size_t size,
        bool carrier_data_preceded_by_ping) noexcept {
        if (!outer_trace_ || outer_trace_->truncated()) return;
        std::size_t offset = 0;
        while (offset < size) {
            switch (outbound_websocket_state_) {
                case OutboundWebSocketParseState::First: {
                    outbound_websocket_current_h2_ping_before_ =
                        carrier_data_preceded_by_ping;
                    const std::uint8_t first = data[offset++];
                    outbound_websocket_frame_.opcode = first & 0x0fU;
                    outbound_websocket_frame_.final =
                        (first & 0x80U) != 0;
                    outbound_websocket_state_ =
                        OutboundWebSocketParseState::Second;
                    break;
                }
                case OutboundWebSocketParseState::Second: {
                    const std::uint8_t second = data[offset++];
                    outbound_websocket_frame_.masked =
                        (second & 0x80U) != 0;
                    const std::uint8_t encoded_length = second & 0x7fU;
                    if (encoded_length < 126) {
                        outbound_websocket_frame_.payload_bytes =
                            encoded_length;
                        outbound_websocket_payload_remaining_ =
                            encoded_length;
                        AdvanceOutboundWebSocketAfterLength();
                    } else {
                        outbound_websocket_frame_.payload_bytes = 0;
                        outbound_websocket_extended_bytes_ =
                            encoded_length == 126 ? 2 : 8;
                        outbound_websocket_state_ =
                            OutboundWebSocketParseState::ExtendedLength;
                    }
                    break;
                }
                case OutboundWebSocketParseState::ExtendedLength:
                    outbound_websocket_frame_.payload_bytes =
                        (outbound_websocket_frame_.payload_bytes << 8U) |
                        data[offset++];
                    if (--outbound_websocket_extended_bytes_ == 0) {
                        outbound_websocket_payload_remaining_ =
                            outbound_websocket_frame_.payload_bytes;
                        AdvanceOutboundWebSocketAfterLength();
                    }
                    break;
                case OutboundWebSocketParseState::Mask: {
                    const std::size_t count = std::min(
                        outbound_websocket_mask_bytes_, size - offset);
                    offset += count;
                    outbound_websocket_mask_bytes_ -= count;
                    if (outbound_websocket_mask_bytes_ == 0) {
                        if (outbound_websocket_payload_remaining_ == 0) {
                            CompleteOutboundWebSocketFrame();
                        } else {
                            outbound_websocket_state_ =
                                OutboundWebSocketParseState::Payload;
                        }
                    }
                    break;
                }
                case OutboundWebSocketParseState::Payload: {
                    const std::uint64_t available = size - offset;
                    const std::uint64_t count = std::min(
                        outbound_websocket_payload_remaining_, available);
                    offset += static_cast<std::size_t>(count);
                    outbound_websocket_payload_remaining_ -= count;
                    if (outbound_websocket_payload_remaining_ == 0) {
                        CompleteOutboundWebSocketFrame();
                    }
                    break;
                }
            }
        }
    }

    static void OnWebSocketFrame(
        void* context, const WebSocketFrameMetadata& frame) noexcept {
        auto& self = *static_cast<Impl*>(context);
        if (!self.outer_trace_) return;
        OuterCarrierEvent event;
        event.kind = OuterCarrierEventKind::WebSocketFrame;
        event.direction = OuterCarrierDirection::Received;
        event.stream_class = OuterCarrierStreamClass::Carrier;
        event.websocket_opcode = frame.opcode;
        event.websocket_final = frame.final;
        event.websocket_masked = frame.masked;
        event.websocket_payload_bytes = frame.payload_bytes;
        self.outer_trace_->Record(std::move(event));
    }

    void ObserveInboundH2Frame(const nghttp2_frame& frame) noexcept {
        if (!outer_trace_ || frame.hd.type != NGHTTP2_HEADERS) return;
        try {
            std::vector<OuterCarrierHeader> headers;
            const auto incoming = incoming_headers_.find(frame.hd.stream_id);
            if (incoming != incoming_headers_.end()) {
                headers = SanitizeHeaders(
                    incoming->second, ClassifyStream(frame.hd.stream_id),
                    OuterCarrierDirection::Received);
            }
            OuterCarrierEvent event;
            event.kind = OuterCarrierEventKind::H2HeadersDecoded;
            event.direction = OuterCarrierDirection::Received;
            event.stream_class = ClassifyStream(frame.hd.stream_id);
            event.h2_stream_id = frame.hd.stream_id;
            event.headers = std::move(headers);
            outer_trace_->Record(std::move(event));
        } catch (...) {
            outer_trace_->MarkTruncated();
        }
    }

#if YUME_ENABLE_DEV_DIAGNOSTICS
    void ObserveWindowUpdate(const nghttp2_frame& frame,
                             bool sent) noexcept {
        if (!collect_timing_ || frame.hd.type != NGHTTP2_WINDOW_UPDATE) {
            return;
        }
        const auto increment = static_cast<std::uint64_t>(
            frame.window_update.window_size_increment);
        const bool connection = frame.hd.stream_id == 0;
        const bool carrier = frame.hd.stream_id == carrier_stream_id_;
        if (!connection && !carrier) return;
        if (sent && connection) {
            ++stats_.window_update_sent_connection_frames;
            stats_.window_update_sent_connection_increment_bytes += increment;
        } else if (sent) {
            ++stats_.window_update_sent_carrier_frames;
            stats_.window_update_sent_carrier_increment_bytes += increment;
        } else if (connection) {
            ++stats_.window_update_received_connection_frames;
            stats_.window_update_received_connection_increment_bytes += increment;
        } else {
            ++stats_.window_update_received_carrier_frames;
            stats_.window_update_received_carrier_increment_bytes += increment;
        }
    }

    void ObserveFlowControlStats() noexcept {
        if (!collect_timing_ || carrier_stream_id_ < 0) return;
        const std::int32_t local_connection =
            nghttp2_session_get_local_window_size(session_.get());
        const std::int32_t local_carrier =
            nghttp2_session_get_stream_local_window_size(
                session_.get(), carrier_stream_id_);
        const std::int32_t remote_connection =
            nghttp2_session_get_remote_window_size(session_.get());
        const std::int32_t remote_carrier =
            nghttp2_session_get_stream_remote_window_size(
                session_.get(), carrier_stream_id_);
        const std::int32_t effective_connection_received =
            nghttp2_session_get_effective_recv_data_length(session_.get());
        const std::int32_t effective_carrier_received =
            nghttp2_session_get_stream_effective_recv_data_length(
                session_.get(), carrier_stream_id_);
        if (local_connection < 0 || local_carrier < 0 ||
            effective_connection_received < 0 ||
            effective_carrier_received < 0) {
            return;
        }
        if (stats_.flow_window_samples == 0) {
            stats_.min_local_connection_window = local_connection;
            stats_.min_local_carrier_window = local_carrier;
            stats_.min_remote_connection_window = remote_connection;
            stats_.min_remote_carrier_window = remote_carrier;
        } else {
            stats_.min_local_connection_window = std::min(
                stats_.min_local_connection_window, local_connection);
            stats_.min_local_carrier_window = std::min(
                stats_.min_local_carrier_window, local_carrier);
            stats_.min_remote_connection_window = std::min(
                stats_.min_remote_connection_window, remote_connection);
            stats_.min_remote_carrier_window = std::min(
                stats_.min_remote_carrier_window, remote_carrier);
        }
        stats_.max_effective_connection_received = std::max(
            stats_.max_effective_connection_received,
            effective_connection_received);
        stats_.max_effective_carrier_received = std::max(
            stats_.max_effective_carrier_received,
            effective_carrier_received);
        ++stats_.flow_window_samples;
    }
#endif

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
#if YUME_ENABLE_DEV_DIAGNOSTICS
            self.ObserveWindowUpdate(*frame, false);
#endif
            self.ObserveInboundH2Frame(*frame);
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

#if YUME_ENABLE_DEV_DIAGNOSTICS
    static int OnFrameSend(nghttp2_session*, const nghttp2_frame* frame,
                           void* user_data) noexcept {
        auto& self = *static_cast<Impl*>(user_data);
        self.ObserveWindowUpdate(*frame, true);
        return 0;
    }
#endif

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
                             std::uint32_t error_code,
                             void* user_data) noexcept {
        auto& self = *static_cast<Impl*>(user_data);
        try {
            if (self.outer_trace_) {
                OuterCarrierEvent event;
                event.kind = OuterCarrierEventKind::StreamClose;
                event.direction = OuterCarrierDirection::Received;
                event.stream_class = self.ClassifyStream(stream_id);
                event.h2_stream_id = stream_id;
                event.error_code = error_code;
                event.completed = error_code == NGHTTP2_NO_ERROR;
                self.outer_trace_->Record(std::move(event));
            }
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
                self.carrier_h2_stream_closed_ = true;
            }
            if (self.role_ == H2CarrierRole::Server) {
                if (self.stream_closes_.size() >=
                    kMaxPendingServerStreamCloses) {
                    self.Fail("too many pending HTTP/2 stream-close events");
                    return NGHTTP2_ERR_CALLBACK_FAILURE;
                }
                self.stream_closes_.push_back(
                    H2StreamClose{stream_id, error_code});
            }
            self.outbound_streams_.erase(stream_id);
            self.incoming_headers_.erase(stream_id);
            self.incoming_header_bytes_.erase(stream_id);
            self.pending_trace_headers_.erase(stream_id);
            self.responded_streams_.erase(stream_id);
            self.requests_.erase(
                std::remove_if(
                    self.requests_.begin(), self.requests_.end(),
                    [stream_id](const H2Request& request) {
                        return request.stream_id == stream_id;
                    }),
                self.requests_.end());
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
        if (count != 0) {
            std::memcpy(buf, front.data() + stream.front_offset, count);
        }
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
            if (requests_.size() >= kMaxPendingServerRequests) {
                Fail("too many pending HTTP/2 requests");
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
            // Cover responses and non-carrier request bodies are bounded by
            // their own parsers and have no downstream sink. Retire their H2
            // credit immediately in both roles so manual carrier credit does
            // not stall or retain ordinary cover traffic.
            if (!ConsumeData(stream_id, len)) return;
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
            if (!ConsumeData(stream_id, len)) return;
            priming_body_bytes_ += len;
            if (priming_body_bytes_ > kMaxResponseBody) {
                Fail("cover rejection body exceeds 8 MiB");
            }
            return;
        }
#if YUME_ENABLE_DEV_DIAGNOSTICS
        diagnostics::Stopwatch decode_timer(collect_timing_);
#endif
        if (len > std::numeric_limits<std::size_t>::max() -
                      received_unconsumed_carrier_bytes_) {
            Fail("HTTP/2 carrier receive-credit ledger overflow");
            return;
        }
        received_unconsumed_carrier_bytes_ += len;
#if YUME_ENABLE_DEV_DIAGNOSTICS
        if (collect_timing_) {
            stats_.max_received_unconsumed_carrier_bytes =
                std::max<std::uint64_t>(
                    stats_.max_received_unconsumed_carrier_bytes,
                    received_unconsumed_carrier_bytes_);
        }
#endif
        websocket_.Feed(data, len);
        if (websocket_.failed()) {
            Fail("WebSocket carrier: " + websocket_.error());
            return;
        }
        auto drain = websocket_.TakeDrain();
        auto decoded = std::move(drain.tunnel_bytes);
        const bool had_decoded_tunnel_bytes = !decoded.empty();
        if (drain.immediately_consumable_wire_bytes >
                received_unconsumed_carrier_bytes_ ||
            decoded.size() >
                received_unconsumed_carrier_bytes_ -
                    drain.immediately_consumable_wire_bytes) {
            Fail("WebSocket/H2 receive-credit ledger mismatch");
            return;
        }
        if (!ConsumeCarrierBytes(
                drain.immediately_consumable_wire_bytes)) {
            return;
        }
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
        if (!replies.empty()) {
            QueueStreamBytes(stream_id, std::move(replies));
        }
        if (role_ == H2CarrierRole::Server && !server_active_ping_sent_ &&
            had_decoded_tunnel_bytes) {
            static constexpr std::uint8_t kFixturePing[] = {
                'f', 'i', 'x', 't', 'u', 'r', 'e', '-', 'p', 'i', 'n', 'g'};
            QueueStreamBytes(
                stream_id,
                websocket_.EncodePing(kFixturePing, std::size(kFixturePing)));
            server_active_ping_sent_ = true;
        }
        if (websocket_.closed()) carrier_closed_ = true;
    }

    bool ConsumeData(std::int32_t stream_id, std::size_t size) {
        if (size == 0) return true;
        return CheckBool(
            nghttp2_session_consume(session_.get(), stream_id, size),
            "consume HTTP/2 receive credit");
    }

    bool ConsumeCarrierBytes(std::size_t size) {
        if (size > received_unconsumed_carrier_bytes_) {
            return Fail("HTTP/2 carrier receive-credit over-consumption");
        }
        const int rv = carrier_h2_stream_closed_
            ? nghttp2_session_consume_connection(session_.get(), size)
            : nghttp2_session_consume(
                  session_.get(), carrier_stream_id_, size);
        if (!CheckBool(rv, carrier_h2_stream_closed_
                               ? "consume closed HTTP/2 carrier connection credit"
                               : "consume HTTP/2 carrier receive credit")) {
            return false;
        }
        received_unconsumed_carrier_bytes_ -= size;
#if YUME_ENABLE_DEV_DIAGNOSTICS
        if (collect_timing_) {
            ++stats_.carrier_credit_consume_calls;
            stats_.carrier_credit_consume_bytes += size;
            ObserveFlowControlStats();
        }
#endif
        return true;
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
        const auto& profile = cover_profile::active();
        if (profile.assets.size() != 2) {
            throw std::runtime_error(
                "Chrome cover profile requires exactly two priming assets");
        }
        H2Headers css_headers =
            profile.render_headers(profile.assets[0].request, authority_);
        auto css_nva = MakeNva(css_headers);
        nghttp2_priority_spec css_priority{};
        nghttp2_priority_spec_init(
            &css_priority,
            profile.assets[0].request.priority.parent_stream_id,
            profile.assets[0].request.priority.weight,
            profile.assets[0].request.priority.exclusive ? 1 : 0);
        css_stream_id_ = nghttp2_submit_request2(
            session_.get(), &css_priority, css_nva.data(), css_nva.size(),
            nullptr, nullptr);
        if (css_stream_id_ < 0) {
            throw std::runtime_error("submit Chrome CSS request: " +
                                     std::string(nghttp2_strerror(css_stream_id_)));
        }
        if (!wire_profile_.QueuePriority(
                css_stream_id_, profile.assets[0].request.priority,
                error_)) {
            throw std::runtime_error(error_);
        }
        QueueTraceHeaders(css_stream_id_, css_headers);

        H2Headers js_headers =
            profile.render_headers(profile.assets[1].request, authority_);
        auto js_nva = MakeNva(js_headers);
        nghttp2_priority_spec js_priority{};
        const std::int32_t js_parent =
            profile.assets[1].request.priority.parent_stream_id < 0
                ? css_stream_id_
                : profile.assets[1].request.priority.parent_stream_id;
        nghttp2_priority_spec_init(
            &js_priority,
            js_parent,
            profile.assets[1].request.priority.weight,
            profile.assets[1].request.priority.exclusive ? 1 : 0);
        js_stream_id_ = nghttp2_submit_request2(
            session_.get(), &js_priority, js_nva.data(), js_nva.size(),
            nullptr, nullptr);
        if (js_stream_id_ < 0) {
            throw std::runtime_error("submit Chrome JS request: " +
                                     std::string(nghttp2_strerror(js_stream_id_)));
        }
        auto js_wire_priority = profile.assets[1].request.priority;
        js_wire_priority.parent_stream_id = js_parent;
        if (!wire_profile_.QueuePriority(
                js_stream_id_, js_wire_priority, error_)) {
            throw std::runtime_error(error_);
        }
        QueueTraceHeaders(js_stream_id_, js_headers);
        Flush();
    }

    void Flush() {
        if (failed()) return;
        ObserveCarrierWindowState();
        const std::size_t trace_output_before =
            outer_trace_ ? serialized_output_.size() : 0;
#if YUME_ENABLE_DEV_DIAGNOSTICS
        diagnostics::Stopwatch flush_timer(collect_timing_);
        const std::size_t output_before = serialized_output_.size();
#endif
        H2Bytes batch;
        while (true) {
            const std::uint8_t* data = nullptr;
            const auto length = nghttp2_session_mem_send2(session_.get(), &data);
            if (length < 0) {
                FailNghttp2("serialize HTTP/2 output", static_cast<int>(length));
                break;
            }
            if (length == 0) break;
            const auto count = static_cast<std::size_t>(length);
            if (count >
                kMaxQueuedOutput -
                    std::min(kMaxQueuedOutput, batch.size()) ||
                serialized_output_.size() >
                    kMaxQueuedOutput - batch.size() - count) {
                Fail("serialized HTTP/2 output exceeded 32 MiB");
                break;
            }
            batch.insert(batch.end(), data, data + count);
        }
        if (!failed() && !batch.empty()) {
            wire_profile_.AppendSerializedBatch(
                batch, kMaxQueuedOutput, serialized_output_, error_);
        }
        if (!failed() && outer_trace_ &&
            serialized_output_.size() > trace_output_before) {
            ObserveOutboundH2Wire(
                serialized_output_.data() + trace_output_before,
                serialized_output_.size() - trace_output_before);
        }
        ObserveCarrierWindowState();
#if YUME_ENABLE_DEV_DIAGNOSTICS
        ObserveFlowControlStats();
        stats_.h2_flush_calls += 1;
        stats_.h2_flush_bytes +=
            serialized_output_.size() - output_before;
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
    std::shared_ptr<OuterCarrierTrace> outer_trace_;
#if YUME_ENABLE_DEV_DIAGNOSTICS
    H2CarrierStats stats_;
    bool collect_timing_{false};
    std::optional<std::chrono::steady_clock::time_point>
        remote_window_stall_started_;
#endif
    std::unique_ptr<nghttp2_session_callbacks, CallbacksDeleter> callbacks_;
    std::unique_ptr<nghttp2_session, SessionDeleter> session_;
    std::unordered_map<std::int32_t, H2Headers> incoming_headers_;
    std::unordered_map<std::int32_t, std::size_t> incoming_header_bytes_;
    std::unordered_map<std::int32_t, PendingTraceHeaders>
        pending_trace_headers_;
    std::unordered_map<std::int32_t, OutboundStream> outbound_streams_;
    detail::H2WireProfile wire_profile_;
    std::unordered_set<std::int32_t> responded_streams_;
    std::vector<H2Request> requests_;
    std::vector<H2StreamClose> stream_closes_;
    H2Bytes serialized_output_;
    H2Bytes tunnel_bytes_;
    std::size_t received_unconsumed_carrier_bytes_{0};
    std::size_t unconsumed_tunnel_bytes_{0};
    std::string authority_;
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
    bool carrier_h2_stream_closed_{false};
    bool authenticated_receive_window_enabled_{false};
    bool graceful_close_started_{false};
    bool server_fragment_fixture_sent_{false};
    bool server_active_ping_sent_{false};
    OutboundWebSocketParseState outbound_websocket_state_{
        OutboundWebSocketParseState::First};
    WebSocketFrameMetadata outbound_websocket_frame_{};
    std::size_t outbound_websocket_extended_bytes_{0};
    std::size_t outbound_websocket_mask_bytes_{0};
    std::uint64_t outbound_websocket_payload_remaining_{0};
    bool outbound_websocket_current_h2_ping_before_{false};
    bool carrier_window_stalled_{false};
    bool inbound_preface_pending_{false};
    std::size_t inbound_preface_used_{0};
    std::array<std::uint8_t, 9> inbound_frame_header_{};
    std::size_t inbound_frame_header_used_{0};
    std::uint32_t inbound_frame_length_{0};
    std::uint32_t inbound_frame_remaining_{0};
    std::uint8_t inbound_frame_type_{0};
    std::uint8_t inbound_frame_flags_{0};
    std::int32_t inbound_frame_stream_id_{0};
    std::array<std::uint8_t, 8> inbound_control_prefix_{};
    std::size_t inbound_control_used_{0};
    std::array<std::uint8_t, 6> inbound_setting_entry_{};
    std::size_t inbound_setting_used_{0};
    std::vector<OuterCarrierSetting> inbound_frame_settings_;
    std::uint64_t next_ping_id_{1};
    std::array<std::uint8_t, 8> last_sent_ping_opaque_{};
    std::array<std::uint8_t, 8> last_received_ping_opaque_{};
    std::uint64_t last_sent_ping_id_{0};
    std::uint64_t last_received_ping_id_{0};
    bool last_sent_ping_valid_{false};
    bool last_received_ping_valid_{false};
};

#if YUME_ENABLE_DEV_DIAGNOSTICS
std::string FormatH2CarrierStats(const H2CarrierStats& stats) {
    return
        "h2_feed_calls=" + std::to_string(stats.h2_feed_calls) +
        " h2_feed_bytes=" + std::to_string(stats.h2_feed_bytes) +
        " h2_feed_us=" + std::to_string(stats.h2_feed_ns / 1000U) +
        " h2_flush_calls=" + std::to_string(stats.h2_flush_calls) +
        " h2_flush_bytes=" + std::to_string(stats.h2_flush_bytes) +
        " h2_flush_us=" + std::to_string(stats.h2_flush_ns / 1000U) +
        " websocket_encode_bytes=" +
            std::to_string(stats.websocket_encode_bytes) +
        " websocket_encode_us=" +
            std::to_string(stats.websocket_encode_ns / 1000U) +
        " websocket_decode_bytes=" +
            std::to_string(stats.websocket_decode_bytes) +
        " websocket_decode_us=" +
            std::to_string(stats.websocket_decode_ns / 1000U) +
        " carrier_credit_calls=" +
            std::to_string(stats.carrier_credit_consume_calls) +
        " carrier_credit_bytes=" +
            std::to_string(stats.carrier_credit_consume_bytes) +
        " carrier_ledger_high_water=" +
            std::to_string(stats.max_received_unconsumed_carrier_bytes) +
        " tunnel_credit_high_water=" +
            std::to_string(stats.max_unconsumed_tunnel_bytes) +
        " wu_tx_conn_frames=" +
            std::to_string(stats.window_update_sent_connection_frames) +
        " wu_tx_conn_bytes=" + std::to_string(
            stats.window_update_sent_connection_increment_bytes) +
        " wu_tx_stream_frames=" +
            std::to_string(stats.window_update_sent_carrier_frames) +
        " wu_tx_stream_bytes=" + std::to_string(
            stats.window_update_sent_carrier_increment_bytes) +
        " wu_rx_conn_frames=" +
            std::to_string(stats.window_update_received_connection_frames) +
        " wu_rx_conn_bytes=" + std::to_string(
            stats.window_update_received_connection_increment_bytes) +
        " wu_rx_stream_frames=" +
            std::to_string(stats.window_update_received_carrier_frames) +
        " wu_rx_stream_bytes=" + std::to_string(
            stats.window_update_received_carrier_increment_bytes) +
        " window_samples=" + std::to_string(stats.flow_window_samples) +
        " min_local_conn_window=" +
            std::to_string(stats.min_local_connection_window) +
        " min_local_stream_window=" +
            std::to_string(stats.min_local_carrier_window) +
        " min_remote_conn_window=" +
            std::to_string(stats.min_remote_connection_window) +
        " min_remote_stream_window=" +
            std::to_string(stats.min_remote_carrier_window) +
        " max_effective_conn_received=" +
            std::to_string(stats.max_effective_connection_received) +
        " max_effective_stream_received=" +
            std::to_string(stats.max_effective_carrier_received) +
        " remote_window_stalls=" +
            std::to_string(stats.remote_window_stall_count) +
        " remote_window_stall_us=" +
            std::to_string(stats.remote_window_stall_ns / 1000U);
}
#endif

H2Carrier::H2Carrier(
    H2CarrierRole role, std::shared_ptr<OuterCarrierTrace> outer_trace)
    : impl_(std::make_unique<Impl>(role, std::move(outer_trace))) {}
H2Carrier::H2Carrier(H2Carrier&&) noexcept = default;
H2Carrier& H2Carrier::operator=(H2Carrier&&) noexcept = default;
H2Carrier::~H2Carrier() = default;
#if YUME_ENABLE_DEV_DIAGNOSTICS
void H2Carrier::set_timing_enabled(bool enabled) noexcept {
    impl_->set_timing_enabled(enabled);
}
#endif

bool H2Carrier::StartClient(std::string authority) {
    return impl_->StartClient(std::move(authority));
}
bool H2Carrier::SubmitExtendedConnect(std::string path,
                                      const H2Headers& additional_headers) {
    return impl_->SubmitExtendedConnect(std::move(path), additional_headers);
}
std::vector<H2Request> H2Carrier::TakeRequests() { return impl_->TakeRequests(); }
std::vector<H2StreamClose> H2Carrier::TakeStreamCloses() {
    return impl_->TakeStreamCloses();
}
bool H2Carrier::RefuseStream(std::int32_t stream_id) {
    return impl_->RefuseStream(stream_id);
}
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
bool H2Carrier::ConsumeTunnelBytes(std::size_t size) {
    return impl_->ConsumeTunnelBytes(size);
}
std::size_t H2Carrier::unconsumed_tunnel_bytes() const noexcept {
    return impl_->unconsumed_tunnel_bytes();
}
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
void H2Carrier::RecordCloseWireResult(bool completed) noexcept {
    impl_->RecordCloseWireResult(completed);
}
bool H2Carrier::capture_observer_active() const noexcept {
    return impl_->capture_observer_active();
}
bool H2Carrier::failed() const noexcept { return impl_->failed(); }
const std::string& H2Carrier::error() const noexcept { return impl_->error(); }

}  // namespace yume::obfs
