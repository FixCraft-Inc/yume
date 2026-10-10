/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "common/timing.hpp"
#include "stealth/cover_profile.hpp"
#include "stealth/outer_carrier_observer.hpp"

namespace yume::obfs {

using H2Bytes = std::vector<std::uint8_t>;
using H2Headers = cover_profile::Headers;

enum class H2CarrierRole {
    Client,
    Server,
};

// Receive credit advertised in either direction after the caller admits the
// carrier, from kAdmittedH2ReceiveWindowBytes through
// kMaxAdmittedH2ReceiveWindowBytes. This layer does not authenticate YUME
// sessions: callers must apply their own secure-channel and carrier-path
// checks before enabling the window. Providers that retain a complete private
// record before returning credit must keep their maximum framed record within
// the window they choose.
inline constexpr std::size_t kAdmittedH2ReceiveWindowBytes =
    8U * 1024U * 1024U;
inline constexpr std::size_t kMaxAdmittedH2ReceiveWindowBytes =
    128U * 1024U * 1024U;

// Chrome sends one PING before it writes to a session that has read nothing
// for longer than this, and sends no second one until the first is answered
// and this long has passed (Chromium's SpdySession "connection at risk of
// loss" and hung intervals, both 10 seconds). The chrome151-node24-v1 capture
// shows it once: after 42 idle seconds, immediately before the WebSocket
// CLOSE.
inline constexpr std::chrono::seconds kH2PrefacePingIdle{10};

// Monotonic time for idle decisions. Null selects std::chrono::steady_clock.
using H2CarrierClock = std::chrono::steady_clock::time_point (*)() noexcept;

struct H2Request {
    std::int32_t stream_id{-1};
    std::string method;
    std::string path;
    std::string authority;
    std::string protocol;
    H2Headers headers;
};

struct H2StreamClose {
    std::int32_t stream_id{-1};
    std::uint32_t error_code{0};
};

#if YUME_ENABLE_DEV_DIAGNOSTICS
struct H2CarrierStats {
    std::uint64_t h2_feed_calls{0};
    std::uint64_t h2_feed_bytes{0};
    std::uint64_t h2_feed_ns{0};
    std::uint64_t h2_flush_calls{0};
    std::uint64_t h2_flush_bytes{0};
    std::uint64_t h2_flush_ns{0};
    std::uint64_t websocket_encode_bytes{0};
    std::uint64_t websocket_encode_ns{0};
    std::uint64_t websocket_decode_bytes{0};
    std::uint64_t websocket_decode_ns{0};
    std::uint64_t carrier_credit_consume_calls{0};
    std::uint64_t carrier_credit_consume_bytes{0};
    std::uint64_t max_received_unconsumed_carrier_bytes{0};
    std::uint64_t max_unconsumed_tunnel_bytes{0};
    std::uint64_t window_update_sent_connection_frames{0};
    std::uint64_t window_update_sent_connection_increment_bytes{0};
    std::uint64_t window_update_sent_carrier_frames{0};
    std::uint64_t window_update_sent_carrier_increment_bytes{0};
    std::uint64_t window_update_received_connection_frames{0};
    std::uint64_t window_update_received_connection_increment_bytes{0};
    std::uint64_t window_update_received_carrier_frames{0};
    std::uint64_t window_update_received_carrier_increment_bytes{0};
    std::uint64_t flow_window_samples{0};
    std::int32_t min_local_connection_window{0};
    std::int32_t min_local_carrier_window{0};
    std::int32_t min_remote_connection_window{0};
    std::int32_t min_remote_carrier_window{0};
    std::int32_t max_effective_connection_received{0};
    std::int32_t max_effective_carrier_received{0};
    std::uint64_t remote_window_stall_count{0};
    std::uint64_t remote_window_stall_ns{0};
};

std::string FormatH2CarrierStats(const H2CarrierStats& stats);
#endif

// A complete in-memory HTTP/2 endpoint around libnghttp2. Socket ownership and
// async scheduling remain with the client/server session. Feed() consumes TLS
// plaintext; TakeOutbound() returns serialized H2 bytes for the single
// strand-serialized TLS write queue. The carrier stream is WebSocket binary
// (RFC 8441), never raw YUME bytes.
class H2Carrier {
public:
    explicit H2Carrier(H2CarrierRole role,
                       std::shared_ptr<OuterCarrierTrace> outer_trace = {},
                       H2CarrierClock clock = nullptr);
    H2Carrier(const H2Carrier&) = delete;
    H2Carrier& operator=(const H2Carrier&) = delete;
    H2Carrier(H2Carrier&&) noexcept;
    H2Carrier& operator=(H2Carrier&&) noexcept;
    ~H2Carrier();

#if YUME_ENABLE_DEV_DIAGNOSTICS
    void set_timing_enabled(bool enabled) noexcept;
#endif

    // Client only. Submits the Chrome-profiled SETTINGS and priming GET. The
    // extended CONNECT cannot be submitted until priming_complete() is true.
    bool StartClient(std::string authority);
    bool SubmitExtendedConnect(std::string path,
                               const H2Headers& additional_headers = {});

    // Server only. Ordinary GET/HEAD requests are returned by TakeRequests().
    // The caller answers each with RespondHttp(), or validates an extended
    // CONNECT and calls AcceptCarrier(). A CONNECT that fails validation gets
    // the same cover answer as any other request, so the carrier has no
    // separate refusal response.
    std::vector<H2Request> TakeRequests();
    // Server only. Reports peer resets and ordinary stream completion so an
    // asynchronous cover backend can cancel/release its matching work.
    std::vector<H2StreamClose> TakeStreamCloses();
    // Server only. Retryable overload response which does not retain an HTTP
    // response body. Normal traffic never takes this path.
    bool RefuseStream(std::int32_t stream_id);
    bool RespondHttp(std::int32_t stream_id,
                     unsigned status,
                     const H2Headers& headers,
                     H2Bytes body,
                     bool head_request = false);
    bool AcceptCarrier(std::int32_t stream_id,
                       const H2Headers& response_headers = {});
    // Both roles. Expands an admitted carrier's connection and stream receive
    // windows to `window_bytes` so a maximum record does not require multiple
    // reverse WINDOW_UPDATE turns. This is not an authentication operation;
    // the caller owns admission policy. The window remains bounded and H2 flow
    // control remains enabled. A repeated call with the same size does
    // nothing, and a different size fails the carrier.
    bool EnableAdmittedReceiveWindow(std::size_t window_bytes);

    void Feed(const std::uint8_t* data, std::size_t size);
    void Feed(const H2Bytes& data) { Feed(data.data(), data.size()); }
    H2Bytes TakeOutbound();
    // The same bytes as TakeOutbound(), cut where the profiled browser starts
    // a new socket write. Chrome writes its preface PING alone, so a caller
    // that sends each part as its own write gives it a TLS record of its own.
    std::vector<H2Bytes> TakeOutboundWrites();
    // The same writes without handing over the buffer that holds them.
    // PendingOutboundBytes() serializes what is queued and returns its size.
    // DrainOutboundWrites() then passes exactly those bytes to `sink`, one
    // call per write in order, empties the output and keeps its capacity up
    // to a bound, so a busy carrier does not allocate it again for every
    // burst. It stops at the first write `sink` refuses and returns false,
    // with the output emptied all the same.
    using OutboundWriteSink =
        bool (*)(void* context, std::span<const std::uint8_t> write) noexcept;
    std::size_t PendingOutboundBytes();
    bool DrainOutboundWrites(OutboundWriteSink sink, void* context);

    bool SendBinary(const std::uint8_t* data, std::size_t size) {
        return SendBinary(std::span<const std::uint8_t>(data, size), {});
    }
    bool SendBinary(const H2Bytes& data) { return SendBinary(data.data(), data.size()); }
    // Sends `head` followed by `body` as one byte stream, such as an envelope
    // header and its record, without joining them first.
    bool SendBinary(std::span<const std::uint8_t> head,
                    std::span<const std::uint8_t> body);
    // Both roles. TakeTunnelBytes() transfers ownership of the matching H2
    // receive credit to the caller. Return that credit after the bytes have
    // drained into the downstream sink. Over-consumption fails closed; credit
    // returned after the carrier stream closes still retires connection-level
    // flow control safely. Non-carrier cover DATA is consumed immediately and
    // never enters this ledger.
    H2Bytes TakeTunnelBytes();
    bool ConsumeTunnelBytes(std::size_t size);
    std::size_t unconsumed_tunnel_bytes() const noexcept;

    bool priming_complete() const noexcept;
    bool peer_extended_connect_enabled() const noexcept;
    H2CarrierRole role() const noexcept;
    bool carrier_active() const noexcept;
    bool carrier_closed() const noexcept;
    std::int32_t carrier_stream_id() const noexcept;
    std::size_t queued_output_bytes() const noexcept;
#if YUME_ENABLE_DEV_DIAGNOSTICS
    H2CarrierStats stats() const noexcept;
#endif

    // Client only. Queues the captured browser's close: the preface PING when
    // the session has been idle (see kH2PrefacePingIdle), then a masked
    // WebSocket CLOSE of the profile's payload length. No GOAWAY follows: the
    // capture records none, and Chrome sends GOAWAY only when it closes a
    // session on an error. The server's echo ends the carrier stream. Returns
    // false when nothing was queued because the carrier is not open.
    bool GracefulClose(std::uint16_t websocket_code = 1000);
    bool websocket_close_received() const noexcept;

    void RecordCloseWireResult(bool completed) noexcept;

    bool failed() const noexcept;
    const std::string& error() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::obfs
