/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "core/diagnostics/timing.hpp"
#include "core/stealth/cover_profile.hpp"
#include "core/stealth/outer_carrier_observer.hpp"

namespace yume::obfs {

using H2Bytes = std::vector<std::uint8_t>;
using H2Headers = cover_profile::Headers;

enum class H2CarrierRole {
    Client,
    Server,
};

// Receive credit advertised in either direction after the caller admits the
// carrier. This layer does not authenticate YUME sessions: callers must apply
// their own secure-channel and carrier-path checks before enabling the window.
// Providers that retain a complete private record before returning credit
// must keep their maximum framed record within this window.
inline constexpr std::size_t kAdmittedH2ReceiveWindowBytes =
    8U * 1024U * 1024U;

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
    explicit H2Carrier(
        H2CarrierRole role,
        std::shared_ptr<OuterCarrierTrace> outer_trace = {});
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
    // The caller either proxies one to Node with RespondHttp(), or validates an
    // extended CONNECT and calls AcceptCarrier()/RejectCarrier().
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
    // Both roles. Expands an admitted carrier's receive credit so a maximum
    // record does not require multiple reverse WINDOW_UPDATE turns. This is
    // not an authentication operation; the caller owns admission policy. The
    // window remains bounded and H2 flow control remains enabled.
    bool EnableAdmittedReceiveWindow();
    bool RejectCarrier(std::int32_t stream_id,
                       unsigned status,
                       const H2Headers& headers,
                       H2Bytes body);

    void Feed(const std::uint8_t* data, std::size_t size);
    void Feed(const H2Bytes& data) { Feed(data.data(), data.size()); }
    H2Bytes TakeOutbound();

    bool SendBinary(const std::uint8_t* data, std::size_t size);
    bool SendBinary(const H2Bytes& data) { return SendBinary(data.data(), data.size()); }
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

    void GracefulClose(std::uint16_t websocket_code = 1000);
    void RecordCloseWireResult(bool completed) noexcept;
    bool capture_observer_active() const noexcept;

    bool failed() const noexcept;
    const std::string& error() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::obfs
