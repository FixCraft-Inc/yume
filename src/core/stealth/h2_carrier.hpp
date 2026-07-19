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

namespace yume::obfs {

using H2Bytes = std::vector<std::uint8_t>;
using H2Headers = std::vector<std::pair<std::string, std::string>>;

enum class H2CarrierRole {
    Client,
    Server,
};

struct H2Request {
    std::int32_t stream_id{-1};
    std::string method;
    std::string path;
    std::string authority;
    std::string protocol;
    H2Headers headers;
};

// A complete in-memory HTTP/2 endpoint around libnghttp2. Socket ownership and
// async scheduling remain with the client/server session. Feed() consumes TLS
// plaintext; TakeOutbound() returns serialized H2 bytes for the single
// strand-serialized TLS write queue. The carrier stream is WebSocket binary
// (RFC 8441), never raw YUME bytes.
class H2Carrier {
public:
    explicit H2Carrier(H2CarrierRole role);
    H2Carrier(const H2Carrier&) = delete;
    H2Carrier& operator=(const H2Carrier&) = delete;
    H2Carrier(H2Carrier&&) noexcept;
    H2Carrier& operator=(H2Carrier&&) noexcept;
    ~H2Carrier();

    // Client only. Submits the Chrome-profiled SETTINGS and priming GET. The
    // extended CONNECT cannot be submitted until priming_complete() is true.
    bool StartClient(std::string authority, std::string user_agent);
    bool SubmitExtendedConnect(std::string path,
                               const H2Headers& additional_headers = {});

    // Server only. Ordinary GET/HEAD requests are returned by TakeRequests().
    // The caller either proxies one to Node with RespondHttp(), or validates an
    // extended CONNECT and calls AcceptCarrier()/RejectCarrier().
    std::vector<H2Request> TakeRequests();
    bool RespondHttp(std::int32_t stream_id,
                     unsigned status,
                     const H2Headers& headers,
                     H2Bytes body,
                     bool head_request = false);
    bool AcceptCarrier(std::int32_t stream_id,
                       const H2Headers& response_headers = {});
    bool RejectCarrier(std::int32_t stream_id,
                       unsigned status,
                       const H2Headers& headers,
                       H2Bytes body);

    void Feed(const std::uint8_t* data, std::size_t size);
    void Feed(const H2Bytes& data) { Feed(data.data(), data.size()); }
    H2Bytes TakeOutbound();

    bool SendBinary(const std::uint8_t* data, std::size_t size);
    bool SendBinary(const H2Bytes& data) { return SendBinary(data.data(), data.size()); }
    H2Bytes TakeTunnelBytes();

    bool priming_complete() const noexcept;
    bool peer_extended_connect_enabled() const noexcept;
    bool carrier_active() const noexcept;
    bool carrier_closed() const noexcept;
    std::int32_t carrier_stream_id() const noexcept;
    std::size_t queued_output_bytes() const noexcept;

    void GracefulClose(std::uint16_t websocket_code = 1000);

    bool failed() const noexcept;
    const std::string& error() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::obfs
