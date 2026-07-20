#include "core/stealth/h2_carrier.hpp"

#include <algorithm>
#include <cassert>
#include <iostream>

namespace {

using yume::obfs::H2Bytes;
using yume::obfs::H2Carrier;
using yume::obfs::H2CarrierRole;
using yume::obfs::H2Headers;

void Pump(H2Carrier& from, H2Carrier& to) {
    for (int i = 0; i < 16; ++i) {
        auto bytes = from.TakeOutbound();
        if (bytes.empty()) return;
        to.Feed(bytes);
        if (to.failed()) std::cerr << to.error() << '\n';
        assert(!to.failed());
    }
    assert(false && "HTTP/2 pump did not quiesce");
}

H2Bytes PumpFragmentedAndTake(H2Carrier& from, H2Carrier& to,
                              std::size_t feed_bytes) {
    H2Bytes decoded;
    for (int round = 0; round < 64; ++round) {
        auto wire = from.TakeOutbound();
        if (wire.empty()) return decoded;
        for (std::size_t offset = 0; offset < wire.size();) {
            const auto size = std::min(feed_bytes, wire.size() - offset);
            to.Feed(wire.data() + offset, size);
            assert(!to.failed());
            auto part = to.TakeTunnelBytes();
            decoded.insert(decoded.end(), part.begin(), part.end());
            offset += size;
        }
    }
    assert(false && "fragmented HTTP/2 pump did not quiesce");
    return {};
}

void CompleteChromeAssets(H2Carrier& client, H2Carrier& server) {
    Pump(client, server);
    auto requests = server.TakeRequests();
    assert(requests.size() == 2);
    assert(requests[0].method == "GET" &&
           requests[0].path == "/assets/site.css");
    assert(requests[1].method == "GET" &&
           requests[1].path == "/assets/site.js");
    assert(server.RespondHttp(requests[0].stream_id, 200,
                              {{"content-type", "text/css"}},
                              H2Bytes{'c', 's', 's'}));
    assert(server.RespondHttp(requests[1].stream_id, 200,
                              {{"content-type", "text/javascript"}},
                              H2Bytes{'j', 's'}));
    Pump(server, client);
    Pump(client, server);
    assert(client.priming_complete());
}

void FullSessionRoundTrip() {
    H2Carrier client(H2CarrierRole::Client);
    H2Carrier server(H2CarrierRole::Server);
    assert(client.StartClient("cover.example", {}));
    Pump(client, server);
    Pump(server, client);

    auto requests = server.TakeRequests();
    assert(requests.size() == 1);
    assert(requests[0].method == "GET" && requests[0].path == "/");
    const H2Headers expected_priming{
        {":method", "GET"}, {":authority", "cover.example"},
        {":scheme", "https"}, {":path", "/"},
        {"sec-ch-ua", "\"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"150\", \"Google Chrome\";v=\"150\""},
        {"sec-ch-ua-mobile", "?0"}, {"sec-ch-ua-platform", "\"Linux\""},
        {"upgrade-insecure-requests", "1"},
        {"user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"},
        {"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
        {"sec-fetch-site", "none"}, {"sec-fetch-mode", "navigate"},
        {"sec-fetch-user", "?1"}, {"sec-fetch-dest", "document"},
        {"accept-encoding", "gzip, deflate, br, zstd"},
        {"accept-language", "en-US,en;q=0.9"}, {"priority", "u=0, i"}};
    assert(requests[0].headers == expected_priming);
    assert(server.RespondHttp(requests[0].stream_id, 200,
                              {{"content-type", "text/html"}},
                              H2Bytes{'o', 'k'}));
    Pump(server, client);
    CompleteChromeAssets(client, server);
    assert(client.peer_extended_connect_enabled());

    assert(client.SubmitExtendedConnect("/.well-known/example"));
    Pump(client, server);
    requests = server.TakeRequests();
    assert(requests.size() == 1);
    assert(requests[0].method == "CONNECT");
    assert(requests[0].stream_id == 7);
    assert(requests[0].protocol == "websocket");
    const H2Headers expected_connect{
        {":method", "CONNECT"}, {":authority", "cover.example"},
        {":scheme", "https"}, {":path", "/.well-known/example"},
        {":protocol", "websocket"}, {"pragma", "no-cache"},
        {"cache-control", "no-cache"},
        {"user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"},
        {"origin", "https://cover.example"},
        {"sec-websocket-version", "13"},
        {"accept-encoding", "gzip, deflate, br, zstd"},
        {"accept-language", "en-US,en;q=0.9"},
        {"sec-websocket-extensions", "permessage-deflate; client_max_window_bits"}};
    assert(requests[0].headers == expected_connect);
    assert(server.AcceptCarrier(requests[0].stream_id));
    // Production enables this only after YUME authentication. A full 256-KiB
    // ratchet epoch must then cross in one direction without waiting for
    // reverse WINDOW_UPDATE traffic between partial sends.
    assert(server.EnableAuthenticatedReceiveWindow());
    assert(server.EnableAuthenticatedReceiveWindow());
    Pump(server, client);
    Pump(client, server);
    assert(client.carrier_active() && server.carrier_active());

    // More than two capture-sized messages proves SendBinary shapes a byte
    // stream into 16-KiB WebSocket messages without losing frame boundaries.
    H2Bytes up(256U * 1024U);
    for (std::size_t i = 0; i < up.size(); ++i) {
        // Every 16-KiB WebSocket message gets a distinct prefix. A uniform
        // payload cannot detect a carrier that accidentally repeats its first
        // message while advancing flow-control state.
        up[i] = static_cast<std::uint8_t>(
            ((i / (16U * 1024U)) * 17U + (i % 251U)) & 0xffU);
    }
    assert(client.SendBinary(up));
    Pump(client, server);
    assert(server.TakeTunnelBytes() == up);

    H2Bytes fragmented_up(200329U);
    for (std::size_t i = 0; i < fragmented_up.size(); ++i) {
        fragmented_up[i] = static_cast<std::uint8_t>(
            ((i / (64U * 1024U)) * 73U + (i % 251U)) & 0xffU);
    }
    assert(client.SendBinary(fragmented_up));
    assert(PumpFragmentedAndTake(client, server, 16381U) == fragmented_up);

    // The server's first full-size message uses the captured 8-KiB + 8-KiB
    // fragmentation, transparently reassembled by the client codec.
    const H2Bytes down(40000, 0x72);
    assert(server.SendBinary(down));
    Pump(server, client);
    assert(client.TakeTunnelBytes() == down);

    // The captured Chrome role originates one H2 PING immediately before its
    // masked WebSocket close. nghttp2 makes the Node/server role ACK it while
    // the WebSocket codec returns the unmasked close response.
    client.GracefulClose();
    Pump(client, server);
    Pump(server, client);
    assert(client.carrier_closed());
    assert(server.carrier_closed());
}

void RejectCarrierLooksHttp() {
    H2Carrier client(H2CarrierRole::Client);
    H2Carrier server(H2CarrierRole::Server);
    assert(client.StartClient("cover.example", {}));
    Pump(client, server);
    Pump(server, client);
    auto requests = server.TakeRequests();
    assert(server.RespondHttp(requests[0].stream_id, 200,
                              {{"content-type", "text/html"}}, {}));
    Pump(server, client);
    CompleteChromeAssets(client, server);
    assert(client.SubmitExtendedConnect("/wrong"));
    Pump(client, server);
    requests = server.TakeRequests();
    assert(server.RejectCarrier(requests[0].stream_id, 404,
                                 {{"content-type", "text/plain"}},
                                 H2Bytes{'N', 'o', 't', ' ', 'F', 'o', 'u', 'n', 'd'}));
    Pump(server, client);
    assert(!client.carrier_active());
}

}  // namespace

int main() {
    FullSessionRoundTrip();
    RejectCarrierLooksHttp();
    return 0;
}
