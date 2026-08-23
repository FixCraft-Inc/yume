#include "core/stealth/h2_carrier.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#include <nghttp2/nghttp2.h>

#include "core/stealth/cover_profile.hpp"

namespace {

using yume::obfs::H2Bytes;
using yume::obfs::H2Carrier;
using yume::obfs::H2CarrierRole;
using yume::obfs::H2Headers;
using yume::obfs::OuterCarrierDirection;
using yume::obfs::OuterCarrierEvent;
using yume::obfs::OuterCarrierEventKind;
using yume::obfs::OuterCarrierStreamClass;

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

H2Bytes RstStream(std::uint32_t stream_id, std::uint32_t error_code) {
    return H2Bytes{
        0x00, 0x00, 0x04,  // payload length
        0x03, 0x00,        // RST_STREAM, no flags
        static_cast<std::uint8_t>((stream_id >> 24U) & 0x7fU),
        static_cast<std::uint8_t>((stream_id >> 16U) & 0xffU),
        static_cast<std::uint8_t>((stream_id >> 8U) & 0xffU),
        static_cast<std::uint8_t>(stream_id & 0xffU),
        static_cast<std::uint8_t>((error_code >> 24U) & 0xffU),
        static_cast<std::uint8_t>((error_code >> 16U) & 0xffU),
        static_cast<std::uint8_t>((error_code >> 8U) & 0xffU),
        static_cast<std::uint8_t>(error_code & 0xffU)};
}

struct WindowUpdateSummary {
    bool connection{false};
    bool carrier_stream{false};
};

WindowUpdateSummary InspectWindowUpdates(const H2Bytes& wire,
                                         std::uint32_t carrier_stream_id) {
    WindowUpdateSummary summary;
    for (std::size_t offset = 0; offset < wire.size();) {
        assert(wire.size() - offset >= 9);
        const std::size_t length =
            (static_cast<std::size_t>(wire[offset]) << 16U) |
            (static_cast<std::size_t>(wire[offset + 1]) << 8U) |
            static_cast<std::size_t>(wire[offset + 2]);
        assert(length + 9 <= wire.size() - offset);
        const auto type = wire[offset + 3];
        const auto id =
            (static_cast<std::uint32_t>(wire[offset + 5] & 0x7fU) << 24U) |
            (static_cast<std::uint32_t>(wire[offset + 6]) << 16U) |
            (static_cast<std::uint32_t>(wire[offset + 7]) << 8U) |
            static_cast<std::uint32_t>(wire[offset + 8]);
        if (type == 0x08) {
            summary.connection |= id == 0;
            summary.carrier_stream |= id == carrier_stream_id;
        }
        offset += 9 + length;
    }
    return summary;
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
            assert(to.ConsumeTunnelBytes(part.size()));
            offset += size;
        }
    }
    assert(false && "fragmented HTTP/2 pump did not quiesce");
    return {};
}

void CompleteChromeAssets(H2Carrier& client, H2Carrier& server) {
    const auto& profile =
        yume::cover_profile::active();
    Pump(client, server);
    auto requests = server.TakeRequests();
    assert(requests.size() == profile.assets.size());
    assert(requests[0].method == "GET" &&
           requests[0].path == profile.assets[0].path);
    assert(requests[1].method == "GET" &&
           requests[1].path == profile.assets[1].path);
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

void OpenCarrier(H2Carrier& client, H2Carrier& server) {
    assert(client.StartClient("cover.example"));
    Pump(client, server);
    Pump(server, client);

    auto requests = server.TakeRequests();
    assert(requests.size() == 1);
    assert(server.RespondHttp(requests[0].stream_id, 200,
                              {{"content-type", "text/html"}}, {}));
    Pump(server, client);
    CompleteChromeAssets(client, server);

    assert(client.SubmitExtendedConnect("/carrier"));
    Pump(client, server);
    requests = server.TakeRequests();
    assert(requests.size() == 1);
    assert(server.AcceptCarrier(requests[0].stream_id));
    Pump(server, client);
    Pump(client, server);
    assert(client.carrier_active() && server.carrier_active());
}

void FullSessionRoundTrip() {
    const auto& profile =
        yume::cover_profile::active();
    const std::string secret_authority = "trace-secret.cover.example";
    const std::string secret_path = "/trace-secret-carrier-path";
    const std::string secret_header = "trace-secret-authorization";
    const std::string secret_origin = "https://trace-secret.invalid";
    auto trace = std::make_shared<yume::obfs::OuterCarrierTrace>();
    H2Carrier client(H2CarrierRole::Client, trace);
    H2Carrier server(H2CarrierRole::Server);
    assert(client.StartClient(secret_authority));
    Pump(client, server);
    Pump(server, client);

    auto requests = server.TakeRequests();
    assert(requests.size() == 1);
    assert(requests[0].method == "GET" && requests[0].path == "/");
    const H2Headers expected_priming =
        profile.render_headers(profile.priming_request, secret_authority);
    assert(requests[0].headers == expected_priming);
    assert(server.RespondHttp(requests[0].stream_id, 200,
                              {{"content-type", "text/html"}},
                              H2Bytes{'o', 'k'}));
    Pump(server, client);
    CompleteChromeAssets(client, server);
    assert(client.peer_extended_connect_enabled());

    assert(client.SubmitExtendedConnect(
        secret_path, {{"authorization", secret_header},
                      {"origin", secret_origin}}));
    Pump(client, server);
    requests = server.TakeRequests();
    assert(requests.size() == 1);
    assert(requests[0].method == "CONNECT");
    assert(requests[0].stream_id == 7);
    assert(requests[0].protocol == "websocket");
    const H2Headers expected_connect = profile.render_headers(
        profile.extended_connect, secret_authority, secret_path);
    H2Headers expected_connect_with_auth = expected_connect;
    expected_connect_with_auth.push_back({"authorization", secret_header});
    expected_connect_with_auth.push_back({"origin", secret_origin});
    assert(requests[0].headers == expected_connect_with_auth);
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
            ((i / profile.websocket_message_bytes) * 17U + (i % 251U)) &
            0xffU);
    }
    assert(client.SendBinary(up));
    Pump(client, server);
    auto received_up = server.TakeTunnelBytes();
    assert(received_up == up);
    assert(server.ConsumeTunnelBytes(received_up.size()));

    H2Bytes fragmented_up(200329U);
    for (std::size_t i = 0; i < fragmented_up.size(); ++i) {
        fragmented_up[i] = static_cast<std::uint8_t>(
            ((i / (64U * 1024U)) * 73U + (i % 251U)) & 0xffU);
    }
    assert(client.SendBinary(fragmented_up));
    assert(PumpFragmentedAndTake(client, server, 16381U) == fragmented_up);

    // The server's first full-size message uses the captured 8-KiB + 8-KiB
    // fragmentation, transparently reassembled by the client codec.
    H2Bytes down(40000, 0x72);
    const H2Bytes control_like(1662, 0x39);
    down.insert(down.end(), control_like.begin(), control_like.end());
    assert(server.SendBinary(down.data(), 40000));
    // The server transport deliberately queues the following ratchet control
    // record before taking H2 output. Preserve both SendBinary calls across a
    // single drain so the control record is not stranded behind another TLS
    // write.
    assert(server.SendBinary(control_like));
    Pump(server, client);
    const auto received_down = client.TakeTunnelBytes();
    assert(received_down == down);
    assert(client.unconsumed_tunnel_bytes() == received_down.size());
    assert(client.ConsumeTunnelBytes(received_down.size()));

    // The captured Chrome role originates one H2 PING immediately before its
    // masked WebSocket close. nghttp2 makes the Node/server role ACK it while
    // the WebSocket codec returns the unmasked close response.
    client.GracefulClose();
    Pump(client, server);
    Pump(server, client);
    client.RecordCloseWireResult(true);
    assert(client.carrier_closed());
    assert(server.carrier_closed());

    bool saw_client_settings = false;
    bool saw_server_settings = false;
    bool saw_connection_window = false;
    bool saw_connect_headers = false;
    bool saw_unexpected_origin = false;
    bool saw_redacted_authorization = false;
    bool saw_sent_binary = false;
    bool saw_received_binary = false;
    bool saw_sent_ping = false;
    bool saw_received_ping_ack = false;
    bool saw_sent_goaway = false;
    bool saw_sent_close = false;
    bool saw_close_wire = false;
    std::uint64_t sent_ping_id = 0;
    std::uint64_t received_ping_id = 0;
    const auto snapshot = trace->Snapshot();
    const std::size_t no_event = snapshot.events.size();
    std::size_t sent_ping_index = no_event;
    std::size_t sent_carrier_data_after_ping_index = no_event;
    std::size_t sent_close_index = no_event;
    std::size_t sent_goaway_index = no_event;
    for (std::size_t event_index = 0;
         event_index < snapshot.events.size(); ++event_index) {
        const auto& event = snapshot.events[event_index];
        if (event.kind == OuterCarrierEventKind::H2Frame) {
            if (event.h2_type == 0x04 &&
                (event.flags & 0x01U) == 0) {
                saw_client_settings |=
                    event.direction == OuterCarrierDirection::Sent;
                saw_server_settings |=
                    event.direction == OuterCarrierDirection::Received;
            }
            saw_connection_window |=
                event.direction == OuterCarrierDirection::Sent &&
                event.stream_class == OuterCarrierStreamClass::Connection &&
                event.h2_stream_id == 0 && event.h2_type == 0x08;
            saw_sent_ping |=
                event.direction == OuterCarrierDirection::Sent &&
                event.h2_type == 0x06 && (event.flags & 0x01U) == 0;
            saw_received_ping_ack |=
                event.direction == OuterCarrierDirection::Received &&
                event.h2_type == 0x06 && (event.flags & 0x01U) != 0;
            if (event.direction == OuterCarrierDirection::Sent &&
                event.h2_type == 0x06 && (event.flags & 0x01U) == 0) {
                sent_ping_id = event.ping_id;
                sent_ping_index = event_index;
            }
            if (event.direction == OuterCarrierDirection::Received &&
                event.h2_type == 0x06 && (event.flags & 0x01U) != 0) {
                received_ping_id = event.ping_id;
            }
            saw_sent_goaway |=
                event.direction == OuterCarrierDirection::Sent &&
                event.h2_type == 0x07;
            if (event.direction == OuterCarrierDirection::Sent &&
                event.h2_type == 0x07) {
                sent_goaway_index = event_index;
            }
            if (sent_ping_index != no_event &&
                sent_carrier_data_after_ping_index == no_event &&
                event.direction == OuterCarrierDirection::Sent &&
                event.stream_class == OuterCarrierStreamClass::Carrier &&
                event.h2_type == 0x00) {
                sent_carrier_data_after_ping_index = event_index;
            }
            if (event.stream_class == OuterCarrierStreamClass::Carrier &&
                event.direction == OuterCarrierDirection::Sent &&
                !event.headers.empty()) {
                saw_connect_headers = true;
                assert(event.h2_stream_id == 7);
            }
            for (const auto& header : event.headers) {
                saw_unexpected_origin |=
                    header.value == "<unexpected-origin>";
                saw_redacted_authorization |=
                    header.name == "<sensitive-header>" &&
                    header.value == "<redacted>";
                assert(header.name.find("trace-secret") == std::string::npos);
                assert(header.value.find("trace-secret") == std::string::npos);
            }
        } else if (event.kind == OuterCarrierEventKind::WebSocketFrame) {
            saw_sent_binary |=
                event.direction == OuterCarrierDirection::Sent &&
                event.websocket_opcode == 0x2;
            saw_received_binary |=
                event.direction == OuterCarrierDirection::Received &&
                (event.websocket_opcode == 0x2 ||
                 event.websocket_opcode == 0x0);
            if (event.direction == OuterCarrierDirection::Sent &&
                event.websocket_opcode == 0x8) {
                saw_sent_close = true;
                sent_close_index = event_index;
                assert(event.h2_ping_immediately_before);
                assert(event.websocket_payload_bytes == 2);
            }
        } else if (event.kind == OuterCarrierEventKind::CloseWire) {
            saw_close_wire |= event.completed;
        }
    }
    assert(!trace->truncated());
    assert(saw_client_settings && saw_server_settings);
    assert(saw_connection_window && saw_connect_headers &&
           saw_unexpected_origin && saw_redacted_authorization);
    assert(saw_sent_binary && saw_received_binary);
    assert(saw_sent_ping && saw_received_ping_ack && saw_sent_goaway);
    assert(sent_ping_id != 0 && received_ping_id == sent_ping_id);
    assert(saw_sent_close && saw_close_wire);
    assert(sent_ping_index < sent_carrier_data_after_ping_index);
    assert(sent_carrier_data_after_ping_index < sent_close_index);
    assert(sent_close_index < sent_goaway_index);
}

void InboundContinuationIsObservedWithoutPayloadRetention() {
    auto trace = std::make_shared<yume::obfs::OuterCarrierTrace>();
    H2Carrier client(H2CarrierRole::Client, trace);
    H2Carrier server(H2CarrierRole::Server);
    assert(client.StartClient("cover.example"));
    Pump(client, server);
    Pump(server, client);
    auto requests = server.TakeRequests();
    assert(requests.size() == 1);
    assert(server.RespondHttp(requests[0].stream_id, 200,
                              {{"content-type", "text/html"}}, {}));
    Pump(server, client);
    CompleteChromeAssets(client, server);
    assert(client.SubmitExtendedConnect("/carrier"));
    Pump(client, server);
    requests = server.TakeRequests();
    assert(requests.size() == 1);

    std::string large_response_header;
    large_response_header.reserve(40000);
    for (std::size_t index = 0; index < 40000; ++index) {
        large_response_header.push_back(static_cast<char>(
            0x21 + ((index * 37U + index / 97U) % 0x5eU)));
    }
    assert(server.AcceptCarrier(
        requests[0].stream_id,
        {{"x-observer-continuation-fixture", large_response_header}}));
    Pump(server, client);

    bool saw_raw_headers = false;
    bool saw_continuation = false;
    bool saw_decoded_headers = false;
    for (const auto& event : trace->Snapshot().events) {
        if (event.direction != OuterCarrierDirection::Received ||
            event.stream_class != OuterCarrierStreamClass::Carrier ||
            event.h2_stream_id != 7) {
            continue;
        }
        saw_raw_headers |= event.kind == OuterCarrierEventKind::H2Frame &&
            event.h2_type == 0x01;
        saw_continuation |= event.kind == OuterCarrierEventKind::H2Frame &&
            event.h2_type == 0x09;
        if (event.kind == OuterCarrierEventKind::H2HeadersDecoded) {
            saw_decoded_headers = true;
            for (const auto& header : event.headers) {
                assert(header.name != "x-observer-continuation-fixture");
                assert(header.value.find(large_response_header.substr(0, 16)) ==
                       std::string::npos);
            }
        }
    }
    assert(!trace->truncated());
    assert(saw_raw_headers && saw_continuation && saw_decoded_headers);
}

void ObserverDoesNotChangeOpeningWire() {
    H2Carrier baseline(H2CarrierRole::Client);
    auto trace = std::make_shared<yume::obfs::OuterCarrierTrace>();
    H2Carrier observed(H2CarrierRole::Client, trace);
    assert(baseline.StartClient("cover.example"));
    assert(observed.StartClient("cover.example"));
    assert(baseline.TakeOutbound() == observed.TakeOutbound());
    assert(!trace->Snapshot().events.empty());
    assert(!trace->truncated());
}

void ObserverCapIsFailOpenAndBounded() {
    yume::obfs::OuterCarrierTrace trace;
    for (std::size_t index = 0;
         index <= yume::obfs::OuterCarrierTrace::kMaxEvents; ++index) {
        OuterCarrierEvent event;
        event.kind = OuterCarrierEventKind::FlowWindowStalled;
        trace.Record(std::move(event));
    }
    assert(trace.truncated());
    assert(trace.Snapshot().events.size() ==
           yume::obfs::OuterCarrierTrace::kMaxEvents);
}

void ObserverClockStartsAtFirstCarrierEvent() {
    yume::obfs::OuterCarrierTrace trace;
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    OuterCarrierEvent event;
    event.kind = OuterCarrierEventKind::H2Frame;
    trace.Record(std::move(event));
    const auto snapshot = trace.Snapshot();
    assert(snapshot.events.size() == 1);
    assert(snapshot.events.front().elapsed_us == 0);
}

void RejectCarrierLooksHttp() {
    H2Carrier client(H2CarrierRole::Client);
    H2Carrier server(H2CarrierRole::Server);
    assert(client.StartClient("cover.example"));
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

void ServerResetDropsPendingRequestAndReportsClose() {
    H2Carrier client(H2CarrierRole::Client);
    H2Carrier server(H2CarrierRole::Server);
    assert(client.StartClient("cover.example"));
    Pump(client, server);

    server.Feed(RstStream(1, NGHTTP2_CANCEL));
    assert(!server.failed());
    assert(server.TakeRequests().empty());
    const auto closes = server.TakeStreamCloses();
    assert(closes.size() == 1);
    assert(closes[0].stream_id == 1);
    assert(closes[0].error_code == NGHTTP2_CANCEL);
    assert(server.TakeStreamCloses().empty());
}

void ServerSaturationRefusalIsRetryableAndReleasesState() {
    H2Carrier client(H2CarrierRole::Client);
    H2Carrier server(H2CarrierRole::Server);
    assert(client.StartClient("cover.example"));
    Pump(client, server);
    auto requests = server.TakeRequests();
    assert(requests.size() == 1);
    assert(server.RefuseStream(requests[0].stream_id));
    assert(!server.failed());
    assert(!server.TakeOutbound().empty());
    const auto closes = server.TakeStreamCloses();
    assert(closes.size() == 1);
    assert(closes[0].stream_id == requests[0].stream_id);
    assert(closes[0].error_code == NGHTTP2_REFUSED_STREAM);
}

void ServerManualFlowControlStallsAndResumes() {
    H2Carrier client(H2CarrierRole::Client);
    H2Carrier server(H2CarrierRole::Server);
    OpenCarrier(client, server);

    H2Bytes payload(3U * 65535U);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<std::uint8_t>((i * 29U + i / 257U) & 0xffU);
    }
    assert(client.SendBinary(payload));
    Pump(client, server);

    H2Bytes received = server.TakeTunnelBytes();
    assert(!received.empty());
    assert(received.size() < payload.size());
    assert(client.queued_output_bytes() != 0);
    assert(client.TakeOutbound().empty());
    assert(server.unconsumed_tunnel_bytes() == received.size());

    (void)server.TakeOutbound();
    const std::size_t first_release = received.size() / 2;
    assert(server.ConsumeTunnelBytes(first_release));
    assert(server.unconsumed_tunnel_bytes() ==
           received.size() - first_release);
    assert(server.TakeOutbound().empty());

    assert(server.ConsumeTunnelBytes(received.size() - first_release));
    assert(server.unconsumed_tunnel_bytes() == 0);
    const auto resume_wire = server.TakeOutbound();
    const auto updates = InspectWindowUpdates(
        resume_wire,
        static_cast<std::uint32_t>(server.carrier_stream_id()));
    assert(updates.connection && updates.carrier_stream);
    client.Feed(resume_wire);
    assert(!client.failed());

    for (int round = 0;
         received.size() < payload.size() && round < 16; ++round) {
        Pump(client, server);
        auto part = server.TakeTunnelBytes();
        assert(!part.empty());
        received.insert(received.end(), part.begin(), part.end());
        assert(server.unconsumed_tunnel_bytes() == part.size());
        assert(server.ConsumeTunnelBytes(part.size()));
        Pump(server, client);
    }
    assert(received == payload);
    assert(client.queued_output_bytes() == 0);
    assert(server.unconsumed_tunnel_bytes() == 0);
}

void ClientCoverDataReturnsCreditImmediately() {
    H2Carrier client(H2CarrierRole::Client);
    H2Carrier server(H2CarrierRole::Server);
    assert(client.StartClient("cover.example"));
    Pump(client, server);
    Pump(server, client);

    auto requests = server.TakeRequests();
    assert(requests.size() == 1);
    const auto stream_id = static_cast<std::uint32_t>(requests[0].stream_id);
    assert(server.RespondHttp(
        requests[0].stream_id, 200, {{"content-type", "text/html"}},
        H2Bytes(8U * 1024U * 1024U, 0x63)));

    // The response is larger than Chrome's 6-MiB stream window. With manual
    // receive credit enabled on the client it can only finish if ordinary
    // cover DATA is consumed immediately rather than retained for a sink.
    auto first_wire = server.TakeOutbound();
    assert(!first_wire.empty());
    client.Feed(first_wire);
    assert(!client.failed());
    assert(client.unconsumed_tunnel_bytes() == 0);
    auto updates_wire = client.TakeOutbound();
    const auto updates = InspectWindowUpdates(updates_wire, stream_id);
    assert(updates.carrier_stream);
    server.Feed(updates_wire);
    assert(!server.failed());

    for (int round = 0; round < 8 && !client.priming_complete(); ++round) {
        Pump(server, client);
        Pump(client, server);
        // Stream completion submits the two asset requests; they are the
        // observable proof that the oversized priming response drained.
        if (!server.TakeRequests().empty()) return;
    }
    assert(false && "oversized cover response did not release receive credit");
}

void ClientManualFlowControlStallsAndResumes() {
    H2Carrier client(H2CarrierRole::Client);
    H2Carrier server(H2CarrierRole::Server);
    OpenCarrier(client, server);
    (void)client.TakeOutbound();

    H2Bytes payload(7U * 1024U * 1024U);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<std::uint8_t>((i * 31U + i / 251U) & 0xffU);
    }
    assert(server.SendBinary(payload));
    Pump(server, client);

    H2Bytes received = client.TakeTunnelBytes();
    assert(!received.empty());
    assert(received.size() < payload.size());
    assert(server.queued_output_bytes() != 0);
    assert(server.TakeOutbound().empty());
    assert(client.unconsumed_tunnel_bytes() == received.size());

    (void)client.TakeOutbound();
    const std::size_t first_release = received.size() / 2;
    assert(client.ConsumeTunnelBytes(first_release));
    assert(client.unconsumed_tunnel_bytes() ==
           received.size() - first_release);
    assert(client.TakeOutbound().empty());

    assert(client.ConsumeTunnelBytes(received.size() - first_release));
    assert(client.unconsumed_tunnel_bytes() == 0);
    const auto resume_wire = client.TakeOutbound();
    const auto updates = InspectWindowUpdates(
        resume_wire,
        static_cast<std::uint32_t>(client.carrier_stream_id()));
    assert(updates.carrier_stream);
    server.Feed(resume_wire);
    assert(!server.failed());

    for (int round = 0;
         received.size() < payload.size() && round < 16; ++round) {
        Pump(server, client);
        auto part = client.TakeTunnelBytes();
        assert(!part.empty());
        received.insert(received.end(), part.begin(), part.end());
        assert(client.unconsumed_tunnel_bytes() == part.size());
        assert(client.ConsumeTunnelBytes(part.size()));
        Pump(client, server);
    }
    assert(received == payload);
    assert(server.queued_output_bytes() == 0);
    assert(client.unconsumed_tunnel_bytes() == 0);
}

void ServerOverConsumeFailsClosed() {
    H2Carrier client(H2CarrierRole::Client);
    H2Carrier server(H2CarrierRole::Server);
    OpenCarrier(client, server);

    const H2Bytes payload(31, 0x5a);
    assert(client.SendBinary(payload));
    Pump(client, server);
    auto received = server.TakeTunnelBytes();
    assert(received == payload);
    assert(server.unconsumed_tunnel_bytes() == payload.size());
    assert(!server.ConsumeTunnelBytes(payload.size() + 1));
    assert(server.failed());
    assert(server.unconsumed_tunnel_bytes() == payload.size());
}

void PaddedDataIsRetiredWithoutTunnelCredit() {
    H2Carrier client(H2CarrierRole::Client);
    H2Carrier server(H2CarrierRole::Server);
    OpenCarrier(client, server);
    (void)server.TakeOutbound();

    const auto stream_id =
        static_cast<std::uint32_t>(server.carrier_stream_id());
    H2Bytes padded_frames;
    constexpr std::size_t kFrameCount = 126;
    constexpr std::size_t kDataLength = 262;
    padded_frames.reserve(kFrameCount * (9 + kDataLength));
    for (std::size_t frame = 0; frame < kFrameCount; ++frame) {
        padded_frames.insert(padded_frames.end(), {
            0x00, 0x01, 0x06,  // 262-byte DATA payload
            0x00, 0x08,        // DATA, PADDED
            static_cast<std::uint8_t>((stream_id >> 24) & 0x7fU),
            static_cast<std::uint8_t>((stream_id >> 16) & 0xffU),
            static_cast<std::uint8_t>((stream_id >> 8) & 0xffU),
            static_cast<std::uint8_t>(stream_id & 0xffU),
            0xff,              // 255 trailing padding bytes
            0x82, 0x80,        // masked empty WebSocket binary frame
            0x00, 0x00, 0x00, 0x00});
        padded_frames.insert(padded_frames.end(), 255, 0x00);
    }
    server.Feed(padded_frames);
    assert(!server.failed());
    assert(server.TakeTunnelBytes().empty());
    assert(server.unconsumed_tunnel_bytes() == 0);

    // nghttp2 owns the Pad Length and trailing padding accounting. Together
    // with the six WebSocket framing bytes per empty message, the consumed
    // DATA crosses half the default window and updates both levels.
    const auto updates = InspectWindowUpdates(server.TakeOutbound(), stream_id);
    assert(updates.connection && updates.carrier_stream);
}

void ServerCreditCanRetireAfterStreamClose() {
    H2Carrier client(H2CarrierRole::Client);
    H2Carrier server(H2CarrierRole::Server);
    OpenCarrier(client, server);

    const H2Bytes payload(40000, 0x6b);
    assert(client.SendBinary(payload));
    Pump(client, server);
    auto received = server.TakeTunnelBytes();
    assert(received == payload);
    assert(server.unconsumed_tunnel_bytes() == payload.size());
    // Discard any unrelated output produced while handling the DATA. The
    // assertion below must be tied specifically to the late credit release.
    (void)server.TakeOutbound();

    const auto stream_id =
        static_cast<std::uint32_t>(server.carrier_stream_id());
    const H2Bytes rst_stream{
        0x00, 0x00, 0x04,  // payload length
        0x03, 0x00,        // RST_STREAM, no flags
        static_cast<std::uint8_t>((stream_id >> 24) & 0x7fU),
        static_cast<std::uint8_t>((stream_id >> 16) & 0xffU),
        static_cast<std::uint8_t>((stream_id >> 8) & 0xffU),
        static_cast<std::uint8_t>(stream_id & 0xffU),
        0x00, 0x00, 0x00, 0x00};  // NGHTTP2_NO_ERROR
    server.Feed(rst_stream);
    assert(!server.failed());
    assert(server.carrier_closed());

    // The carrier retires connection-level credit after its stream object is
    // gone. The release crosses the half-window threshold and therefore
    // produces a connection WINDOW_UPDATE, never a stream update.
    assert(server.ConsumeTunnelBytes(received.size()));
    assert(server.unconsumed_tunnel_bytes() == 0);
    const auto updates =
        InspectWindowUpdates(server.TakeOutbound(), stream_id);
    assert(updates.connection);
    assert(!updates.carrier_stream);
}

}  // namespace

int main() {
    FullSessionRoundTrip();
    InboundContinuationIsObservedWithoutPayloadRetention();
    ObserverDoesNotChangeOpeningWire();
    ObserverCapIsFailOpenAndBounded();
    ObserverClockStartsAtFirstCarrierEvent();
    RejectCarrierLooksHttp();
    ServerResetDropsPendingRequestAndReportsClose();
    ServerSaturationRefusalIsRetryableAndReleasesState();
    ServerManualFlowControlStallsAndResumes();
    ClientCoverDataReturnsCreditImmediately();
    ClientManualFlowControlStallsAndResumes();
    ServerOverConsumeFailsClosed();
    PaddedDataIsRetiredWithoutTunnelCredit();
    ServerCreditCanRetireAfterStreamClose();
    return 0;
}
