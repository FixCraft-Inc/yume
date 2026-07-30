/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/stealth/obfs_h2.hpp"
#include "core/stealth/obfs_signal.hpp"
#include "core/stealth/obfs.hpp"

#include <cassert>
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

namespace {

void test_carrier_alpn_wire_order() {
    const std::vector<unsigned char> expected_h2{
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1',
    };
    const std::vector<unsigned char> expected_http1{
        8, 'h', 't', 't', 'p', '/', '1', '.', '1',
    };

    assert(yume::obfs::carrier_alpn_protocols(true) ==
           std::vector<std::string>({"h2", "http/1.1"}));
    assert(yume::obfs::carrier_alpn_protocols(false) ==
           std::vector<std::string>({"http/1.1"}));
    assert(yume::obfs::carrier_alpn_wire(true) == expected_h2);
    assert(yume::obfs::carrier_alpn_wire(false) == expected_http1);
}

void test_carrier_alpn_selection_prefers_h2() {
    const std::vector<unsigned char> chrome_offer{
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1',
    };
    const std::vector<unsigned char> http1_offer{
        8, 'h', 't', 't', 'p', '/', '1', '.', '1',
    };
    const std::vector<unsigned char> reversed_offer{
        8, 'h', 't', 't', 'p', '/', '1', '.', '1',
        2, 'h', '2',
    };

    assert(yume::obfs::select_carrier_alpn(chrome_offer.data(),
                                           static_cast<unsigned int>(chrome_offer.size()),
                                           true) == "h2");
    assert(yume::obfs::select_carrier_alpn(reversed_offer.data(),
                                           static_cast<unsigned int>(reversed_offer.size()),
                                           true) == "h2");
    assert(yume::obfs::select_carrier_alpn(chrome_offer.data(),
                                           static_cast<unsigned int>(chrome_offer.size()),
                                           false) == "http/1.1");
    assert(yume::obfs::select_carrier_alpn(http1_offer.data(),
                                           static_cast<unsigned int>(http1_offer.size()),
                                           true) == "http/1.1");
}

void test_path_token_round_trip() {
    yume::crypto::Bytes signal = yume::obfs::derive_signal_key("alpha-secret");
    std::int64_t now_s = static_cast<std::int64_t>(std::time(nullptr));
    std::int64_t hour = now_s / 3600;

    std::string nonce = yume::obfs::random_nonce_hex();
    assert(nonce.size() == yume::obfs::kH2NonceHexLen);
    std::string token = yume::obfs::derive_path_token(
        signal, "carrier.example", hour, nonce);
    assert(token.size() == yume::obfs::kH2TokenHexLen);

    std::string path = yume::obfs::build_path(token, nonce);
    assert(path.size() == yume::obfs::kH2PathLen);
    assert(path[0] == '/');
    assert(path[1 + yume::obfs::kH2TokenHexLen] == '/');

    std::vector<yume::crypto::Bytes> keys{signal};
    assert(yume::obfs::verify_path_token(keys, "carrier.example", path, now_s));

    const auto previous_token = yume::obfs::derive_path_token(
        signal, "carrier.example", hour - 1, nonce);
    const auto previous_path = yume::obfs::build_path(previous_token, nonce);
    assert(yume::obfs::verify_path_token(
        keys, "carrier.example", previous_path, now_s));

    const auto expired_token = yume::obfs::derive_path_token(
        signal, "carrier.example", hour - 2, nonce);
    assert(!yume::obfs::verify_path_token(
        keys, "carrier.example", yume::obfs::build_path(expired_token, nonce), now_s));

    assert(!yume::obfs::verify_path_token(keys, "different.host", path, now_s));

    std::string tampered_nonce = path;
    tampered_nonce.back() = tampered_nonce.back() == '0' ? '1' : '0';
    assert(!yume::obfs::verify_path_token(
        keys, "carrier.example", tampered_nonce, now_s));

    yume::crypto::Bytes other = yume::obfs::derive_signal_key("different-secret");
    assert(!yume::obfs::verify_path_token({other}, "carrier.example", path, now_s));

    std::string malformed_nonce = path;
    malformed_nonce.back() = 'z';
    assert(!yume::obfs::valid_path_shape(malformed_nonce));
    assert(!yume::obfs::verify_path_token(keys, "carrier.example", malformed_nonce, now_s));

    std::string malformed_token = path;
    malformed_token[1] = '/';
    assert(!yume::obfs::valid_path_shape(malformed_token));
    assert(!yume::obfs::verify_path_token(keys, "carrier.example", malformed_token, now_s));
}

void test_authority_matches_tls_sni() {
    assert(yume::obfs::authority_matches_tls_sni("Example.COM", "example.com"));
    assert(yume::obfs::authority_matches_tls_sni("example.com:443", "example.com"));
    assert(yume::obfs::authority_matches_tls_sni("example.com.", "example.com"));
    assert(yume::obfs::authority_matches_tls_sni("example.com", "example.com", 443));
    assert(yume::obfs::authority_matches_tls_sni("example.com:443", "example.com", 443));
    assert(yume::obfs::authority_matches_tls_sni("[::1]", "::1", 443));
    assert(yume::obfs::authority_matches_tls_sni("[::1]:443", "::1", 443));
    assert(!yume::obfs::authority_matches_tls_sni("other.example", "example.com"));
    assert(!yume::obfs::authority_matches_tls_sni("", "example.com"));
    assert(!yume::obfs::authority_matches_tls_sni("user@example.com", "example.com"));
    assert(!yume::obfs::authority_matches_tls_sni("::1", "::1", 443));
    assert(!yume::obfs::authority_matches_tls_sni("[::1]:bad", "::1", 443));
    assert(!yume::obfs::authority_matches_tls_sni("[::1]:443:evil", "::1", 443));
    assert(!yume::obfs::authority_matches_tls_sni("example.com:444", "example.com", 443));
    assert(!yume::obfs::authority_matches_tls_sni("example.com:99999", "example.com", 443));
    assert(!yume::obfs::authority_matches_tls_sni("example.com:443:evil", "example.com", 443));
}

void test_carrier_path_admission_boundary() {
    const std::string sni = "admission.example";
    const std::int64_t now_s = static_cast<std::int64_t>(std::time(nullptr));
    const auto key = yume::obfs::derive_signal_key("shared-secret");
    const std::string nonce(yume::obfs::kH2NonceHexLen, '1');
    const auto token = yume::obfs::derive_path_token(
        key, sni, now_s / 3600, nonce);
    const auto path = yume::obfs::build_path(token, nonce);

    assert(yume::obfs::carrier_path_admitted(
        "shared-secret", sni, sni, path, now_s));
    assert(yume::obfs::carrier_path_admitted(
        "shared-secret", sni + ":443", sni, path, now_s));
    assert(yume::obfs::carrier_path_admitted(
        "shared-secret", sni + ":443", sni, path, now_s, 443));
    assert(!yume::obfs::carrier_path_admitted(
        "shared-secret", sni + ":444", sni, path, now_s, 443));
    assert(!yume::obfs::carrier_path_admitted(
        "wrong-secret", sni, sni, path, now_s));
    assert(!yume::obfs::carrier_path_admitted(
        "shared-secret", "other.example", sni, path, now_s));
    assert(!yume::obfs::carrier_path_admitted(
        "shared-secret", sni, sni, "/malformed", now_s));

    assert(!yume::obfs::carrier_path_admitted("", sni, sni, path, now_s));
    assert(!yume::obfs::carrier_path_admitted(
        "", sni, sni, "/malformed", now_s));

    yume::obfs::AdmissionReplayCache replay(2, 7200);
    assert(replay.AcceptPath(path, now_s));
    assert(!replay.AcceptPath(path, now_s));
}

void test_handshake_extracts_path() {
    const std::string sni = "stealth.example";
    yume::crypto::Bytes signal = yume::obfs::derive_signal_key("test-secret");
    std::int64_t hour = static_cast<std::int64_t>(std::time(nullptr)) / 3600;
    std::string nonce = yume::obfs::random_nonce_hex();
    std::string token = yume::obfs::derive_path_token(signal, sni, hour, nonce);
    std::string path = yume::obfs::build_path(token, nonce);

    auto handshake = yume::obfs::encode_client_handshake(sni, path,
        "Mozilla/5.0 Chrome/135.0");

    yume::obfs::H2InboundDecoder decoder(true);
    decoder.feed(handshake.data(), handshake.size());
    assert(!decoder.failed());
    assert(decoder.client_preface_seen());
    assert(decoder.headers_seen());
    assert(decoder.headers_end_stream());
    assert(decoder.extracted_path() == path);
    assert(decoder.extracted_authority() == sni);
}

void test_data_round_trip_with_padding() {
    std::vector<std::uint8_t> payload;
    for (int i = 0; i < 4096; ++i) payload.push_back(static_cast<std::uint8_t>(i & 0xFF));

    yume::obfs::H2EncodeParams params;
    params.padding_mean = 24;
    params.padding_max = 64;
    params.max_data_payload = 1024;

    auto framed = yume::obfs::encode_data_frames(payload.data(), payload.size(), params);
    assert(framed.size() > payload.size());

    yume::obfs::H2InboundDecoder decoder(true);
    decoder.mark_carrier_active();
    decoder.feed(framed.data(), framed.size());
    assert(!decoder.failed());
    assert(decoder.decoded_available() == payload.size());

    std::vector<std::uint8_t> recovered(payload.size(), 0);
    assert(decoder.consume_decoded(recovered.data(), recovered.size()));
    assert(recovered == payload);
}

void test_decoder_rejects_garbage_preface() {
    const std::string garbage(24, 'X');
    yume::obfs::H2InboundDecoder decoder(true);
    decoder.feed(reinterpret_cast<const std::uint8_t*>(garbage.data()), garbage.size());
    assert(decoder.failed());
}

void test_decoder_handles_streamed_input() {
    const std::string sni = "split.example";
    yume::crypto::Bytes signal = yume::obfs::derive_signal_key("");
    std::int64_t hour = static_cast<std::int64_t>(std::time(nullptr)) / 3600;
    std::string nonce = yume::obfs::random_nonce_hex();
    std::string token = yume::obfs::derive_path_token(signal, sni, hour, nonce);
    std::string path = yume::obfs::build_path(token, nonce);
    auto bytes = yume::obfs::encode_client_handshake(sni, path, "ua");

    yume::obfs::H2InboundDecoder decoder(true);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        decoder.feed(bytes.data() + i, 1);
    }
    assert(!decoder.failed());
    assert(decoder.headers_seen());
    assert(decoder.extracted_path() == path);
}

void test_decoder_parses_peer_settings() {
    // Construct a minimal preface + SETTINGS frame that advertises
    //   HEADER_TABLE_SIZE      = 65536
    //   ENABLE_PUSH            = 0       (ignored by us)
    //   MAX_CONCURRENT_STREAMS = 200
    //   INITIAL_WINDOW_SIZE    = 1048576
    //   MAX_FRAME_SIZE         = 16777215  (clamped to peer max)
    //   MAX_HEADER_LIST_SIZE   = 32768
    std::vector<std::uint8_t> input;
    const char kPref[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    input.insert(input.end(), kPref, kPref + 24);
    // Frame header: length=36, type=4 (SETTINGS), flags=0, stream=0
    input.push_back(0x00); input.push_back(0x00); input.push_back(0x24);
    input.push_back(0x04);
    input.push_back(0x00);
    input.push_back(0x00); input.push_back(0x00); input.push_back(0x00); input.push_back(0x00);
    auto add = [&](std::uint16_t id, std::uint32_t val) {
        input.push_back(static_cast<std::uint8_t>(id >> 8));
        input.push_back(static_cast<std::uint8_t>(id & 0xff));
        input.push_back(static_cast<std::uint8_t>((val >> 24) & 0xff));
        input.push_back(static_cast<std::uint8_t>((val >> 16) & 0xff));
        input.push_back(static_cast<std::uint8_t>((val >> 8)  & 0xff));
        input.push_back(static_cast<std::uint8_t>( val        & 0xff));
    };
    add(0x1, 65536);
    add(0x2, 0);
    add(0x3, 200);
    add(0x4, 1048576);
    add(0x5, 16777215);
    add(0x6, 32768);

    yume::obfs::H2InboundDecoder decoder(true);
    decoder.feed(input.data(), input.size());
    assert(!decoder.failed());
    assert(decoder.peer_settings_seen());
    assert(decoder.peer_header_table_size() == 65536);
    assert(decoder.peer_max_concurrent_streams() == 200);
    assert(decoder.peer_initial_window_size() == 1048576);
    assert(decoder.peer_max_frame_size() == 16777215);
    assert(decoder.peer_max_header_list_size() == 32768);
}

void test_decoder_clamps_oversize_max_frame_size() {
    // Peer advertises MAX_FRAME_SIZE > 16777215, which is illegal
    // per RFC 7540 §6.5.2. Verify we clamp rather than fault.
    std::vector<std::uint8_t> input;
    const char kPref[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    input.insert(input.end(), kPref, kPref + 24);
    input.push_back(0x00); input.push_back(0x00); input.push_back(0x06);
    input.push_back(0x04);
    input.push_back(0x00);
    input.push_back(0x00); input.push_back(0x00); input.push_back(0x00); input.push_back(0x00);
    input.push_back(0x00); input.push_back(0x05);
    input.push_back(0xFF); input.push_back(0xFF); input.push_back(0xFF); input.push_back(0xFF);

    yume::obfs::H2InboundDecoder decoder(true);
    decoder.feed(input.data(), input.size());
    assert(!decoder.failed());
    assert(decoder.peer_settings_seen());
    assert(decoder.peer_max_frame_size() == 16777215u);
}

void test_decoder_defaults_match_rfc_7540() {
    // Fresh decoder, no SETTINGS seen: getters return §6.5.2 defaults.
    yume::obfs::H2InboundDecoder decoder(true);
    assert(!decoder.peer_settings_seen());
    assert(decoder.peer_header_table_size() == 4096);
    assert(decoder.peer_initial_window_size() == 65535);
    assert(decoder.peer_max_frame_size() == 16384);
    // §6.9 defaults: conn-level send window starts at 65535;
    // unseen stream windows fall back to peer_initial_window_size().
    assert(decoder.conn_send_window() == 65535);
    assert(decoder.stream_send_window(1) == 65535);
}

// Build a frame on the wire: [length:24][type:8][flags:8][stream_id:32].
void push_frame(std::vector<std::uint8_t>& out,
                std::uint32_t length, std::uint8_t type, std::uint8_t flags,
                std::uint32_t stream_id) {
    out.push_back(static_cast<std::uint8_t>((length >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((length >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(length & 0xFF));
    out.push_back(type);
    out.push_back(flags);
    out.push_back(static_cast<std::uint8_t>((stream_id >> 24) & 0x7F));
    out.push_back(static_cast<std::uint8_t>((stream_id >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((stream_id >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(stream_id & 0xFF));
}

void push_be32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

void push_empty_settings(std::vector<std::uint8_t>& out) {
    push_frame(out, 0, 0x04, 0, 0);
}

bool has_header(const yume::obfs::H2InboundDecoder& decoder,
                const std::string& name,
                const std::string& value) {
    for (const auto& [header_name, header_value] : decoder.decoded_headers()) {
        if (header_name == name && header_value == value) return true;
    }
    return false;
}

struct FrameMeta {
    std::uint32_t length{0};
    std::uint8_t type{0};
    std::uint8_t flags{0};
    std::uint32_t stream_id{0};
};

FrameMeta frame_meta_at(const std::vector<std::uint8_t>& bytes,
                        std::size_t offset) {
    assert(offset + 9 <= bytes.size());
    FrameMeta frame;
    frame.length = (static_cast<std::uint32_t>(bytes[offset]) << 16) |
                   (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
                    static_cast<std::uint32_t>(bytes[offset + 2]);
    frame.type = bytes[offset + 3];
    frame.flags = bytes[offset + 4];
    frame.stream_id = ((static_cast<std::uint32_t>(bytes[offset + 5]) & 0x7f) << 24) |
                      (static_cast<std::uint32_t>(bytes[offset + 6]) << 16) |
                      (static_cast<std::uint32_t>(bytes[offset + 7]) << 8) |
                       static_cast<std::uint32_t>(bytes[offset + 8]);
    assert(offset + 9 + frame.length <= bytes.size());
    return frame;
}

void test_request_header_indexes_decode_to_intended_names() {
    const std::string sni = "indexes.example";
    const std::string path = "/0123456789abcdef0123456789abcdef/0123456789abcdef";
    auto request = yume::obfs::encode_client_handshake(sni, path, "profile-user-agent");

    yume::obfs::H2InboundDecoder decoder(true);
    decoder.feed(request.data(), request.size());
    assert(!decoder.failed());
    assert(has_header(decoder, "accept", "application/grpc-web+proto"));
    assert(has_header(decoder, "accept-encoding", "gzip, deflate, br, zstd"));
    assert(has_header(decoder, "accept-language", "en-US,en;q=0.9"));
    assert(has_header(decoder, "content-type", "application/grpc-web+proto"));
    assert(has_header(decoder, "user-agent", "profile-user-agent"));
    assert(decoder.header_value("allow").empty());
    assert(decoder.header_value("authorization").empty());
    assert(decoder.header_value("range").empty());
}

void test_http1_decoy_conversion_and_h2_end_stream() {
    const std::string http1 =
        "HTTP/1.1 404 Not Found\r\n"
        "Server: profile-server\r\n"
        "Content-Type: text/plain\r\n"
        "Connection: close\r\n"
        "Content-Length: 999\r\n\r\n"
        "not found\n";
    auto parsed = yume::obfs::parse_http1_response_for_h2(http1);
    assert(parsed.has_value());
    assert(parsed->status == 404);
    assert(parsed->body == yume::crypto::Bytes(
        {'n', 'o', 't', ' ', 'f', 'o', 'u', 'n', 'd', '\n'}));

    yume::crypto::Bytes wire = yume::obfs::encode_server_settings();
    auto peer_ack = yume::obfs::encode_settings_ack();
    wire.insert(wire.end(), peer_ack.begin(), peer_ack.end());
    auto headers = yume::obfs::encode_response_headers(
        *parsed, parsed->body.size(), false);
    wire.insert(wire.end(), headers.begin(), headers.end());
    yume::obfs::H2EncodeParams params;
    params.padding_mean = 0;
    params.padding_max = 0;
    params.end_stream = true;
    auto data = yume::obfs::encode_data_frames(
        parsed->body.data(), parsed->body.size(), params);
    wire.insert(wire.end(), data.begin(), data.end());

    std::size_t offset = 0;
    const auto settings = frame_meta_at(wire, offset);
    assert(settings.type == 0x04 && settings.flags == 0 && settings.stream_id == 0);
    offset += 9 + settings.length;
    const auto ack = frame_meta_at(wire, offset);
    assert(ack.type == 0x04 && ack.flags == 0x01 && ack.length == 0);
    offset += 9 + ack.length;
    const auto response_headers = frame_meta_at(wire, offset);
    assert(response_headers.type == 0x01);
    assert((response_headers.flags & 0x04) != 0);
    assert((response_headers.flags & 0x01) == 0);
    offset += 9 + response_headers.length;
    const auto response_data = frame_meta_at(wire, offset);
    assert(response_data.type == 0x00);
    assert((response_data.flags & 0x01) != 0);
    assert(response_data.stream_id == 1);

    yume::obfs::H2InboundDecoder decoder(false);
    decoder.feed(wire.data(), wire.size());
    assert(!decoder.failed());
    assert(decoder.headers_seen());
    assert(decoder.peer_settings_ack_seen());
    assert(has_header(decoder, ":status", "404"));
    assert(has_header(decoder, "server", "profile-server"));
    assert(has_header(decoder, "content-type", "text/plain"));
    assert(has_header(decoder, "content-length", "10"));
    assert(decoder.header_value("connection").empty());
    assert(!decoder.is_carrier_accept_response());

    auto local_ack = decoder.take_outbound_replies();
    assert(local_ack.size() == 9);
    const auto local_ack_frame = frame_meta_at(local_ack, 0);
    assert(local_ack_frame.type == 0x04 && local_ack_frame.flags == 0x01);

    decoder.mark_carrier_active();
    assert(!decoder.failed());
    assert(decoder.response_complete());
    assert(decoder.decoded_available() == parsed->body.size());
    yume::crypto::Bytes recovered(parsed->body.size());
    assert(decoder.consume_decoded(recovered.data(), recovered.size()));
    assert(recovered == parsed->body);
}

void test_carrier_accept_classification_and_frame_order() {
    yume::obfs::H2ResponseSpec accepted;
    accepted.status = 200;
    accepted.headers.emplace_back("content-type", "application/grpc-web+proto");
    accepted.headers.emplace_back("server", "configured-profile");

    yume::crypto::Bytes wire = yume::obfs::encode_server_settings();
    auto ack = yume::obfs::encode_settings_ack();
    wire.insert(wire.end(), ack.begin(), ack.end());
    auto headers = yume::obfs::encode_response_headers(accepted, std::nullopt, false);
    wire.insert(wire.end(), headers.begin(), headers.end());

    yume::obfs::H2InboundDecoder accepted_decoder(false);
    accepted_decoder.feed(wire.data(), wire.size());
    assert(!accepted_decoder.failed());
    assert(accepted_decoder.is_carrier_accept_response());
    assert(has_header(accepted_decoder, "server", "configured-profile"));

    yume::obfs::H2ResponseSpec decoy = accepted;
    decoy.headers.emplace_back("content-length", "0");
    auto decoy_headers = yume::obfs::encode_response_headers(decoy, 0, true);
    yume::crypto::Bytes decoy_wire = yume::obfs::encode_server_settings();
    decoy_wire.insert(decoy_wire.end(), decoy_headers.begin(), decoy_headers.end());
    yume::obfs::H2InboundDecoder decoy_decoder(false);
    decoy_decoder.feed(decoy_wire.data(), decoy_wire.size());
    assert(!decoy_decoder.failed());
    assert(!decoy_decoder.is_carrier_accept_response());

    yume::obfs::H2InboundDecoder bad_order(false);
    bad_order.feed(headers.data(), headers.size());
    assert(bad_order.failed());
}

void test_decoder_tracks_window_update() {
    // Preface + WINDOW_UPDATE on stream 0 (+1000) and on stream 1
    // (+2000). conn_send_window goes 65535 → 66535; stream(1) goes
    // 65535 → 67535. Unseen stream still returns the default.
    std::vector<std::uint8_t> input;
    const char kPref[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    input.insert(input.end(), kPref, kPref + 24);
    push_empty_settings(input);
    push_frame(input, 4, 0x08, 0, 0);
    push_be32(input, 1000);
    push_frame(input, 4, 0x08, 0, 1);
    push_be32(input, 2000);

    yume::obfs::H2InboundDecoder decoder(true);
    decoder.feed(input.data(), input.size());
    assert(!decoder.failed());
    assert(decoder.conn_send_window() == 65535 + 1000);
    assert(decoder.stream_send_window(1) == 65535 + 2000);
    assert(decoder.stream_send_window(99) == 65535);  // never touched
}

void test_decoder_rejects_zero_window_update() {
    // RFC 7540 §6.9: WINDOW_UPDATE with 0 increment is a protocol
    // error (PROTOCOL_ERROR / FLOW_CONTROL_ERROR depending on
    // stream_id). We surface as error_ — connection is broken.
    std::vector<std::uint8_t> input;
    const char kPref[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    input.insert(input.end(), kPref, kPref + 24);
    push_empty_settings(input);
    push_frame(input, 4, 0x08, 0, 0);
    push_be32(input, 0);

    yume::obfs::H2InboundDecoder decoder(true);
    decoder.feed(input.data(), input.size());
    assert(decoder.failed());
}

void test_decoder_rejects_bad_window_update_length() {
    // WINDOW_UPDATE payload must be exactly 4 bytes (RFC 7540 §6.9).
    std::vector<std::uint8_t> input;
    const char kPref[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    input.insert(input.end(), kPref, kPref + 24);
    push_empty_settings(input);
    push_frame(input, 6, 0x08, 0, 0);
    push_be32(input, 1000);
    input.push_back(0); input.push_back(0);

    yume::obfs::H2InboundDecoder decoder(true);
    decoder.feed(input.data(), input.size());
    assert(decoder.failed());
}

void test_decoder_clamps_window_overflow() {
    // RFC 7540 §6.9.1: a WINDOW_UPDATE that would push the window
    // past 2^31-1 is a FLOW_CONTROL_ERROR. We clamp instead of
    // erroring (consistent with how we handle other peer-malformation),
    // so the window saturates at 2^31-1.
    std::vector<std::uint8_t> input;
    const char kPref[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    input.insert(input.end(), kPref, kPref + 24);
    push_empty_settings(input);
    push_frame(input, 4, 0x08, 0, 0);
    push_be32(input, 0x7FFFFFFFu);

    yume::obfs::H2InboundDecoder decoder(true);
    decoder.feed(input.data(), input.size());
    assert(!decoder.failed());
    assert(decoder.conn_send_window() == 0x7FFFFFFFLL);
}

void test_decoder_initial_window_size_delta_applies() {
    // RFC 7540 §6.9.2: a SETTINGS_INITIAL_WINDOW_SIZE change delta-
    // applies to every per-stream window already in flight. Verify:
    //   1. WINDOW_UPDATE on stream 1 takes it to 65535+1000.
    //   2. SETTINGS lowering INITIAL_WINDOW_SIZE to 8192 makes
    //      delta = 8192 - 65535 = -57343, so stream 1 ends at
    //      (65535+1000) + (-57343) = 9192.
    //   3. Conn-level window is independent and untouched (it's
    //      controlled only by WINDOW_UPDATE on stream 0).
    //   4. Unseen stream returns the new lower default.
    std::vector<std::uint8_t> input;
    const char kPref[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    input.insert(input.end(), kPref, kPref + 24);
    push_empty_settings(input);
    push_frame(input, 4, 0x08, 0, 1);
    push_be32(input, 1000);
    push_frame(input, 6, 0x04, 0, 0);
    input.push_back(0x00); input.push_back(0x04);
    push_be32(input, 8192);

    yume::obfs::H2InboundDecoder decoder(true);
    decoder.feed(input.data(), input.size());
    assert(!decoder.failed());
    assert(decoder.peer_initial_window_size() == 8192);
    assert(decoder.conn_send_window() == 65535);
    assert(decoder.stream_send_window(1) == 65535 + 1000 - (65535 - 8192));
    assert(decoder.stream_send_window(99) == 8192);
}

void test_on_local_data_sent_debits_both_windows() {
    yume::obfs::H2InboundDecoder decoder(true);
    decoder.on_local_data_sent(1, 1024);
    assert(decoder.conn_send_window() == 65535 - 1024);
    assert(decoder.stream_send_window(1) == 65535 - 1024);
    decoder.on_local_data_sent(1, 0);  // no-op
    assert(decoder.conn_send_window() == 65535 - 1024);
}

void test_hpack_encoder_emits_incremental_indexing_opcode() {
    // RFC 7541 incremental indexing uses a 0x40-prefix opcode. Verify the
    // stateful encoder emits that representation without claiming an exact
    // browser-version capture.
    std::vector<std::uint8_t> out;
    yume::obfs::HpackEncoder enc;
    enc.emit_literal_with_indexing(out, /*name_index=*/1,
        std::string_view(), std::string_view("example.com"));
    assert(!out.empty());
    // First byte: 01 in high two bits + name_index=1 in low 6 bits.
    assert((out[0] & 0xC0) == 0x40);
    assert((out[0] & 0x3F) == 1);
}

void test_hpack_encoder_evicts_on_table_shrink() {
    // Default max is 4096. Fill the table to ~80 entries (each ~50
    // bytes: short name + short value + 32 overhead), then shrink
    // max to 200 and verify eviction occurred and the size accounting
    // is correct.
    yume::obfs::HpackEncoder enc;
    std::vector<std::uint8_t> sink;
    for (int i = 0; i < 80; ++i) {
        std::string val = "v" + std::to_string(i);
        enc.emit_literal_with_indexing(sink, /*name_index=*/0,
            std::string_view("x-test-header"), std::string_view(val));
    }
    assert(enc.dyn_table_entry_count() > 0);
    const auto initial_count = enc.dyn_table_entry_count();
    enc.set_peer_max_table_size(200);
    assert(enc.dyn_table_size_bytes() <= 200);
    assert(enc.dyn_table_entry_count() < initial_count);
}

void test_hpack_encoder_size_update_opcode() {
    // After a max-size change, emit_size_update_if_needed must emit
    // the 001x xxxx opcode at the start of the next HEADERS block.
    yume::obfs::HpackEncoder enc;
    enc.set_peer_max_table_size(256);
    std::vector<std::uint8_t> out;
    enc.emit_size_update_if_needed(out);
    assert(!out.empty());
    // First byte: 001 in top 3 bits + (256 doesn't fit in 5-bit
    // prefix), so prefix saturates and bytes follow as varint.
    assert((out[0] & 0xE0) == 0x20);
    // Second call is a no-op (we already signaled).
    out.clear();
    enc.emit_size_update_if_needed(out);
    assert(out.empty());
    assert(enc.signaled_max_table_size() == 256);
}

void test_hpack_encoder_drops_oversize_entry() {
    // §4.4: entry larger than max table size MUST NOT be added.
    yume::obfs::HpackEncoder enc;
    enc.set_peer_max_table_size(64);
    std::vector<std::uint8_t> sink;
    std::string huge_value(200, 'A');
    enc.emit_literal_with_indexing(sink, /*name_index=*/0,
        std::string_view("name"), std::string_view(huge_value));
    // Output still includes the literal header (the peer's decoder
    // sees the value either way), but the dynamic table stays empty
    // because the entry was too big to fit.
    assert(enc.dyn_table_entry_count() == 0);
    assert(enc.dyn_table_size_bytes() == 0);
}

void test_handshake_round_trip_with_stateful_encoder() {
    // The carrier handshake now uses HpackEncoder. Verify the decoder
    // can still extract the :authority and :path — it must, because
    // the decoder already handled the 0x40-prefix opcode (the literal
    // values are still emitted identically; only the opcode byte
    // changes).
    const std::string sni = "stateful.example";
    yume::crypto::Bytes signal = yume::obfs::derive_signal_key("");
    std::int64_t hour = static_cast<std::int64_t>(std::time(nullptr)) / 3600;
    std::string nonce = yume::obfs::random_nonce_hex();
    std::string token = yume::obfs::derive_path_token(signal, sni, hour, nonce);
    std::string path = yume::obfs::build_path(token, nonce);
    auto bytes = yume::obfs::encode_client_handshake(
        sni, path, "profile-test-user-agent");

    yume::obfs::H2InboundDecoder decoder(true);
    decoder.feed(bytes.data(), bytes.size());
    assert(!decoder.failed());
    assert(decoder.headers_seen());
    assert(decoder.extracted_authority() == sni);
    assert(decoder.extracted_path() == path);
}

void test_encoder_respects_send_window() {
    // Body bigger than the budget should be truncated; budget = 100
    // means we emit at most 100 payload bytes total across all DATA
    // frames in the returned buffer.
    std::vector<std::uint8_t> payload(2000, 0xAB);
    yume::obfs::H2EncodeParams params;
    params.padding_mean = 0;
    params.padding_max = 0;
    params.max_data_payload = 1024;
    params.send_window = 100;

    auto framed = yume::obfs::encode_data_frames(payload.data(), payload.size(), params);

    yume::obfs::H2InboundDecoder decoder(true);
    decoder.mark_carrier_active();
    decoder.feed(framed.data(), framed.size());
    assert(!decoder.failed());
    assert(decoder.decoded_available() == 100);
}

}  // namespace

int main() {
    test_carrier_alpn_wire_order();
    test_carrier_alpn_selection_prefers_h2();
    test_path_token_round_trip();
    test_authority_matches_tls_sni();
    test_carrier_path_admission_boundary();
    test_handshake_extracts_path();
    test_data_round_trip_with_padding();
    test_decoder_rejects_garbage_preface();
    test_decoder_handles_streamed_input();
    test_decoder_parses_peer_settings();
    test_decoder_clamps_oversize_max_frame_size();
    test_decoder_defaults_match_rfc_7540();
    test_request_header_indexes_decode_to_intended_names();
    test_http1_decoy_conversion_and_h2_end_stream();
    test_carrier_accept_classification_and_frame_order();
    test_decoder_tracks_window_update();
    test_decoder_rejects_zero_window_update();
    test_decoder_rejects_bad_window_update_length();
    test_decoder_clamps_window_overflow();
    test_decoder_initial_window_size_delta_applies();
    test_on_local_data_sent_debits_both_windows();
    test_encoder_respects_send_window();
    test_hpack_encoder_emits_incremental_indexing_opcode();
    test_hpack_encoder_evicts_on_table_shrink();
    test_hpack_encoder_size_update_opcode();
    test_hpack_encoder_drops_oversize_entry();
    test_handshake_round_trip_with_stateful_encoder();
    std::puts("obfs_test: all cases passed");
    return 0;
}
