/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "core/obfs_h2.hpp"
#include "core/obfs_signal.hpp"

#include <cassert>
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

namespace {

void test_path_token_round_trip() {
    yume::crypto::Bytes signal = yume::obfs::derive_signal_key("alpha-secret");
    std::int64_t now_s = static_cast<std::int64_t>(std::time(nullptr));
    std::int64_t hour = now_s / 3600;

    std::string token = yume::obfs::derive_path_token(signal, "fixcraft.net", hour);
    assert(token.size() == yume::obfs::kH2TokenHexLen);

    std::string nonce = yume::obfs::random_nonce_hex();
    assert(nonce.size() == yume::obfs::kH2NonceHexLen);

    std::string path = yume::obfs::build_path(token, nonce);
    assert(path.size() == yume::obfs::kH2PathLen);
    assert(path[0] == '/');
    assert(path[1 + yume::obfs::kH2TokenHexLen] == '/');

    std::vector<yume::crypto::Bytes> keys{signal};
    assert(yume::obfs::verify_path_token(keys, "fixcraft.net", path, now_s));

    assert(yume::obfs::verify_path_token(keys, "fixcraft.net", path, now_s - 1800));

    assert(!yume::obfs::verify_path_token(keys, "fixcraft.net", path, now_s - 7200));

    assert(!yume::obfs::verify_path_token(keys, "different.host", path, now_s));

    yume::crypto::Bytes other = yume::obfs::derive_signal_key("different-secret");
    assert(!yume::obfs::verify_path_token({other}, "fixcraft.net", path, now_s));
}

void test_handshake_extracts_path() {
    const std::string sni = "stealth.example";
    yume::crypto::Bytes signal = yume::obfs::derive_signal_key("test-secret");
    std::int64_t hour = static_cast<std::int64_t>(std::time(nullptr)) / 3600;
    std::string token = yume::obfs::derive_path_token(signal, sni, hour);
    std::string path = yume::obfs::build_path(token, yume::obfs::random_nonce_hex());

    auto handshake = yume::obfs::encode_client_handshake(sni, path,
        "Mozilla/5.0 Chrome/135.0");

    yume::obfs::H2InboundDecoder decoder(true);
    decoder.feed(handshake.data(), handshake.size());
    assert(!decoder.failed());
    assert(decoder.client_preface_seen());
    assert(decoder.headers_seen());
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
    std::string token = yume::obfs::derive_path_token(signal, sni, hour);
    std::string path = yume::obfs::build_path(token, yume::obfs::random_nonce_hex());
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
}

}  // namespace

int main() {
    test_path_token_round_trip();
    test_handshake_extracts_path();
    test_data_round_trip_with_padding();
    test_decoder_rejects_garbage_preface();
    test_decoder_handles_streamed_input();
    test_decoder_parses_peer_settings();
    test_decoder_clamps_oversize_max_frame_size();
    test_decoder_defaults_match_rfc_7540();
    std::puts("obfs_test: all 8 cases passed");
    return 0;
}
