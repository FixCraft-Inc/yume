/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "core/stealth/obfs_h2.hpp"
#include "core/stealth/obfs_signal.hpp"

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

void test_decoder_tracks_window_update() {
    // Preface + WINDOW_UPDATE on stream 0 (+1000) and on stream 1
    // (+2000). conn_send_window goes 65535 → 66535; stream(1) goes
    // 65535 → 67535. Unseen stream still returns the default.
    std::vector<std::uint8_t> input;
    const char kPref[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    input.insert(input.end(), kPref, kPref + 24);
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
    // Real Chrome uses 0x40-prefix opcodes ("literal with incremental
    // indexing"). The pre-stateful encoder used 0x00. Verify the new
    // encoder emits the right pattern: opcode high nibble bits 0100xx.
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
    std::string token = yume::obfs::derive_path_token(signal, sni, hour);
    std::string path = yume::obfs::build_path(token, yume::obfs::random_nonce_hex());
    auto bytes = yume::obfs::encode_client_handshake(sni, path, "Mozilla/5.0 Chrome/131.0");

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
    test_path_token_round_trip();
    test_handshake_extracts_path();
    test_data_round_trip_with_padding();
    test_decoder_rejects_garbage_preface();
    test_decoder_handles_streamed_input();
    test_decoder_parses_peer_settings();
    test_decoder_clamps_oversize_max_frame_size();
    test_decoder_defaults_match_rfc_7540();
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
    std::puts("obfs_test: all 20 cases passed");
    return 0;
}
