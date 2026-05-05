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

}  // namespace

int main() {
    test_path_token_round_trip();
    test_handshake_extracts_path();
    test_data_round_trip_with_padding();
    test_decoder_rejects_garbage_preface();
    test_decoder_handles_streamed_input();
    std::puts("obfs_test: all 5 cases passed");
    return 0;
}
