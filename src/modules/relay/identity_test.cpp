/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "modules/relay/identity.hpp"

#include <cassert>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>

#include "modules/relay/base64.hpp"

#ifndef YUME_RELAY_TESTDATA
#error "YUME_RELAY_TESTDATA must name the relay test data directory"
#endif

namespace {

using yume::relay::base64_decode;
using yume::relay::base64_encode;
namespace identity = yume::relay::identity;

void TestBase64Vectors() {
    // RFC 4648, section 10.
    const std::pair<std::string_view, std::string_view> vectors[] = {
        {"", ""},         {"f", "Zg=="},     {"fo", "Zm8="},       {"foo", "Zm9v"},
        {"foob", "Zm9vYg=="}, {"fooba", "Zm9vYmE="}, {"foobar", "Zm9vYmFy"},
    };
    for (const auto& [raw, text] : vectors) {
        assert(base64_encode(raw) == text);
        const auto decoded = base64_decode(text);
        assert(decoded && *decoded == raw);
    }
    std::string all;
    for (int value = 0; value < 256; ++value) all.push_back(static_cast<char>(value));
    assert(base64_decode(base64_encode(all)) == all);
}

void TestBase64RefusesOtherSpellings() {
    for (const std::string_view text : {
             "Zg=",        // length
             "Zh==",       // nonzero bits after the last byte
             "Zm9=",       // nonzero bits after the last two bytes
             "Zm9v\n",     // whitespace
             " Zm9v",      // whitespace
             "Zm8=Zm8=",   // padding before the end
             "Z===",       // too much padding
             "====",       // padding only
             "Zm9-",       // URL-safe alphabet
             "Zm9_",       // URL-safe alphabet
             "Zm9vYmFy=",  // length
         }) {
        assert(!base64_decode(text));
    }
}

void TestSha256Hex() {
    assert(identity::sha256_hex("abc") ==
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

// The fingerprint equals the YTP/1 identity fingerprint that yume-setup
// computes. The expected value came from tools/yume_setup.py for this file.
void TestFingerprintMatchesYumeSetup() {
    std::ifstream input(std::string(YUME_RELAY_TESTDATA) + "/composite_identity.pub",
                        std::ios::binary);
    assert(input.good());
    const identity::Bytes pem{std::istreambuf_iterator<char>(input),
                              std::istreambuf_iterator<char>()};
    const auto parsed = identity::parse_composite_identity(pem);
    assert(parsed.valid());
    assert(identity::composite_fingerprint(parsed) ==
           "c9a538991801eb64abad33798343b68fa7af7098eb095fe3a97463d7ba6f5bcc");
    // The file is in the canonical spelling the relay handshake carries.
    assert(identity::encode_composite_identity(parsed.classical.get(), parsed.pq.get()) == pem);

    // A generated identity gets a distinct, well-formed fingerprint.
    const auto generated = identity::generate_composite_keypair();
    const auto encoded = identity::encode_composite_identity(
        generated.classical.public_key.get(), generated.pq.public_key.get());
    const auto other = identity::composite_fingerprint(identity::parse_composite_identity(encoded));
    assert(other.size() == 64 && other != identity::composite_fingerprint(parsed));
    bool threw = false;
    try {
        (void)identity::composite_fingerprint(identity::CompositePublicKey{});
    } catch (const std::exception&) {
        threw = true;
    }
    assert(threw);
}

}  // namespace

int main() {
    TestBase64Vectors();
    TestBase64RefusesOtherSpellings();
    TestSha256Hex();
    TestFingerprintMatchesYumeSetup();
    return 0;
}
