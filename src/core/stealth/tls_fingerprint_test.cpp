/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <cassert>
#include <iostream>
#include <tuple>

#include "core/stealth/tls_fingerprint.hpp"
#include "core/stealth/tls_stealth.hpp"

namespace {

void test_official_ja4_vector() {
    yume::tls_fingerprint::JA4Components components;
    components.protocol_version = "t13";
    components.sni_present = "d";
    components.cipher_count = 15;
    components.extension_count = 16;
    components.first_alpn = "h2";
    components.cipher_suites = {
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
        0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    };
    components.extensions = {
        0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d,
        0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
    };
    components.signature_algorithms = {
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    };

    assert(yume::tls_fingerprint::calculate_ja4_hash(components) ==
           "t13d1516h2_8daaf6152771_e5627efa2ab1");
}

void test_empty_components_and_count_clamp() {
    yume::tls_fingerprint::JA4Components empty;
    empty.protocol_version = "t12";
    empty.sni_present = "i";
    assert(yume::tls_fingerprint::calculate_ja4_hash(empty) ==
           "t12i000000_000000000000_000000000000");

    empty.cipher_count = 120;
    empty.extension_count = 101;
    empty.first_alpn = "http/1.1";
    assert(yume::tls_fingerprint::calculate_ja4_hash(empty).starts_with("t12i9999h1_"));
}

void test_browser_match_thresholds() {
    const auto known = yume::tls_fingerprint::get_browser_profile_info(
        yume::tls_fingerprint::BrowserProfile::CHROME_131);
    assert(known.has_value());

    yume::tls_fingerprint::FingerprintData observed;
    observed.ja3_hash = known->ja3_hash;
    observed.ja4_hash = known->ja4_hash;
    auto [profile, score] = yume::tls_fingerprint::match_browser_profile(observed);
    assert(profile == known->profile);
    assert(score == 100.0);

    observed.ja4_hash.clear();
    std::tie(profile, score) = yume::tls_fingerprint::match_browser_profile(observed);
    assert(profile == known->profile);
    assert(score == 50.0);
    assert(!yume::tls_fingerprint::evaluate_fingerprint(observed).looks_like_browser);
}

void test_connection_profile_rotation() {
    using yume::tls_fingerprint::BrowserProfile;
    using yume::tls_stealth::profile_for_connection;

    assert(profile_for_connection(BrowserProfile::CHROME_131, false, 2, 100) ==
           BrowserProfile::CHROME_131);
    assert(profile_for_connection(BrowserProfile::CHROME_131, true, 2, 0) ==
           BrowserProfile::CHROME_131);
    assert(profile_for_connection(BrowserProfile::CHROME_131, true, 2, 1) ==
           BrowserProfile::CHROME_131);
    assert(profile_for_connection(BrowserProfile::CHROME_131, true, 2, 2) ==
           BrowserProfile::FIREFOX_126);
    assert(profile_for_connection(BrowserProfile::CHROME_131, true, 2, 4) ==
           BrowserProfile::SAFARI_18);
    assert(profile_for_connection(BrowserProfile::CHROME_131, true, 2, 6) ==
           BrowserProfile::CHROME_131);
    assert(profile_for_connection(BrowserProfile::FIREFOX_126, true, 1, 1) ==
           BrowserProfile::SAFARI_18);
}

}  // namespace

int main() {
    test_official_ja4_vector();
    test_empty_components_and_count_clamp();
    test_browser_match_thresholds();
    test_connection_profile_rotation();
    std::cout << "tls_fingerprint_test ok\n";
    return 0;
}
