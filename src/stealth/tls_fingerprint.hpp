/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// The browser ClientHello YUME presents. JA3 and JA4 analysis of an observed
// ClientHello is test support (test_support/tls_fingerprint_analysis.hpp).
namespace yume::tls_fingerprint {

// Browser profile identifiers
enum class BrowserProfile {
    CHROME_151,
    UNKNOWN
};

// The ClientHello fields of one browser profile, from the generated cover
// profile.
struct BrowserFingerprint {
    BrowserProfile profile;
    std::string name;
    std::vector<uint16_t> cipher_suites;
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> supported_groups;
    // Subset of supported_groups that must carry a key_share. Not a JA3/JA4
    // component -- it exists because OpenSSL needs to be told, per group,
    // whether to generate a share.
    std::vector<uint16_t> key_share_groups;
    std::vector<uint8_t> ec_point_formats;
    std::vector<std::string> alpn_protocols;
    std::vector<uint16_t> signature_algorithms;
    uint16_t tls_version{0x0304};  // TLS 1.3
};

std::optional<BrowserFingerprint> get_browser_profile_info(
    BrowserProfile profile);

}  // namespace yume::tls_fingerprint
