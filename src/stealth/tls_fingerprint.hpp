/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <optional>

namespace yume::tls_fingerprint {

// TLS extension types
enum class ExtensionType : uint16_t {
    SERVER_NAME = 0,
    MAX_FRAGMENT_LENGTH = 1,
    STATUS_REQUEST = 5,
    SUPPORTED_GROUPS = 10,
    EC_POINT_FORMATS = 11,
    SIGNATURE_ALGORITHMS = 13,
    ALPN = 16,
    SIGNED_CERTIFICATE_TIMESTAMP = 18,
    PADDING = 21,
    EXTENDED_MASTER_SECRET = 23,
    SESSION_TICKET = 35,
    SUPPORTED_VERSIONS = 43,
    PSK_KEY_EXCHANGE_MODES = 45,
    KEY_SHARE = 51,
    RENEGOTIATION_INFO = 65281,
};

// Browser profile identifiers
enum class BrowserProfile {
    CHROME_151,
    UNKNOWN
};

// JA3 fingerprint components
struct JA3Components {
    uint16_t tls_version{0};
    std::vector<uint16_t> cipher_suites;
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> supported_groups;
    std::vector<uint8_t> ec_point_formats;
};

// JA4 TLS-client fingerprint components. The protocol_version field includes
// the transport prefix (for example, "t13" for TLS 1.3 over TCP).
struct JA4Components {
    std::string protocol_version;
    std::string sni_present;             // "d" or "i"
    std::size_t cipher_count{0};
    std::size_t extension_count{0};
    std::string first_alpn;              // first ALPN value
    std::vector<uint16_t> cipher_suites;
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> signature_algorithms;
};

// Complete fingerprint data
struct FingerprintData {
    std::string ja3_hash;
    std::string ja4_hash;
    std::string akamai_hash;
    std::vector<std::string> alpn_protocols;
    JA3Components ja3_components;
    JA4Components ja4_components;
    bool matches_known_browser{false};
    BrowserProfile matched_profile{BrowserProfile::UNKNOWN};
    double similarity_score{0.0};
    std::string client_hello_hex;  // Raw ClientHello for debugging
};

// Known browser fingerprint database
struct BrowserFingerprint {
    BrowserProfile profile;
    std::string name;
    std::string ja3_hash;
    std::string ja4_hash;
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

std::string calculate_ja3_hash(const JA3Components& components);
std::string calculate_ja4_hash(const JA4Components& components);
std::string calculate_akamai_hash(const JA3Components& components);
std::vector<BrowserFingerprint> get_known_browser_fingerprints();
std::pair<BrowserProfile, double> match_browser_profile(const FingerprintData& fingerprint);
std::optional<BrowserFingerprint> get_browser_profile_info(BrowserProfile profile);
std::string browser_profile_name(BrowserProfile profile);
FingerprintData parse_client_hello(const uint8_t* data, size_t length);

struct FingerprintEvaluation {
    bool looks_like_browser{false};
    bool needs_stealth_mode{true};
    BrowserProfile recommended_profile{BrowserProfile::CHROME_151};
    std::vector<std::string> warnings;
    std::vector<std::string> recommendations;
};

FingerprintEvaluation evaluate_fingerprint(const FingerprintData& fingerprint);

}  // namespace yume::tls_fingerprint
