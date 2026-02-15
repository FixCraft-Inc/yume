/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "core/tls_fingerprint.hpp"

#include <openssl/md5.h>
#include <openssl/sha.h>

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <cstring>

namespace yume::tls_fingerprint {

namespace {

std::string md5_hash(const std::string& input) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const unsigned char*>(input.data()), input.size(), digest);
    
    std::ostringstream oss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
    }
    return oss.str();
}

std::string sha256_hash(const std::string& input) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), digest);
    
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
    }
    return oss.str();
}

template<typename T>
std::string join_numbers(const std::vector<T>& nums, const std::string& sep = "-") {
    std::ostringstream oss;
    for (size_t i = 0; i < nums.size(); ++i) {
        if (i > 0) oss << sep;
        oss << static_cast<uint32_t>(nums[i]);
    }
    return oss.str();
}

}  // namespace

std::string calculate_ja3_hash(const JA3Components& components) {
    // JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
    std::ostringstream ja3_string;
    
    ja3_string << components.tls_version << ",";
    ja3_string << join_numbers(components.cipher_suites, "-") << ",";
    ja3_string << join_numbers(components.extensions, "-") << ",";
    ja3_string << join_numbers(components.supported_groups, "-") << ",";
    ja3_string << join_numbers(components.ec_point_formats, "-");
    
    return md5_hash(ja3_string.str());
}

std::string calculate_ja4_hash(const JA4Components& components) {
    // JA4 format: <protocol><sni><cipher_count><ext_count>_<cipher_hash>_<ext_hash>_<alpn>
    std::ostringstream ja4_string;
    
    ja4_string << components.protocol_version;
    ja4_string << components.sni_present;
    ja4_string << std::setw(2) << std::setfill('0') << static_cast<int>(components.cipher_count);
    ja4_string << std::setw(2) << std::setfill('0') << static_cast<int>(components.extension_count);
    ja4_string << "_";
    
    // Hash cipher suites (first 12 chars of SHA256)
    std::string cipher_str = join_numbers(components.cipher_suites, ",");
    std::string cipher_hash = sha256_hash(cipher_str).substr(0, 12);
    ja4_string << cipher_hash << "_";
    
    // Hash extensions (first 12 chars of SHA256)
    std::string ext_str = join_numbers(components.extensions, ",");
    std::string ext_hash = sha256_hash(ext_str).substr(0, 12);
    ja4_string << ext_hash << "_";
    
    // First ALPN
    ja4_string << (components.first_alpn.empty() ? "00" : components.first_alpn);
    
    return ja4_string.str();
}

std::string calculate_akamai_hash(const JA3Components& components) {
    // Akamai uses similar to JA3 but different separator and format
    std::ostringstream akamai_string;
    
    akamai_string << std::hex << components.tls_version << "|";
    for (size_t i = 0; i < components.cipher_suites.size(); ++i) {
        if (i > 0) akamai_string << ":";
        akamai_string << std::hex << components.cipher_suites[i];
    }
    akamai_string << "|";
    for (size_t i = 0; i < components.extensions.size(); ++i) {
        if (i > 0) akamai_string << ":";
        akamai_string << std::hex << components.extensions[i];
    }
    
    return sha256_hash(akamai_string.str()).substr(0, 32);
}

std::vector<BrowserFingerprint> get_known_browser_fingerprints() {
    std::vector<BrowserFingerprint> fingerprints;
    
    // Chrome 135 (Latest as of Feb 2026)
    {
        BrowserFingerprint fp;
        fp.profile = BrowserProfile::CHROME_135;
        fp.name = "Chrome 135";
        fp.tls_version = 0x0303;  // TLS 1.2 in ClientHello, upgrades to 1.3
        fp.cipher_suites = {
            0x1301,  // TLS_AES_128_GCM_SHA256
            0x1302,  // TLS_AES_256_GCM_SHA384
            0x1303,  // TLS_CHACHA20_POLY1305_SHA256
            0xc02c,  // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc02b,  // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc030,  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xc02f,  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        };
        fp.extensions = {
            0,      // server_name
            23,     // extended_master_secret
            65281,  // renegotiation_info
            10,     // supported_groups
            11,     // ec_point_formats
            35,     // session_ticket
            16,     // application_layer_protocol_negotiation
            5,      // status_request
            13,     // signature_algorithms
            18,     // signed_certificate_timestamp
            43,     // supported_versions
            45,     // psk_key_exchange_modes
            51,     // key_share
            21,     // padding
        };
        fp.supported_groups = {
            0x001d,  // x25519
            0x0017,  // secp256r1
            0x0018,  // secp384r1
        };
        fp.ec_point_formats = {0};  // uncompressed
        fp.alpn_protocols = {"h2", "http/1.1"};
        fp.signature_algorithms = {
            0x0403,  // ecdsa_secp256r1_sha256
            0x0503,  // ecdsa_secp384r1_sha384
            0x0603,  // ecdsa_secp521r1_sha512
            0x0804,  // rsa_pss_rsae_sha256
            0x0805,  // rsa_pss_rsae_sha384
            0x0806,  // rsa_pss_rsae_sha512
            0x0401,  // rsa_pkcs1_sha256
            0x0501,  // rsa_pkcs1_sha384
            0x0601,  // rsa_pkcs1_sha512
        };
        
        // Calculate hashes
        JA3Components ja3;
        ja3.tls_version = fp.tls_version;
        ja3.cipher_suites = fp.cipher_suites;
        ja3.extensions = fp.extensions;
        ja3.supported_groups = fp.supported_groups;
        ja3.ec_point_formats = fp.ec_point_formats;
        fp.ja3_hash = calculate_ja3_hash(ja3);
        
        JA4Components ja4;
        ja4.protocol_version = "t13";
        ja4.sni_present = "d";
        ja4.cipher_count = static_cast<uint8_t>(fp.cipher_suites.size());
        ja4.extension_count = static_cast<uint8_t>(fp.extensions.size());
        ja4.first_alpn = "h2";
        ja4.cipher_suites = fp.cipher_suites;
        ja4.extensions = fp.extensions;
        ja4.signature_algorithms = fp.signature_algorithms;
        fp.ja4_hash = calculate_ja4_hash(ja4);
        
        fingerprints.push_back(fp);
    }
    
    // Firefox 126
    {
        BrowserFingerprint fp;
        fp.profile = BrowserProfile::FIREFOX_126;
        fp.name = "Firefox 126";
        fp.tls_version = 0x0303;  // TLS 1.2 in ClientHello
        fp.cipher_suites = {
            0x1301,  // TLS_AES_128_GCM_SHA256
            0x1303,  // TLS_CHACHA20_POLY1305_SHA256
            0x1302,  // TLS_AES_256_GCM_SHA384
            0xc02c,  // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc02b,  // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc030,  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xc02f,  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        };
        fp.extensions = {
            0,      // server_name
            23,     // extended_master_secret
            65281,  // renegotiation_info
            10,     // supported_groups
            11,     // ec_point_formats
            13,     // signature_algorithms
            16,     // application_layer_protocol_negotiation
            5,      // status_request
            43,     // supported_versions
            45,     // psk_key_exchange_modes
            51,     // key_share
            35,     // session_ticket
            21,     // padding
        };
        fp.supported_groups = {
            0x001d,  // x25519
            0x0017,  // secp256r1
            0x0018,  // secp384r1
        };
        fp.ec_point_formats = {0};  // uncompressed
        fp.alpn_protocols = {"h2", "http/1.1"};
        fp.signature_algorithms = {
            0x0403,  // ecdsa_secp256r1_sha256
            0x0503,  // ecdsa_secp384r1_sha384
            0x0603,  // ecdsa_secp521r1_sha512
            0x0804,  // rsa_pss_rsae_sha256
            0x0805,  // rsa_pss_rsae_sha384
            0x0806,  // rsa_pss_rsae_sha512
            0x0401,  // rsa_pkcs1_sha256
            0x0501,  // rsa_pkcs1_sha384
            0x0601,  // rsa_pkcs1_sha512
        };
        
        JA3Components ja3;
        ja3.tls_version = fp.tls_version;
        ja3.cipher_suites = fp.cipher_suites;
        ja3.extensions = fp.extensions;
        ja3.supported_groups = fp.supported_groups;
        ja3.ec_point_formats = fp.ec_point_formats;
        fp.ja3_hash = calculate_ja3_hash(ja3);
        
        JA4Components ja4;
        ja4.protocol_version = "t13";
        ja4.sni_present = "d";
        ja4.cipher_count = static_cast<uint8_t>(fp.cipher_suites.size());
        ja4.extension_count = static_cast<uint8_t>(fp.extensions.size());
        ja4.first_alpn = "h2";
        ja4.cipher_suites = fp.cipher_suites;
        ja4.extensions = fp.extensions;
        ja4.signature_algorithms = fp.signature_algorithms;
        fp.ja4_hash = calculate_ja4_hash(ja4);
        
        fingerprints.push_back(fp);
    }
    
    // Safari 17
    {
        BrowserFingerprint fp;
        fp.profile = BrowserProfile::SAFARI_17;
        fp.name = "Safari 17";
        fp.tls_version = 0x0303;
        fp.cipher_suites = {
            0x1301,  // TLS_AES_128_GCM_SHA256
            0x1302,  // TLS_AES_256_GCM_SHA384
            0x1303,  // TLS_CHACHA20_POLY1305_SHA256
            0xc02c,  // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc02b,  // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc030,  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xc02f,  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        };
        fp.extensions = {
            0,      // server_name
            10,     // supported_groups
            11,     // ec_point_formats
            13,     // signature_algorithms
            16,     // application_layer_protocol_negotiation
            43,     // supported_versions
            51,     // key_share
            45,     // psk_key_exchange_modes
            23,     // extended_master_secret
            35,     // session_ticket
            5,      // status_request
            18,     // signed_certificate_timestamp
            65281,  // renegotiation_info
            21,     // padding
        };
        fp.supported_groups = {
            0x001d,  // x25519
            0x0017,  // secp256r1
            0x0018,  // secp384r1
        };
        fp.ec_point_formats = {0};
        fp.alpn_protocols = {"h2", "http/1.1"};
        fp.signature_algorithms = {
            0x0403, 0x0503, 0x0603,
            0x0804, 0x0805, 0x0806,
            0x0401, 0x0501, 0x0601,
        };
        
        JA3Components ja3;
        ja3.tls_version = fp.tls_version;
        ja3.cipher_suites = fp.cipher_suites;
        ja3.extensions = fp.extensions;
        ja3.supported_groups = fp.supported_groups;
        ja3.ec_point_formats = fp.ec_point_formats;
        fp.ja3_hash = calculate_ja3_hash(ja3);
        
        JA4Components ja4;
        ja4.protocol_version = "t13";
        ja4.sni_present = "d";
        ja4.cipher_count = static_cast<uint8_t>(fp.cipher_suites.size());
        ja4.extension_count = static_cast<uint8_t>(fp.extensions.size());
        ja4.first_alpn = "h2";
        ja4.cipher_suites = fp.cipher_suites;
        ja4.extensions = fp.extensions;
        ja4.signature_algorithms = fp.signature_algorithms;
        fp.ja4_hash = calculate_ja4_hash(ja4);
        
        fingerprints.push_back(fp);
    }
    
    return fingerprints;
}

std::pair<BrowserProfile, double> match_browser_profile(const FingerprintData& fingerprint) {
    auto known_fingerprints = get_known_browser_fingerprints();
    double best_score = 0.0;
    BrowserProfile best_profile = BrowserProfile::UNKNOWN;
    
    for (const auto& known : known_fingerprints) {
        double score = 0.0;
        int total_checks = 0;
        
        // JA3 exact match (50% weight)
        if (fingerprint.ja3_hash == known.ja3_hash) {
            score += 50.0;
        }
        total_checks += 1;
        
        // JA4 exact match (50% weight)
        if (fingerprint.ja4_hash == known.ja4_hash) {
            score += 50.0;
        }
        total_checks += 1;
        
        // Normalize score
        if (total_checks > 0) {
            score = (score / (total_checks * 50.0)) * 100.0;
        }
        
        if (score > best_score) {
            best_score = score;
            best_profile = known.profile;
        }
    }
    
    return {best_profile, best_score};
}

std::optional<BrowserFingerprint> get_browser_profile_info(BrowserProfile profile) {
    auto fingerprints = get_known_browser_fingerprints();
    for (const auto& fp : fingerprints) {
        if (fp.profile == profile) {
            return fp;
        }
    }
    return std::nullopt;
}

std::string browser_profile_name(BrowserProfile profile) {
    switch (profile) {
        case BrowserProfile::CHROME_135: return "Chrome 135";
        case BrowserProfile::CHROME_123: return "Chrome 123";
        case BrowserProfile::FIREFOX_126: return "Firefox 126";
        case BrowserProfile::FIREFOX_115_ESR: return "Firefox 115 ESR";
        case BrowserProfile::SAFARI_17: return "Safari 17";
        case BrowserProfile::EDGE_123: return "Edge 123";
        case BrowserProfile::UNKNOWN: return "Unknown";
    }
    return "Unknown";
}

FingerprintData parse_client_hello(const uint8_t* data, size_t length) {
    FingerprintData result;
    
    // This is a simplified parser - in production you'd want full TLS parsing
    // For now, we'll just store the raw data and set empty components
    
    // Convert to hex string for debugging
    std::ostringstream oss;
    for (size_t i = 0; i < std::min(length, size_t(256)); ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    result.client_hello_hex = oss.str();
    
    // TODO: Parse actual ClientHello message
    // This would involve parsing TLS handshake protocol
    // For now, return empty fingerprint
    
    return result;
}

FingerprintEvaluation evaluate_fingerprint(const FingerprintData& fingerprint) {
    FingerprintEvaluation eval;
    
    auto [profile, score] = match_browser_profile(fingerprint);
    
    eval.looks_like_browser = (score > 80.0);
    eval.needs_stealth_mode = !eval.looks_like_browser;
    eval.recommended_profile = (profile != BrowserProfile::UNKNOWN) 
        ? profile 
        : BrowserProfile::CHROME_135;
    
    if (!eval.looks_like_browser) {
        eval.warnings.push_back("TLS fingerprint does not match known browser profiles");
        eval.warnings.push_back("May be detected by DPI/fingerprinting systems");
        eval.recommendations.push_back("Enable stealth mode to mimic browser fingerprints");
        eval.recommendations.push_back("Recommended profile: " + browser_profile_name(eval.recommended_profile));
    }
    
    // Check for common suspicious patterns
    if (fingerprint.ja3_components.cipher_suites.size() < 5) {
        eval.warnings.push_back("Too few cipher suites (looks like automation)");
    }
    
    if (fingerprint.ja3_components.extensions.size() < 10) {
        eval.warnings.push_back("Too few TLS extensions (looks like automation)");
    }
    
    if (fingerprint.alpn_protocols.empty()) {
        eval.warnings.push_back("No ALPN protocols advertised");
        eval.recommendations.push_back("Add h2 and http/1.1 to ALPN");
    } else if (fingerprint.alpn_protocols[0] != "h2") {
        eval.warnings.push_back("First ALPN is not h2 (browsers prefer h2)");
        eval.recommendations.push_back("Reorder ALPN to prioritize h2");
    }
    
    return eval;
}

}  // namespace yume::tls_fingerprint
