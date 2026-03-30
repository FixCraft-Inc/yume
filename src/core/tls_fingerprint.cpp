/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "core/tls_fingerprint.hpp"

#include <openssl/md5.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <vector>

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

bool is_grease_value(uint16_t value) {
    return ((value & 0x0f0fU) == 0x0a0aU) && ((value >> 8) == (value & 0x00ffU));
}

struct Cursor {
    const uint8_t* ptr;
    const uint8_t* end;

    size_t remaining() const {
        return static_cast<size_t>(end - ptr);
    }
};

bool read_u8(Cursor& cursor, uint8_t& value) {
    if (cursor.remaining() < 1) {
        return false;
    }
    value = *cursor.ptr++;
    return true;
}

bool read_u16(Cursor& cursor, uint16_t& value) {
    if (cursor.remaining() < 2) {
        return false;
    }
    value = static_cast<uint16_t>(cursor.ptr[0] << 8)
        | static_cast<uint16_t>(cursor.ptr[1]);
    cursor.ptr += 2;
    return true;
}

bool read_u24(Cursor& cursor, uint32_t& value) {
    if (cursor.remaining() < 3) {
        return false;
    }
    value = (static_cast<uint32_t>(cursor.ptr[0]) << 16)
        | (static_cast<uint32_t>(cursor.ptr[1]) << 8)
        | static_cast<uint32_t>(cursor.ptr[2]);
    cursor.ptr += 3;
    return true;
}

bool skip_bytes(Cursor& cursor, size_t count) {
    if (cursor.remaining() < count) {
        return false;
    }
    cursor.ptr += count;
    return true;
}

std::optional<Cursor> take_block(Cursor& cursor, size_t count) {
    if (cursor.remaining() < count) {
        return std::nullopt;
    }
    Cursor block{cursor.ptr, cursor.ptr + count};
    cursor.ptr += count;
    return block;
}

std::string tls_version_token(uint16_t version) {
    switch (version) {
        case 0x0304: return "t13";
        case 0x0303: return "t12";
        case 0x0302: return "t11";
        case 0x0301: return "t10";
        default: return "t00";
    }
}

void append_extension_id(std::vector<uint16_t>& extensions, uint16_t type) {
    if (!is_grease_value(type)) {
        extensions.push_back(type);
    }
}

void parse_server_name_extension(Cursor ext_cursor, JA4Components& ja4) {
    uint16_t list_len = 0;
    if (!read_u16(ext_cursor, list_len)) {
        return;
    }
    auto list_block = take_block(ext_cursor, list_len);
    if (!list_block.has_value()) {
        return;
    }
    Cursor names = *list_block;
    while (names.remaining() > 0) {
        uint8_t name_type = 0;
        uint16_t name_len = 0;
        if (!read_u8(names, name_type) || !read_u16(names, name_len)) {
            return;
        }
        auto name_block = take_block(names, name_len);
        if (!name_block.has_value()) {
            return;
        }
        if (name_type == 0 && name_len > 0) {
            ja4.sni_present = "d";
            return;
        }
    }
}

void parse_supported_groups_extension(Cursor ext_cursor, JA3Components& ja3) {
    uint16_t list_len = 0;
    if (!read_u16(ext_cursor, list_len)) {
        return;
    }
    auto list_block = take_block(ext_cursor, list_len);
    if (!list_block.has_value()) {
        return;
    }
    Cursor groups = *list_block;
    while (groups.remaining() >= 2) {
        uint16_t group = 0;
        if (!read_u16(groups, group)) {
            return;
        }
        if (!is_grease_value(group)) {
            ja3.supported_groups.push_back(group);
        }
    }
}

void parse_ec_point_formats_extension(Cursor ext_cursor, JA3Components& ja3) {
    uint8_t list_len = 0;
    if (!read_u8(ext_cursor, list_len)) {
        return;
    }
    auto list_block = take_block(ext_cursor, list_len);
    if (!list_block.has_value()) {
        return;
    }
    Cursor formats = *list_block;
    while (formats.remaining() > 0) {
        uint8_t format = 0;
        if (!read_u8(formats, format)) {
            return;
        }
        ja3.ec_point_formats.push_back(format);
    }
}

void parse_signature_algorithms_extension(Cursor ext_cursor, JA4Components& ja4) {
    uint16_t list_len = 0;
    if (!read_u16(ext_cursor, list_len)) {
        return;
    }
    auto list_block = take_block(ext_cursor, list_len);
    if (!list_block.has_value()) {
        return;
    }
    Cursor algorithms = *list_block;
    while (algorithms.remaining() >= 2) {
        uint16_t algorithm = 0;
        if (!read_u16(algorithms, algorithm)) {
            return;
        }
        if (!is_grease_value(algorithm)) {
            ja4.signature_algorithms.push_back(algorithm);
        }
    }
}

void parse_alpn_extension(Cursor ext_cursor,
                          std::vector<std::string>& alpn_protocols,
                          JA4Components& ja4) {
    uint16_t list_len = 0;
    if (!read_u16(ext_cursor, list_len)) {
        return;
    }
    auto list_block = take_block(ext_cursor, list_len);
    if (!list_block.has_value()) {
        return;
    }
    Cursor protocols = *list_block;
    while (protocols.remaining() > 0) {
        uint8_t proto_len = 0;
        if (!read_u8(protocols, proto_len)) {
            return;
        }
        auto proto_block = take_block(protocols, proto_len);
        if (!proto_block.has_value()) {
            return;
        }
        std::string proto(reinterpret_cast<const char*>(proto_block->ptr), proto_len);
        alpn_protocols.push_back(proto);
    }
    if (!alpn_protocols.empty()) {
        ja4.first_alpn = alpn_protocols.front();
    }
}

std::optional<uint16_t> parse_supported_versions_extension(Cursor ext_cursor) {
    uint8_t list_len = 0;
    if (!read_u8(ext_cursor, list_len)) {
        return std::nullopt;
    }
    auto list_block = take_block(ext_cursor, list_len);
    if (!list_block.has_value()) {
        return std::nullopt;
    }
    Cursor versions = *list_block;
    uint16_t best = 0;
    while (versions.remaining() >= 2) {
        uint16_t version = 0;
        if (!read_u16(versions, version)) {
            return std::nullopt;
        }
        if (!is_grease_value(version)) {
            best = std::max(best, version);
        }
    }
    if (best == 0) {
        return std::nullopt;
    }
    return best;
}

std::vector<uint8_t> extract_handshake_bytes(const uint8_t* data, size_t length) {
    if (!data || length == 0) {
        return {};
    }
    if (length >= 5 && data[0] == 22) {
        std::vector<uint8_t> handshake;
        size_t offset = 0;
        while (offset + 5 <= length) {
            const uint8_t record_type = data[offset];
            const uint16_t record_len = static_cast<uint16_t>(data[offset + 3] << 8)
                | static_cast<uint16_t>(data[offset + 4]);
            offset += 5;
            if (offset + record_len > length) {
                break;
            }
            if (record_type != 22) {
                break;
            }
            handshake.insert(handshake.end(), data + offset, data + offset + record_len);
            offset += record_len;
            if (!handshake.empty() && handshake[0] == 1) {
                if (handshake.size() >= 4) {
                    const uint32_t message_len = (static_cast<uint32_t>(handshake[1]) << 16)
                        | (static_cast<uint32_t>(handshake[2]) << 8)
                        | static_cast<uint32_t>(handshake[3]);
                    if (handshake.size() >= 4 + message_len) {
                        break;
                    }
                }
            }
        }
        if (!handshake.empty()) {
            return handshake;
        }
    }
    return std::vector<uint8_t>(data, data + length);
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

    std::ostringstream oss;
    for (size_t i = 0; i < std::min(length, size_t(256)); ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    result.client_hello_hex = oss.str();

    if (!data || length == 0) {
        return result;
    }

    std::vector<uint8_t> handshake = extract_handshake_bytes(data, length);
    if (handshake.size() < 4) {
        return result;
    }

    Cursor cursor{handshake.data(), handshake.data() + handshake.size()};
    uint8_t handshake_type = 0;
    uint32_t hello_len = 0;
    if (!read_u8(cursor, handshake_type) || !read_u24(cursor, hello_len) || handshake_type != 1) {
        return result;
    }

    auto hello_block = take_block(cursor, hello_len);
    if (!hello_block.has_value()) {
        return result;
    }

    Cursor hello = *hello_block;
    uint16_t legacy_version = 0;
    if (!read_u16(hello, legacy_version)) {
        return result;
    }
    result.ja3_components.tls_version = legacy_version;
    result.ja4_components.protocol_version = tls_version_token(legacy_version);
    result.ja4_components.sni_present = "i";

    if (!skip_bytes(hello, 32)) {
        return result;
    }

    uint8_t session_id_len = 0;
    if (!read_u8(hello, session_id_len) || !skip_bytes(hello, session_id_len)) {
        return result;
    }

    uint16_t cipher_len = 0;
    if (!read_u16(hello, cipher_len) || (cipher_len % 2) != 0) {
        return result;
    }
    auto cipher_block = take_block(hello, cipher_len);
    if (!cipher_block.has_value()) {
        return result;
    }
    Cursor ciphers = *cipher_block;
    while (ciphers.remaining() >= 2) {
        uint16_t suite = 0;
        if (!read_u16(ciphers, suite)) {
            return result;
        }
        if (!is_grease_value(suite)) {
            result.ja3_components.cipher_suites.push_back(suite);
        }
    }

    uint8_t compression_len = 0;
    if (!read_u8(hello, compression_len) || !skip_bytes(hello, compression_len)) {
        return result;
    }

    if (hello.remaining() >= 2) {
        uint16_t extensions_len = 0;
        if (!read_u16(hello, extensions_len)) {
            return result;
        }
        auto extensions_block = take_block(hello, extensions_len);
        if (!extensions_block.has_value()) {
            return result;
        }
        Cursor extensions = *extensions_block;
        std::optional<uint16_t> supported_version;
        while (extensions.remaining() >= 4) {
            uint16_t ext_type = 0;
            uint16_t ext_len = 0;
            if (!read_u16(extensions, ext_type) || !read_u16(extensions, ext_len)) {
                return result;
            }
            auto ext_block = take_block(extensions, ext_len);
            if (!ext_block.has_value()) {
                return result;
            }
            append_extension_id(result.ja3_components.extensions, ext_type);
            Cursor ext_cursor = *ext_block;
            switch (ext_type) {
                case static_cast<uint16_t>(ExtensionType::SERVER_NAME):
                    parse_server_name_extension(ext_cursor, result.ja4_components);
                    break;
                case static_cast<uint16_t>(ExtensionType::SUPPORTED_GROUPS):
                    parse_supported_groups_extension(ext_cursor, result.ja3_components);
                    break;
                case static_cast<uint16_t>(ExtensionType::EC_POINT_FORMATS):
                    parse_ec_point_formats_extension(ext_cursor, result.ja3_components);
                    break;
                case static_cast<uint16_t>(ExtensionType::SIGNATURE_ALGORITHMS):
                    parse_signature_algorithms_extension(ext_cursor, result.ja4_components);
                    break;
                case static_cast<uint16_t>(ExtensionType::ALPN):
                    parse_alpn_extension(ext_cursor, result.alpn_protocols, result.ja4_components);
                    break;
                case static_cast<uint16_t>(ExtensionType::SUPPORTED_VERSIONS):
                    supported_version = parse_supported_versions_extension(ext_cursor);
                    break;
                default:
                    break;
            }
        }
        if (supported_version.has_value()) {
            result.ja4_components.protocol_version = tls_version_token(*supported_version);
        }
    }

    result.ja4_components.cipher_suites = result.ja3_components.cipher_suites;
    result.ja4_components.extensions = result.ja3_components.extensions;
    result.ja4_components.cipher_count = static_cast<uint8_t>(result.ja4_components.cipher_suites.size());
    result.ja4_components.extension_count = static_cast<uint8_t>(result.ja4_components.extensions.size());

    result.ja3_hash = calculate_ja3_hash(result.ja3_components);
    result.ja4_hash = calculate_ja4_hash(result.ja4_components);
    result.akamai_hash = calculate_akamai_hash(result.ja3_components);

    auto [profile, score] = match_browser_profile(result);
    result.matched_profile = profile;
    result.similarity_score = score;
    result.matches_known_browser = (profile != BrowserProfile::UNKNOWN) && (score >= 80.0);

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
