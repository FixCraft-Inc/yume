/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/stealth/tls_stealth.hpp"

#include "core/stealth/http_profile.hpp"

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/connect.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <atomic>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>

#include <nlohmann/json.hpp>

namespace yume::tls_stealth {

namespace {

// RFC 8701 §2.1: GREASE values reserved for cipher_suites,
// supported_groups, extensions, and ALPN. We pick one per category
// per-connection (via a rotating process-local counter). Different categories
// use different "buckets" of the
// wheel so they don't collide in a single ClientHello (RFC 8701
// §3.3: "the GREASE value used for one extension SHOULD be
// different from any other GREASE value used in the same
// ClientHello").
constexpr std::uint16_t kGreaseValues[16] = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
};
std::uint16_t pick_grease(unsigned bucket) {
    static std::atomic<unsigned> seed{0};
    const unsigned s = seed.fetch_add(1, std::memory_order_relaxed);
    return kGreaseValues[(s + bucket * 7u) & 0x0Fu];
}

std::string current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
#if defined(_WIN32)
    localtime_s(&tm, &time_t);
#else
    localtime_r(&time_t, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

struct VerificationEndpoint {
    std::string host;
    std::string authority;
    std::string path;
    uint16_t port{443};
};

std::string trim_copy(std::string value) {
    auto not_space = [](unsigned char ch) { return std::isspace(ch) == 0; };
    auto begin = std::find_if(value.begin(), value.end(), not_space);
    auto end = std::find_if(value.rbegin(), value.rend(), not_space).base();
    if (begin >= end) {
        return {};
    }
    return std::string(begin, end);
}

VerificationEndpoint parse_verification_endpoint(const std::string& input, uint16_t default_port) {
    std::string value = trim_copy(input);
    if (value.empty()) {
        throw std::runtime_error("TLS fingerprint test endpoint is empty");
    }
    const std::string https_prefix = "https://";
    const std::string http_prefix = "http://";
    if (value.rfind(https_prefix, 0) == 0) {
        value.erase(0, https_prefix.size());
    } else if (value.rfind(http_prefix, 0) == 0) {
        value.erase(0, http_prefix.size());
    }

    VerificationEndpoint endpoint;
    endpoint.port = default_port;

    const std::size_t slash = value.find('/');
    std::string authority = slash == std::string::npos ? value : value.substr(0, slash);
    endpoint.path = slash == std::string::npos ? "/api/all" : value.substr(slash);
    if (endpoint.path.empty()) {
        endpoint.path = "/api/all";
    } else if (endpoint.path.front() != '/') {
        endpoint.path.insert(endpoint.path.begin(), '/');
    }
    if (authority.empty()) {
        throw std::runtime_error("TLS fingerprint test endpoint is missing a host");
    }

    if (authority.front() == '[') {
        const std::size_t close = authority.find(']');
        if (close == std::string::npos) {
            throw std::runtime_error("Invalid IPv6 TLS fingerprint test endpoint");
        }
        endpoint.host = authority.substr(1, close - 1);
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') {
                throw std::runtime_error("Invalid TLS fingerprint test endpoint port");
            }
            endpoint.port = static_cast<uint16_t>(std::stoul(authority.substr(close + 2)));
        }
    } else {
        const std::size_t first_colon = authority.find(':');
        const std::size_t last_colon = authority.rfind(':');
        if (first_colon != std::string::npos && first_colon == last_colon) {
            endpoint.host = authority.substr(0, first_colon);
            endpoint.port = static_cast<uint16_t>(std::stoul(authority.substr(first_colon + 1)));
        } else {
            endpoint.host = authority;
        }
    }

    if (endpoint.host.empty()) {
        throw std::runtime_error("TLS fingerprint test endpoint is missing a host");
    }
    endpoint.authority = endpoint.host;
    if (endpoint.port != 443) {
        endpoint.authority += ":" + std::to_string(endpoint.port);
    }
    return endpoint;
}

void hpack_encode_integer(std::vector<uint8_t>& out,
                          uint32_t value,
                          uint8_t prefix_bits,
                          uint8_t prefix_mask) {
    const uint8_t prefix_max = static_cast<uint8_t>((1u << prefix_bits) - 1u);
    out.push_back(prefix_mask);
    if (value < prefix_max) {
        out.back() |= static_cast<uint8_t>(value);
        return;
    }
    out.back() |= prefix_max;
    value -= prefix_max;
    while (value >= 128) {
        out.push_back(static_cast<uint8_t>((value & 0x7fu) | 0x80u));
        value >>= 7;
    }
    out.push_back(static_cast<uint8_t>(value));
}

void hpack_encode_string(std::vector<uint8_t>& out, const std::string& value) {
    hpack_encode_integer(out, static_cast<uint32_t>(value.size()), 7, 0x00);
    out.insert(out.end(), value.begin(), value.end());
}

void hpack_encode_indexed_field(std::vector<uint8_t>& out, uint32_t index) {
    hpack_encode_integer(out, index, 7, 0x80);
}

void hpack_encode_literal_indexed_name(std::vector<uint8_t>& out,
                                       uint32_t name_index,
                                       const std::string& value) {
    hpack_encode_integer(out, name_index, 4, 0x00);
    hpack_encode_string(out, value);
}

std::vector<uint8_t> build_http2_request_headers(const VerificationEndpoint& endpoint) {
    std::vector<uint8_t> block;
    hpack_encode_indexed_field(block, 2);   // :method: GET
    hpack_encode_indexed_field(block, 7);   // :scheme: https
    hpack_encode_literal_indexed_name(block, 4, endpoint.path);       // :path
    hpack_encode_literal_indexed_name(block, 1, endpoint.authority);  // :authority
    // UA: pulled from yume::http_profile::active_client_ua() so that
    // --hide-in-the-crowd <chrome|firefox|…> on the client CLI is
    // reflected in stealth-probe traffic too. Defaults to the
    // historical "yume-tls-verify/1.0" if no profile was set.
    hpack_encode_literal_indexed_name(block, 58, yume::http_profile::active_client_ua());
    hpack_encode_literal_indexed_name(block, 19, "application/json");
    return block;
}

void append_http2_frame(std::vector<uint8_t>& out,
                        uint8_t type,
                        uint8_t flags,
                        uint32_t stream_id,
                        const std::vector<uint8_t>& payload) {
    const uint32_t length = static_cast<uint32_t>(payload.size());
    out.push_back(static_cast<uint8_t>((length >> 16) & 0xffu));
    out.push_back(static_cast<uint8_t>((length >> 8) & 0xffu));
    out.push_back(static_cast<uint8_t>(length & 0xffu));
    out.push_back(type);
    out.push_back(flags);
    out.push_back(static_cast<uint8_t>((stream_id >> 24) & 0x7fu));
    out.push_back(static_cast<uint8_t>((stream_id >> 16) & 0xffu));
    out.push_back(static_cast<uint8_t>((stream_id >> 8) & 0xffu));
    out.push_back(static_cast<uint8_t>(stream_id & 0xffu));
    out.insert(out.end(), payload.begin(), payload.end());
}

template <typename Stream>
void write_http2_ping_ack(Stream& stream, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> frame;
    append_http2_frame(frame, 0x6, 0x1, 0, payload);
    boost::asio::write(stream, boost::asio::buffer(frame));
}

template <typename Stream>
void write_http2_settings_ack(Stream& stream) {
    std::vector<uint8_t> frame;
    append_http2_frame(frame, 0x4, 0x1, 0, {});
    boost::asio::write(stream, boost::asio::buffer(frame));
}

std::string extract_http_body(const std::string& response) {
    const std::size_t header_end = response.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        throw std::runtime_error("TLS fingerprint verification returned an invalid HTTP response");
    }
    return response.substr(header_end + 4);
}

template <typename Stream>
std::string fetch_http11_json(Stream& stream, const VerificationEndpoint& endpoint) {
    const std::string request =
        "GET " + endpoint.path + " HTTP/1.1\r\n"
        "Host: " + endpoint.authority + "\r\n"
        "User-Agent: " + yume::http_profile::active_client_ua() + "\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n\r\n";
    boost::asio::write(stream, boost::asio::buffer(request));

    boost::system::error_code ec;
    std::string response;
    std::array<char, 4096> buffer{};
    for (;;) {
        const std::size_t n = stream.read_some(boost::asio::buffer(buffer), ec);
        if (n > 0) {
            response.append(buffer.data(), n);
        }
        if (ec == boost::asio::error::eof) {
            break;
        }
        if (ec) {
            throw boost::system::system_error(ec);
        }
    }
    return extract_http_body(response);
}

template <typename Stream>
std::string fetch_http2_json(Stream& stream, const VerificationEndpoint& endpoint) {
    std::vector<uint8_t> request;
    static constexpr char kClientPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    request.insert(request.end(), kClientPreface, kClientPreface + sizeof(kClientPreface) - 1);
    append_http2_frame(request, 0x4, 0x0, 0, {});
    append_http2_frame(request, 0x1, 0x5, 1, build_http2_request_headers(endpoint));
    boost::asio::write(stream, boost::asio::buffer(request));

    std::string body;
    bool end_stream = false;
    while (!end_stream) {
        std::array<uint8_t, 9> header{};
        boost::asio::read(stream, boost::asio::buffer(header));
        const uint32_t length = (static_cast<uint32_t>(header[0]) << 16)
            | (static_cast<uint32_t>(header[1]) << 8)
            | static_cast<uint32_t>(header[2]);
        const uint8_t type = header[3];
        const uint8_t flags = header[4];
        const uint32_t stream_id = ((static_cast<uint32_t>(header[5]) & 0x7fu) << 24)
            | (static_cast<uint32_t>(header[6]) << 16)
            | (static_cast<uint32_t>(header[7]) << 8)
            | static_cast<uint32_t>(header[8]);

        std::vector<uint8_t> payload(length);
        if (length > 0) {
            boost::asio::read(stream, boost::asio::buffer(payload));
        }

        switch (type) {
            case 0x0: {
                if (stream_id != 1) {
                    break;
                }
                size_t offset = 0;
                size_t payload_size = payload.size();
                if ((flags & 0x8u) != 0) {
                    if (payload.empty()) {
                        throw std::runtime_error("Invalid padded HTTP/2 DATA frame");
                    }
                    const size_t padding = payload.front();
                    if (padding + 1 > payload_size) {
                        throw std::runtime_error("Invalid HTTP/2 DATA padding");
                    }
                    offset = 1;
                    payload_size -= padding + 1;
                }
                body.append(reinterpret_cast<const char*>(payload.data() + offset), payload_size);
                if ((flags & 0x1u) != 0) {
                    end_stream = true;
                }
                break;
            }
            case 0x1:
            case 0x9:
                if (stream_id == 1 && (flags & 0x1u) != 0) {
                    end_stream = true;
                }
                break;
            case 0x3:
                if (stream_id == 1) {
                    throw std::runtime_error("HTTP/2 stream reset during TLS fingerprint verification");
                }
                break;
            case 0x4:
                if ((flags & 0x1u) == 0) {
                    write_http2_settings_ack(stream);
                }
                break;
            case 0x6:
                if ((flags & 0x1u) == 0) {
                    write_http2_ping_ack(stream, payload);
                }
                break;
            case 0x7:
                if (body.empty()) {
                    throw std::runtime_error("HTTP/2 connection closed before TLS fingerprint response body arrived");
                }
                end_stream = true;
                break;
            default:
                break;
        }
    }
    return body;
}

tls_fingerprint::FingerprintData parse_tls_verify_response(const std::string& body) {
    const auto json = nlohmann::json::parse(body);
    tls_fingerprint::FingerprintData fingerprint;

    if (json.contains("tls") && json["tls"].is_object()) {
        const auto& tls = json["tls"];
        fingerprint.ja3_hash = tls.value("ja3_hash", "");
        fingerprint.ja4_hash = tls.value("ja4", tls.value("ja4_hash", ""));
        if (tls.contains("extensions") && tls["extensions"].is_array()) {
            for (const auto& ext : tls["extensions"]) {
                if (!ext.is_object()) {
                    continue;
                }
                const std::string name = ext.value("name", "");
                if (name.find("application_layer_protocol_negotiation") == std::string::npos) {
                    continue;
                }
                if (!ext.contains("protocols") || !ext["protocols"].is_array()) {
                    continue;
                }
                for (const auto& proto : ext["protocols"]) {
                    if (proto.is_string()) {
                        fingerprint.alpn_protocols.push_back(proto.get<std::string>());
                    }
                }
            }
        }
    }
    if (json.contains("http2") && json["http2"].is_object()) {
        fingerprint.akamai_hash = json["http2"].value("akamai_fingerprint_hash", "");
    }

    auto [profile, score] = tls_fingerprint::match_browser_profile(fingerprint);
    fingerprint.matched_profile = profile;
    fingerprint.similarity_score = score;
    fingerprint.matches_known_browser =
        (profile != tls_fingerprint::BrowserProfile::UNKNOWN) && (score >= 80.0);
    return fingerprint;
}

}  // namespace

std::map<uint16_t, std::string> cipher_name_map = {
    {0x1301, "TLS_AES_128_GCM_SHA256"},
    {0x1302, "TLS_AES_256_GCM_SHA384"},
    {0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
    {0xc02c, "ECDHE-ECDSA-AES256-GCM-SHA384"},
    {0xc02b, "ECDHE-ECDSA-AES128-GCM-SHA256"},
    {0xc030, "ECDHE-RSA-AES256-GCM-SHA384"},
    {0xc02f, "ECDHE-RSA-AES128-GCM-SHA256"},
    {0xc024, "ECDHE-ECDSA-AES256-SHA384"},
    {0xc023, "ECDHE-ECDSA-AES128-SHA256"},
    {0xc028, "ECDHE-RSA-AES256-SHA384"},
    {0xc027, "ECDHE-RSA-AES128-SHA256"},
};

std::map<uint16_t, std::string> group_name_map = {
    {0x001d, "X25519"},
    {0x0017, "secp256r1"},
    {0x0018, "secp384r1"},
    {0x0019, "secp521r1"},
    {0x001e, "X448"},
};

std::string cipher_suite_name(uint16_t code) {
    auto it = cipher_name_map.find(code);
    if (it != cipher_name_map.end()) {
        return it->second;
    }
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(4) << std::setfill('0') << code;
    return oss.str();
}

std::string supported_group_name(uint16_t code) {
    auto it = group_name_map.find(code);
    if (it != group_name_map.end()) {
        return it->second;
    }
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(4) << std::setfill('0') << code;
    return oss.str();
}

std::string cipher_list_to_openssl_string(const std::vector<uint16_t>& cipher_suites) {
    std::ostringstream oss;
    for (size_t i = 0; i < cipher_suites.size(); ++i) {
        if (i > 0) oss << ":";
        oss << cipher_suite_name(cipher_suites[i]);
    }
    return oss.str();
}

std::string groups_to_openssl_string(const std::vector<uint16_t>& groups) {
    std::ostringstream oss;
    for (size_t i = 0; i < groups.size(); ++i) {
        if (i > 0) oss << ":";
        oss << supported_group_name(groups[i]);
    }
    return oss.str();
}

StealthContext::StealthContext(const StealthConfig& config)
    : config_(config)
    , ssl_context_(boost::asio::ssl::context::tlsv13_client)
    , current_profile_(config.target_profile) {
    ssl_context_.set_options(boost::asio::ssl::context::default_workarounds);

    if (config_.enabled) {
        apply_stealth_profile(current_profile_);
    }
}

StealthContext::~StealthContext() = default;

boost::asio::ssl::context& StealthContext::get_context() {
    return ssl_context_;
}

void StealthContext::apply_stealth_profile(tls_fingerprint::BrowserProfile profile) {
    current_profile_ = profile;

    auto profile_info = tls_fingerprint::get_browser_profile_info(profile);
    if (!profile_info) {
        profile_info = tls_fingerprint::get_browser_profile_info(
            cover_profile::active().tls_profile);
        if (!profile_info) return;
    }

    configure_cipher_suites(profile_info->cipher_suites);
    configure_supported_groups(profile_info->supported_groups);
    configure_signature_algorithms(profile_info->signature_algorithms);
    configure_alpn(profile_info->alpn_protocols);

    SSL_CTX* ctx = ssl_context_.native_handle();
    const auto& cover = cover_profile::active();
    if (SSL_CTX_set_min_proto_version(ctx, cover.tls_min_version) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, cover.tls_max_version) != 1) {
        throw std::runtime_error(
            "failed to enforce cover-profile TLS version bounds");
    }

    // RFC 8701 GREASE: register one extension at a GREASE-range type
    // (0x0A0A, 0x1A1A, …, 0xFAFA, rotated per-connection via
    // pick_grease). add_cb returning 1 + setting *out_len=0 emits
    // the extension with an empty payload, a standards-conformant GREASE
    // shape. SSL_EXT_CLIENT_HELLO scopes it to
    // outbound ClientHellos only. Registration once per CTX; the
    // callback is invoked per handshake.
    static const auto grease_add_cb =
        +[](SSL*, unsigned int /*ext_type*/, unsigned int /*context*/,
            const unsigned char** out, size_t* out_len,
            X509* /*x*/, size_t /*chainidx*/, int* /*al*/,
            void* /*add_arg*/) -> int {
            *out = nullptr;
            *out_len = 0;
            return 1;
        };
    static const auto grease_free_cb =
        +[](SSL*, unsigned int /*ext_type*/, unsigned int /*context*/,
            const unsigned char* /*out*/, void* /*add_arg*/) {};
    const unsigned int grease_ext_type = pick_grease(/*bucket=*/1);
    // Verified against OpenSSL 3.5.6 (Debian 13) by hex-dumping the
    // rendered ClientHello via the JA3-self-check BIO-mem pattern:
    // returns 1, and the extension appears at the front of the
    // extensions block (e.g. "7a 7a 00 00" — GREASE type, length 0
    // payload). Best-effort: a 0 return (already registered on
    // rotate_profile re-entry, or hypothetical future OpenSSL that
    // rejects the type) is harmless — handshake proceeds normally.
    (void)SSL_CTX_add_custom_ext(
        ctx, grease_ext_type, SSL_EXT_CLIENT_HELLO,
        grease_add_cb, grease_free_cb, nullptr,
        /*parse_cb=*/nullptr, /*parse_arg=*/nullptr);
}

void StealthContext::configure_cipher_suites(const std::vector<uint16_t>& suites) {
    SSL_CTX* ctx = ssl_context_.native_handle();
    // Split the profile's cipher list into TLS 1.3 vs TLS 1.2 IDs.
    // OpenSSL takes them through two separate APIs and preserves
    // each's emit order, which is what we need for per-profile JA3
    // divergence. TLS 1.3 suites are 0x1301-0x1305; everything else
    // is TLS 1.2 or lower.
    std::vector<std::uint16_t> tls13_ids;
    std::vector<std::uint16_t> tls12_ids;
    for (std::uint16_t s : suites) {
        if (s >= 0x1301 && s <= 0x1305) tls13_ids.push_back(s);
        else                            tls12_ids.push_back(s);
    }

    auto tls13_name = [](std::uint16_t id) -> const char* {
        switch (id) {
            case 0x1301: return "TLS_AES_128_GCM_SHA256";
            case 0x1302: return "TLS_AES_256_GCM_SHA384";
            case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
            case 0x1304: return "TLS_AES_128_CCM_SHA256";
            case 0x1305: return "TLS_AES_128_CCM_8_SHA256";
            default:     return nullptr;
        }
    };
    std::string tls13_str;
    for (std::uint16_t id : tls13_ids) {
        const char* n = tls13_name(id);
        if (!n) continue;
        if (!tls13_str.empty()) tls13_str += ":";
        tls13_str += n;
    }
    if (tls13_str.empty()) {
        // Fallback to the historical default if the profile didn't list
        // any TLS 1.3 suites (e.g. an outdated profile entry).
        tls13_str = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
    }
    SSL_CTX_set_ciphersuites(ctx, tls13_str.c_str());

    std::string tls12_str = cipher_list_to_openssl_string(tls12_ids);
    if (tls12_str.empty()) {
        tls12_str = cipher_list_to_openssl_string(suites);  // legacy fallback
    }
    SSL_CTX_set_cipher_list(ctx, tls12_str.c_str());
}

void StealthContext::configure_supported_groups(const std::vector<uint16_t>& groups) {
    // Use the name-based string API. The uint16-array API
    // (SSL_CTX_set1_groups) was tried during 1.x development but
    // OpenSSL 3.5 silently rejects any unknown / GREASE-range
    // values in the array AND falls back to its own defaults
    // (which include 0x11ec = X25519MLKEM768) — net effect: the
    // supported_groups extension drifted away from our profile
    // data. Stick with the string form, which validates per name
    // and emits the result verbatim when every name is known.
    std::string groups_string = groups_to_openssl_string(groups);
    SSL_CTX* ctx = ssl_context_.native_handle();
    SSL_CTX_set1_groups_list(ctx, groups_string.c_str());
}

void StealthContext::configure_signature_algorithms(const std::vector<uint16_t>& algorithms) {
    // Map IANA TLS SignatureScheme values to OpenSSL sigalg string
    // tokens. The string passed to SSL_CTX_set1_sigalgs_list is a
    // colon-separated list of names from RFC 8446 §4.2.3 / OpenSSL's
    // X509 namespace; the emit order in the ClientHello matches the
    // string order, which is exactly what we need for per-profile
    // sigalg differentiation in JA4 (and helps cluster the right
    // browser even where JA3 doesn't cover sigalgs).
    SSL_CTX* ctx = ssl_context_.native_handle();
    if (algorithms.empty()) {
        SSL_CTX_set1_sigalgs_list(ctx,
            "ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:"
            "RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:"
            "RSA+SHA256:RSA+SHA384:RSA+SHA512");
        return;
    }
    std::string list;
    auto add = [&](const char* tok) {
        if (!list.empty()) list += ":";
        list += tok;
    };
    for (std::uint16_t a : algorithms) {
        switch (a) {
            case 0x0403: add("ECDSA+SHA256"); break;
            case 0x0503: add("ECDSA+SHA384"); break;
            case 0x0603: add("ECDSA+SHA512"); break;
            case 0x0804: add("rsa_pss_rsae_sha256"); break;
            case 0x0805: add("rsa_pss_rsae_sha384"); break;
            case 0x0806: add("rsa_pss_rsae_sha512"); break;
            case 0x0809: add("rsa_pss_pss_sha256"); break;
            case 0x080a: add("rsa_pss_pss_sha384"); break;
            case 0x080b: add("rsa_pss_pss_sha512"); break;
            case 0x0401: add("RSA+SHA256"); break;
            case 0x0501: add("RSA+SHA384"); break;
            case 0x0601: add("RSA+SHA512"); break;
            case 0x0807: add("ed25519"); break;
            case 0x0808: add("ed448"); break;
            default: break;  // ignore unknown IDs
        }
    }
    if (list.empty()) {
        // Fall back rather than emit a sigalgs ext we don't want.
        SSL_CTX_set1_sigalgs_list(ctx,
            "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256");
    } else {
        SSL_CTX_set1_sigalgs_list(ctx, list.c_str());
    }
}

void StealthContext::configure_alpn(const std::vector<std::string>& protocols) {
    std::vector<unsigned char> alpn_data;
    for (const auto& proto : protocols) {
        alpn_data.push_back(static_cast<unsigned char>(proto.size()));
        alpn_data.insert(alpn_data.end(), proto.begin(), proto.end());
    }

    SSL_CTX* ctx = ssl_context_.native_handle();
    SSL_CTX_set_alpn_protos(ctx, alpn_data.data(),
                            static_cast<unsigned int>(alpn_data.size()));
}

void StealthContext::log_connection_metrics(const ConnectionMetrics& metrics) {
    if (!config_.log_fingerprints || config_.log_file_path.empty()) {
        return;
    }
    
    // Log to file in JSON format
    nlohmann::json j;
    j["connection_id"] = metrics.connection_id;
    j["timestamp"] = metrics.timestamp;
    j["server_host"] = metrics.server_host;
    j["server_port"] = metrics.server_port;
    j["profile"] = tls_fingerprint::browser_profile_name(metrics.used_profile);
    j["ja3_hash"] = metrics.fingerprint.ja3_hash;
    j["ja4_hash"] = metrics.fingerprint.ja4_hash;
    j["handshake_succeeded"] = metrics.handshake_succeeded;
    j["handshake_duration_ms"] = metrics.handshake_duration_ms;
    if (!metrics.error_message.empty()) {
        j["error"] = metrics.error_message;
    }
    
    std::ofstream log_file(config_.log_file_path, std::ios::app);
    if (log_file) {
        log_file << j.dump() << "\n";
    }

}

boost::asio::ssl::context generate_stealth_tls_config(
    tls_fingerprint::BrowserProfile profile,
    bool verbose) {
    StealthConfig config;
    config.enabled = true;
    config.target_profile = profile;

    StealthContext stealth_ctx(config);

    if (verbose) {
        std::cout << "Generated stealth TLS configuration for: "
                  << tls_fingerprint::browser_profile_name(profile) << "\n";
    }

    return std::move(stealth_ctx.get_context());
}

std::optional<SelfFingerprint> compute_self_fingerprint(
    tls_fingerprint::BrowserProfile profile) {
    // Build a stealth client context for the profile.
    StealthConfig config;
    config.enabled = true;
    config.target_profile = profile;
    StealthContext stealth_ctx(config);

    SSL* ssl = SSL_new(stealth_ctx.get_context().native_handle());
    if (!ssl) return std::nullopt;

    // BIO mem pair: SSL writes into write_bio (we own the other end).
    BIO* read_bio  = BIO_new(BIO_s_mem());
    BIO* write_bio = BIO_new(BIO_s_mem());
    if (!read_bio || !write_bio) {
        if (read_bio) BIO_free(read_bio);
        if (write_bio) BIO_free(write_bio);
        SSL_free(ssl);
        return std::nullopt;
    }
    SSL_set_bio(ssl, read_bio, write_bio);  // SSL takes ownership
    SSL_set_connect_state(ssl);
    SSL_set_tlsext_host_name(ssl, "example.com");

    // Drive the handshake once. It will fail (no server to read from)
    // but the ClientHello has already been written to write_bio.
    SSL_do_handshake(ssl);

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(write_bio, &bptr);
    if (!bptr || bptr->length == 0) {
        SSL_free(ssl);
        return std::nullopt;
    }

    // Parse the ClientHello. The record-layer prefix (1 byte type +
    // 2 bytes version + 2 bytes length = 5 bytes) sits in front of
    // the handshake message; parse_client_hello expects the
    // ClientHello including the handshake-message wrapper.
    const std::uint8_t* data = reinterpret_cast<const std::uint8_t*>(bptr->data);
    std::size_t length = static_cast<std::size_t>(bptr->length);
    if (length < 6 || data[0] != 0x16) {  // TLS record content_type = handshake
        SSL_free(ssl);
        return std::nullopt;
    }
    // Skip the 5-byte record header; the next byte is the handshake
    // type (0x01 = ClientHello) which parse_client_hello expects.
    auto fp = tls_fingerprint::parse_client_hello(data + 5, length - 5);
    SSL_free(ssl);

    SelfFingerprint out;
    out.ja3_hash    = fp.ja3_hash;
    out.fingerprint = std::move(fp);
    return out;
}

StealthConnectionResult connect_with_stealth_mode(
    boost::asio::io_context& io_context,
    const std::string& server_host,
    uint16_t port,
    tls_fingerprint::BrowserProfile profile,
    const StealthConfig& config) {
    StealthConnectionResult result;
    result.metrics.server_host = server_host;
    result.metrics.server_port = port;
    result.metrics.used_profile = profile;
    result.metrics.timestamp = current_timestamp();

    auto start_time = std::chrono::steady_clock::now();

    try {
        StealthContext stealth_ctx(config);
        boost::asio::ip::tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve(server_host, std::to_string(port));
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(
            io_context, stealth_ctx.get_context());
        SSL_set_tlsext_host_name(stream.native_handle(), server_host.c_str());
        boost::asio::connect(stream.lowest_layer(), endpoints);
        stream.handshake(boost::asio::ssl::stream_base::client);

        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time);

        result.success = true;
        result.metrics.handshake_succeeded = true;
        result.metrics.handshake_duration_ms = static_cast<uint32_t>(duration.count());

        boost::system::error_code ec;
        stream.lowest_layer().close(ec);
    } catch (const std::exception& e) {
        result.success = false;
        result.error_message = e.what();
        result.metrics.handshake_succeeded = false;
        result.metrics.error_message = e.what();
    }

    return result;
}

FingerprintTestResult evaluate_tls_fingerprint(
    const std::string& test_endpoint,
    uint16_t port,
    tls_fingerprint::BrowserProfile target_profile) {
    FingerprintTestResult result;
    try {
        const VerificationEndpoint endpoint = parse_verification_endpoint(test_endpoint, port);
        boost::asio::io_context io_context;
        StealthConfig config;
        config.enabled = true;
        config.target_profile = target_profile;

        StealthContext stealth_ctx(config);
        boost::asio::ip::tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve(endpoint.host, std::to_string(endpoint.port));
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(
            io_context, stealth_ctx.get_context());
        SSL_set_tlsext_host_name(stream.native_handle(), endpoint.host.c_str());
        boost::asio::connect(stream.lowest_layer(), endpoints);
        stream.handshake(boost::asio::ssl::stream_base::client);

        const unsigned char* alpn_data = nullptr;
        unsigned int alpn_len = 0;
        SSL_get0_alpn_selected(stream.native_handle(), &alpn_data, &alpn_len);
        const std::string negotiated_alpn(
            reinterpret_cast<const char*>(alpn_data),
            static_cast<size_t>(alpn_len));

        const std::string body = negotiated_alpn == "h2"
            ? fetch_http2_json(stream, endpoint)
            : fetch_http11_json(stream, endpoint);

        result.detected_fingerprint = parse_tls_verify_response(body);
        result.ja3_from_server = result.detected_fingerprint.ja3_hash;
        result.ja4_from_server = result.detected_fingerprint.ja4_hash;

        auto profile_info = tls_fingerprint::get_browser_profile_info(target_profile);
        if (profile_info) {
            result.matches_target_profile =
                result.detected_fingerprint.ja3_hash == profile_info->ja3_hash
                && result.detected_fingerprint.ja4_hash == profile_info->ja4_hash;
        }
        result.success = !result.detected_fingerprint.ja3_hash.empty()
            || !result.detected_fingerprint.ja4_hash.empty();
        if (!result.success) {
            throw std::runtime_error("TLS fingerprint test endpoint returned no JA3/JA4 hashes");
        }

        boost::system::error_code ec;
        stream.lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        stream.lowest_layer().close(ec);
    } catch (const std::exception& e) {
        result.success = false;
        result.error_message = e.what();
    }
    
    return result;
}

MetricsLogger::MetricsLogger(const std::string& log_file_path)
    : log_file_path_(log_file_path) {
    
    if (!log_file_path_.empty()) {
        log_stream_ = std::make_unique<std::ofstream>(
            log_file_path_, std::ios::app);
    }
}

MetricsLogger::~MetricsLogger() {
    flush();
}

void MetricsLogger::log_metrics(const ConnectionMetrics& metrics) {
    if (!log_stream_ || !log_stream_->is_open()) {
        return;
    }
    
    nlohmann::json j;
    j["connection_id"] = metrics.connection_id;
    j["timestamp"] = metrics.timestamp;
    j["server_host"] = metrics.server_host;
    j["server_port"] = metrics.server_port;
    j["profile"] = tls_fingerprint::browser_profile_name(metrics.used_profile);
    j["ja3_hash"] = metrics.fingerprint.ja3_hash;
    j["ja4_hash"] = metrics.fingerprint.ja4_hash;
    j["handshake_succeeded"] = metrics.handshake_succeeded;
    j["handshake_duration_ms"] = metrics.handshake_duration_ms;
    
    if (!metrics.error_message.empty()) {
        j["error"] = metrics.error_message;
    }
    
    *log_stream_ << j.dump() << "\n";
}

void MetricsLogger::flush() {
    if (log_stream_) {
        log_stream_->flush();
    }
}

StealthManager& StealthManager::instance() {
    static StealthManager instance;
    return instance;
}

void StealthManager::initialize(const StealthConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
    context_ = std::make_unique<StealthContext>(config);
    
    if (!config.log_file_path.empty()) {
        logger_ = std::make_unique<MetricsLogger>(config.log_file_path);
    }
}

StealthContext& StealthManager::get_context() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!context_) {
        StealthConfig default_config;
        default_config.enabled = true;
        context_ = std::make_unique<StealthContext>(default_config);
    }
    return *context_;
}

void StealthManager::log_connection(const ConnectionMetrics& metrics) {
    std::lock_guard<std::mutex> lock(mutex_);

    stats_.total_connections++;
    if (metrics.handshake_succeeded) {
        stats_.successful_connections++;
    } else {
        stats_.failed_connections++;
    }

    stats_.profile_usage[metrics.used_profile]++;

    double total_duration = stats_.average_handshake_duration_ms *
                            (stats_.total_connections - 1);
    total_duration += metrics.handshake_duration_ms;
    stats_.average_handshake_duration_ms = total_duration / stats_.total_connections;

    if (logger_) {
        logger_->log_metrics(metrics);
    }
}

StealthManager::Statistics StealthManager::get_statistics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

}  // namespace yume::tls_stealth
