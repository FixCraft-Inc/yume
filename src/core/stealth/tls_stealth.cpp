/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/stealth/tls_stealth.hpp"

#include "core/security/crypto.hpp"
#include "core/stealth/cover_profile.hpp"
#include "core/stealth/http_profile.hpp"
#include "core/stealth/tls_verify_fetch.hpp"
#include "util.hpp"

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/connect.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <atomic>

#if !defined(_WIN32)
#include <sys/socket.h>
#include <sys/time.h>
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdio>
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

// Downstream OpenSSL control kept numeric here on purpose. Calling the stable
// SSL_CTX_ctrl symbol avoids a new dynamic-link dependency; stock libssl
// returns 0 for the unknown command and the native Chrome backend fails closed.
constexpr int kYumeChromeClientHelloCtrl = 0x5943;

// RFC 8701 §2.1: GREASE values reserved for cipher_suites,
// supported_groups, extensions, and ALPN. This backend currently uses the
// picker while configuring injected extension types on an SSL_CTX. OpenSSL
// binds each custom-extension number at registration, so a long-lived context
// reuses it across connections. Different categories use different buckets of the
// wheel so they don't collide in a single ClientHello (RFC 8701
// §3.3: "the GREASE value used for one extension SHOULD be
// different from any other GREASE value used in the same
// ClientHello").
constexpr std::uint16_t kGreaseValues[16] = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
};
std::uint16_t pick_grease(unsigned bucket) {
    // The starting point must come from the CSPRNG, not from zero. A fixed
    // seed makes the first ClientHello of every process on every install carry
    // the same two GREASE values -- constant where a browser's are random,
    // which is itself the distinguisher this extension exists to avoid.
    static std::atomic<unsigned> seed{[] {
        try {
            const auto draw = crypto::random_bytes(2);
            return static_cast<unsigned>((draw[0] << 8) | draw[1]);
        } catch (const std::exception&) {
            // Never fail a handshake over GREASE selection; a clock-derived
            // start is still install-varying, unlike a constant.
            return static_cast<unsigned>(
                std::chrono::steady_clock::now().time_since_epoch().count());
        }
    }()};
    const unsigned s = seed.fetch_add(1, std::memory_order_relaxed);
    // bucket * 7 keeps two GREASE slots in one ClientHello on different wheel
    // positions: 7 and 14 are distinct mod 16.
    return kGreaseValues[(s + bucket * 7u) & 0x0Fu];
}

// Bodies for extensions stock OpenSSL will not emit itself. SSL_CTX_add_custom_ext
// accepts any extension number OpenSSL does not already own internally, which
// covers the GREASE range, SCT (0x0012), ALPS (0x44cd) and ECH (0xfe0d). The
// buffer handed back through *out must stay valid until free_cb runs, so each
// body is heap-allocated per handshake and released there.
std::vector<std::uint8_t> build_alps_body() {
    // ALPN-shaped protocol vector: u16 list length, then u8-prefixed names.
    std::vector<std::uint8_t> list;
    for (std::string_view proto : cover_profile::active().tls_alps_protocols) {
        list.push_back(static_cast<std::uint8_t>(proto.size()));
        list.insert(list.end(), proto.begin(), proto.end());
    }
    std::vector<std::uint8_t> body;
    body.push_back(static_cast<std::uint8_t>(list.size() >> 8));
    body.push_back(static_cast<std::uint8_t>(list.size() & 0xFFU));
    body.insert(body.end(), list.begin(), list.end());
    return body;
}

std::vector<std::uint8_t> build_grease_ech_body() {
    // draft-ietf-tls-esni outer ECHClientHello carrying random bytes. A browser
    // emits exactly this shape whenever it holds no ECHConfig for the
    // destination, which is the common case, so random content IS the correct
    // content here -- no HPKE operation is performed, and none is needed. The
    // permitted total lengths come from the captured browser.
    const auto lengths = cover_profile::active().tls_ech_grease_lengths;
    // 1 type + 2 KDF + 2 AEAD + 1 config_id + 2 enc length + 32 enc + 2 payload
    // length. Keep in step with ECH_OUTER_OVERHEAD in the generator.
    constexpr std::size_t kOverhead = 42;
    constexpr std::size_t kEncLen = 32;  // X25519 HPKE encapsulated key
    std::size_t total = lengths.empty()
        ? kOverhead + 144
        : lengths[crypto::random_bytes(1)[0] % lengths.size()];
    if (total <= kOverhead) total = kOverhead + 144;

    const std::size_t payload_len = total - kOverhead;
    const auto entropy = crypto::random_bytes(1 + kEncLen + payload_len);

    std::vector<std::uint8_t> body;
    body.reserve(total);
    body.push_back(0x00);                     // ECHClientHelloType.outer
    body.push_back(0x00); body.push_back(0x01);  // HKDF-SHA256
    body.push_back(0x00); body.push_back(0x01);  // AES-128-GCM
    body.push_back(entropy[0]);               // config_id
    body.push_back(0x00); body.push_back(static_cast<std::uint8_t>(kEncLen));
    body.insert(body.end(), entropy.begin() + 1, entropy.begin() + 1 + kEncLen);
    body.push_back(static_cast<std::uint8_t>(payload_len >> 8));
    body.push_back(static_cast<std::uint8_t>(payload_len & 0xFFU));
    body.insert(body.end(), entropy.begin() + 1 + kEncLen, entropy.end());
    return body;
}

std::vector<std::uint8_t> build_injected_body(
    cover_profile::InjectedExtensionPayload kind) {
    using P = cover_profile::InjectedExtensionPayload;
    switch (kind) {
        case P::Empty:         return {};
        case P::GreaseEmpty:   return {};
        case P::GreaseOneByte: return {0x00};
        case P::Alps:          return build_alps_body();
        case P::GreaseEch:     return build_grease_ech_body();
    }
    return {};
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
    // The TLS 1.2 tail of the captured Chrome cipher list. Without these the
    // profile's suites silently fall back to a hex string, which OpenSSL
    // rejects, and the offered list is truncated to whatever happened to map.
    {0xcca9, "ECDHE-ECDSA-CHACHA20-POLY1305"},
    {0xcca8, "ECDHE-RSA-CHACHA20-POLY1305"},
    {0xc009, "ECDHE-ECDSA-AES128-SHA"},
    {0xc00a, "ECDHE-ECDSA-AES256-SHA"},
    {0xc013, "ECDHE-RSA-AES128-SHA"},
    {0xc014, "ECDHE-RSA-AES256-SHA"},
    {0x009c, "AES128-GCM-SHA256"},
    {0x009d, "AES256-GCM-SHA384"},
    {0x002f, "AES128-SHA"},
    {0x0035, "AES256-SHA"},
};

std::map<uint16_t, std::string> group_name_map = {
    // Hybrid post-quantum key exchange, and the group real Chrome 151
    // negotiates against the committed cover capture. OpenSSL only gained an
    // emitter for it in 3.5; on an older library SSL_CTX_set1_groups_list
    // rejects the whole list, so configure_supported_groups() drops unknown
    // names rather than failing the connection.
    {0x11ec, "X25519MLKEM768"},
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

// A "*" prefix tells SSL_CTX_set1_groups_list to generate a key_share for that
// group. Without it OpenSSL shares only the first group, while a browser
// offering a hybrid and a classical share sends both -- so the prefix is what
// closes the key_share count against the capture.
std::string groups_to_openssl_string(const std::vector<uint16_t>& groups,
                                     const std::vector<uint16_t>& key_share_groups) {
    std::ostringstream oss;
    for (size_t i = 0; i < groups.size(); ++i) {
        if (i > 0) oss << ":";
        if (std::find(key_share_groups.begin(), key_share_groups.end(),
                      groups[i]) != key_share_groups.end()) {
            oss << "*";
        }
        oss << supported_group_name(groups[i]);
    }
    return oss.str();
}

std::string groups_to_openssl_string(const std::vector<uint16_t>& groups) {
    return groups_to_openssl_string(groups, {});
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
        if (!profile_info) {
            throw std::runtime_error("no TLS profile data is available");
        }
    }

    SSL_CTX* ctx = ssl_context_.native_handle();
    if (config_.native_chrome_client_hello &&
        SSL_CTX_ctrl(ctx, kYumeChromeClientHelloCtrl, 1, nullptr) != 1) {
        throw std::runtime_error(
            "tls_backend openssl-chrome151 requires YUME's pinned, patched "
            "OpenSSL 3.5.7; stock libssl cannot provide Chrome ClientHello parity");
    }

    configure_cipher_suites(profile_info->cipher_suites);
    configure_supported_groups(profile_info->supported_groups,
                               profile_info->key_share_groups);
    configure_signature_algorithms(profile_info->signature_algorithms);
    configure_alpn(profile_info->alpn_protocols);

    const auto& cover = cover_profile::active();
    if (SSL_CTX_set_min_proto_version(ctx, cover.tls_min_version) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, cover.tls_max_version) != 1) {
        throw std::runtime_error(
            "failed to enforce cover-profile TLS version bounds");
    }

    // Chrome does not offer encrypt_then_mac; OpenSSL does by default. Dropping
    // it closes the one extension we would otherwise emit that the capture
    // does not contain.
    if (cover.tls_no_encrypt_then_mac) {
        SSL_CTX_set_options(ctx, SSL_OP_NO_ENCRYPT_THEN_MAC);
    }
    // status_request (0x0005) is internally owned by OpenSSL, so add_custom_ext
    // refuses it; the dedicated setter emits the same 5-byte body the capture
    // records.
    if (cover.tls_status_request_ocsp) {
        if (SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp) != 1) {
            throw std::runtime_error(
                "failed to install the cover-profile OCSP status request");
        }
    }
    // compress_certificate (0x001b). OpenSSL defaults to advertising every
    // algorithm the build carries -- zlib+zstd on a stock Debian build, a
    // 5-byte body -- while the capture offers exactly one, a 3-byte body.
    //
    // This is a build-time limit, not an API one: set1_cert_comp_preference
    // returns 0 for an algorithm the library was not compiled with. Configure
    // OpenSSL with enable-brotli (scripts/ensure-openssl.sh does) to satisfy
    // the profile. The native Chrome backend fails closed if it cannot; the
    // explicitly selected diagnostic backend records the degradation.
    configure_cert_compression(cover.tls_cert_compression);

    // Extensions OpenSSL will not emit itself, driven entirely from the
    // registry so that a new browser profile is a data change. add_cb returning
    // 1 emits the extension; SSL_EXT_CLIENT_HELLO scopes it to outbound
    // ClientHellos. Registration happens once per CTX, the callback runs per
    // handshake, so per-connection randomness (GREASE ECH body) is drawn there.
    //
    // Verified against OpenSSL 3.5.6 (Debian 13) by dumping the rendered
    // ClientHello: every type below returns 1. A 0 return is survivable --
    // it means the type is already registered (rotate_profile re-entry) or a
    // future OpenSSL claimed the number -- but it silently narrows the
    // fingerprint, so it is counted and reported rather than ignored.
    static const auto injected_add_cb =
        +[](SSL*, unsigned int /*ext_type*/, unsigned int /*context*/,
            const unsigned char** out, size_t* out_len,
            X509* /*x*/, size_t /*chainidx*/, int* al,
            void* add_arg) -> int {
            const auto encoded = reinterpret_cast<std::uintptr_t>(add_arg);
            const bool fail_closed = (encoded & 0x100U) != 0;
            const auto kind = static_cast<cover_profile::InjectedExtensionPayload>(
                encoded & 0xFFU);
            std::vector<std::uint8_t> body;
            try {
                body = build_injected_body(kind);
            } catch (const std::exception&) {
                if (fail_closed && al != nullptr) *al = SSL_AD_INTERNAL_ERROR;
                return fail_closed ? -1 : 0;
            }
            if (body.empty()) {
                *out = nullptr;
                *out_len = 0;
                return 1;
            }
            auto* buffer = new (std::nothrow) std::uint8_t[body.size()];
            if (buffer == nullptr) {
                if (fail_closed && al != nullptr) *al = SSL_AD_INTERNAL_ERROR;
                return fail_closed ? -1 : 0;
            }
            std::copy(body.begin(), body.end(), buffer);
            *out = buffer;
            *out_len = body.size();
            return 1;
        };
    static const auto injected_free_cb =
        +[](SSL*, unsigned int /*ext_type*/, unsigned int /*context*/,
            const unsigned char* out, void* /*add_arg*/) {
            delete[] out;
        };

    std::size_t rejected = 0;
    std::size_t slot = 0;
    for (const auto& injected : cover.tls_injected_extensions) {
        // The patched backend generates its two GREASE extension slots inside
        // libssl so they can vary per connection and bracket the shuffled
        // middle block. Registering the diagnostic callbacks as well would
        // emit four GREASE extensions.
        if (config_.native_chrome_client_hello && injected.type == 0) {
            continue;
        }
        // A registry type of 0 means "pick an RFC 8701 GREASE value while this
        // SSL_CTX is configured". The bucket is the slot index, so the two
        // registered GREASE extensions cannot collide (RFC 8701 §3.3).
        const unsigned int ext_type =
            injected.type != 0 ? injected.type
                               : pick_grease(static_cast<unsigned>(++slot));
        if (SSL_CTX_add_custom_ext(
                ctx, ext_type, SSL_EXT_CLIENT_HELLO,
                injected_add_cb, injected_free_cb,
                reinterpret_cast<void*>(
                    static_cast<std::uintptr_t>(injected.payload) |
                    (config_.native_chrome_client_hello ? 0x100U : 0U)),
                /*parse_cb=*/nullptr, /*parse_arg=*/nullptr) != 1) {
            ++rejected;
        }
    }
    if (rejected != 0 && config_.native_chrome_client_hello) {
        throw std::runtime_error(
            "patched OpenSSL refused " + std::to_string(rejected) +
            " required Chrome ClientHello extension(s)");
    }
    if (rejected != 0) {
        util::log_warn("tls: " + std::to_string(rejected) + " of " +
                       std::to_string(cover.tls_injected_extensions.size()) +
                       " cover-profile extensions were refused by OpenSSL; "
                       "the emitted ClientHello is narrower than the profile");
    }
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
    // No silent default here. Substituting a stock list would emit suites the
    // cover profile never asked for, which is precisely the fingerprint
    // divergence this class exists to prevent.
    if (tls13_str.empty()) {
        throw std::runtime_error(
            "cover profile lists no TLS 1.3 cipher suites");
    }
    if (SSL_CTX_set_ciphersuites(ctx, tls13_str.c_str()) != 1) {
        throw std::runtime_error(
            "cover profile TLS 1.3 cipher list rejected by OpenSSL: " + tls13_str);
    }

    // Every TLS 1.2 suite in the profile must map to a name OpenSSL knows.
    // cipher_suite_name falls back to a hex string, which OpenSSL cannot parse,
    // and SSL_CTX_set_cipher_list drops unparseable entries while still
    // returning success -- so an unmapped suite silently shortens the offered
    // list and moves the fingerprint. Refuse instead of degrading quietly.
    std::vector<std::uint16_t> unmapped;
    for (std::uint16_t id : tls12_ids) {
        if (cipher_name_map.find(id) == cipher_name_map.end()) unmapped.push_back(id);
    }
    if (!unmapped.empty()) {
        std::string names;
        for (std::uint16_t id : unmapped) {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "0x%04x", id);
            if (!names.empty()) names += ",";
            names += buf;
        }
        throw std::runtime_error(
            "cover profile lists TLS 1.2 cipher suites with no OpenSSL name: " +
            names);
    }

    // A profile that offers TLS 1.3 only has no TLS 1.2 suites to install, and
    // that is not an error -- but feeding TLS 1.3 names to set_cipher_list, as
    // the previous fallback did, is. Leave the TLS 1.2 list alone instead.
    if (tls12_ids.empty()) return;

    const std::string tls12_str = cipher_list_to_openssl_string(tls12_ids);
    if (SSL_CTX_set_cipher_list(ctx, tls12_str.c_str()) != 1) {
        throw std::runtime_error(
            "cover profile TLS 1.2 cipher list rejected by OpenSSL: " + tls12_str);
    }
}

void StealthContext::configure_cert_compression(
    std::span<const std::uint16_t> algorithms) {
    if (algorithms.empty()) {
        return;
    }
    SSL_CTX* ctx = ssl_context_.native_handle();
    std::vector<int> preference(algorithms.begin(), algorithms.end());
    if (SSL_CTX_set1_cert_comp_preference(ctx, preference.data(),
                                          preference.size()) == 1) {
        return;
    }

    // Report what the profile asked for by name; the numeric IDs alone would
    // not tell a packager which OpenSSL option is missing.
    std::string requested;
    for (std::uint16_t algorithm : algorithms) {
        if (!requested.empty()) requested += ", ";
        switch (algorithm) {
            case 1: requested += "zlib"; break;
            case 2: requested += "brotli"; break;
            case 3: requested += "zstd"; break;
            default: requested += std::to_string(algorithm); break;
        }
    }
    if (config_.native_chrome_client_hello) {
        throw std::runtime_error(
            "tls_backend openssl-chrome151 requires certificate compression "
            "(" + requested + "); rebuild pinned OpenSSL with enable-brotli");
    }
    util::log_warn(
        "TLS profile degraded: this OpenSSL build cannot offer certificate "
        "compression (" + requested + "), so compress_certificate advertises "
        "the build's own algorithms and no longer matches the cover profile; "
        "rebuild OpenSSL with enable-brotli to close it");
}

void StealthContext::configure_supported_groups(
    const std::vector<uint16_t>& groups,
    const std::vector<uint16_t>& key_share_groups) {
    // Use the name-based string API. The uint16-array API
    // (SSL_CTX_set1_groups) was tried during 1.x development but
    // OpenSSL 3.5 silently rejects any unknown / GREASE-range
    // values in the array AND falls back to its own defaults
    // (which include 0x11ec = X25519MLKEM768) — net effect: the
    // supported_groups extension drifted away from our profile
    // data. Stick with the string form, which validates per name
    // and emits the result verbatim when every name is known.
    //
    // The list is rejected as a whole if ANY name is unknown, and a rejected
    // call leaves OpenSSL's defaults in place. That is a silent stealth
    // regression, so the result is checked: the profile now offers
    // X25519MLKEM768, which only exists from OpenSSL 3.5. On an older library
    // we drop the groups this build cannot name and retry, reporting exactly
    // what was lost, rather than emitting an unrelated default list.
    SSL_CTX* ctx = ssl_context_.native_handle();
    const std::string groups_string =
        groups_to_openssl_string(groups, key_share_groups);
    if (SSL_CTX_set1_groups_list(ctx, groups_string.c_str()) == 1) {
        return;
    }
    if (config_.native_chrome_client_hello) {
        throw std::runtime_error(
            "tls_backend openssl-chrome151 requires the exact supported_groups "
            "and key_share list: " + groups_string);
    }

    // The "*" key_share prefix is newer than the groups-list API itself. If the
    // starred form is rejected as a whole, retry the plain names before
    // bisecting: a library that knows every group but not the prefix should
    // lose only the second key_share, not the whole profile. Losing it changes
    // the ClientHello, so say so rather than degrading quietly.
    if (!key_share_groups.empty()) {
        const std::string unstarred = groups_to_openssl_string(groups, {});
        if (SSL_CTX_set1_groups_list(ctx, unstarred.c_str()) == 1) {
            util::log_warn(
                "TLS profile degraded: this OpenSSL build rejected the key_share "
                "group prefix, so only the first group carries a share; the "
                "emitted key_share no longer matches the cover profile");
            return;
        }
    }

    std::vector<uint16_t> supported;
    std::vector<uint16_t> dropped;
    for (uint16_t group : groups) {
        // Probe each name on its own; a single-entry list keeps the failure
        // attributable instead of bisecting the whole profile.
        const std::string one = supported_group_name(group);
        if (SSL_CTX_set1_groups_list(ctx, one.c_str()) == 1) {
            supported.push_back(group);
        } else {
            dropped.push_back(group);
        }
    }

    if (supported.empty()) {
        // Leaving OpenSSL's defaults installed would silently emit a
        // supported_groups extension that belongs to no profile.
        throw std::runtime_error(
            "TLS profile supported_groups rejected by this OpenSSL build: " +
            groups_string);
    }

    std::vector<uint16_t> reduced_shares;
    for (uint16_t group : key_share_groups) {
        if (std::find(supported.begin(), supported.end(), group) != supported.end()) {
            reduced_shares.push_back(group);
        }
    }
    std::string reduced = groups_to_openssl_string(supported, reduced_shares);
    if (SSL_CTX_set1_groups_list(ctx, reduced.c_str()) != 1) {
        // Same prefix fallback as above, now on the reduced list.
        reduced = groups_to_openssl_string(supported, {});
        if (SSL_CTX_set1_groups_list(ctx, reduced.c_str()) != 1) {
            throw std::runtime_error(
                "TLS profile supported_groups could not be installed: " + reduced);
        }
    }

    std::string lost;
    for (uint16_t group : dropped) {
        if (!lost.empty()) lost += ", ";
        lost += supported_group_name(group);
    }
    util::log_warn(
        "TLS profile degraded: this OpenSSL build does not support " + lost +
        "; the offered supported_groups no longer matches the cover profile");
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
    std::vector<std::uint16_t> unmapped;
    auto add = [&](const char* tok) {
        if (!list.empty()) list += ":";
        list += tok;
    };
    for (std::uint16_t a : algorithms) {
        switch (a) {
            // ML-DSA. OpenSSL 3.5 emits all three, which is what lets the
            // diagnostic backend reproduce the captured sigalgs list exactly --
            // JA4 hashes signature algorithms in order, so these are load-bearing.
            case 0x0904: add("mldsa44"); break;
            case 0x0905: add("mldsa65"); break;
            case 0x0906: add("mldsa87"); break;
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
            default: unmapped.push_back(a); break;
        }
    }
    if (list.empty()) {
        // Fall back rather than emit a sigalgs ext we don't want.
        SSL_CTX_set1_sigalgs_list(ctx,
            "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256");
        return;
    }
    // Same fail-open shape as the supported_groups path: OpenSSL rejects the
    // list as a whole and leaves its own defaults installed, which would
    // silently emit a non-cover sigalgs extension. Refuse instead.
    if (SSL_CTX_set1_sigalgs_list(ctx, list.c_str()) != 1) {
        throw std::runtime_error(
            "cover profile signature algorithms rejected by OpenSSL: " + list);
    }
    if (!unmapped.empty()) {
        std::string dropped;
        for (std::uint16_t a : unmapped) {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "0x%04x", a);
            if (!dropped.empty()) dropped += ",";
            dropped += buf;
        }
        util::log_warn(
            "tls: cover profile lists signature algorithms with no OpenSSL "
            "name (" + dropped + "); the emitted sigalgs extension is narrower "
            "than the profile");
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

using verify_fetch::fetch_http11_json;
using verify_fetch::fetch_http2_json;
using verify_fetch::parse_verification_endpoint;
using verify_fetch::VerificationEndpoint;
using verify_fetch::VerifyFetchLimits;

// Ceiling for one diagnostic exchange. Long enough that a slow endpoint on a
// distant network still answers, short enough that a redirected one cannot
// hold the client indefinitely.
constexpr std::chrono::seconds kVerifyFetchTimeout{30};

// The fetch checks its deadline between reads, which bounds an endpoint that
// keeps sending. An endpoint that completes the handshake and then goes silent
// blocks inside one synchronous read instead, so the socket needs its own
// receive timeout. Asio exposes no portable option for it; POSIX is the only
// platform this diagnostic builds for today, and a failure here is not fatal
// because the deadline still bounds every other shape of stall.
void set_verify_socket_timeout(int fd, std::chrono::seconds timeout) {
#if defined(_WIN32)
    (void)fd;
    (void)timeout;
#else
    if (fd < 0) {
        return;
    }
    timeval tv{};
    tv.tv_sec = static_cast<decltype(tv.tv_sec)>(timeout.count());
    tv.tv_usec = 0;
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
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
        set_verify_socket_timeout(stream.lowest_layer().native_handle(),
                                  kVerifyFetchTimeout);
        stream.handshake(boost::asio::ssl::stream_base::client);

        const unsigned char* alpn_data = nullptr;
        unsigned int alpn_len = 0;
        SSL_get0_alpn_selected(stream.native_handle(), &alpn_data, &alpn_len);
        const std::string negotiated_alpn(
            reinterpret_cast<const char*>(alpn_data),
            static_cast<size_t>(alpn_len));

        VerifyFetchLimits limits;
        limits.deadline = std::chrono::steady_clock::now() + kVerifyFetchTimeout;
        const std::string body = negotiated_alpn == "h2"
            ? fetch_http2_json(stream, endpoint, limits)
            : fetch_http11_json(stream, endpoint, limits);

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
