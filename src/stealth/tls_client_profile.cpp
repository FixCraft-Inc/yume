/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "stealth/tls_client_profile.hpp"
#include "stealth/cover_profile.hpp"

#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <iomanip>
#include <map>
#include <new>
#include <span>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace yume::tls_stealth {
namespace {

// This entropy belongs to the TLS wire-profile integration, independently of
// either YUME session-security implementation.
std::vector<std::uint8_t> random_bytes(std::size_t size) {
    if (size > static_cast<std::size_t>(INT_MAX)) {
        throw std::length_error("TLS profile entropy request exceeds its bound");
    }
    std::vector<std::uint8_t> output(size);
    if (RAND_bytes(output.data(), static_cast<int>(size)) != 1) {
        throw std::runtime_error("TLS profile entropy generation failed");
    }
    return output;
}

// Downstream OpenSSL control kept numeric here on purpose. Calling the stable
// SSL_CTX_ctrl symbol avoids a new dynamic-link dependency; stock libssl
// returns 0 for the unknown command and the native Chrome backend fails closed.
constexpr int kYumeChromeClientHelloCtrl = 0x5943;

// RFC 8701 §2.1: GREASE values reserved for cipher_suites,
// supported_groups, extensions, and ALPN. Diagnostic mode uses this picker
// while configuring injected extension types on an SSL_CTX. OpenSSL
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
            const auto draw = random_bytes(2);
            return static_cast<unsigned>((draw[0] << 8) | draw[1]);
        } catch (const std::exception&) {
            // Diagnostic mode tolerates degraded randomness here. Native mode
            // skips this picker and uses the patched libssl GREASE generator.
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
        : lengths[random_bytes(1)[0] % lengths.size()];
    if (total <= kOverhead) total = kOverhead + 144;

    const std::size_t payload_len = total - kOverhead;
    const auto entropy = random_bytes(1 + kEncLen + payload_len);

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


const std::map<uint16_t, std::string> cipher_name_map = {
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

const std::map<uint16_t, std::string> group_name_map = {
    // Hybrid post-quantum key exchange, and the group real Chrome 151
    // negotiates against the committed cover capture. OpenSSL only gained an
    // emitter for it in 3.5; on an older library SSL_CTX_set1_groups_list
    // rejects the whole list. Native mode refuses that mismatch; only the
    // explicitly selected diagnostic mode may reduce the offer.
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

class ClientProfileConfigurator final {
public:
    ClientProfileConfigurator(SSL_CTX* context, bool native) noexcept
        : context_(context), native_chrome_client_hello_(native) {}

    void apply_stealth_profile(tls_fingerprint::BrowserProfile profile);
    std::vector<std::string> take_warnings() && {
        return std::move(warnings_);
    }

private:
    void configure_cipher_suites(const std::vector<uint16_t>& suites);
    void configure_cert_compression(std::span<const std::uint16_t> algorithms);
    void configure_supported_groups(const std::vector<uint16_t>& groups,
                                    const std::vector<uint16_t>& key_share_groups);
    void configure_signature_algorithms(const std::vector<uint16_t>& algorithms);
    void configure_alpn(const std::vector<std::string>& protocols);

    SSL_CTX* context_;
    bool native_chrome_client_hello_;
    std::vector<std::string> warnings_;
};

void ClientProfileConfigurator::apply_stealth_profile(tls_fingerprint::BrowserProfile profile) {
    auto profile_info = tls_fingerprint::get_browser_profile_info(profile);
    if (!profile_info) {
        if (native_chrome_client_hello_) {
            throw std::runtime_error("requested TLS browser profile is unavailable");
        }
        profile_info = tls_fingerprint::get_browser_profile_info(
            cover_profile::active().tls_profile);
        if (!profile_info) {
            throw std::runtime_error("no TLS profile data is available");
        }
    }

    SSL_CTX* ctx = context_;
    if (native_chrome_client_hello_ &&
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
    // A rejected registration narrows the fingerprint. Native mode refuses
    // it; diagnostic mode reports it. Callers supply a fresh context because
    // re-registering an extension on the same context is also rejected.
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
        if (native_chrome_client_hello_ && injected.type == 0) {
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
                    (native_chrome_client_hello_ ? 0x100U : 0U)),
                /*parse_cb=*/nullptr, /*parse_arg=*/nullptr) != 1) {
            ++rejected;
        }
    }
    if (rejected != 0 && native_chrome_client_hello_) {
        throw std::runtime_error(
            "patched OpenSSL refused " + std::to_string(rejected) +
            " required Chrome ClientHello extension(s)");
    }
    if (rejected != 0) {
        warnings_.push_back("tls: " + std::to_string(rejected) + " of " +
                       std::to_string(cover.tls_injected_extensions.size()) +
                       " cover-profile extensions were refused by OpenSSL; "
                       "the emitted ClientHello is narrower than the profile");
    }
}

void ClientProfileConfigurator::configure_cipher_suites(const std::vector<uint16_t>& suites) {
    SSL_CTX* ctx = context_;
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

void ClientProfileConfigurator::configure_cert_compression(
    std::span<const std::uint16_t> algorithms) {
    if (algorithms.empty()) {
        return;
    }
    SSL_CTX* ctx = context_;
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
    if (native_chrome_client_hello_) {
        throw std::runtime_error(
            "tls_backend openssl-chrome151 requires certificate compression "
            "(" + requested + "); rebuild pinned OpenSSL with enable-brotli");
    }
    warnings_.push_back(
        "TLS profile degraded: this OpenSSL build cannot offer certificate "
        "compression (" + requested + "), so compress_certificate advertises "
        "the build's own algorithms and no longer matches the cover profile; "
        "rebuild OpenSSL with enable-brotli to close it");
}

void ClientProfileConfigurator::configure_supported_groups(
    const std::vector<uint16_t>& groups,
    const std::vector<uint16_t>& key_share_groups) {
    // The name-based API supports the explicit key_share prefix and rejects
    // unknown groups as a whole. A rejected call leaves the previous list
    // installed, so check its result before using the context.
    //
    // The list is rejected as a whole if ANY name is unknown, and a rejected
    // call leaves OpenSSL's defaults in place. That is a silent stealth
    // regression, so the result is checked: the profile now offers
    // X25519MLKEM768, which only exists from OpenSSL 3.5. On an older library
    // native mode fails. Diagnostic mode may drop unavailable groups and
    // report the resulting divergence.
    SSL_CTX* ctx = context_;
    const std::string groups_string =
        groups_to_openssl_string(groups, key_share_groups);
    if (SSL_CTX_set1_groups_list(ctx, groups_string.c_str()) == 1) {
        return;
    }
    if (native_chrome_client_hello_) {
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
            warnings_.push_back(
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
    warnings_.push_back(
        "TLS profile degraded: this OpenSSL build does not support " + lost +
        "; the offered supported_groups no longer matches the cover profile");
}

void ClientProfileConfigurator::configure_signature_algorithms(const std::vector<uint16_t>& algorithms) {
    // Map IANA TLS SignatureScheme values to OpenSSL sigalg string
    // tokens. The string passed to SSL_CTX_set1_sigalgs_list is a
    // colon-separated list of names from RFC 8446 §4.2.3 / OpenSSL's
    // X509 namespace; the emit order in the ClientHello matches the
    // string order, which is exactly what we need for per-profile
    // sigalg differentiation in JA4 (and helps cluster the right
    // browser even where JA3 doesn't cover sigalgs).
    SSL_CTX* ctx = context_;
    if (algorithms.empty()) {
        if (native_chrome_client_hello_) {
            throw std::runtime_error("cover profile lists no signature algorithms");
        }
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
    if (native_chrome_client_hello_ && (list.empty() || !unmapped.empty())) {
        throw std::runtime_error(
            "cover profile signature algorithms cannot be applied exactly");
    }
    if (list.empty()) {
        // Diagnostic mode can emit this substitute list. Native mode already
        // rejected an empty mapping above.
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
        warnings_.push_back(
            "tls: cover profile lists signature algorithms with no OpenSSL "
            "name (" + dropped + "); the emitted sigalgs extension is narrower "
            "than the profile");
    }
}

void ClientProfileConfigurator::configure_alpn(const std::vector<std::string>& protocols) {
    std::vector<unsigned char> alpn_data;
    for (const auto& proto : protocols) {
        if (native_chrome_client_hello_ && (proto.empty() || proto.size() > 255U)) {
            throw std::runtime_error("cover profile ALPN name is invalid");
        }
        if (native_chrome_client_hello_ &&
            alpn_data.size() > 65535U - (1U + proto.size())) {
            throw std::runtime_error("cover profile ALPN list exceeds its bound");
        }
        alpn_data.push_back(static_cast<unsigned char>(proto.size()));
        alpn_data.insert(alpn_data.end(), proto.begin(), proto.end());
    }

    SSL_CTX* ctx = context_;
    if (native_chrome_client_hello_ &&
        (alpn_data.empty() || alpn_data.size() > 65535U)) {
        throw std::runtime_error("cover profile ALPN list is invalid");
    }
    const int result = SSL_CTX_set_alpn_protos(
        ctx, alpn_data.data(), static_cast<unsigned int>(alpn_data.size()));
    if (result != 0 && native_chrome_client_hello_) {
        throw std::runtime_error("cover profile ALPN list was rejected by OpenSSL");
    }
}

}  // namespace

std::vector<std::string> configure_client_profile(
    SSL_CTX* context, tls_fingerprint::BrowserProfile profile,
    bool native_chrome_client_hello) {
    if (context == nullptr) {
        throw std::invalid_argument("TLS profile context must not be null");
    }
    ClientProfileConfigurator configurator(context, native_chrome_client_hello);
    configurator.apply_stealth_profile(profile);
    return std::move(configurator).take_warnings();
}

}  // namespace yume::tls_stealth
