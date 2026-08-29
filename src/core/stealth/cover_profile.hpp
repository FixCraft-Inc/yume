/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/stealth/tls_fingerprint.hpp"

namespace yume::cover_profile {

using Headers = std::vector<std::pair<std::string, std::string>>;

struct H2Setting {
    std::uint32_t id;
    std::uint32_t value;
};

struct H2Priority {
    std::int32_t parent_stream_id;
    std::int32_t weight;
    bool exclusive;
};

enum class HeaderValueSource {
    Literal,
    Authority,
    CarrierPath,
    UserAgent,
    ClientHintBrand,
    ClientHintMobile,
    ClientHintPlatform,
    Origin,
    RootReferer,
};

struct HeaderTemplate {
    std::string_view name;
    HeaderValueSource value_source;
    std::string_view literal;
};

struct RequestTemplate {
    std::span<const HeaderTemplate> headers;
    H2Priority priority;
};

// Body shape for an extension injected via SSL_CTX_add_custom_ext.
enum class InjectedExtensionPayload : std::uint8_t {
    Empty,          // zero-length body (signed_certificate_timestamp, 0x0012)
    Alps,           // ALPN-shaped protocol vector (application_settings, 0x44cd)
    GreaseEch,      // draft-ietf-tls-esni outer ECHClientHello, random body
    GreaseEmpty,    // RFC 8701 GREASE, zero-length body
    GreaseOneByte,  // RFC 8701 GREASE, single zero byte
};

struct InjectedExtension {
    // 0 means "allocate an RFC 8701 GREASE value when the SSL_CTX is
    // configured" rather than a registry-fixed extension number. OpenSSL
    // binds that number at registration, so one context reuses it across its
    // connections; the generator emits 0 for a "GREASE" entry.
    std::uint16_t type;
    InjectedExtensionPayload payload;
};

struct AssetTemplate {
    std::string_view path;
    RequestTemplate request;
};

struct Profile {
    // Authenticated wire identity and implementation routing metadata. The
    // profile ID is security-sensitive; aliases are presentation-only.
    std::string_view id;
    std::string_view registry_name;
    std::string_view tls_backend;
    std::string_view helper_build_id;
    std::string_view browser_name;
    std::string_view browser_version;
    std::string_view operating_system;
    std::string_view user_agent;
    std::string_view client_hint_brand;
    std::string_view client_hint_mobile;
    std::string_view client_hint_platform;
    tls_fingerprint::BrowserProfile tls_profile;
    std::uint16_t tls_min_version;
    std::uint16_t tls_max_version;
    // The version the handshake must actually end on, or 0 for "no constraint".
    // The offered range is browser-shaped -- Chrome offers TLS 1.2 and 1.3, and
    // offering only 1.3 costs the TLS 1.2 half of the cipher list plus extension
    // 0xff01 -- while this keeps the carrier from settling on the older version.
    std::uint16_t tls_required_version;

    // ClientHello selection policy handed to stock OpenSSL by the
    // openssl-diagnostic backend. Previously these were free literals inside
    // tls_fingerprint.cpp keyed only by the BrowserProfile enum, so the cover
    // identity had two owners and nothing bound the cipher/group/sigalg lists
    // to the committed capture. They are generated from the registry now, and
    // scripts/generate_transport_profiles.py pins their exact gap against the
    // captured browser ClientHello.
    //
    // This is NOT a byte-parity claim. Stock OpenSSL cannot place GREASE in the
    // cipher list, supported_groups, supported_versions, or key_share, and it
    // does not let the caller fix extension emission order. It CAN be driven to
    // Chrome's exact non-GREASE cipher list, extension set, and signature
    // algorithm list, which is what JA4 actually hashes -- JA4 sorts extensions
    // and excludes GREASE, and Chrome has permuted its own extension order per
    // connection since v110, so order was never a stable target. The remaining
    // gap is recorded in known_tls_divergence in config/transport_profiles.json
    // and gated in both directions by tests/test_yume_native_tls_wire.py.
    std::span<const std::uint16_t> tls_cipher_suites;
    std::span<const std::uint16_t> tls_extensions;
    std::span<const std::uint16_t> tls_supported_groups;
    // Subset of tls_supported_groups that must carry a key_share. OpenSSL sends
    // a share only for groups marked with a "*" prefix in the groups list, and
    // defaults to the first group alone -- so a browser offering both a hybrid
    // and a classical share needs both named here.
    std::span<const std::uint16_t> tls_key_share_groups;
    std::span<const std::uint16_t> tls_signature_algorithms;
    std::span<const std::uint8_t> tls_ec_point_formats;
    // RFC 8879 algorithm IDs for compress_certificate (0x001b), in preference
    // order. OpenSSL can only advertise an algorithm the build was compiled
    // with, so this is a request: a build without brotli offers its own
    // zlib/zstd list instead, which is visible in the ClientHello.
    std::span<const std::uint16_t> tls_cert_compression;
    std::span<const std::string_view> tls_alpn_protocols;

    // Extensions stock OpenSSL will not emit on its own. SSL_CTX_add_custom_ext
    // accepts any extension number OpenSSL does not already own internally,
    // which covers the RFC 8701 GREASE range, SCT, ALPS, and ECH. Extensions
    // OpenSSL *does* own (status_request, renegotiation_info) are refused by
    // that API and must be requested through their own setters instead --
    // hence tls_status_request_ocsp below rather than an injected 0x0005.
    std::span<const InjectedExtension> tls_injected_extensions;
    std::span<const std::string_view> tls_alps_protocols;
    // Permitted total lengths for a GREASE ECH body, copied from the captured
    // browser. One is chosen per connection.
    std::span<const std::uint16_t> tls_ech_grease_lengths;
    // Drops extension 0x0016, which OpenSSL offers by default and Chrome does
    // not send.
    bool tls_no_encrypt_then_mac;
    // Emits extension 0x0005 (status_request) with Chrome's exact 5-byte body.
    bool tls_status_request_ocsp;

    std::string_view cover_runtime;
    std::string_view cover_runtime_version;
    std::span<const H2Setting> client_settings;
    std::span<const H2Setting> server_settings;
    std::uint32_t connection_window_update;
    RequestTemplate priming_request;
    RequestTemplate extended_connect;
    std::span<const AssetTemplate> assets;
    std::size_t websocket_message_bytes;

    Headers render_headers(const RequestTemplate& request,
                           std::string_view authority,
                           std::string_view carrier_path = {}) const;
};

// Immutable build-time registry generated from committed capture artifacts.
// Production code uses active(); adding a profile must not add browser-specific
// branches to TLS/HTTP/H2 consumers.
std::span<const Profile> all();
const Profile* find_by_id(std::string_view id);
const Profile* find_by_registry_name(std::string_view name);
const Profile& active();

}  // namespace yume::cover_profile
