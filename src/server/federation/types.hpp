/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>

namespace yume::server {

// Federation peer IDs become the namespace prefix in visible relay endpoint
// IDs ("peer:endpoint"). Keep the prefix deliberately small and exclude the
// separator so it is impossible for configuration or an authenticated peer to
// create an ambiguous namespace.
inline constexpr std::size_t kMaxFederationPeerIdBytes = 64;
inline constexpr std::size_t kFederationTlsPinHexBytes = 64;
inline constexpr std::size_t kMaxFederationPublicErrorBytes = 512;

inline bool is_valid_federation_peer_id(std::string_view value) noexcept {
    if (value.empty() || value.size() > kMaxFederationPeerIdBytes) {
        return false;
    }
    for (const char raw_ch : value) {
        const auto ch = static_cast<unsigned char>(raw_ch);
        const bool alpha_numeric =
            (ch >= static_cast<unsigned char>('a') &&
             ch <= static_cast<unsigned char>('z')) ||
            (ch >= static_cast<unsigned char>('A') &&
             ch <= static_cast<unsigned char>('Z')) ||
            (ch >= static_cast<unsigned char>('0') &&
             ch <= static_cast<unsigned char>('9'));
        if (!alpha_numeric && ch != static_cast<unsigned char>('.') &&
            ch != static_cast<unsigned char>('_') &&
            ch != static_cast<unsigned char>('-')) {
            return false;
        }
    }
    return true;
}

// TLS leaf pins are compared to hex_encode(SHA-256(DER)), which has one
// canonical representation. Rejecting alternate spellings at configuration
// time avoids a pin that looks plausible but can never match at runtime.
inline bool is_valid_federation_tls_pin(std::string_view value) noexcept {
    if (value.size() != kFederationTlsPinHexBytes) {
        return false;
    }
    for (const char ch : value) {
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
            return false;
        }
    }
    return true;
}

// std::stoi accepts a valid numeric prefix (for example "443junk"). Peer
// configuration is a trust boundary, so the whole port token must parse.
inline bool parse_federation_port(std::string_view value,
                                  int* port) noexcept {
    if (value.empty() || port == nullptr) {
        return false;
    }
    int parsed = 0;
    const auto result =
        std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size() ||
        parsed <= 0 || parsed > 65535) {
        return false;
    }
    *port = parsed;
    return true;
}

// FederationPeer stores IPv6 literals without brackets. Add them only at an
// address-rendering boundary so host:port output remains unambiguous.
inline std::string format_federation_host_port(std::string_view host,
                                               int port) {
    std::string result;
    const bool already_bracketed =
        host.size() >= 2U && host.front() == '[' && host.back() == ']';
    const bool needs_brackets =
        host.find(':') != std::string_view::npos && !already_bracketed;
    result.reserve(host.size() + 8U);
    if (needs_brackets) {
        result.push_back('[');
    }
    result.append(host.data(), host.size());
    if (needs_brackets) {
        result.push_back(']');
    }
    result.push_back(':');
    result.append(std::to_string(port));
    return result;
}

// Status text crosses the local control API and may be printed by multiple
// consumers. Keep it single-line, terminal-safe, valid ASCII, and bounded even
// if a remote error or library diagnostic contains control/non-UTF-8 bytes.
inline std::string sanitize_federation_public_error(
        std::string_view value) {
    const bool truncated = value.size() > kMaxFederationPublicErrorBytes;
    const std::size_t limit = truncated
        ? kMaxFederationPublicErrorBytes - 3U
        : kMaxFederationPublicErrorBytes;
    std::string result;
    result.reserve(truncated ? kMaxFederationPublicErrorBytes : value.size());
    for (std::size_t index = 0; index < value.size() && index < limit;
         ++index) {
        const auto ch = static_cast<unsigned char>(value[index]);
        result.push_back(ch >= 0x20U && ch <= 0x7eU
                             ? static_cast<char>(ch)
                             : '?');
    }
    if (truncated) {
        result.append("...");
    }
    return result;
}

struct FederationPeer {
    std::string id;
    std::string host;
    int port{0};
    std::string tls_pin_sha256;
    // Pairwise PSK shared with this peer out of band. Both endpoints must load
    // the same 32 bytes: AUTH v2 derives the ratchet root from it, so a
    // mismatch fails establishment rather than degrading.
    std::string psk_file;
    // This peer's carrier admission secret -- the value its yumed runs with
    // --obfs-secret-file. The dialer needs it to pass the peer's H2 admission,
    // which every YUME 2.0 AUTH (client or federating server) goes through.
    std::string carrier_secret_file;
    std::string raw_json;
};

struct FederationPeerStatus {
    std::string id;
    // Overall direct connectivity. An inbound-only bootstrap peer is ready
    // even though this process has no dial-out link for it.
    std::string state{"idle"};
    bool ready{false};
    // Dial-out state remains separate so an inbound connection cannot hide a
    // failed configured outbound link.
    std::string outbound_state{"not-configured"};
    bool outbound_ready{false};
    std::uint32_t inbound_connections{0};
    std::string last_error;
    std::int64_t last_handshake_ms{0};
    // Canonical total for both direct directions. Manager recomputes this
    // from its active-channel registry before publishing status.
    std::uint32_t channels_active{0};
};

}  // namespace yume::server
