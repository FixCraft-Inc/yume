/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <string_view>
#include <string>

namespace yume::server {

// Federation peer IDs become the namespace prefix in visible relay endpoint
// IDs ("peer:endpoint"). Keep the prefix deliberately small and exclude the
// separator so it is impossible for configuration or an authenticated peer to
// create an ambiguous namespace.
inline constexpr std::size_t kMaxFederationPeerIdBytes = 64;

inline bool is_valid_federation_peer_id(std::string_view value) noexcept {
    if (value.empty() || value.size() > kMaxFederationPeerIdBytes) {
        return false;
    }
    for (const unsigned char ch : value) {
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
    std::string state{"idle"};
    bool ready{false};
    std::string last_error;
    std::int64_t last_handshake_ts{0};
    std::uint32_t channels_active{0};
};

}  // namespace yume::server
