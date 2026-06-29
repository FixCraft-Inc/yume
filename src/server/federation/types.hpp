/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <string>

namespace yume::server {

struct FederationPeer {
    std::string id;
    std::string host;
    int port{0};
    std::string tls_pin_sha256;
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
