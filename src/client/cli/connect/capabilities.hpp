/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>
#include <string_view>

namespace yume::client {

struct ServerCapabilityInput {
    std::string server_version;
    std::string server_inner_mode;
    bool inner_crypto_requested = false;
    bool inner_disabled_for_session = false;
    bool have_inner_caps = false;
    bool server_inner_supported = false;
    bool server_inner_required = false;
    bool server_inner_dual = false;
    bool server_cap_pq = false;
};

struct ServerCapabilityResult {
    std::string error;
    bool want_inner = false;
};

ServerCapabilityResult evaluate_server_capabilities(const ServerCapabilityInput& input);

}  // namespace yume::client
