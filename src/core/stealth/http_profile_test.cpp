/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// The transport-v2 HTTP client registry must mirror the active cover
// profile. The profile itself is checked against its capture by
// cover_profile_test.cpp, which the native graph runs.

#include <cassert>

#include "core/stealth/cover_profile.hpp"
#include "core/stealth/http_profile.hpp"

int main() {
    const auto& profile = yume::cover_profile::active();
    const auto client = yume::http_profile::transport_client(
        profile.registry_name);
    assert(client.has_value());
    assert(client->user_agent == profile.user_agent);
    assert(client->tls_profile == profile.tls_profile);
    assert(yume::http_profile::active_client_ua() == profile.user_agent);
    return 0;
}
