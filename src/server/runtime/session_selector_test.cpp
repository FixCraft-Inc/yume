/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/session_selector.hpp"

#include <cassert>

int main() {
    using yume::server::RuntimeSessionSelector;
    using yume::server::runtime_session_selector_matches;

    // These identities deliberately collide across fields. Selecting the
    // numeric ID "42" must not also match an endpoint or IP named "42".
    assert(runtime_session_selector_matches(
        RuntimeSessionSelector::SessionId,
        "42", 42, "endpoint-a", "198.51.100.1"));
    assert(!runtime_session_selector_matches(
        RuntimeSessionSelector::SessionId,
        "42", 7, "42", "42"));

    assert(runtime_session_selector_matches(
        RuntimeSessionSelector::EndpointId,
        "42", 7, "42", "198.51.100.2"));
    assert(!runtime_session_selector_matches(
        RuntimeSessionSelector::EndpointId,
        "42", 42, "endpoint-a", "42"));

    assert(runtime_session_selector_matches(
        RuntimeSessionSelector::ClientIp,
        "42", 7, "endpoint-b", "42"));
    assert(!runtime_session_selector_matches(
        RuntimeSessionSelector::ClientIp,
        "42", 42, "42", "198.51.100.3"));

    // Session IDs use their canonical decimal spelling only.
    assert(!runtime_session_selector_matches(
        RuntimeSessionSelector::SessionId,
        "042", 42, "endpoint-a", "198.51.100.1"));
    return 0;
}
