/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/host/host_types.hpp"

#include <cassert>
#include <iostream>

int main() {
    using namespace yume::server::host;

    assert(parse_host_mode("private").value() == HostMode::Private);
    assert(parse_host_mode("relay").value() == HostMode::Relay);
    assert(parse_deny_action("reset").value() == DenyAction::Reset);
    assert(parse_listener_mode("starttls_mail").value() == ListenerMode::StartTlsMail);

    std::string error;
    assert(backend_is_loopback_only("loopback://127.0.0.1:8080", &error));
    assert(backend_is_loopback_only("loopback://[::1]:8080", &error));
    assert(!backend_is_loopback_only("loopback://localhost:8080", &error));
    assert(!backend_is_loopback_only("loopback://192.168.1.1:8080", &error));
    assert(!backend_is_loopback_only("loopback://127.0.0.1:70000", &error));
    assert(!backend_is_loopback_only("unix:///run/yume.sock", &error));
    assert(!backend_is_loopback_only("codec://monero-rpc-v1", &error));

    std::cout << "host_types_test: ok\n";
    return 0;
}
