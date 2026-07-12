/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/host/host_routes.hpp"
#include "server/host/host_types.hpp"

#include <cassert>
#include <iostream>

namespace {

bool route_matches(const std::string& prefix, const std::string& path) {
    yume::server::host::HostRoute route;
    route.path_prefix = prefix;
    route.backend = "loopback://127.0.0.1:8080";
    yume::server::host::HostRouteTable table;
    table.set_routes({route});
    return table.match("", "", path).has_value();
}

}  // namespace

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

    assert(route_matches("", ""));
    assert(route_matches("", "/apiv2"));
    assert(route_matches("/", "/"));
    assert(route_matches("/", "/api"));
    assert(!route_matches("/", ""));
    assert(route_matches("/api", "/api"));
    assert(route_matches("/api", "/api/"));
    assert(route_matches("/api", "/api/v1"));
    assert(route_matches("/api", "/api?x=1"));
    assert(route_matches("/api", "/api#frag"));
    assert(!route_matches("/api", "/apiv2"));
    assert(!route_matches("/api", "/api2?x=1"));
    assert(route_matches("/api/", "/api/?x=1"));
    assert(!route_matches("/api/", "/api"));

    std::cout << "host_types_test: ok\n";
    return 0;
}
