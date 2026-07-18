/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/http_masq.hpp"

#include <cassert>
#include <cstdio>

namespace {

using yume::server::http_masq::connection_has_token;
using yume::server::http_masq::parse_request_line;
using yume::server::http_masq::response_keep_alive;

void test_parse_request_line() {
    auto a = parse_request_line("GET / HTTP/1.1");
    assert(a.method == "GET" && a.target == "/" && a.version == "HTTP/1.1");
    auto b = parse_request_line("HEAD /assets/app.js HTTP/1.0");
    assert(b.method == "HEAD" && b.target == "/assets/app.js" && b.version == "HTTP/1.0");
    // Missing version leaves it empty; target is preserved.
    auto c = parse_request_line("GET /x");
    assert(c.method == "GET" && c.target == "/x" && c.version.empty());
    // Empty / garbage lines keep the "/" target default and empty method.
    auto d = parse_request_line("");
    assert(d.method.empty() && d.target == "/" && d.version.empty());
    // Extra whitespace around the version is trimmed.
    auto e = parse_request_line("GET /  HTTP/1.1 ");
    assert(e.method == "GET" && e.version == "HTTP/1.1");
}

void test_connection_has_token() {
    assert(connection_has_token("keep-alive", "keep-alive"));
    assert(connection_has_token("close", "close"));
    assert(connection_has_token("Keep-Alive", "keep-alive"));       // case-insensitive
    assert(connection_has_token("keep-alive, Upgrade", "upgrade"));  // list member
    assert(connection_has_token(" close , TE", "close"));            // trimmed
    assert(!connection_has_token("keep-alive", "close"));
    assert(!connection_has_token("", "close"));
    assert(!connection_has_token("keepalive", "keep-alive"));        // no substring match
}

void test_response_keep_alive() {
    // HTTP/1.1 GET/HEAD stay alive by default.
    assert(response_keep_alive("GET", "HTTP/1.1", "", false, 0, 100));
    assert(response_keep_alive("HEAD", "HTTP/1.1", "", false, 5, 100));
    // Explicit close wins on 1.1.
    assert(!response_keep_alive("GET", "HTTP/1.1", "close", false, 0, 100));
    // HTTP/1.0 needs an explicit keep-alive.
    assert(!response_keep_alive("GET", "HTTP/1.0", "", false, 0, 100));
    assert(response_keep_alive("GET", "HTTP/1.0", "keep-alive", false, 0, 100));
    assert(!response_keep_alive("GET", "HTTP/1.0", "keep-alive, close", false, 0, 100));
    // Bodies and non-GET/HEAD methods never keep-alive (would desync the stream).
    assert(!response_keep_alive("GET", "HTTP/1.1", "", true, 0, 100));
    assert(!response_keep_alive("POST", "HTTP/1.1", "", false, 0, 100));
    assert(!response_keep_alive("OPTIONS", "HTTP/1.1", "", false, 0, 100));
    // Request cap closes the connection.
    assert(!response_keep_alive("GET", "HTTP/1.1", "", false, 100, 100));
    assert(!response_keep_alive("GET", "HTTP/1.1", "", false, 101, 100));
    // Unknown versions close.
    assert(!response_keep_alive("GET", "HTTP/2.0", "", false, 0, 100));
}

}  // namespace

int main() {
    test_parse_request_line();
    test_connection_has_token();
    test_response_keep_alive();
    std::puts("http_masq_test: all cases passed");
    return 0;
}
