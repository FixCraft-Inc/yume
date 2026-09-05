/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/cover_response.hpp"

#include <cassert>
#include <string>

int main() {
    using yume::server::cover_response::normalize_http1_response;

    std::string normalized;
    std::string error;
    assert(normalize_http1_response(
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        1024, &normalized, &error));
    assert(normalized ==
           "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    assert(error.empty());

    assert(normalize_http1_response(
        "HTTP/1.1 200 OK\nContent-Length: 0\n\n",
        1024, &normalized, &error));
    assert(normalized ==
           "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

    const std::string binary_body("a\nb\0\xff", 5);
    const std::string binary_capture =
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n" + binary_body;
    assert(normalize_http1_response(binary_capture, 1024, &normalized, &error));
    assert(normalized == binary_capture);

    const std::string chunked_capture =
        "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n"
        "3\r\na\nb\r\n0\r\n\r\n";
    assert(normalize_http1_response(chunked_capture, 1024, &normalized, &error));
    assert(normalized.substr(normalized.find("\r\n\r\n") + 4) ==
           "3\r\na\nb\r\n0\r\n\r\n");

    assert(!normalize_http1_response(
        "not an HTTP response\n", 1024, &normalized, &error));
    assert(normalized.empty());
    assert(error.find("HTTP/1.") != std::string::npos);

    const std::string expansion = "HTTP/1.1 200 OK\n\n";
    assert(!normalize_http1_response(
        expansion, expansion.size(), &normalized, &error));
    assert(normalized.empty());
    assert(error.find("normalized") != std::string::npos);

    assert(!normalize_http1_response(
        "HTTP/1.garbage 200 OK\r\nContent-Length: 0\r\n\r\n",
        1024, &normalized, &error));
    assert(!normalize_http1_response(
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\na\nb",
        1024, &normalized, &error));

    assert(!normalize_http1_response(
        "HTTP/1.1 200 OK\r\n\r\n", 8, &normalized, &error));
    assert(normalized.empty());
    assert(error.find("size limit") != std::string::npos);
    for (const auto* invalid : {
        "HTTP/1.1 200\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nextra",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nx\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX: a\r\n b\r\n\r\n",
        "HTTP/1.1 100 Continue\r\n\r\n"}) {
        assert(!normalize_http1_response(invalid, 1024, &normalized, &error));
        assert(normalized.empty() && !error.empty());
    }
    normalized = binary_capture;
    assert(normalize_http1_response(normalized, 1024, &normalized, &error));
    assert(normalized == binary_capture);
    return 0;
}
