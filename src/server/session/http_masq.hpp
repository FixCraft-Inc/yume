/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Pure HTTP/1.x helpers for the masquerade responder's keep-alive loop. Kept
// dependency-free so the framing decisions that keep the byte stream in sync
// (request-line parsing and whether to hold the connection open) are unit
// tested in isolation. Getting keep-alive eligibility wrong desyncs the stream,
// so the rule here is deliberately conservative.

#pragma once

#include <string>
#include <string_view>

namespace yume::server::http_masq {

struct RequestLine {
    std::string method;
    std::string target;   // defaults to "/" when the line omits it
    std::string version;  // e.g. "HTTP/1.1"; empty when unparseable
};

// Parse "METHOD TARGET VERSION". Missing pieces are left empty (target keeps
// its "/" default) rather than rejected, matching how a lenient server fills in
// a bare request line.
RequestLine parse_request_line(std::string_view line);

// Whether `connection_header` (a raw HTTP Connection value, possibly a
// comma-separated list) carries `token` as a case-insensitive element.
bool connection_has_token(std::string_view connection_header,
                          std::string_view token);

// Whether the masquerade responder should keep the connection open for a
// further request after answering this one. Only bodyless GET/HEAD under the
// per-connection request cap qualify: HTTP/1.1 stays alive unless the client
// sent "Connection: close"; HTTP/1.0 only when it explicitly sent
// "Connection: keep-alive". Anything else closes.
bool response_keep_alive(std::string_view method,
                         std::string_view version,
                         std::string_view connection_header,
                         bool request_has_body,
                         int requests_served,
                         int max_requests);

}  // namespace yume::server::http_masq
