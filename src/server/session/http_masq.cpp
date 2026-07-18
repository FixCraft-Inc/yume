/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/http_masq.hpp"

#include <cctype>

namespace yume::server::http_masq {

namespace {

char lower(char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); }

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    return s;
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (lower(a[i]) != lower(b[i])) return false;
    }
    return true;
}

}  // namespace

RequestLine parse_request_line(std::string_view line) {
    RequestLine r;
    r.target = "/";
    const auto p1 = line.find(' ');
    if (p1 == std::string_view::npos) {
        return r;
    }
    r.method = std::string(line.substr(0, p1));
    const std::string_view rest = line.substr(p1 + 1);
    const auto p2 = rest.find(' ');
    if (p2 == std::string_view::npos) {
        if (!rest.empty()) r.target = std::string(rest);
        return r;
    }
    if (p2 > 0) r.target = std::string(rest.substr(0, p2));
    r.version = std::string(trim(rest.substr(p2 + 1)));
    return r;
}

bool connection_has_token(std::string_view connection_header, std::string_view token) {
    std::size_t start = 0;
    while (true) {
        const auto comma = connection_header.find(',', start);
        const std::string_view part =
            connection_header.substr(start, comma == std::string_view::npos
                                                ? std::string_view::npos
                                                : comma - start);
        if (iequals(trim(part), token)) return true;
        if (comma == std::string_view::npos) break;
        start = comma + 1;
    }
    return false;
}

bool response_keep_alive(std::string_view method,
                         std::string_view version,
                         std::string_view connection_header,
                         bool request_has_body,
                         int requests_served,
                         int max_requests) {
    if (method != "GET" && method != "HEAD") return false;
    if (request_has_body) return false;
    if (requests_served >= max_requests) return false;

    const bool wants_close = connection_has_token(connection_header, "close");
    if (version == "HTTP/1.1") return !wants_close;
    if (version == "HTTP/1.0") {
        return connection_has_token(connection_header, "keep-alive") && !wants_close;
    }
    return false;
}

}  // namespace yume::server::http_masq
