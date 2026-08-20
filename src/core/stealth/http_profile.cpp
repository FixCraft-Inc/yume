/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/stealth/http_profile.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_map>

// strptime / timegm are POSIX/GNU extensions not guaranteed by <ctime>.
#include <time.h>

#include "core/stealth/cover_profile.hpp"

namespace yume::http_profile {

namespace {

std::string to_lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// Server profile registry. Each entry's headers_404 is a profile template
// whose field order and body shape are based on real server software,
// captured from public deployments
// (nginx.org, caddyserver.com, cloudflare.com 2026-05) and / or
// from the upstream source:
//   - nginx: src/http/ngx_http_special_response.c
//   - httpd: server/main.c default error page + ServerTokens Full
//   - caddy: caddyhttp/replacer.go (Server header) + global Alt-Svc
//   - cloudflare: edge response (CF-RAY uppercase, Alt-Svc, NEL, etc.)
//   - express: finalhandler.js + helmet defaults
//   - gunicorn: gunicorn/http/wsgi.py + werkzeug default 404
const std::unordered_map<std::string, ServerProfile>& server_registry() {
    static const std::unordered_map<std::string, ServerProfile> kRegistry = []{
        std::unordered_map<std::string, ServerProfile> m;

        // nginx — Server / Date / Content-Type (utf-8) / Content-Length /
        // Connection close (default 404 closes, keep-alive only on 200/304).
        m["nginx"] = ServerProfile{
            "nginx",
            "Server: nginx/1.24.0\r\n"
            "Date: {date}\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Content-Length: {len}\r\n"
            "Connection: close\r\n"
            "\r\n",
            "<html>\r\n"
            "<head><title>404 Not Found</title></head>\r\n"
            "<body>\r\n"
            "<center><h1>404 Not Found</h1></center>\r\n"
            "<hr><center>nginx/1.24.0</center>\r\n"
            "</body>\r\n"
            "</html>\r\n",
            "nginx/1.24.0", "",
        };

        m["nginx-stable"] = ServerProfile{
            "nginx-stable",
            "Server: nginx\r\n"
            "Date: {date}\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Content-Length: {len}\r\n"
            "Connection: close\r\n"
            "\r\n",
            "<html>\r\n"
            "<head><title>404 Not Found</title></head>\r\n"
            "<body>\r\n"
            "<center><h1>404 Not Found</h1></center>\r\n"
            "<hr><center>nginx</center>\r\n"
            "</body>\r\n"
            "</html>\r\n",
            "nginx", "",
        };

        // Apache 2.4 default 404 (Ubuntu/Debian package) — Date is
        // emitted BEFORE Server (httpd builds the response in that
        // order via ap_send_error_response). Body uses LF endings
        // (real Apache emits literal \n inside the HTML body, not
        // \r\n, regardless of the wire CRLFs for headers).
        m["apache"] = ServerProfile{
            "apache",
            "Date: {date}\r\n"
            "Server: Apache/2.4.58 (Ubuntu)\r\n"
            "Content-Length: {len}\r\n"
            "Connection: close\r\n"
            "Content-Type: text/html; charset=iso-8859-1\r\n"
            "\r\n",
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
            "<html><head>\n"
            "<title>404 Not Found</title>\n"
            "</head><body>\n"
            "<h1>Not Found</h1>\n"
            "<p>The requested URL was not found on this server.</p>\n"
            "<hr>\n"
            "<address>Apache/2.4.58 (Ubuntu) Server at localhost Port 443</address>\n"
            "</body></html>\n",
            "Apache/2.4.58 (Ubuntu)", "",
        };

        // Caddy 2 — Alt-Svc h3 advertisement is part of every response
        // when QUIC is enabled (the default since 2.4). Server: Caddy
        // with no version. Empty body for unrouted 404s.
        m["caddy"] = ServerProfile{
            "caddy",
            "Alt-Svc: h3=\":443\"; ma=2592000\r\n"
            "Server: Caddy\r\n"
            "Date: {date}\r\n"
            "Content-Length: 0\r\n"
            "\r\n",
            "",
            "Caddy", "",
        };

        // Cloudflare edge — captured shape from cloudflare.com 2026-05:
        // many Cloudflare-specific headers in their on-wire order.
        // CF-RAY uses UPPERCASE in the header name (real CF response)
        // even though most other Cloudflare docs say "CF-Ray".
        m["cloudflare"] = ServerProfile{
            "cloudflare",
            "Date: {date}\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Content-Length: {len}\r\n"
            "Connection: keep-alive\r\n"
            "Cache-Control: max-age=10\r\n"
            "Strict-Transport-Security: max-age=15780000; includeSubDomains\r\n"
            "Server: cloudflare\r\n"
            "CF-RAY: {cf_ray}\r\n"
            "alt-svc: h3=\":443\"; ma=86400\r\n"
            "\r\n",
            "<!DOCTYPE html>\n"
            "<html lang=\"en\">\n"
            "<head>\n"
            "<meta charset=\"utf-8\">\n"
            "<title>Not Found</title>\n"
            "</head>\n"
            "<body>\n"
            "<center><h1>404 Not Found</h1></center>\n"
            "</body>\n"
            "</html>\n",
            "cloudflare", "",
        };

        // Express + finalhandler — real default 404 emits:
        //   X-Powered-By, Content-Security-Policy, X-Content-Type-Options,
        //   Content-Type (utf-8), Content-Length, ETag, Date, Connection.
        // ETag is computed from the body; we use a stable fake.
        m["express"] = ServerProfile{
            "express",
            "X-Powered-By: Express\r\n"
            "Content-Security-Policy: default-src 'none'\r\n"
            "X-Content-Type-Options: nosniff\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Content-Length: {len}\r\n"
            "ETag: W/\"95-1LjBYZdHzg7r4kIqvSDcVeR3FzU\"\r\n"
            "Date: {date}\r\n"
            "Connection: close\r\n"
            "\r\n",
            "<!DOCTYPE html>\n"
            "<html lang=\"en\">\n"
            "<head>\n"
            "<meta charset=\"utf-8\">\n"
            "<title>Error</title>\n"
            "</head>\n"
            "<body>\n"
            "<pre>Cannot GET /</pre>\n"
            "</body>\n"
            "</html>\n",
            "", "X-Powered-By: Express\r\n",
        };

        // Gunicorn + werkzeug default 404. Real gunicorn omits the
        // version by default since 21.x ("Server: gunicorn"); we
        // emit the version here because it's the more common default.
        m["gunicorn"] = ServerProfile{
            "gunicorn",
            "Server: gunicorn\r\n"
            "Date: {date}\r\n"
            "Connection: close\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Content-Length: {len}\r\n"
            "\r\n",
            "<!doctype html>\n"
            "<html lang=en>\n"
            "<title>404 Not Found</title>\n"
            "<h1>Not Found</h1>\n"
            "<p>The requested URL was not found on the server. "
            "If you entered the URL manually please check your spelling and try again.</p>\n",
            "gunicorn", "",
        };

        // No Server header at all. Some sites do this deliberately for
        // stealth (e.g. CDNs that strip identifying headers).
        m["none"] = ServerProfile{
            "none",
            "Date: {date}\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n",
            "",
            "", "",
        };

        return m;
    }();
    return kRegistry;
}

const std::unordered_map<std::string, ClientProfile>& client_registry() {
    static const std::unordered_map<std::string, ClientProfile> kRegistry = []{
        std::unordered_map<std::string, ClientProfile> m;
        const auto& cover = cover_profile::active();

        m[std::string(cover.registry_name)] = ClientProfile{
            std::string(cover.registry_name),
            std::string(cover.user_agent),
            cover.tls_profile,
            true,
        };

        return m;
    }();
    return kRegistry;
}

std::string generate_cf_ray() {
    // CF-RAY format: 16-char lowercase hex, dash, 3-char POP code.
    thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<std::uint64_t> dist;
    char hex[17];
    std::snprintf(hex, sizeof(hex), "%016llx", static_cast<unsigned long long>(dist(rng)));
    static const std::array<const char*, 14> kPops{
        "LAX", "SFO", "ORD", "JFK", "ATL", "LHR", "AMS", "FRA",
        "NRT", "SIN", "DXB", "GRU", "JNB", "SYD",
    };
    return std::string(hex) + "-" + kPops[dist(rng) % kPops.size()];
}

std::string replace_placeholders(std::string s, const std::string& body) {
    const std::string len_str = std::to_string(body.size());
    auto replace_all = [](std::string& haystack, std::string_view needle, std::string_view repl) {
        std::size_t pos = 0;
        while ((pos = haystack.find(needle, pos)) != std::string::npos) {
            haystack.replace(pos, needle.size(), repl);
            pos += repl.size();
        }
    };
    replace_all(s, "{len}", len_str);
    // Only compute date / cf_ray if a placeholder is present so
    // profiles that don't use them don't pay the cost.
    if (s.find("{date}") != std::string::npos) {
        replace_all(s, "{date}", http_date_now());
    }
    if (s.find("{cf_ray}") != std::string::npos) {
        replace_all(s, "{cf_ray}", generate_cf_ray());
    }
    return s;
}

}  // namespace

std::string http_date(std::time_t when) {
    std::tm gm{};
#if defined(_WIN32)
    gmtime_s(&gm, &when);
#else
    gmtime_r(&when, &gm);
#endif
    char buf[64];
    // RFC 7231 IMF-fixdate, e.g. "Sun, 06 Nov 1994 08:49:37 GMT"
    std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &gm);
    return std::string(buf);
}

std::string http_date_now() {
    return http_date(std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now()));
}

std::optional<std::time_t> parse_http_date(std::string_view value) {
    // Trim surrounding whitespace; strptime wants a NUL-terminated string.
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t' ||
                              value.back() == '\r' || value.back() == '\n')) {
        value.remove_suffix(1);
    }
    if (value.empty() || value.size() > 64) {
        return std::nullopt;
    }
    const std::string text(value);
    // The three HTTP-date formats (RFC 7231 §7.1.1.1).
    static const char* kFormats[] = {
        "%a, %d %b %Y %H:%M:%S GMT",  // IMF-fixdate
        "%A, %d-%b-%y %H:%M:%S GMT",  // RFC 850
        "%a %b %e %H:%M:%S %Y",       // asctime
    };
    for (const char* fmt : kFormats) {
        std::tm tm{};
        if (::strptime(text.c_str(), fmt, &tm) != nullptr) {
#if defined(_WIN32)
            const std::time_t t = _mkgmtime(&tm);
#else
            const std::time_t t = ::timegm(&tm);  // interpret tm as UTC
#endif
            if (t != static_cast<std::time_t>(-1)) {
                return t;
            }
        }
    }
    return std::nullopt;
}

std::optional<ServerProfile> server(std::string_view name) {
    const auto& reg = server_registry();
    auto it = reg.find(to_lower(name));
    if (it == reg.end()) return std::nullopt;
    return it->second;
}

std::optional<ClientProfile> client(std::string_view name) {
    const auto& reg = client_registry();
    auto it = reg.find(to_lower(name));
    if (it == reg.end()) return std::nullopt;
    return it->second;
}

std::vector<std::string> server_names() {
    std::vector<std::string> out;
    for (const auto& [k, _] : server_registry()) out.push_back(k);
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<std::string> transport_client_names() {
    std::vector<std::string> out;
    for (const auto& [name, profile] : client_registry()) {
        if (profile.complete_transport_fixture) out.push_back(name);
    }
    std::sort(out.begin(), out.end());
    return out;
}

std::optional<ClientProfile> transport_client(std::string_view name) {
    auto profile = client(name);
    if (!profile || !profile->complete_transport_fixture ||
        profile->tls_profile == tls_fingerprint::BrowserProfile::UNKNOWN) {
        return std::nullopt;
    }
    return profile;
}

std::optional<ClientProfile> transport_client_for_tls_profile(
    tls_fingerprint::BrowserProfile tls_profile) {
    for (const auto& [_, profile] : client_registry()) {
        if (profile.complete_transport_fixture && profile.tls_profile == tls_profile) {
            return profile;
        }
    }
    return std::nullopt;
}

bool transport_client_supported(std::string_view name) {
    return transport_client(name).has_value();
}

void set_active_client_ua(std::string ua) {
    const auto expected =
        cover_profile::active().user_agent;
    if (ua != expected) {
        throw std::invalid_argument(
            "YUME 2.0 only accepts the pinned cover-profile User-Agent");
    }
}

std::string active_client_ua() {
    return std::string(
        cover_profile::active().user_agent);
}

std::string render_404(const ServerProfile& p, bool /*connection_close*/) {
    std::string out = "HTTP/1.1 404 Not Found\r\n";
    out += replace_placeholders(p.headers_404, p.body_404);
    out += p.body_404;
    return out;
}

}  // namespace yume::http_profile
