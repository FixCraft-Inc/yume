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
#include <mutex>
#include <random>
#include <string>
#include <unordered_map>

namespace yume::http_profile {

namespace {

std::string to_lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// Server profile registry. Each entry's headers_404 is the EXACT
// header block (in the EXACT header order) that the real server
// software emits, captured from canonical public deployments
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

        // Legacy default: short response that says yumed. Not for
        // stealth; kept for back-compat with operators who explicitly
        // opt out of disguise.
        m["yumed"] = ServerProfile{
            "yumed",
            "Server: yumed\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n",
            "",
            "yumed", "",
        };

        return m;
    }();
    return kRegistry;
}

const std::unordered_map<std::string, ClientProfile>& client_registry() {
    static const std::unordered_map<std::string, ClientProfile> kRegistry = []{
        std::unordered_map<std::string, ClientProfile> m;

        // Current stable UAs captured from each browser's about-page
        // 2026-05. Held stable here so traffic from one yume install
        // doesn't drift relative to others under a UA-version pinning
        // fingerprint.
        m["chrome"] = ClientProfile{
            "chrome",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        };

        m["firefox"] = ClientProfile{
            "firefox",
            "Mozilla/5.0 (Windows NT 10.0; rv:133.0) Gecko/20100101 Firefox/133.0",
        };

        m["safari"] = ClientProfile{
            "safari",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/18.1 Safari/605.1.15",
        };

        m["edge"] = ClientProfile{
            "edge",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
        };

        m["curl"] = ClientProfile{
            "curl",
            "curl/8.10.1",
        };

        m["wget"] = ClientProfile{
            "wget",
            "Wget/1.24.5",
        };

        m["yume"] = ClientProfile{
            "yume",
            "yume-tls-verify/1.0",
        };

        return m;
    }();
    return kRegistry;
}

std::string http_date_now() {
    using namespace std::chrono;
    auto t = system_clock::to_time_t(system_clock::now());
    std::tm gm{};
#if defined(_WIN32)
    gmtime_s(&gm, &t);
#else
    gmtime_r(&t, &gm);
#endif
    char buf[64];
    // RFC 7231 IMF-fixdate, e.g. "Sun, 06 Nov 1994 08:49:37 GMT"
    std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &gm);
    return std::string(buf);
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

std::vector<std::string> client_names() {
    std::vector<std::string> out;
    for (const auto& [k, _] : client_registry()) out.push_back(k);
    std::sort(out.begin(), out.end());
    return out;
}

namespace {

// Set once at client startup; read on every probe. The default
// matches the historical hard-coded UA so callers that bypass the
// CLI (unit tests, embedded uses) see no behavior change.
std::mutex g_ua_mu;
std::string g_active_ua = "yume-tls-verify/1.0";

}  // namespace

void set_active_client_ua(std::string ua) {
    std::lock_guard<std::mutex> lock(g_ua_mu);
    g_active_ua = std::move(ua);
}

std::string active_client_ua() {
    std::lock_guard<std::mutex> lock(g_ua_mu);
    return g_active_ua;
}

std::string render_404(const ServerProfile& p, bool /*connection_close*/) {
    std::string out = "HTTP/1.1 404 Not Found\r\n";
    out += replace_placeholders(p.headers_404, p.body_404);
    out += p.body_404;
    return out;
}

}  // namespace yume::http_profile
