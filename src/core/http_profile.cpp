#include "core/http_profile.hpp"

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

// Builds a registry of canonical-named ServerProfile entries. Body
// text mirrors the shape real servers ship — short and recognizable,
// not byte-perfect (real fingerprinters that compare body bytes
// against a known-good capture will still see a difference, but the
// header-level disguise is the primary goal here and that DOES
// fool layer-7 inspectors that key on Server:/X-Powered-By).
const std::unordered_map<std::string, ServerProfile>& server_registry() {
    static const std::unordered_map<std::string, ServerProfile> kRegistry = []{
        std::unordered_map<std::string, ServerProfile> m;

        m["nginx"] = ServerProfile{
            "nginx",
            "nginx/1.24.0",
            "",
            "<html>\r\n<head><title>404 Not Found</title></head>\r\n"
            "<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
            "<hr><center>nginx/1.24.0</center>\r\n</body>\r\n</html>\r\n",
            "text/html",
            true,
        };

        m["nginx-stable"] = ServerProfile{
            "nginx-stable",
            "nginx",
            "",
            "<html>\r\n<head><title>404 Not Found</title></head>\r\n"
            "<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
            "<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n",
            "text/html",
            true,
        };

        m["apache"] = ServerProfile{
            "apache",
            "Apache/2.4.58 (Ubuntu)",
            "",
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
            "<html><head>\n<title>404 Not Found</title>\n</head><body>\n"
            "<h1>Not Found</h1>\n"
            "<p>The requested URL was not found on this server.</p>\n"
            "<hr>\n<address>Apache/2.4.58 (Ubuntu) Server at localhost Port 443</address>\n"
            "</body></html>\n",
            "text/html; charset=iso-8859-1",
            true,
        };

        m["caddy"] = ServerProfile{
            "caddy",
            "Caddy",
            "",
            "",
            "text/plain",
            true,
        };

        m["cloudflare"] = ServerProfile{
            "cloudflare",
            "cloudflare",
            "",  // CF-Ray is generated per response in render_404
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
            "<title>Page not found | example.com</title>\n</head>\n<body>\n"
            "<div>404 Not Found</div>\n</body></html>\n",
            "text/html; charset=UTF-8",
            true,
        };

        m["express"] = ServerProfile{
            "express",
            "",  // express doesn't set Server by default
            "X-Powered-By: Express\r\n",
            "Cannot GET /\n",
            "text/html; charset=utf-8",
            true,
        };

        m["gunicorn"] = ServerProfile{
            "gunicorn",
            "gunicorn/21.2.0",
            "",
            "<!doctype html><html><head><title>404 Not Found</title></head>"
            "<body><h1>Not Found</h1>"
            "<p>The requested URL was not found on the server.  "
            "If you entered the URL manually please check your spelling and try again.</p>"
            "</body></html>",
            "text/html; charset=utf-8",
            true,
        };

        m["none"] = ServerProfile{
            "none",
            "",
            "",
            "",
            "text/plain",
            true,
        };

        m["yumed"] = ServerProfile{
            "yumed",
            "yumed",
            "",
            "",
            "text/plain",
            false,
        };

        return m;
    }();
    return kRegistry;
}

const std::unordered_map<std::string, ClientProfile>& client_registry() {
    static const std::unordered_map<std::string, ClientProfile> kRegistry = []{
        std::unordered_map<std::string, ClientProfile> m;

        m["chrome"] = ClientProfile{
            "chrome",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        };

        m["firefox"] = ClientProfile{
            "firefox",
            "Mozilla/5.0 (Windows NT 10.0; rv:121.0) Gecko/20100101 Firefox/121.0",
        };

        m["safari"] = ClientProfile{
            "safari",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        };

        m["edge"] = ClientProfile{
            "edge",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        };

        m["curl"] = ClientProfile{
            "curl",
            "curl/8.4.0",
        };

        m["wget"] = ClientProfile{
            "wget",
            "Wget/1.21.4",
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
    // CF-Ray format: 16-char lowercase hex, dash, 3-char POP code.
    thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<std::uint64_t> dist;
    char hex[17];
    std::snprintf(hex, sizeof(hex), "%016llx", static_cast<unsigned long long>(dist(rng)));
    static const std::array<const char*, 10> kPops{
        "LAX", "SFO", "ORD", "JFK", "ATL", "LHR", "AMS", "FRA", "NRT", "SIN",
    };
    return std::string(hex) + "-" + kPops[dist(rng) % kPops.size()];
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

std::string render_404(const ServerProfile& p, bool connection_close) {
    std::string out = "HTTP/1.1 404 Not Found\r\n";
    if (!p.server_header.empty()) {
        out += "Server: " + p.server_header + "\r\n";
    }
    if (p.include_date) {
        out += "Date: " + http_date_now() + "\r\n";
    }
    if (p.name == "cloudflare") {
        out += "CF-Ray: " + generate_cf_ray() + "\r\n";
    }
    if (!p.extra_headers.empty()) {
        out += p.extra_headers;
    }
    out += "Content-Type: " + p.content_type + "\r\n";
    out += "Content-Length: " + std::to_string(p.body_404.size()) + "\r\n";
    if (connection_close) {
        out += "Connection: close\r\n";
    }
    out += "\r\n";
    out += p.body_404;
    return out;
}

}  // namespace yume::http_profile
