/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// HTTP-layer disguise profiles. The TLS stealth layer
// (core/tls_stealth.*) already rotates JA3/JA4 fingerprints to look
// like a browser; this module sits one layer above and controls the
// HTTP headers + body shape so a layer-7 inspector reading response
// headers also sees something other than `Server: yumed`.
//
// Each ServerProfile carries a per-profile header template for the
// 404 disguise so the wire bytes match the canonical real-server
// shape: nginx headers in nginx's order with charset=utf-8;
// Apache's Date-before-Server order with iso-8859-1; Caddy's Alt-Svc
// h3 advertisement; CloudFlare's CF-RAY (uppercase) + Alt-Svc +
// NEL; Express's Content-Security-Policy + X-Content-Type-Options +
// X-Powered-By; gunicorn's body taken from werkzeug's default 404.
//
// Used by:
//   - server obfs / session paths that emit a disguise HTTP response
//   - client probes that issue HTTP/1.1 or H2 requests
//
// Profile selection is driven by the `--hide-in-the-crowd <profile>`
// CLI flag on both binaries; the server reads a ServerProfile from
// the name, the client reads a ClientProfile.

#pragma once

#include <ctime>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yume::http_profile {

// Server-side disguise.
//
// `headers_404` is a complete header block in the profile's canonical
// on-wire order, including the trailing \r\n that separates headers
// from the body. Placeholders substituted at render time:
//   {date}    → RFC 7231 IMF-fixdate
//   {len}     → body length as decimal
//   {cf_ray}  → 16-hex + 3-char POP code (only used in cloudflare)
// The status line ("HTTP/1.1 404 Not Found\r\n") is prepended; the
// body is appended after the header block.
//
// `server_header_value` / `extra_response_headers` are used by
// non-404 responses (send_real_http_response with --real) where the
// disguise just needs the Server identification, not the full
// per-profile header order.
struct ServerProfile {
    std::string name;
    std::string headers_404;
    std::string body_404;
    std::string server_header_value;     // for --real cover-page
    std::string extra_response_headers;  // e.g. X-Powered-By: Express
};

// Client-side disguise.
struct ClientProfile {
    std::string name;
    std::string user_agent;
};

// Lookups. Names are matched case-insensitively for ergonomics on
// the CLI; the canonical form returned in .name is always lowercase.
std::optional<ServerProfile> server(std::string_view name);
std::optional<ClientProfile> client(std::string_view name);

// For --help text + validation messages.
std::vector<std::string> server_names();
std::vector<std::string> client_names();

// RFC 7231 IMF-fixdate, e.g. "Sun, 06 Nov 1994 08:49:37 GMT". Used for the
// Date / Last-Modified headers of disguise and static-file responses.
std::string http_date(std::time_t when);
std::string http_date_now();

// Render a complete 404 response as a single string ready for
// boost::asio::write — substitutes the placeholders in headers_404
// and appends body_404. `connection_close` does nothing; the
// per-profile header_template already specifies its own connection
// behavior (some profiles use keep-alive, some close).
std::string render_404(const ServerProfile& profile, bool connection_close = true);

// Process-wide setter/getter for the active client User-Agent. The
// client CLI calls set_active_client_ua() once at startup based on
// --hide-in-the-crowd; tls_stealth and any other probe code reads
// the current value via active_client_ua() instead of threading a
// parameter through every call site.
//
// active_client_ua() returns the default "yume-tls-verify/1.0" if no
// profile was set, so existing tests / unit tests that don't go
// through the CLI keep working.
void set_active_client_ua(std::string ua);
std::string active_client_ua();

}  // namespace yume::http_profile
