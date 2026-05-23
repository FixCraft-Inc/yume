// HTTP-layer disguise profiles. The TLS stealth layer
// (core/tls_stealth.*) already rotates JA3/JA4 fingerprints to look
// like a browser; this module sits one layer above and controls the
// HTTP headers + body shape so a layer-7 inspector reading response
// headers also sees something other than `Server: yumed`.
//
// Used by:
//   - server obfs / session paths that emit a disguise HTTP response
//   - client probes that issue HTTP/1.1 or H2 requests
//
// Profile selection is driven by the `--hide-in-the-crowd <profile>`
// CLI flag on both binaries; the server reads a ServerProfile from
// the name, the client reads a ClientProfile.

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yume::http_profile {

// Server-side disguise. Each field is a literal HTTP fragment ready
// to splice into a response. Body is text-only; the caller fills in
// Content-Length / Connection from runtime data.
struct ServerProfile {
    std::string name;           // canonical name as passed on the CLI
    std::string server_header;  // value for `Server:` header, or "" to omit
    std::string extra_headers;  // additional headers, each ending in \r\n
    std::string body_404;       // body text for a 404 response
    std::string content_type;   // value for `Content-Type:` header
    bool include_date{true};    // emit a Date: header (most real servers do)
};

// Client-side disguise. Currently just the User-Agent string; more
// fields (Accept, Accept-Language ordering, etc.) may join later.
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

// Render a complete 404 response as a single string ready for
// boost::asio::write — handles status line, profile headers, body
// length, and the trailing CRLFCRLF. `connection_close` adds a
// `Connection: close` header (the default for short-circuit responses).
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
