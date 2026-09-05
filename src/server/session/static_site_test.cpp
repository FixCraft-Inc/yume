/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/static_site.hpp"

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>

namespace {

namespace fs = std::filesystem;
using yume::server::static_site::ByteRange;
using yume::server::static_site::mime_type;
using yume::server::static_site::parse_byte_range;
using yume::server::static_site::read_under_root;
using yume::server::static_site::resolve_target;

std::string resolved_or_empty(std::string_view target) {
    auto r = resolve_target(target, "index.html");
    return r.has_value() ? r->rel_path : std::string("<reject>");
}

void test_resolve_index_and_simple_paths() {
    assert(resolved_or_empty("/") == "index.html");
    assert(resolved_or_empty("/index.html") == "index.html");
    assert(resolved_or_empty("/style.css") == "style.css");
    assert(resolved_or_empty("/assets/app.js") == "assets/app.js");
    assert(resolved_or_empty("/img/logo.png?v=3") == "img/logo.png");
    assert(resolved_or_empty("/a/b/c.txt#frag") == "a/b/c.txt");
    // Directory targets resolve to the index file.
    assert(resolved_or_empty("/docs/") == "docs/index.html");
    // "." and empty segments normalize away without escaping.
    assert(resolved_or_empty("/./a//b.js") == "a/b.js");
    // Percent-decoding of ordinary characters is allowed.
    assert(resolved_or_empty("/a%20b.txt") == "a b.txt");
}

void test_resolve_rejects_traversal_and_tricks() {
    assert(!resolve_target("", "index.html").has_value());
    assert(!resolve_target("*", "index.html").has_value());
    assert(!resolve_target("http://evil/x", "index.html").has_value());
    assert(!resolve_target("/../etc/passwd", "index.html").has_value());
    assert(!resolve_target("/a/../../etc/passwd", "index.html").has_value());
    assert(!resolve_target("/a/../b", "index.html").has_value());  // any ".." rejected
    assert(!resolve_target("/%2e%2e/passwd", "index.html").has_value());
    assert(!resolve_target("/%2fetc/passwd", "index.html").has_value());  // encoded slash
    assert(!resolve_target("/%5cwindows", "index.html").has_value());     // encoded backslash
    assert(!resolve_target("/a\\b", "index.html").has_value());           // literal backslash
    assert(!resolve_target("/a%00b", "index.html").has_value());          // NUL
    assert(!resolve_target("/a%01b", "index.html").has_value());          // control
    assert(!resolve_target("/a%zz", "index.html").has_value());           // bad escape
    assert(!resolve_target("/a%2", "index.html").has_value());            // truncated escape
    assert(!resolve_target(std::string("/") + std::string(3000, 'a'), "index.html").has_value());
}

void test_mime_types() {
    assert(mime_type("index.html") == "text/html; charset=utf-8");
    assert(mime_type("a/b/app.JS") == "text/javascript; charset=utf-8");
    assert(mime_type("style.css") == "text/css; charset=utf-8");
    assert(mime_type("logo.png") == "image/png");
    assert(mime_type("photo.JPEG") == "image/jpeg");
    assert(mime_type("font.woff2") == "font/woff2");
    assert(mime_type("data.json") == "application/json");
    assert(mime_type("archive.bin") == "application/octet-stream");
    assert(mime_type("noext") == "application/octet-stream");
    assert(mime_type("trailing.") == "application/octet-stream");
}

void test_parse_byte_range() {
    using S = ByteRange::Status;
    // No/!bytes header -> Absent (serve full 200).
    assert(parse_byte_range("", 1000).status == S::Absent);
    assert(parse_byte_range("items=0-1", 1000).status == S::Absent);
    // Simple closed range.
    auto a = parse_byte_range("bytes=0-99", 1000);
    assert(a.status == S::Satisfiable && a.start == 0 && a.end == 99 && a.length() == 100);
    // Open-ended range to EOF.
    auto b = parse_byte_range("bytes=100-", 1000);
    assert(b.status == S::Satisfiable && b.start == 100 && b.end == 999);
    // Suffix (last N bytes), including N larger than the file.
    auto c = parse_byte_range("bytes=-100", 1000);
    assert(c.status == S::Satisfiable && c.start == 900 && c.end == 999);
    auto d = parse_byte_range("bytes=-5000", 1000);
    assert(d.status == S::Satisfiable && d.start == 0 && d.end == 999);
    // End past EOF clamps.
    auto e = parse_byte_range("bytes=990-100000", 1000);
    assert(e.status == S::Satisfiable && e.start == 990 && e.end == 999);
    // Whitespace tolerated.
    assert(parse_byte_range("  bytes=0-0", 1000).status == S::Satisfiable);
    // Unsatisfiable: start at/after EOF, empty suffix, empty file.
    assert(parse_byte_range("bytes=1000-", 1000).status == S::Unsatisfiable);
    assert(parse_byte_range("bytes=-0", 1000).status == S::Unsatisfiable);
    assert(parse_byte_range("bytes=0-0", 0).status == S::Unsatisfiable);
    // Malformed / multi-range -> Absent (fall back to full 200).
    assert(parse_byte_range("bytes=abc-1", 1000).status == S::Absent);
    assert(parse_byte_range("bytes=5-1", 1000).status == S::Absent);
    assert(parse_byte_range("bytes=0-9,20-29", 1000).status == S::Absent);
    assert(parse_byte_range("bytes=18446744073709551616-", 1000).status == S::Absent);
}

void test_read_under_root_and_symlink_escape() {
    const fs::path base =
        fs::canonical(fs::temp_directory_path()) /
        ("yume_static_site_test_" + std::to_string(std::random_device{}()));
    fs::remove_all(base);
    const fs::path root = base / "www";
    fs::create_directories(root / "assets");
    const fs::path secret = base / "secret.txt";
    {
        std::ofstream(root / "index.html") << "<h1>hi</h1>";
        std::ofstream(root / "assets" / "app.js") << "console.log(1)";
        std::ofstream(secret) << "TOP SECRET";
    }

    auto index = read_under_root(root.string(), "index.html", 1 << 20);
#if defined(_WIN32)
    assert(!index);  // Confined directory reads are unsupported here.
    fs::remove_all(base);
    return;
#endif
    assert(index.has_value() && index->bytes == "<h1>hi</h1>");
    auto app = read_under_root(root.string(), "assets/app.js", 1 << 20);
    assert(app.has_value() && app->bytes == "console.log(1)");

    // Missing file, oversize cap, and directory targets all fail closed.
    assert(!read_under_root(root.string(), "missing.txt", 1 << 20).has_value());
    assert(!read_under_root(root.string(), "index.html", 4).has_value());
    assert(!read_under_root(root.string(), "assets", 1 << 20).has_value());

    // A symlink inside the root that points outside must not be served.
    std::error_code ec;
    fs::create_symlink(secret, root / "leak.txt", ec);
    if (!ec) {  // some filesystems/permissions forbid symlink creation
        assert(!read_under_root(root.string(), "leak.txt", 1 << 20).has_value());
    }

    fs::remove_all(base);
}

}  // namespace

int main() {
    test_resolve_index_and_simple_paths();
    test_resolve_rejects_traversal_and_tricks();
    test_mime_types();
    test_parse_byte_range();
    test_read_under_root_and_symlink_escape();
    std::puts("static_site_test: all cases passed");
    return 0;
}
