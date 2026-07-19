/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/static_site.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <system_error>
#include <vector>

namespace yume::server::static_site {

namespace {

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string lower_ascii(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return out;
}

}  // namespace

std::optional<Resolved> resolve_target(std::string_view target,
                                       std::string_view index_file) {
    // Origin-form only. Reject authority-form ("http://..."), asterisk-form,
    // and empty targets before they can reach path logic.
    if (target.empty() || target.front() != '/' || target.size() > kMaxTargetBytes) {
        return std::nullopt;
    }
    // Strip query and fragment; only the path selects a file.
    target = target.substr(0, target.find_first_of("?#"));

    // Percent-decode. An escape that produces a control byte, a backslash, or
    // a slash is an evasion attempt (%2f/%5c/%00), so reject rather than fold
    // it into the path. Literal '/' stays a separator; literal '\\' is banned.
    std::string decoded;
    decoded.reserve(target.size());
    for (std::size_t i = 0; i < target.size(); ++i) {
        char c = target[i];
        bool from_escape = false;
        if (c == '%') {
            if (i + 2 >= target.size()) return std::nullopt;
            const int hi = hex_value(target[i + 1]);
            const int lo = hex_value(target[i + 2]);
            if (hi < 0 || lo < 0) return std::nullopt;
            c = static_cast<char>((hi << 4) | lo);
            i += 2;
            from_escape = true;
        }
        const unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7f) return std::nullopt;  // controls incl. NUL
        if (c == '\\') return std::nullopt;
        if (from_escape && c == '/') return std::nullopt;  // encoded-slash trick
        decoded.push_back(c);
    }

    // decoded is non-empty and starts with '/'. Split on '/', drop "." and
    // empty segments, and reject any ".." outright — no traversal, even when
    // it would resolve back inside the root.
    const bool trailing_slash = decoded.back() == '/';
    std::vector<std::string> segments;
    std::size_t start = 1;  // skip the leading '/'
    for (std::size_t i = 1; i <= decoded.size(); ++i) {
        if (i == decoded.size() || decoded[i] == '/') {
            std::string seg = decoded.substr(start, i - start);
            start = i + 1;
            if (seg.empty() || seg == ".") continue;
            if (seg == "..") return std::nullopt;
            if (seg.size() > kMaxSegmentBytes) return std::nullopt;
            segments.push_back(std::move(seg));
        }
    }

    std::string rel;
    for (std::size_t i = 0; i < segments.size(); ++i) {
        if (i != 0) rel.push_back('/');
        rel += segments[i];
    }
    // "/" and directory targets serve the index file.
    if (rel.empty() || trailing_slash) {
        if (!rel.empty()) rel.push_back('/');
        rel.append(index_file);
    }
    return Resolved{std::move(rel)};
}

std::string mime_type(std::string_view path) {
    const auto slash = path.find_last_of('/');
    const std::string_view name =
        slash == std::string_view::npos ? path : path.substr(slash + 1);
    const auto dot = name.find_last_of('.');
    if (dot == std::string_view::npos || dot + 1 == name.size()) {
        return "application/octet-stream";
    }
    const std::string ext = lower_ascii(name.substr(dot + 1));

    // Common static-site asset types. Text formats carry charset=utf-8 to match
    // what nginx serves by default.
    static const std::array<std::pair<std::string_view, std::string_view>, 24> kTable{{
        {"html", "text/html; charset=utf-8"},
        {"htm", "text/html; charset=utf-8"},
        {"css", "text/css; charset=utf-8"},
        {"js", "text/javascript; charset=utf-8"},
        {"mjs", "text/javascript; charset=utf-8"},
        {"json", "application/json"},
        {"map", "application/json"},
        {"xml", "application/xml"},
        {"txt", "text/plain; charset=utf-8"},
        {"svg", "image/svg+xml"},
        {"png", "image/png"},
        {"jpg", "image/jpeg"},
        {"jpeg", "image/jpeg"},
        {"gif", "image/gif"},
        {"webp", "image/webp"},
        {"avif", "image/avif"},
        {"ico", "image/x-icon"},
        {"woff", "font/woff"},
        {"woff2", "font/woff2"},
        {"ttf", "font/ttf"},
        {"otf", "font/otf"},
        {"wasm", "application/wasm"},
        {"pdf", "application/pdf"},
        {"webmanifest", "application/manifest+json"},
    }};
    for (const auto& [key, value] : kTable) {
        if (ext == key) return std::string(value);
    }
    return "application/octet-stream";
}

ByteRange parse_byte_range(std::string_view range_header, std::uint64_t file_size) {
    ByteRange out;
    // Trim leading/trailing spaces and require the "bytes=" unit.
    while (!range_header.empty() && (range_header.front() == ' ' || range_header.front() == '\t')) {
        range_header.remove_prefix(1);
    }
    constexpr std::string_view kUnit = "bytes=";
    if (range_header.size() < kUnit.size() || range_header.substr(0, kUnit.size()) != kUnit) {
        return out;  // Absent
    }
    std::string_view spec = range_header.substr(kUnit.size());
    // We only serve a single range; a comma means a multi-range request, which
    // we answer with the full 200 instead of multipart/byteranges.
    if (spec.find(',') != std::string_view::npos) {
        return out;  // Absent
    }
    const auto dash = spec.find('-');
    if (dash == std::string_view::npos) {
        return out;  // malformed -> Absent
    }
    const std::string_view first = spec.substr(0, dash);
    const std::string_view last = spec.substr(dash + 1);

    auto to_u64 = [](std::string_view s, std::uint64_t& v) -> bool {
        if (s.empty()) return false;
        std::uint64_t acc = 0;
        for (char c : s) {
            if (c < '0' || c > '9') return false;
            acc = acc * 10 + static_cast<std::uint64_t>(c - '0');
        }
        v = acc;
        return true;
    };

    if (file_size == 0) {
        out.status = ByteRange::Status::Unsatisfiable;
        return out;
    }

    if (first.empty()) {
        // Suffix form "bytes=-N": the final N bytes.
        std::uint64_t n = 0;
        if (!to_u64(last, n) || n == 0) {
            out.status = ByteRange::Status::Unsatisfiable;
            return out;
        }
        out.start = n >= file_size ? 0 : file_size - n;
        out.end = file_size - 1;
        out.status = ByteRange::Status::Satisfiable;
        return out;
    }

    std::uint64_t start = 0;
    if (!to_u64(first, start)) {
        return out;  // malformed -> Absent
    }
    if (start >= file_size) {
        out.status = ByteRange::Status::Unsatisfiable;
        return out;
    }
    std::uint64_t end = file_size - 1;
    if (!last.empty()) {
        if (!to_u64(last, end)) {
            return out;  // malformed -> Absent
        }
        if (end < start) {
            return out;  // malformed -> Absent
        }
        if (end >= file_size) {
            end = file_size - 1;  // clamp to the file
        }
    }
    out.start = start;
    out.end = end;
    out.status = ByteRange::Status::Satisfiable;
    return out;
}

std::optional<FileContents> read_under_root(const std::string& root,
                                            const std::string& rel_path,
                                            std::size_t max_bytes) {
    namespace fs = std::filesystem;
    std::error_code ec;

    const fs::path root_canon = fs::weakly_canonical(fs::path(root), ec);
    if (ec) return std::nullopt;
    const fs::path full = fs::weakly_canonical(root_canon / fs::path(rel_path), ec);
    if (ec) return std::nullopt;

    // Component-wise containment: full must be root_canon or a descendant.
    // weakly_canonical has already resolved any symlink, so a link pointing
    // outside the root yields an outside path that fails this check. Compare
    // components (not string prefixes) so "/srv/www" does not match
    // "/srv/www-secret".
    auto rit = root_canon.begin();
    auto fit = full.begin();
    for (; rit != root_canon.end(); ++rit, ++fit) {
        if (fit == full.end() || *fit != *rit) return std::nullopt;
    }

    if (!fs::is_regular_file(full, ec) || ec) return std::nullopt;
    const auto size = fs::file_size(full, ec);
    if (ec || size > max_bytes) return std::nullopt;

    std::ifstream in(full, std::ios::binary);
    if (!in) return std::nullopt;
    FileContents out;
    out.bytes.resize(static_cast<std::size_t>(size));
    if (size != 0) {
        in.read(out.bytes.data(), static_cast<std::streamsize>(size));
        if (static_cast<std::uintmax_t>(in.gcount()) != size) return std::nullopt;
    }
    out.mtime = fs::last_write_time(full, ec);  // best-effort; ec ignored
    return out;
}

}  // namespace yume::server::static_site
