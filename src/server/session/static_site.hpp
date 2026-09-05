/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Static-site masquerade cover (`--real-root <dir>`). This is the layer that
// turns the decoy from "GET / => 200, everything else => 404" into a coherent
// multi-asset web property, so an active prober that walks more than one URL
// sees a real site instead of a single-page tell.
//
// Everything here is pure (path grammar + MIME) plus one bounded filesystem
// read; there is no session or network state, so the security-critical target
// resolution is unit-tested in isolation (static_site_test.cpp). The rules are
// deliberately stricter than a general web server: any request that could only
// exist to escape the root (`..`, encoded slash, backslash, control bytes,
// absolute/authority form, over-length) is rejected outright rather than
// normalized, because a real static asset never needs those shapes.

#pragma once

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <string_view>

namespace yume::server::static_site {

// Raw request-target caps. A real asset path stays well under these; anything
// larger is a probe/fuzz artifact, not a file.
inline constexpr std::size_t kMaxTargetBytes = 2048;
inline constexpr std::size_t kMaxSegmentBytes = 255;  // POSIX NAME_MAX

struct Resolved {
    // Root-relative, forward-slash, no leading '/'. A bare "/" or a directory
    // target resolves to "<dir>/<index_file>".
    std::string rel_path;
};

// Map an HTTP request target (origin-form, e.g. "/assets/app.js?v=2") to a
// safe root-relative path, or nullopt if it must never touch the filesystem.
// Percent-encoding is decoded, but an encoded slash or backslash is a rejected
// evasion attempt, not a path separator.
std::optional<Resolved> resolve_target(std::string_view target,
                                       std::string_view index_file);

// Content-Type for a filename, matched on the final extension
// (case-insensitive). Unknown extensions map to application/octet-stream.
std::string mime_type(std::string_view path);

// Evaluation of a single-range HTTP `Range` header against a known file size.
// Multi-range and malformed values report Absent so the caller serves the full
// 200 (we do not emit multipart/byteranges). Satisfiable ranges are clamped to
// the file; a start past the end is Unsatisfiable (416).
struct ByteRange {
    enum class Status { Absent, Satisfiable, Unsatisfiable };
    Status status = Status::Absent;
    std::uint64_t start = 0;  // inclusive
    std::uint64_t end = 0;    // inclusive
    std::uint64_t length() const { return end - start + 1; }
};
ByteRange parse_byte_range(std::string_view range_header, std::uint64_t file_size);

struct FileContents {
    std::string bytes;
    std::time_t mtime{};
};

// Open root and each child through pinned directory descriptors. Reject all
// symlinks and parent components; read bytes and mtime from the same regular
// file handle under max_bytes. Unsupported platforms and read failures return
// nullopt so the caller falls back to the profile 404.
std::optional<FileContents> read_under_root(const std::string& root,
                                            const std::string& rel_path,
                                            std::size_t max_bytes);

}  // namespace yume::server::static_site
