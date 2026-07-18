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
#include <filesystem>
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

struct FileContents {
    std::string bytes;
    std::filesystem::file_time_type mtime;
};

// Read `rel_path` beneath `root`, verifying via canonicalization that the real
// path stays inside `root` (this is what defeats a symlink pointing outside),
// that it is a regular file, and that its size is at most `max_bytes`. Returns
// nullopt on any failure so the caller falls back to the profile 404.
std::optional<FileContents> read_under_root(const std::string& root,
                                            const std::string& rel_path,
                                            std::size_t max_bytes);

}  // namespace yume::server::static_site
