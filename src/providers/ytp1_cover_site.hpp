/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <cstddef>
#include <filesystem>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "engine/status.hpp"

namespace yume::providers {

struct Ytp1CoverFile final {
    std::string path;
    std::filesystem::path relative_file;
    std::string content_type;
};

struct Ytp1CoverLimits final {
    std::size_t max_routes{256U};
    std::size_t max_file_bytes{1024U * 1024U};
    // Includes loaded bodies, route names and response header names/values.
    std::size_t max_total_bytes{16U * 1024U * 1024U};
    std::size_t max_path_bytes{4096U};
    std::size_t max_header_bytes{1024U};
};

struct Ytp1CoverResponse final {
    int status_code{404};
    std::span<const std::pair<std::string, std::string>> headers;
    std::string_view body;
};

// A snapshot of an operator-supplied static website. Startup requires an index
// route and an explicit HTML not-found file; no synthetic site is available.
// Files are confined through runtime::FileRoot and no descriptor is retained.
// Requests perform no allocation, filesystem access or DNS resolution.
class Ytp1CoverSite final {
public:
    static engine::Result<std::shared_ptr<const Ytp1CoverSite>> load(
        const std::filesystem::path& root,
        const std::vector<Ytp1CoverFile>& routes,
        const std::filesystem::path& not_found_file,
        Ytp1CoverLimits limits = {}) noexcept;

    // Load an operator-owned tree with index.html at / and 404.html for misses.
    // Every regular file becomes an exact route; nested index.html also maps
    // to its directory URL. Hidden entries, links, special files, excessive
    // depth and enumeration limits fail startup. FileRoot owns content reads;
    // enumeration never makes request-time filesystem access necessary.
    static engine::Result<std::shared_ptr<const Ytp1CoverSite>> load_directory(
        const std::filesystem::path& root, Ytp1CoverLimits limits = {}) noexcept;

    // Returned views remain valid while this immutable site is retained.
    // GET/HEAD select configured routes; all other methods and invalid targets
    // receive the same configured not-found representation. HEAD omits only
    // the body, retaining the GET content-length. Queries do not select files.
    Ytp1CoverResponse respond(std::string_view method,
                             std::string_view target) const noexcept;

private:
    struct Representation final {
        std::array<std::pair<std::string, std::string>, 2U> headers;
        std::string body;
    };

    explicit Ytp1CoverSite(Ytp1CoverLimits limits) noexcept : limits_(limits) {}

    Ytp1CoverLimits limits_;
    std::map<std::string, Representation, std::less<>> routes_;
    Representation not_found_;
};

}  // namespace yume::providers
