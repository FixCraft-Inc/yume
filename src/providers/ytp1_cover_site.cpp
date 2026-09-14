/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/ytp1_cover_site.hpp"

#include <algorithm>
#include <new>
#include <optional>

#include "core/runtime/bounded_file.hpp"

namespace yume::providers {
namespace {

constexpr std::size_t kMaxPathBytes = 4096U;
constexpr std::size_t kMaxRoutes = 4096U;
constexpr std::size_t kMaxFileBytes = 16U * 1024U * 1024U;
constexpr std::size_t kMaxTotalBytes = 256U * 1024U * 1024U;
constexpr std::size_t kMaxHeaderBytes = 16U * 1024U;
constexpr std::string_view kNotFoundContentType = "text/html";

bool valid_limits(const Ytp1CoverLimits& limits) noexcept {
    return limits.max_routes > 0U && limits.max_routes <= kMaxRoutes &&
           limits.max_file_bytes > 0U && limits.max_file_bytes <= kMaxFileBytes &&
           limits.max_total_bytes > 0U && limits.max_total_bytes <= kMaxTotalBytes &&
           limits.max_path_bytes > 0U && limits.max_path_bytes <= kMaxPathBytes &&
           limits.max_header_bytes > 0U && limits.max_header_bytes <= kMaxHeaderBytes;
}

int hex_value(char value) noexcept {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

bool path_character(char value) noexcept {
    return (value >= 'a' && value <= 'z') ||
           (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9') ||
           std::string_view("-._~!$&'()*+,;=:@/").find(value) !=
               std::string_view::npos;
}

// Decode one origin-form ASCII path, reject ambiguous separators and dot
// components, and validate (but do not retain) the query. No decoded text is
// ever used as a filesystem path; it selects only a preloaded route.
std::optional<std::string_view> normalize_target(
    std::string_view target, std::size_t maximum,
    std::array<char, kMaxPathBytes>& buffer) noexcept {
    if (target.empty() || target.size() > maximum || target.front() != '/') {
        return std::nullopt;
    }
    const auto query = target.find('?');
    const auto path = target.substr(0U, query);
    std::size_t count = 0U;
    for (std::size_t index = 0U; index < target.size(); ++index) {
        char value = target[index];
        const bool in_path = index < path.size();
        if (value == '%') {
            if (index + 2U >= target.size()) return std::nullopt;
            const int high = hex_value(target[index + 1U]);
            const int low = hex_value(target[index + 2U]);
            if (high < 0 || low < 0) return std::nullopt;
            value = static_cast<char>((high << 4U) | low);
            index += 2U;
            // Encoded slash could otherwise create new path components.
            if (in_path && (index >= path.size() || value == '/')) {
                return std::nullopt;
            }
            if (!in_path) continue;
        } else if (!in_path && value == '?') {
            continue;
        }
        if (!path_character(value)) return std::nullopt;
        if (in_path) buffer[count++] = value;
    }
    const std::string_view normalized(buffer.data(), count);
    if (normalized.find("//") != std::string_view::npos) return std::nullopt;
    std::size_t component = 1U;
    while (component < count) {
        const auto separator = normalized.find('/', component);
        const auto part = normalized.substr(
            component, separator == std::string_view::npos
                           ? count - component : separator - component);
        if (part == "." || part == "..") return std::nullopt;
        if (separator == std::string_view::npos) break;
        component = separator + 1U;
    }
    return normalized;
}

bool valid_content_type(std::string_view type, std::size_t maximum) noexcept {
    const auto slash = type.find('/');
    if (type.empty() || type.size() > maximum || slash == std::string_view::npos ||
        slash == 0U || slash + 1U == type.size() || type.front() == ' ' ||
        type.back() == ' ') {
        return false;
    }
    return std::all_of(type.begin(), type.end(), [](unsigned char value) {
        return value >= 0x20U && value <= 0x7eU;
    });
}

std::string_view content_type(const std::filesystem::path& file) {
    const auto extension = file.extension().string();
    if (extension == ".html" || extension == ".htm") return "text/html; charset=utf-8";
    if (extension == ".css") return "text/css; charset=utf-8";
    if (extension == ".js") return "text/javascript; charset=utf-8";
    if (extension == ".json") return "application/json";
    if (extension == ".txt") return "text/plain; charset=utf-8";
    if (extension == ".svg") return "image/svg+xml";
    if (extension == ".png") return "image/png";
    if (extension == ".jpg" || extension == ".jpeg") return "image/jpeg";
    if (extension == ".webp") return "image/webp";
    if (extension == ".gif") return "image/gif";
    if (extension == ".ico") return "image/x-icon";
    if (extension == ".woff2") return "font/woff2";
    return "application/octet-stream";
}

}  // namespace

engine::Result<std::shared_ptr<const Ytp1CoverSite>> Ytp1CoverSite::load_directory(
    const std::filesystem::path& root, Ytp1CoverLimits limits) noexcept {
    using engine::Status;
    using engine::StatusCode;
    using SiteResult = engine::Result<std::shared_ptr<const Ytp1CoverSite>>;
    namespace fs = std::filesystem;
    try {
        // FileRoot validates every root component before enumeration as well
        // as when reading the selected files. Concurrent mutation may fail or
        // change the snapshot; it cannot authorize a symlink content read.
        if (!valid_limits(limits) || !runtime::FileRoot::open(root))
            return SiteResult(Status(StatusCode::InvalidArgument, "cover site root or limits are invalid"));
        std::vector<Ytp1CoverFile> routes;
        std::size_t entries = 0U;
        std::size_t path_bytes = 0U;
        for (fs::recursive_directory_iterator it(root), end; it != end; ++it) {
            if (++entries > limits.max_routes || it.depth() >= 16)
                return SiteResult(Status(StatusCode::ResourceExhausted, "cover directory enumeration limit exceeded"));
            const auto relative = it->path().lexically_relative(root);
            const auto filename = relative.filename().string();
            const auto status = it->symlink_status();
            if (filename.empty() || filename.front() == '.' ||
                (!fs::is_directory(status) && !fs::is_regular_file(status)))
                return SiteResult(Status(StatusCode::InvalidArgument, "cover tree contains a hidden or nonregular entry"));
            const auto path = "/" + relative.generic_string();
            if (path.size() > limits.max_path_bytes ||
                path.size() > limits.max_total_bytes - path_bytes)
                return SiteResult(Status(StatusCode::ResourceExhausted, "cover directory path limit exceeded"));
            path_bytes += path.size();
            if (fs::is_directory(status)) continue;
            routes.push_back({path, relative, std::string(content_type(relative))});
            if (filename == "index.html")
                routes.push_back({path.substr(0U, path.size() - filename.size()), relative,
                                  "text/html; charset=utf-8"});
            if (routes.size() > limits.max_routes)
                return SiteResult(Status(StatusCode::ResourceExhausted, "cover site route limit exceeded"));
        }
        return load(root, routes, "404.html", limits);
    } catch (const std::bad_alloc&) {
        return SiteResult(Status(StatusCode::ResourceExhausted));
    } catch (const fs::filesystem_error&) {
        return SiteResult(Status(StatusCode::InvalidArgument));
    } catch (...) {
        return SiteResult(Status(StatusCode::Internal));
    }
}

engine::Result<std::shared_ptr<const Ytp1CoverSite>> Ytp1CoverSite::load(
    const std::filesystem::path& root,
    const std::vector<Ytp1CoverFile>& routes,
    const std::filesystem::path& not_found_file,
    Ytp1CoverLimits limits) noexcept {
    using engine::Status;
    using engine::StatusCode;
    using SiteResult = engine::Result<std::shared_ptr<const Ytp1CoverSite>>;
    try {
        if (!valid_limits(limits) || routes.empty() || not_found_file.empty()) {
            return SiteResult(Status(StatusCode::InvalidArgument,
                                     "cover site configuration is invalid"));
        }
        if (routes.size() > limits.max_routes) {
            return SiteResult(Status(StatusCode::ResourceExhausted,
                                     "cover site route limit exceeded"));
        }
        auto site = std::shared_ptr<Ytp1CoverSite>(new Ytp1CoverSite(limits));
        std::array<char, kMaxPathBytes> normalized{};
        std::size_t route_bytes = 0U;
        for (const auto& route : routes) {
            const auto path = normalize_target(route.path, limits.max_path_bytes,
                                               normalized);
            if (!path || *path != route.path || route.relative_file.empty() ||
                !valid_content_type(route.content_type, limits.max_header_bytes)) {
                return SiteResult(Status(StatusCode::InvalidArgument,
                                         "cover site route is invalid"));
            }
            if (route.path.size() > limits.max_total_bytes - route_bytes) {
                return SiteResult(Status(StatusCode::ResourceExhausted,
                                         "cover site route storage limit exceeded"));
            }
            if (!site->routes_.try_emplace(route.path).second) {
                return SiteResult(Status(StatusCode::AlreadyExists,
                                         "cover site route is duplicated"));
            }
            route_bytes += route.path.size();
        }
        if (!site->routes_.contains("/")) {
            return SiteResult(Status(StatusCode::InvalidArgument,
                                     "cover site index route is missing"));
        }
        auto files = runtime::FileRoot::open(root);
        if (!files) {
            return SiteResult(Status(StatusCode::InvalidArgument,
                                     "cover site root cannot be opened"));
        }
        std::size_t retained = route_bytes;
        const auto read_representation = [&](const std::filesystem::path& file,
                                             std::string_view content_type,
                                             Representation& output) -> Status {
            const std::size_t fixed_bytes =
                std::string_view("content-type").size() +
                content_type.size() + std::string_view("content-length").size();
            // Every representation has at least one content-length digit.
            if (fixed_bytes >= limits.max_header_bytes) {
                return Status(StatusCode::ResourceExhausted,
                              "cover site header limit exceeded");
            }
            if (fixed_bytes > limits.max_total_bytes - retained) {
                return Status(StatusCode::ResourceExhausted,
                              "cover site total limit exceeded");
            }
            const auto remaining = limits.max_total_bytes - retained - fixed_bytes;
            if (!files->read_text(file, std::min(limits.max_file_bytes, remaining),
                                  &output.body)) {
                return Status(StatusCode::InvalidArgument,
                              "cover site file is unavailable or exceeds its bound");
            }
            auto length = std::to_string(output.body.size());
            const std::size_t header_bytes = fixed_bytes + length.size();
            if (header_bytes > limits.max_header_bytes ||
                length.size() > remaining - output.body.size()) {
                return Status(StatusCode::ResourceExhausted,
                              "cover site response limit exceeded");
            }
            output.headers = {{{"content-type", std::string(content_type)},
                               {"content-length", std::move(length)}}};
            retained += header_bytes + output.body.size();
            return Status::success();
        };
        for (const auto& route : routes) {
            auto status = read_representation(route.relative_file, route.content_type,
                                               site->routes_.at(route.path));
            if (!status.ok()) return SiteResult(std::move(status));
        }
        auto status = read_representation(not_found_file, kNotFoundContentType,
                                          site->not_found_);
        if (!status.ok()) return SiteResult(std::move(status));
        return SiteResult(std::shared_ptr<const Ytp1CoverSite>(std::move(site)));
    } catch (const std::bad_alloc&) {
        // Empty diagnostics keep the allocation-failure boundary nonallocating.
        return SiteResult(Status(StatusCode::ResourceExhausted));
    } catch (...) {
        return SiteResult(Status(StatusCode::Internal));
    }
}

Ytp1CoverResponse Ytp1CoverSite::respond(std::string_view method,
                                       std::string_view target) const noexcept {
    const Representation* representation = &not_found_;
    int status = 404;
    if (method == "GET" || method == "HEAD") {
        std::array<char, kMaxPathBytes> buffer{};
        if (const auto path = normalize_target(target, limits_.max_path_bytes, buffer)) {
            if (const auto route = routes_.find(*path); route != routes_.end()) {
                representation = &route->second;
                status = 200;
            }
        }
    }
    return {status, representation->headers,
            method == "HEAD" ? std::string_view{} : representation->body};
}

}  // namespace yume::providers
