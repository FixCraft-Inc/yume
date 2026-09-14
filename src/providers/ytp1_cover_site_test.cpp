/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/ytp1_cover_site.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <limits>
#include <new>
#include <stdexcept>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {
thread_local int allocation_failure_after = -1;
thread_local bool allocation_failed = false;
}

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmismatched-new-delete"
#endif
void* operator new(std::size_t size) {
    if (allocation_failure_after == 0) {
        allocation_failed = true;
        throw std::bad_alloc();
    }
    if (allocation_failure_after > 0) --allocation_failure_after;
    if (void* storage = std::malloc(size == 0U ? 1U : size)) return storage;
    throw std::bad_alloc();
}
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* storage) noexcept { std::free(storage); }
void operator delete[](void* storage) noexcept { ::operator delete(storage); }
void operator delete(void* storage, std::size_t) noexcept { ::operator delete(storage); }
void operator delete[](void* storage, std::size_t) noexcept { ::operator delete(storage); }
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

namespace {
using namespace yume::providers;
using yume::engine::StatusCode;
namespace fs = std::filesystem;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

#if !defined(_WIN32)
class SiteFiles final {
public:
    SiteFiles() {
        std::string pattern = (fs::temp_directory_path() /
                               "yume-cover-site-XXXXXX").string();
        const auto* created = ::mkdtemp(pattern.data());
        require(created != nullptr, "cannot create cover test directory");
        root_ = fs::canonical(created);
        write("index.html", "<title>Garden</title><link rel=stylesheet href=/style.css>");
        write("style.css", "body { color: green; }");
        write("missing.html", "<title>Page unavailable</title><a href=/>Home</a>");
        write("image.bin", std::string_view("\0\1\xff\0", 4U));
    }
    ~SiteFiles() {
        try {
            std::error_code error;
            fs::remove_all(root_, error);
        } catch (...) {}
    }
    SiteFiles(const SiteFiles&) = delete;
    SiteFiles& operator=(const SiteFiles&) = delete;

    void write(const fs::path& path, std::string_view data) const {
        std::ofstream file(root_ / path, std::ios::binary | std::ios::trunc);
        file.write(data.data(), static_cast<std::streamsize>(data.size()));
        file.close();
        require(static_cast<bool>(file), "cannot write cover test file");
    }
    const fs::path& root() const noexcept { return root_; }
    std::vector<Ytp1CoverFile> routes() const {
        return {{"/", "index.html", "text/html; charset=utf-8"},
                {"/style.css", "style.css", "text/css"},
                {"/image.bin", "image.bin", "application/octet-stream"}};
    }
    std::shared_ptr<const Ytp1CoverSite> load(Ytp1CoverLimits limits = {}) const {
        auto result = Ytp1CoverSite::load(root_, routes(), "missing.html", limits);
        require(result.ok(), "cover fixture did not load");
        return std::move(result).take_value();
    }

private:
    fs::path root_;
};

std::string_view header(const Ytp1CoverResponse& response, std::string_view name) {
    for (const auto& [field, value] : response.headers) {
        if (field == name) return value;
    }
    return {};
}

void test_real_site_snapshot_and_head() {
    SiteFiles files;
    const auto site = files.load();
    const auto index = site->respond("GET", "/");
    require(index.status_code == 200 && index.body.find("Garden") != std::string_view::npos,
            "configured index was not served");
    require(header(index, "content-type") == "text/html; charset=utf-8",
            "configured content type was not preserved");
    require(header(index, "content-length") == std::to_string(index.body.size()),
            "index content length is incorrect");
    const auto head = site->respond("HEAD", "/?v=1");
    require(head.status_code == 200 && head.body.empty() &&
                head.headers.data() == index.headers.data(),
            "HEAD did not preserve GET representation headers");
    const auto stylesheet = site->respond("GET", "/%73tyle.css?v=1%20two");
    require(stylesheet.status_code == 200 && stylesheet.body == "body { color: green; }",
            "static asset or normal query handling failed");
    const auto image = site->respond("GET", "/image.bin");
    require(image.status_code == 200 && image.body == std::string_view("\0\1\xff\0", 4U),
            "binary cover asset changed");

    files.write("index.html", "changed after startup");
    require(fs::remove(files.root() / "style.css"), "cannot remove fixture asset");
    require(site->respond("GET", "/").body == index.body &&
                site->respond("GET", "/style.css").body == stylesheet.body,
            "request observed filesystem changes after startup");

    allocation_failure_after = 0;
    allocation_failed = false;
    const auto under_pressure = site->respond("GET", "/style.css?cache=1");
    const auto denied_under_pressure = site->respond("CONNECT", "/invalid-proof");
    allocation_failure_after = -1;
    require(!allocation_failed && under_pressure.body == stylesheet.body &&
                denied_under_pressure.status_code == 404,
            "cover response attempted an allocation");
}

void test_missing_invalid_and_unsupported_are_ordinary_cover() {
    SiteFiles files;
    const auto site = files.load();
    const auto missing = site->respond("GET", "/missing");
    require(missing.status_code == 404 &&
                missing.body == "<title>Page unavailable</title><a href=/>Home</a>",
            "configured not-found file was not served");
    for (const auto method : {"CONNECT", "POST", "OPTIONS", "get", ""}) {
        const auto response = site->respond(method, "/");
        require(response.status_code == 404 && response.body == missing.body &&
                    response.headers.data() == missing.headers.data(),
                "unsupported method exposed a separate rejection response");
    }
    const std::vector<std::string> invalid = {
        "", "*", "https://example.test/", "//style.css", "/../style.css",
        "/./style.css", "/%2e%2e/style.css", "/%2fstyle.css", "/%5cstyle.css",
        "/style.css/..", "/%00", "/style.css%", "/style.css%q1",
        "/style.css#fragment", "/style.css?x=#fragment", "/style.css?x=%",
        "/style.css\r\n", std::string("/style.css\0", 11U),
        std::string(4097U, '/')};
    for (const auto& target : invalid) {
        const auto response = site->respond("GET", target);
        require(response.status_code == 404 && response.body == missing.body &&
                    response.headers.data() == missing.headers.data(),
                "invalid target did not use ordinary not-found response");
    }
    const auto head = site->respond("HEAD", "/missing");
    require(head.status_code == 404 && head.body.empty() &&
                head.headers.data() == missing.headers.data(),
            "HEAD of missing resource lost representation headers");
}

void test_configuration_and_retained_bounds() {
    SiteFiles files;
    const auto routes = files.routes();
    auto absent = Ytp1CoverSite::load(files.root(), {}, "missing.html");
    require(!absent.ok(), "site started without any routes");
    require(!Ytp1CoverSite::load(files.root(), routes, {}).ok(),
            "site started without configured not-found content");
    auto changed = routes;
    changed.erase(changed.begin());
    require(!Ytp1CoverSite::load(files.root(), changed, "missing.html").ok(),
            "site started without index route");
    changed = routes;
    changed.push_back(routes.front());
    const auto duplicate = Ytp1CoverSite::load(files.root(), changed, "missing.html");
    require(!duplicate.ok() && duplicate.status().code() == StatusCode::AlreadyExists,
            "duplicate route was accepted");
    for (const auto path : {"/%73tyle.css", "/?q=1", "/..", "/a//b"}) {
        changed = routes;
        changed[1U].path = path;
        require(!Ytp1CoverSite::load(files.root(), changed, "missing.html").ok(),
                "noncanonical configured route was accepted");
    }
    changed = routes;
    changed[0U].content_type = "text/html\r\nx-extra: value";
    require(!Ytp1CoverSite::load(files.root(), changed, "missing.html").ok(),
            "configured header injection was accepted");

    auto limits = Ytp1CoverLimits{};
    limits.max_routes = routes.size() - 1U;
    require(!Ytp1CoverSite::load(files.root(), routes, "missing.html", limits).ok(),
            "route count bound was ignored");
    limits = {};
    limits.max_file_bytes = 3U;
    require(!Ytp1CoverSite::load(files.root(), routes, "missing.html", limits).ok(),
            "per-file bound was ignored");
    limits = {};
    limits.max_header_bytes = 16U;
    require(!Ytp1CoverSite::load(files.root(), routes, "missing.html", limits).ok(),
            "response header bound was ignored");
    limits = {};
    limits.max_path_bytes = 4U;
    require(!Ytp1CoverSite::load(files.root(), routes, "missing.html", limits).ok(),
            "configured path bound was ignored");

    const auto site = files.load();
    std::size_t retained = 0U;
    for (const auto& route : routes) {
        const auto response = site->respond("GET", route.path);
        retained += route.path.size() + response.body.size();
        for (const auto& [name, value] : response.headers) retained += name.size() + value.size();
    }
    const auto missing = site->respond("GET", "/missing");
    retained += missing.body.size();
    for (const auto& [name, value] : missing.headers) retained += name.size() + value.size();
    limits = {};
    limits.max_total_bytes = retained;
    require(Ytp1CoverSite::load(files.root(), routes, "missing.html", limits).ok(),
            "exact aggregate bound was refused");
    --limits.max_total_bytes;
    require(!Ytp1CoverSite::load(files.root(), routes, "missing.html", limits).ok(),
            "aggregate bound was ignored");

    for (const auto member : {&Ytp1CoverLimits::max_routes, &Ytp1CoverLimits::max_file_bytes,
                              &Ytp1CoverLimits::max_total_bytes, &Ytp1CoverLimits::max_path_bytes,
                              &Ytp1CoverLimits::max_header_bytes}) {
        for (const auto value : {std::size_t{0U}, std::numeric_limits<std::size_t>::max()}) {
            limits = {};
            limits.*member = value;
            const auto result = Ytp1CoverSite::load(files.root(), routes, "missing.html", limits);
            require(!result.ok() && result.status().code() == StatusCode::InvalidArgument,
                    "invalid configured resource limit was accepted");
        }
    }
}

void test_file_confinement_and_special_files() {
    SiteFiles files;
    SiteFiles outside;
    auto routes = files.routes();
    require(::symlink((outside.root() / "index.html").c_str(),
                      (files.root() / "linked.html").c_str()) == 0,
            "cannot create linked-file fixture");
    require(::symlink(outside.root().c_str(), (files.root() / "linked-dir").c_str()) == 0,
            "cannot create linked-directory fixture");
    require(::mkfifo((files.root() / "fifo").c_str(), 0600) == 0,
            "cannot create FIFO fixture");
    require(fs::create_directory(files.root() / "directory"),
            "cannot create directory fixture");
    for (const fs::path& candidate : {fs::path("linked.html"), fs::path("linked-dir/index.html"),
                                    fs::path("fifo"), fs::path("directory"), fs::path("absent"),
                                    fs::path("../index.html"), outside.root() / "index.html"}) {
        routes[0U].relative_file = candidate;
        require(!Ytp1CoverSite::load(files.root(), routes, "missing.html").ok(),
                "unsafe cover file was accepted");
        require(!Ytp1CoverSite::load(files.root(), files.routes(), candidate).ok(),
                "unsafe not-found file was accepted");
    }
    require(!Ytp1CoverSite::load(files.root() / "linked-dir", files.routes(),
                                "missing.html").ok(),
            "symlink root was accepted");
}

void test_startup_allocation_failures_are_contained() {
    SiteFiles files;
    const auto routes = files.routes();
    const fs::path not_found = "missing.html";
    bool completed = false;
    for (int index = 0; index < 512; ++index) {
        allocation_failure_after = index;
        allocation_failed = false;
        const auto result = Ytp1CoverSite::load(files.root(), routes, not_found);
        allocation_failure_after = -1;
        require(!allocation_failed || !result.ok(),
                "partially loaded site escaped after allocation failure");
        if (!allocation_failed) {
            require(result.ok(), "load failed without injected allocation failure");
            completed = true;
            break;
        }
    }
    require(completed, "allocation failure sweep did not reach successful startup");
}

void test_directory_snapshot_and_bounds() {
    SiteFiles files;
    files.write("404.html", "<title>Not found</title>");
    require(fs::create_directory(files.root() / "assets"), "cannot create assets");
    files.write("assets/site.js", "document.documentElement.dataset.ready = 'yes';");
    files.write("assets/index.html", "<title>Assets</title>");
    auto loaded = Ytp1CoverSite::load_directory(files.root());
    require(loaded.ok(), "directory site did not load");
    const auto& site = loaded.value();
    require(site->respond("GET", "/index.html").body == site->respond("GET", "/").body,
            "index file and root route disagree");
    require(site->respond("GET", "/assets/").body == "<title>Assets</title>",
            "nested index route missing");
    require(header(site->respond("GET", "/assets/site.js"), "content-type") ==
                "text/javascript; charset=utf-8", "asset MIME type missing");
    auto bounds = Ytp1CoverLimits{};
    bounds.max_routes = 4U;
    require(!Ytp1CoverSite::load_directory(files.root(), bounds).ok(),
            "enumeration or route bound ignored");
    files.write(".secret", "not public");
    require(!Ytp1CoverSite::load_directory(files.root()).ok(), "hidden file published");
    require(fs::remove(files.root() / ".secret"), "cannot remove test hidden file");
    require(::symlink(files.root().c_str(), (files.root() / "loop").c_str()) == 0,
            "cannot create directory link");
    require(!Ytp1CoverSite::load_directory(files.root()).ok(), "directory link accepted");
    require(fs::remove(files.root() / "loop"), "cannot remove test link");
    require(::mkfifo((files.root() / "fifo").c_str(), 0600) == 0, "cannot create FIFO");
    require(!Ytp1CoverSite::load_directory(files.root()).ok(), "special file accepted");
    require(fs::remove(files.root() / "fifo"), "cannot remove test FIFO");
    require(fs::remove(files.root() / "404.html"), "cannot remove test 404");
    require(!Ytp1CoverSite::load_directory(files.root()).ok(), "missing 404 accepted");
}
#endif

}  // namespace

int main() {
    try {
#if !defined(_WIN32)
        test_real_site_snapshot_and_head();
        test_missing_invalid_and_unsupported_are_ordinary_cover();
        test_configuration_and_retained_bounds();
        test_file_confinement_and_special_files();
        test_startup_allocation_failures_are_contained();
        test_directory_snapshot_and_bounds();
#else
        require(!Ytp1CoverSite::load(".", {{"/", "index.html", "text/html"}},
                                    "missing.html").ok(),
                "unsupported platform failed to close file confinement boundary");
#endif
        return 0;
    } catch (const std::exception& exception) {
        allocation_failure_after = -1;
        std::cerr << exception.what() << '\n';
        return 1;
    }
}
