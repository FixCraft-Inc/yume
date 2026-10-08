/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/cover_site.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <stdlib.h>

namespace {

namespace fs = std::filesystem;
using yume::providers::CoverSite;

constexpr std::array<std::pair<std::string_view, std::string_view>, 4U> kFiles{{
    {"index.html", "<title>Garden</title>"},
    {"404.html", "<title>Not found</title>"},
    {"style.css", "body { color: green; }"},
    {"notes/index.html", "<title>Notes</title>"},
}};

// The site any visitor without an admission token sees. It is loaded once
// and its files are removed at once, since answering never reads them.
std::shared_ptr<const CoverSite> load_site() {
    std::string pattern =
        (fs::temp_directory_path() / "yume-fuzz-cover-XXXXXX").string();
    if (::mkdtemp(pattern.data()) == nullptr) std::abort();
    const fs::path root(pattern);
    for (const auto& [name, body] : kFiles) {
        fs::create_directories((root / name).parent_path());
        std::ofstream(root / name, std::ios::binary) << body;
    }
    auto site = CoverSite::load_directory(root);
    std::error_code ignored;
    fs::remove_all(root, ignored);
    if (!site.ok()) std::abort();
    return std::move(site).take_value();
}

// Every regular file is a route, 404.html among them, so a found answer
// carries one of these bodies.
bool is_site_body(std::string_view body) {
    for (const auto& [name, content] : kFiles) {
        if (body == content) return true;
    }
    return false;
}

}  // namespace

// The input is the request method, a newline, then the request target.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    static const auto site = load_site();
    const std::string_view input(reinterpret_cast<const char*>(data), size);
    const auto newline = input.find('\n');
    const auto method = input.substr(0U, newline);
    const auto target = newline == std::string_view::npos
                            ? std::string_view{}
                            : input.substr(newline + 1U);

    const auto response = site->respond(method, target);
    const bool readable = method == "GET" || method == "HEAD";
    if (response.status_code == 200) {
        // Only GET and HEAD select a file, and only one of the site's own.
        if (!readable) __builtin_trap();
        if (method == "GET" && !is_site_body(response.body)) __builtin_trap();
    } else if (response.status_code != 404) {
        __builtin_trap();
    }
    if (method == "HEAD" && !response.body.empty()) __builtin_trap();
    if (readable) {
        // GET and HEAD of one target agree on the answer.
        const auto other =
            site->respond(method == "GET" ? "HEAD" : "GET", target);
        if (other.status_code != response.status_code) __builtin_trap();
    }
    return 0;
}
