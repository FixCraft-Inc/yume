/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * The client config loader had no coverage for malformed numeric fields, and
 * that is exactly where a bug lived: a negative JSON integer was cast straight
 * to uint32_t, so "obfs_jitter_ms": -1 became roughly 49 days of jitter rather
 * than a rejected config. The server loader validated the same field family
 * correctly, which is what made the divergence easy to miss.
 */

#include "client/cli/config/config.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace {

int failures = 0;

void expect(bool condition, const char* what) {
    if (!condition) {
        std::cerr << "FAIL: " << what << "\n";
        ++failures;
    }
}

class TempDir {
public:
    TempDir() {
        base_ = std::filesystem::temp_directory_path() /
                ("yume-client-config-" + std::to_string(::getpid()));
        std::filesystem::create_directories(base_);
    }
    ~TempDir() {
        std::error_code ignored;
        std::filesystem::remove_all(base_, ignored);
    }
    const std::filesystem::path& path() const { return base_; }

private:
    std::filesystem::path base_;
};

// Returns true when the loader refused the document.
bool rejects(const TempDir& dir, const char* name, const std::string& json) {
    const auto file = dir.path() / name;
    {
        std::ofstream out(file, std::ios::binary);
        out << json;
    }
    yume::client::ParsedArgs args;
    args.config_path = file.string();
    yume::client::ClientConfig cfg;
    std::string error;
    const bool loaded = yume::client::load_client_config_file(
        args, dir.path().string(), &cfg, &error);
    return !loaded;
}

bool accepts(const TempDir& dir, const char* name, const std::string& json) {
    return !rejects(dir, name, json);
}

}  // namespace

int main() {
    TempDir dir;

    expect(rejects(dir, "negative-jitter.json", R"({"obfs_jitter_ms":-1})"),
           "a negative obfs_jitter_ms must be rejected, not wrapped to a "
           "49-day jitter");
    expect(rejects(dir, "negative-pad.json", R"({"obfs_pad_multiple":-1})"),
           "a negative obfs_pad_multiple must be rejected");
    expect(rejects(dir, "oversized-jitter.json",
                   R"({"obfs_jitter_ms":4294967296})"),
           "an out-of-range obfs_jitter_ms must not wrap");
    expect(rejects(dir, "string-jitter.json", R"({"obfs_jitter_ms":"5"})"),
           "a string must not be coerced into an unsigned field");

    // The valid forms must still load, or the guard above would be a denial of
    // service rather than a fix.
    expect(accepts(dir, "zero-jitter.json", R"({"obfs_jitter_ms":0})"),
           "zero is a valid obfs_jitter_ms");
    expect(accepts(dir, "valid-jitter.json", R"({"obfs_jitter_ms":25})"),
           "an ordinary obfs_jitter_ms must load");

    if (failures == 0) {
        std::cout << "client config loader test passed\n";
    }
    return failures == 0 ? 0 : 1;
}
