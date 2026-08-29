/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/config/profiles.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

namespace fs = std::filesystem;
namespace profiles = yume::facade::profiles;

void write_text(const fs::path& path, const std::string& value) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(value.data(), static_cast<std::streamsize>(value.size()));
    output.close();
    assert(output);
}

std::string read_text(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

void reset_profiles() {
    std::error_code error;
    fs::remove_all(profiles::profiles_dir(), error);
    assert(!error);
}

#ifndef _WIN32
void assert_mode(const fs::path& path, mode_t mode) {
    struct stat status {};
    assert(::lstat(path.c_str(), &status) == 0);
    assert((status.st_mode & 07777) == mode);
    assert(status.st_uid == ::geteuid());
}
#endif

void test_slugging() {
    assert(profiles::slug_from("  My__Profile...Name  ") ==
           "my-profile-name");
    assert(profiles::slug_from("A---B") == "a-b");
    const std::string fallback = profiles::slug_from("...///...");
    assert(fallback.size() == 24U);
    assert(fallback.starts_with("profile-"));
    assert(std::all_of(fallback.begin() + 8, fallback.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    }));
}

void test_create_load_save_and_remove() {
    reset_profiles();
    yume::client::ClientConfig config;
    config.server = "edge.example.test";
    config.port = 8443;
    std::string error;
    const auto first = profiles::create("Daily Profile", config, &error);
    assert(first == std::optional<std::string>("daily-profile"));
    const auto second = profiles::create("Daily Profile", config, &error);
    assert(second == std::optional<std::string>("daily-profile-1"));
    assert(error.empty());

    const fs::path first_path = profiles::profiles_dir() / (*first + ".json");
#ifndef _WIN32
    assert_mode(profiles::profiles_dir(), 0700);
    assert_mode(first_path, 0600);
#endif
    const std::string serialized = read_text(first_path);
    const std::size_t display = serialized.find("\"display_name\"");
    assert(display != std::string::npos);
    assert(serialized.find("\"display_name\"", display + 1U) ==
           std::string::npos);

    const auto loaded = profiles::load(*first, &error);
    assert(loaded.has_value());
    assert(loaded->server == config.server);
    assert(loaded->port == config.port);
    assert(profiles::set_active(*first, &error));
    assert(profiles::active_id(&error) == *first);
#ifndef _WIN32
    assert_mode(profiles::active_pointer_path(), 0600);
#endif

    config.port = 9443;
    assert(profiles::save(*first, "Renamed", config, &error));
    const auto saved = profiles::load(*first, &error);
    assert(saved.has_value() && saved->port == 9443);
    assert(profiles::remove(*first, &error));
    assert(!fs::exists(first_path));
    assert(!fs::exists(profiles::active_pointer_path()));
}

void test_invalid_ids_and_active_pointer() {
    reset_profiles();
    yume::client::ClientConfig config;
    std::string error;
    for (const std::string id : {"", "../escape", "a/b", "a\\b", ".",
                                 "Upper"}) {
        assert(!profiles::save(id, "invalid", config, &error));
        assert(!profiles::load(id, &error));
        assert(!profiles::set_active(id, &error));
        assert(!profiles::remove(id, &error));
    }

    for (const std::string id : {"-legacy", "legacy-", "legacy--profile"}) {
        assert(profiles::save(id, "Legacy", config, &error));
        assert(profiles::load(id, &error));
        assert(profiles::remove(id, &error));
    }

    assert(profiles::create("Valid", config, &error));
    write_text(profiles::active_pointer_path(), "../escape\n");
    assert(profiles::active_id(&error).empty());
    assert(!error.empty());
    write_text(profiles::active_pointer_path(),
               std::string(profiles::kMaximumProfileIdBytes + 3U, 'a'));
    assert(profiles::active_id(&error).empty());
    assert(!error.empty());

    write_text(profiles::active_pointer_path(), "missing-profile\n");
    assert(profiles::active_id(&error).empty());
    assert(!error.empty());

    fs::remove(profiles::active_pointer_path());
    const fs::path victim = profiles::profiles_dir() / "active-victim";
    write_text(victim, "unchanged");
    fs::create_symlink(victim, profiles::active_pointer_path());
    assert(profiles::active_id(&error).empty());
    assert(!profiles::set_active("valid", &error));
    assert(read_text(victim) == "unchanged");
}

void test_profile_entry_boundaries() {
    reset_profiles();
    yume::client::ClientConfig config;
    std::string error;
    assert(profiles::create("Seed", config, &error));

    const fs::path victim = profiles::profiles_dir() / "victim.json.data";
    write_text(victim, "unchanged");
    const fs::path link = profiles::profiles_dir() / "linked.json";
    fs::create_symlink(victim, link);
    assert(profiles::list(&error).empty());
    assert(!error.empty());
    fs::remove(link);

    const fs::path oversized = profiles::profiles_dir() / "oversized.json";
    write_text(oversized,
               std::string(profiles::kMaximumProfileBytes + 1U, ' '));
    assert(profiles::list(&error).empty());
    assert(error.find("size limit") != std::string::npos);
    fs::remove(oversized);

    const fs::path invalid = profiles::profiles_dir() / "invalid.json";
    write_text(invalid, "[]");
    assert(!profiles::set_active("invalid", &error));
    assert(!error.empty());
    fs::remove(invalid);

    const fs::path save_victim = profiles::profiles_dir() / "save-victim";
    write_text(save_victim, "unchanged");
    const fs::path save_link = profiles::profiles_dir() / "linked.json";
    fs::create_symlink(save_victim, save_link);
    assert(!profiles::save("linked", "Linked", config, &error));
    assert(read_text(save_victim) == "unchanged");
}

void test_display_limit_and_concurrency() {
    reset_profiles();
    yume::client::ClientConfig config;
    std::string error;
    assert(!profiles::create(
        std::string(profiles::kMaximumDisplayNameBytes + 1U, 'x'),
        config, &error));

    constexpr std::size_t kThreads = 8U;
    std::vector<std::string> ids(kThreads);
    std::vector<std::thread> workers;
    for (std::size_t index = 0; index < kThreads; ++index) {
        workers.emplace_back([&, index] {
            std::string thread_error;
            const auto id = profiles::create("Concurrent", config,
                                             &thread_error);
            if (id) ids[index] = *id;
        });
    }
    for (auto& worker : workers) worker.join();
    assert(std::all_of(ids.begin(), ids.end(), [](const std::string& id) {
        return !id.empty();
    }));
    const std::set<std::string> unique(ids.begin(), ids.end());
    assert(unique.size() == kThreads);
    assert(profiles::list(&error).size() == kThreads);
    assert(error.empty());
}

}  // namespace

int main() {
#ifdef _WIN32
    return 0;
#else
    char temporary_home[] = "/tmp/yume-profiles-XXXXXX";
    assert(::mkdtemp(temporary_home) != nullptr);
    const char* previous_home_value = std::getenv("HOME");
    const std::string previous_home =
        previous_home_value ? previous_home_value : "";
    assert(::setenv("HOME", temporary_home, 1) == 0);

    test_slugging();
    test_create_load_save_and_remove();
    test_invalid_ids_and_active_pointer();
    test_profile_entry_boundaries();
    test_display_limit_and_concurrency();

    if (previous_home_value) {
        assert(::setenv("HOME", previous_home.c_str(), 1) == 0);
    } else {
        assert(::unsetenv("HOME") == 0);
    }
    std::error_code cleanup_error;
    fs::remove_all(temporary_home, cleanup_error);
    assert(!cleanup_error);
    return 0;
#endif
}
