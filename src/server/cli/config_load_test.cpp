/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/config_load.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include "facade/config/config_io.hpp"
#include "server/config/config.hpp"

namespace {

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        const auto nonce = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        path_ = std::filesystem::temp_directory_path() /
                ("yume-server-config-test-" + std::to_string(nonce));
        if (!std::filesystem::create_directory(path_)) {
            throw std::runtime_error("failed to create temporary directory");
        }
    }

    ~TemporaryDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

bool expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
    }
    return condition;
}

bool test_cli_config_load(const std::filesystem::path& base) {
    const auto config_path = base / "yumed.json";
    {
        std::ofstream config(config_path);
        config << R"({"auth_keys":"authorized_keys","admin_keys":"admin_keys"})";
        if (!config) {
            std::cerr << "FAIL: could not write CLI config fixture\n";
            return false;
        }
    }

    yume::server::ServerConfig cfg;
    yume::server::cli::ServerConfigLoadContext context;
    context.config_path = config_path.string();
    context.config_specified = true;
    const yume::server::cli::ServerConfigOverrides overrides;
    if (!expect(yume::server::cli::load_server_config_file_and_resolve_paths(
                    cfg, context, overrides),
                "CLI config should load")) {
        return false;
    }
    if (!expect(cfg.auth_keys == (base / "authorized_keys").string(),
                "auth_keys should resolve relative to the config")) {
        return false;
    }
    if (!expect(cfg.admin_keys == (base / "admin_keys").string(),
                "admin_keys should resolve relative to the config")) {
        return false;
    }

    yume::server::ServerConfig cli_cfg;
    cli_cfg.admin_keys = (base / "cli-admin-keys").string();
    yume::server::cli::ServerConfigLoadContext cli_context;
    cli_context.config_path = config_path.string();
    cli_context.config_specified = true;
    if (!expect(yume::server::cli::load_server_config_file_and_resolve_paths(
                    cli_cfg, cli_context, overrides),
                "CLI-precedence config should load")) {
        return false;
    }
    return expect(cli_cfg.admin_keys == (base / "cli-admin-keys").string(),
                  "an explicit --admin-keys value should win over the config");
}

bool test_facade_round_trip(const std::filesystem::path& base) {
    std::string error;
    auto parsed = yume::facade::config_io::parse_server_json(
        R"({"admin_keys":"parsed-admin-keys"})", base, &error);
    if (!expect(parsed.has_value(), "facade JSON should parse") ||
        !expect(error.empty(), "facade parse should not report an error")) {
        return false;
    }
    if (!expect(parsed->admin_keys == (base / "parsed-admin-keys").string(),
                "facade should resolve admin_keys relative to the config")) {
        return false;
    }

    yume::server::ServerConfig saved;
    saved.admin_keys = "saved-admin-keys";
    const auto saved_path = base / "facade-yumed.json";
    if (!expect(yume::facade::config_io::save_server(saved, saved_path, &error),
                "facade config should save") ||
        !expect(error.empty(), "facade save should not report an error")) {
        return false;
    }
    auto loaded = yume::facade::config_io::load_server(saved_path, &error);
    if (!expect(loaded.has_value(), "saved facade config should load") ||
        !expect(error.empty(), "facade load should not report an error")) {
        return false;
    }
    return expect(loaded->admin_keys == (base / "saved-admin-keys").string(),
                  "facade should serialize and restore admin_keys");
}

}  // namespace

int main() {
    try {
        const TemporaryDirectory temporary;
        return test_cli_config_load(temporary.path()) &&
                       test_facade_round_trip(temporary.path())
                   ? 0
                   : 1;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
