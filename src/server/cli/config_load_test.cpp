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
#include <vector>

#include "facade/config/config_io.hpp"
#include "server/cli/args.hpp"
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
        config << R"({"listen_address":"127.0.0.1","listen_port":9443,"auth_keys":"authorized_keys","admin_keys":"admin_keys","allow_embedded_master":true,"preauth_services":["bootstrap-v1"]})";
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
    if (!expect(cfg.listen_address == "127.0.0.1",
                "listen_address should load from the config")) {
        return false;
    }
    if (!expect(cfg.listen_port == 9443,
                "listen_port should load from the config")) {
        return false;
    }
    if (!expect(cfg.allow_embedded_master,
                "allow_embedded_master should load from the config")) {
        return false;
    }
    if (!expect(cfg.preauth_services ==
                    std::vector<std::string>{"bootstrap-v1"},
                "preauth_services should load from the config")) {
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
    if (!expect(cli_cfg.admin_keys == (base / "cli-admin-keys").string(),
                "an explicit --admin-keys value should win over the config")) {
        return false;
    }

    auto parse_and_load = [&](const std::string& listen,
                              yume::server::ServerConfig* parsed_cfg) {
        std::vector<std::string> arguments{
            "yumed", "--config", config_path.string(), "--listen", listen};
        std::vector<char*> argv;
        argv.reserve(arguments.size());
        for (auto& argument : arguments) {
            argv.push_back(argument.data());
        }
        yume::server::cli::ServerCliParseResult result;
        if (!yume::server::cli::parse_server_cli_args(
                static_cast<int>(argv.size()), argv.data(), base.string(),
                *parsed_cfg, &result)) {
            return false;
        }
        return result.config_overrides.listen &&
               yume::server::cli::load_server_config_file_and_resolve_paths(
                   *parsed_cfg, result.config_context,
                   result.config_overrides);
    };

    yume::server::ServerConfig wildcard_cfg;
    if (!expect(parse_and_load("443", &wildcard_cfg),
                "explicit wildcard listen should parse and load") ||
        !expect(wildcard_cfg.listen_port == 443,
                "explicit default-valued listen port should beat config") ||
        !expect(wildcard_cfg.listen_address.empty(),
                "port-only --listen should keep the wildcard bind")) {
        return false;
    }

    yume::server::ServerConfig addressed_cfg;
    if (!expect(parse_and_load("0.0.0.0:8443", &addressed_cfg),
                "explicit addressed listen should parse and load") ||
        !expect(addressed_cfg.listen_port == 8443,
                "explicit non-default listen port should beat config") ||
        !expect(addressed_cfg.listen_address == "0.0.0.0",
                "explicit listen address should beat config")) {
        return false;
    }

    std::vector<std::string> removed_arguments{
        "yumed", "--allow-remote-server-admin"};
    std::vector<char*> removed_argv;
    for (auto& argument : removed_arguments) {
        removed_argv.push_back(argument.data());
    }
    yume::server::ServerConfig removed_cfg;
    yume::server::cli::ServerCliParseResult removed_result;
    return expect(!yume::server::cli::parse_server_cli_args(
                      static_cast<int>(removed_argv.size()),
                      removed_argv.data(), base.string(), removed_cfg,
                      &removed_result),
                  "retired --allow-remote-server-admin must fail unknown");
}

bool test_facade_round_trip(const std::filesystem::path& base) {
    std::string error;
    auto parsed = yume::facade::config_io::parse_server_json(
        R"({"admin_keys":"parsed-admin-keys","preauth_services":["bootstrap-v1"]})",
        base, &error);
    if (!expect(parsed.has_value(), "facade JSON should parse") ||
        !expect(error.empty(), "facade parse should not report an error")) {
        return false;
    }
    if (!expect(parsed->admin_keys == (base / "parsed-admin-keys").string(),
                "facade should resolve admin_keys relative to the config")) {
        return false;
    }
    if (!expect(parsed->preauth_services ==
                    std::vector<std::string>{"bootstrap-v1"},
                "facade should parse preauth_services")) {
        return false;
    }

    yume::server::ServerConfig saved;
    saved.listen_address = "127.0.0.1";
    saved.admin_keys = "saved-admin-keys";
    saved.allow_embedded_master = true;
    saved.preauth_services = {"bootstrap-v1"};
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
                  "facade should serialize and restore admin_keys") &&
           expect(loaded->listen_address == "127.0.0.1",
                  "facade should serialize and restore listen_address") &&
           expect(loaded->allow_embedded_master,
                  "facade should serialize and restore allow_embedded_master") &&
           expect(loaded->preauth_services ==
                      std::vector<std::string>{"bootstrap-v1"},
                  "facade should serialize and restore preauth_services");
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
