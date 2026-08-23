/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/config_load.hpp"
#include "server/cli/entry.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "facade/config/config_io.hpp"
#include "server/cli/args.hpp"
#include "server/cli/cluster.hpp"
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

bool test_shutdown_request_latch() {
    yume::server::ShutdownRequestLatch latch;
    return expect(
               latch.request() == yume::server::ShutdownRequest::Graceful,
               "the first termination request should begin graceful shutdown") &&
           expect(
               latch.request() == yume::server::ShutdownRequest::Force,
               "a second termination request should force shutdown") &&
           expect(
               latch.request() == yume::server::ShutdownRequest::Force,
               "all later termination requests should remain forceful");
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

    const auto expanded = nlohmann::json::parse(
        yume::server::cli::expand_cluster_join_spec(
            "peer-a@example.test:9443?psk_file=/run/peer.psk&"
            "carrier_secret_file=/run/peer.carrier&pin=abcd"));
    if (!expect(expanded.value("id", "") == "peer-a",
                "cluster join should preserve the explicit peer id") ||
        !expect(expanded.value("psk_file", "") == "/run/peer.psk",
                "cluster join should carry the pairwise PSK path") ||
        !expect(expanded.value("carrier_secret_file", "") ==
                    "/run/peer.carrier",
                "cluster join should carry the carrier-secret path")) {
        return false;
    }
    bool missing_secrets_rejected = false;
    try {
        (void)yume::server::cli::expand_cluster_join_spec(
            "peer-a@example.test:9443");
    } catch (const std::runtime_error&) {
        missing_secrets_rejected = true;
    }
    if (!expect(missing_secrets_rejected,
                "cluster join without both secret paths must fail closed")) {
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

bool test_cli_rejects_malformed_collections(
    const std::filesystem::path& base) {
    const auto rejects = [&](const std::string& name,
                             const std::string& document) {
        const auto path = base / name;
        {
            std::ofstream output(path);
            output << document;
            if (!output) return false;
        }
        yume::server::ServerConfig config;
        yume::server::cli::ServerConfigLoadContext context;
        context.config_path = path.string();
        context.config_specified = true;
        return !yume::server::cli::load_server_config_file_and_resolve_paths(
            config, context, {});
    };

    return expect(rejects("non-object.json", R"([])"),
                  "CLI must reject a non-object server config") &&
           expect(rejects("filter-lists-object.json",
                          R"({"filter_lists":{}})"),
                  "CLI must reject a non-array filter_lists value") &&
           expect(rejects("filter-lists-entry.json",
                          R"({"filter_lists":["allow.txt",7]})"),
                  "CLI must reject a non-string filter_lists entry") &&
           expect(rejects("federation-peers-object.json",
                          R"({"federation_peers":{}})"),
                  "CLI must reject a non-array federation_peers value") &&
           expect(rejects("federation-peers-entry.json",
                          R"({"federation_peers":["peer.example"]})"),
                  "CLI must reject a non-object federation peer");
}

bool test_cli_load_is_type_strict_and_transactional(
    const std::filesystem::path& base) {
    const auto rejects_without_mutation = [&](const std::string& name,
                                               const std::string& document,
                                               const auto& configure_overrides) {
        const auto path = base / name;
        {
            std::ofstream output(path);
            output << document;
            if (!output) return false;
        }

        yume::server::ServerConfig config;
        config.listen_address = "original-listen";
        config.max_sessions = 37;
        config.allowed_services = {"original-service"};
        yume::server::cli::ServerConfigLoadContext context;
        context.config_path = path.string();
        context.config_specified = true;
        context.config_dir = "original-config-dir";
        yume::server::cli::ServerConfigOverrides overrides;
        configure_overrides(&overrides);

        if (yume::server::cli::load_server_config_file_and_resolve_paths(
                config, context, overrides)) {
            return false;
        }
        return config.listen_address == "original-listen" &&
               config.max_sessions == 37 &&
               config.allowed_services ==
                   std::vector<std::string>{"original-service"} &&
               context.config_dir == "original-config-dir";
    };
    const auto no_overrides = [](auto*) {};

    return expect(
               rejects_without_mutation(
                   "partial-before-error.json",
                   R"({"listen_address":"must-not-escape","allow_services":["new-service",7]})",
                   no_overrides),
               "a late collection error must not expose earlier server fields") &&
           expect(
               rejects_without_mutation(
                   "float-port.json", R"({"listen_port":443.5})",
                   no_overrides),
               "floating-point JSON must not be coerced into an integer port") &&
           expect(
               rejects_without_mutation(
                   "numeric-bool.json", R"({"obfuscation":1})",
                   no_overrides),
               "numeric JSON must not be coerced into a boolean") &&
           expect(
               rejects_without_mutation(
                   "negative-u32.json", R"({"max_sessions":-1})",
                   no_overrides),
               "negative JSON must not be accepted for an unsigned field") &&
           expect(
               rejects_without_mutation(
                   "oversized-u32.json", R"({"max_sessions":4294967296})",
                   no_overrides),
               "out-of-range JSON must not wrap an unsigned field") &&
           expect(
               rejects_without_mutation(
                   "overridden-wrong-type.json", R"({"listen_address":7})",
                   [](auto* overrides) { overrides->listen = true; }),
               "CLI precedence must not hide a malformed config value") &&
           expect(
               rejects_without_mutation(
                   "security-float.json",
                   R"({"security_mode":"ultimate","security_custom":{"epoch_bytes":262144.5,"epoch_frames":1,"epoch_active_ms":500}})",
                   no_overrides),
               "custom security limits must require exact integer JSON");
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

    auto wrong_type = yume::facade::config_io::parse_server_json(
        R"({"listen_port":"443"})", base, &error);
    if (!expect(!wrong_type.has_value(),
                "facade must reject a wrong-typed server field") ||
        !expect(error.find("listen_port") != std::string::npos,
                "wrong-typed server field should name its key")) {
        return false;
    }
    auto wrong_root = yume::facade::config_io::parse_server_json(
        R"([])", base, &error);
    if (!expect(!wrong_root.has_value(),
                "facade must reject a non-object server config") ||
        !expect(error.find("JSON object") != std::string::npos,
                "non-object server config should report its contract")) {
        return false;
    }
    auto wrong_codec_list = yume::facade::config_io::parse_server_json(
        R"({"allow_codecs":["not-a-codec"]})", base, &error);
    if (!expect(!wrong_codec_list.has_value(),
                "facade must reject an unsupported server codec") ||
        !expect(error.find("unsupported application codec") !=
                    std::string::npos,
                "unsupported server codec should report its contract")) {
        return false;
    }

    yume::server::ServerConfig saved;
    saved.listen_address = "127.0.0.1";
    saved.admin_keys = "saved-admin-keys";
    saved.allow_embedded_master = true;
    saved.preauth_services = {"bootstrap-v1"};
    saved.obfs_secret = "inline-secret-must-not-survive";
    const auto saved_path = base / "facade-yumed.json";
    if (!expect(yume::facade::config_io::save_server(saved, saved_path, &error),
                "facade config should save") ||
        !expect(error.empty(), "facade save should not report an error")) {
        return false;
    }
    {
        std::ifstream input(saved_path);
        nlohmann::json document;
        input >> document;
        if (!expect(input.good() || input.eof(),
                    "saved facade server config should be readable") ||
            !expect(!document.contains("obfs_secret"),
                    "server writer must not serialize inline legacy secrets")) {
            return false;
        }
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

bool test_typed_facade_load_errors(const std::filesystem::path& base) {
    using Error = yume::facade::config_io::ConfigLoadError;
    std::string detail;
    Error error = Error::None;
    if (!expect(!yume::facade::config_io::load_server(
                    base / "missing-server.json", &detail, &error),
                "missing server config should fail") ||
        !expect(error == Error::NotFound,
                "missing server config should have a typed not-found error")) {
        return false;
    }

    const auto invalid = base / "invalid-server.json";
    std::ofstream output(invalid);
    output << R"({"listen_port":"not-a-number"})";
    output.close();
    error = Error::None;
    return expect(!yume::facade::config_io::load_server(
                      invalid, &detail, &error),
                  "invalid server config should fail") &&
           expect(error == Error::Parse,
                  "invalid server config should have a typed parse error");
}

}  // namespace

int main() {
    try {
        const TemporaryDirectory temporary;
        return test_shutdown_request_latch() &&
                       test_cli_config_load(temporary.path()) &&
                       test_cli_rejects_malformed_collections(
                           temporary.path()) &&
                       test_cli_load_is_type_strict_and_transactional(
                           temporary.path()) &&
                       test_facade_round_trip(temporary.path()) &&
                       test_typed_facade_load_errors(temporary.path())
                   ? 0
                   : 1;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
