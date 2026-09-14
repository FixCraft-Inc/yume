/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "client/cli/config/config.hpp"
#include "facade/config/config_io.hpp"
#include "server/cli/config_json_types.hpp"
#include "server/cli/config_load.hpp"
#include "server/runtime/security_config.hpp"

namespace {

using nlohmann::json;
namespace io = yume::facade::config_io;
using yume::client::ClientConfig;
using yume::server::ServerConfig;

void require(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        path_ = std::filesystem::temp_directory_path() /
                ("yume-config-parity-" + std::to_string(
                    std::chrono::steady_clock::now().time_since_epoch().count()));
        require(std::filesystem::create_directory(path_), "create fixture directory");
        std::filesystem::permissions(path_, std::filesystem::perms::owner_all);
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

void write(const std::filesystem::path& path, const json& document) {
    std::ofstream output(path);
    output << document.dump();
    require(output.good(), "write fixture");
}

std::string read(const std::filesystem::path& path) {
    std::ifstream input(path);
    require(input.good(), "open fixture");
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

yume::client::ParsedArgs client_args(const std::filesystem::path& path) {
    yume::client::ParsedArgs args;
    args.config_path = path.string();
    args.config_specified = true;
    args.save_server = true;
    return args;
}

yume::server::cli::ServerConfigLoadContext server_context(
        const std::filesystem::path& path) {
    yume::server::cli::ServerConfigLoadContext context;
    context.config_path = path.string();
    context.config_specified = true;
    context.config_dir = "unchanged-config-dir";
    return context;
}

bool has_error(const io::ValidationReport& report, std::string_view field) {
    return std::any_of(report.errors.begin(), report.errors.end(),
        [field](const auto& error) { return error.starts_with(field); });
}

void test_server_shaping(const std::filesystem::path& base) {
    for (const auto& [padding, jitter] : {std::pair{16U, 0U}, {0U, 25U}, {0U, 0U}}) {
        const auto path = base / "server-shaping.json";
        write(path, {{"obfs_pad_multiple", padding}, {"obfs_jitter_ms", jitter},
                     {"obfs_secret_file", "admission.key"}, {"inner_psk_file", "session.key"}});
        std::string error;
        auto facade = io::load_server(path, &error);
        require(facade.has_value(), error);
        require(io::save_server(*facade, path, &error), error);
        const auto saved = json::parse(read(path));
        require(saved.at("obfs_pad_multiple") == padding &&
                saved.at("obfs_jitter_ms") == jitter, "server save lost shaping");
        auto reloaded = io::load_server(path, &error);
        require(reloaded.has_value(), error);
        ServerConfig cli;
        auto context = server_context(path);
        require(yume::server::cli::load_server_config_file_and_resolve_paths(
                    cli, context, {}), "CLI shaping reload");
        for (auto* config : {&cli, &*reloaded}) {
            require(config->obfs_pad_multiple == padding && config->obfs_jitter_ms == jitter,
                    "paired shaping reload differs");
            const bool shaped = padding != 0 || jitter != 0;
            require(has_error(io::validate(*config), "obfs_pad_multiple/obfs_jitter_ms") == shaped,
                    "shaping validation does not match the runtime profile");
            if (shaped) {
                // This rejection precedes file loading and the backend health
                // check. No keys, sockets or authenticated state are created.
                require(!yume::server::prepare_v2_security_config(*config, false, &error),
                        "runtime accepted shaping");
                require(error.find("padding/jitter") != std::string::npos,
                        "runtime failed for an unrelated reason");
                require(!config->obfs_secret_material && !config->inner_psk_material &&
                        config->obfs_pad_multiple == padding && config->obfs_jitter_ms == jitter,
                        "runtime rejection published security state or rewrote shaping");
            }
        }
    }
}

void test_server_paths(const std::filesystem::path& base) {
    using Field = std::pair<const char*, std::string ServerConfig::*>;
    for (const auto& [key, member] : {
        Field{"tls_cert", &ServerConfig::tls_cert}, {"tls_key", &ServerConfig::tls_key},
        {"auth_keys", &ServerConfig::auth_keys}, {"auth_keys_meta", &ServerConfig::auth_keys_meta},
        {"admin_keys", &ServerConfig::admin_keys}, {"pq_private_key", &ServerConfig::pq_private_key},
        {"real_index_path", &ServerConfig::real_index_path}, {"real_root", &ServerConfig::real_root},
        {"obfs_secret_file", &ServerConfig::obfs_secret_file}, {"inner_psk_file", &ServerConfig::inner_psk_file},
        {"real_secret_file", &ServerConfig::real_secret_file}, {"anonym_token_file", &ServerConfig::anonym_token_file},
        {"anonym_ca_key", &ServerConfig::anonym_ca_key}, {"anonym_ca_cert", &ServerConfig::anonym_ca_cert},
        {"anonym_sub_key", &ServerConfig::anonym_sub_key}, {"anonym_sub_cert", &ServerConfig::anonym_sub_cert},
        {"ipc_path", &ServerConfig::ipc_path}, {"federation_identity", &ServerConfig::federation_identity},
        {"federation_operator_ca", &ServerConfig::federation_operator_ca},
        {"operator_keys", &ServerConfig::operator_keys}, {"operator_keys_meta", &ServerConfig::operator_keys_meta},
        {"filter_geolite", &ServerConfig::filter_geolite}, {"upstream_response_dir", &ServerConfig::upstream_response_dir}
    }) {
        const auto path = base / "server-path.json";
        for (const auto& value : {std::string{}, std::string("sub/../target"), (base / "absolute").string()}) {
            write(path, {{key, value}});
            auto context = server_context(path);
            ServerConfig cli;
            require(yume::server::cli::load_server_config_file_and_resolve_paths(cli, context, {}), key);
            std::string error;
            const auto facade = io::load_server(path, &error);
            require(facade.has_value(), error);
            const auto expected = value.empty() ? std::string{} : (base / value).lexically_normal().string();
            require(cli.*member == expected && (*facade).*member == expected, key);
        }
    }
}

void test_server_override_types(const std::filesystem::path& base) {
    const auto path = base / "server-overrides.json";
    for (const char* key : {"pq_auto_generate", "allow_embedded_master"}) {
        for (const auto& value : {json("false"), json(1), json::array(), json(nullptr)}) {
            write(path, {{"listen_address", "must-not-publish"}, {key, value}});
            ServerConfig cli;
            cli.max_sessions = 37;
            cli.auth_keys_meta = "keep-relative-metadata";
            cli.pq_auto_generate = true;
            cli.allow_embedded_master = true;
            auto context = server_context(path);
            yume::server::cli::ServerConfigOverrides overrides;
            overrides.pq_auto_generate = true;
            overrides.allow_embedded_master = true;
            require(!yume::server::cli::load_server_config_file_and_resolve_paths(cli, context, overrides), key);
            require(cli.listen_address.empty() && cli.max_sessions == 37 && cli.pq_auto_generate &&
                    cli.allow_embedded_master && cli.auth_keys_meta == "keep-relative-metadata" &&
                    context.config_path == path.string() && context.config_dir == "unchanged-config-dir",
                    "failed server load published partial config or path context");
            std::string error, pointer;
            require(!io::parse_server_json(read(path), base, &error, &pointer), key);
            require(pointer == std::string("/") + key, "server error lost its field pointer");
        }
    }
    write(path, {{"pq_auto_generate", false}, {"allow_embedded_master", false}});
    ServerConfig cli;
    cli.pq_auto_generate = true;
    cli.allow_embedded_master = true;
    auto context = server_context(path);
    yume::server::cli::ServerConfigOverrides overrides;
    overrides.pq_auto_generate = true;
    overrides.allow_embedded_master = true;
    require(yume::server::cli::load_server_config_file_and_resolve_paths(cli, context, overrides) &&
            cli.pq_auto_generate && cli.allow_embedded_master, "valid CLI overrides lost precedence");

    // All types pass preflight. host_mode fails after earlier fields and
    // collections have changed in the private candidate.
    write(path, {{"listen_address", "must-not-publish"}, {"max_sessions", 88},
                 {"auth_keys_meta", "new-metadata"}, {"allow_services", {"new-service"}},
                 {"host_mode", "invalid"}});
    cli.listen_address = "original";
    cli.max_sessions = 37;
    cli.auth_keys_meta = "original-metadata";
    cli.allowed_services = {"original-service"};
    context = server_context(path);
    require(!yume::server::cli::load_server_config_file_and_resolve_paths(cli, context, {}),
            "CLI accepted a late semantic error");
    require(cli.listen_address == "original" && cli.max_sessions == 37 &&
            cli.auth_keys_meta == "original-metadata" &&
            cli.allowed_services == std::vector<std::string>{"original-service"} &&
            context.config_dir == "unchanged-config-dir", "late server failure published candidate state");
    std::string error;
    require(!io::parse_server_json(read(path), base, &error) && error.starts_with("host_mode"),
            "facade accepted the paired late semantic error");
}

void test_client_rejection(const std::filesystem::path& base) {
    const auto path = base / "client-rejection.json";
    for (const auto& document : {
        json{{"server", "must-not-publish"}, {"app_codec_listen", "127.0.0.1:bad"}},
        json{{"server", "must-not-publish"}, {"tls_pin", ""}, {"tls_pin_sha256", 7}}
    }) {
        write(path, document);
        for (bool overridden : {false, true}) {
            auto args = client_args(path);
            args.app_codec_listen_override = overridden;
            ClientConfig cli;
            cli.port = 9443;
            cli.identity = "keep-relative-identity";
            cli.app_codec_listen_port = 18090;
            std::string error, pointer;
            require(!yume::client::load_client_config_file(args, "", &cli, &error),
                    "CLI accepted a malformed client field");
            require(cli.server.empty() && cli.port == 9443 && cli.identity == "keep-relative-identity" &&
                    cli.app_codec_listen_port == 18090, "late client failure published partial state");
            require(!io::parse_client_json(document.dump(), base, &error, &pointer),
                    "facade accepted a malformed client field");
            require(pointer == (document.contains("app_codec_listen") ? "/app_codec_listen" : "/tls_pin_sha256"),
                    "client rejection lost its field pointer");
        }
    }
}

void test_client_save_resets(const std::filesystem::path& base) {
    const auto path = base / "client-reset.json";
    write(path, {{"server", "old"}, {"threads", 8}, {"tunnels", 4},
        {"socks_port", 1080}, {"socks_bind", "127.0.0.1"},
        {"obfs_pad_multiple", 16}, {"obfs_jitter_ms", 25}, {"server_in_charge_port", 9000},
        {"identity", "old-identity"}, {"tls_pin", std::string(64, 'a')},
        {"tls_server_name", "old-name"}, {"history_dir", "old-history"},
        {"anonym_pubkey_material_id", "old-material"},
        {"app_codec_listen_host", "127.0.0.2"}, {"app_codec_listen_port", 18090}});
    ClientConfig saved;
    saved.server = "new";
    saved.app_codec = "monero-rpc";
    auto args = client_args(path);
    std::string error;
    require(yume::client::save_client_config_file(args, saved, &error), error);
    const auto document = json::parse(read(path));
    require(!document.contains("app_codec_listen_host") && !document.contains("app_codec_listen_port"),
            "stale split endpoint would override the saved combined endpoint");
    ClientConfig cli;
    require(yume::client::load_client_config_file(args, "", &cli, &error), error);
    auto facade = io::load_client(path, &error);
    require(facade.has_value(), error);
    for (const auto* config : {&cli, &*facade}) {
        require(config->io_threads == 0 && config->tunnel_count == 1 && config->socks_port == 0 &&
                config->socks_bind_host.empty() && config->obfs_pad_multiple == 0 && config->obfs_jitter_ms == 0 &&
                config->server_in_charge_port == 0,
                "CLI save retained superseded defaults");
        require(config->identity.empty() && config->tls_pin_sha256.empty() && config->tls_server_name.empty() &&
                config->history_dir.empty() && config->anonym_pubkey_material_id.empty(),
                "CLI save retained cleared identity, trust or storage fields");
        require(config->app_codec_listen_host == saved.app_codec_listen_host &&
                config->app_codec_listen_port == saved.app_codec_listen_port, "codec endpoint did not round trip");
    }
}

void test_shaping_validation_and_stages(const std::filesystem::path& base) {
    std::string error;
    for (const auto& document : {json{{"obfs_pad_multiple", 16}}, json{{"obfs_jitter_ms", 25}},
                                  json{{"obfs_jitter_ms", 4294967295U}}}) {
        auto parsed = io::parse_client_json(document.dump(), base, &error);
        require(parsed.has_value(), "representable shaping should parse before validation");
        require(has_error(io::validate(*parsed), "obfs_pad_multiple/obfs_jitter_ms"),
                "facade validation accepted nonzero client shaping");
    }
    for (unsigned int value : {65535U, 65536U}) {
        const auto path = base / "server-bulk.json";
        write(path, {{"bulk_key_max_sessions", value}});
        auto context = server_context(path);
        ServerConfig cli;
        require(yume::server::cli::load_server_config_file_and_resolve_paths(cli, context, {}),
                "representable positive bulk limit should parse");
        const auto facade = io::load_server(path, &error);
        require(facade.has_value(), error);
        require(has_error(io::validate(cli), "bulk_key_max_sessions") == (value > 65535U) &&
                has_error(io::validate(*facade), "bulk_key_max_sessions") == (value > 65535U),
                "parse acceptance was confused with the startup limit");
    }
}

void test_save_failure(const std::filesystem::path& base) {
    const auto path = base / "save-failure.json";
    const json original = {{"server", "preserve"}};
    write(path, original);
    const auto bytes = read(path);
    const auto bad_text = std::string("bad-") + static_cast<char>(0xff);
    std::string error;
    ServerConfig server;
    server.server_name = bad_text;
    require(!io::save_server(server, path, &error) && !error.empty(), "server serialization must report failure");
    require(read(path) == bytes, "server serialization failure replaced the file");
    ClientConfig client;
    client.server = bad_text;
    std::string serialized = "preserve serialization destination";
    require(!io::serialize_client_json(client, std::nullopt, &serialized, &error), "client serialization must fail");
    require(serialized == "preserve serialization destination", "failed serializer erased caller state");
    require(!io::save_client(client, path, &error), "facade save must fail");
    require(read(path) == bytes, "facade save failure replaced the file");
    require(!yume::client::save_client_config_file(client_args(path), client, &error), "CLI save must fail");
    require(read(path) == bytes, "CLI save failure replaced the file");
    for (const auto& entry : std::filesystem::directory_iterator(base)) {
        require(!entry.path().filename().string().starts_with("save-failure.json.tmp."),
                "failed serialization left a staged file");
    }
}

void test_first_error_and_null(const std::filesystem::path& base) {
    const json document = {{"tls_cert", 7}, {"listen_port", "bad"}};
    std::string error, pointer;
    require(!yume::server::cli::validate_server_config_json_types(document, &error) &&
            error.starts_with("tls_cert"), "CLI type-pass diagnostic order changed");
    require(!io::parse_server_json(document.dump(), base, &error, &pointer) && pointer == "/listen_port",
            "facade member-read diagnostic order changed");
    for (const char* key : {"auth_keys_meta", "upstream_response_dir", "obfs_pad_multiple", "obfs_jitter_ms"}) {
        const auto path = base / "server-null.json";
        write(path, {{key, nullptr}});
        ServerConfig cli;
        cli.server_name = "keep";
        auto context = server_context(path);
        require(!yume::server::cli::load_server_config_file_and_resolve_paths(cli, context, {}) &&
                cli.server_name == "keep" && context.config_dir == "unchanged-config-dir", "CLI null rejection changed state");
        require(!io::parse_server_json(read(path), base, &error, &pointer) && pointer == std::string("/") + key,
                "facade treated null as omission");
    }
    const auto omitted = io::parse_server_json("{}", base, &error);
    require(omitted && omitted->auth_keys_meta.empty() && omitted->upstream_response_dir.empty() &&
            omitted->obfs_pad_multiple == 0 && omitted->obfs_jitter_ms == 0, "omission defaults changed");
}

void test_cover_activation(const std::filesystem::path& base) {
    for (const char* field : {"real_root", "real_backend"}) {
        for (const auto& value : {std::string{}, std::string("loopback://127.0.0.1:3000")}) {
            const auto path = base / "cover-activation.json";
            write(path, {{field, value}, {"real_http", false}});
            auto context = server_context(path);
            ServerConfig cli;
            require(yume::server::cli::load_server_config_file_and_resolve_paths(cli, context, {}), field);
            std::string error;
            const auto facade = io::load_server(path, &error);
            require(facade && facade->real_http == !value.empty() && cli.real_http == !value.empty(),
                    "a nonempty cover root/backend must activate HTTP cover in both readers");
            if (std::string_view(field) == "real_backend" && !value.empty()) {
                require(has_error(io::validate(*facade), "real_index_path/real_root/upstream_response_dir"),
                        "facade validation skipped the cover-source requirement");
            }
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    try {
        require(argc <= 2, "expected at most one case name");
        const TemporaryDirectory temporary;
        using Case = std::pair<std::string_view, void (*)(const std::filesystem::path&)>;
        unsigned int count = 0;
        for (const auto& [name, run] : {
            Case{"server-shaping", test_server_shaping}, {"server-paths", test_server_paths},
            {"server-overrides", test_server_override_types}, {"client-rejection", test_client_rejection},
            {"client-save", test_client_save_resets}, {"validation-stages", test_shaping_validation_and_stages},
            {"save-failure", test_save_failure}, {"first-error-null", test_first_error_and_null},
            {"cover-activation", test_cover_activation}
        }) {
            if (argc == 1 || name == argv[1]) {
                run(temporary.path());
                ++count;
            }
        }
        require(count != 0, "unknown case name");
        std::cout << count << " configuration parity cases passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
