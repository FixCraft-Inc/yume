/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/config/config_io.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

#include "client/cli/config/args.hpp"
#include "client/cli/config/config.hpp"
#include "core/runtime/atomic_file.hpp"

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace {

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        const auto nonce = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        path_ = std::filesystem::temp_directory_path() /
                ("yume-client-config-test-" + std::to_string(nonce));
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

bool write_json(const std::filesystem::path& path,
                const nlohmann::json& value) {
    std::ofstream output(path);
    output << value.dump(2);
    return output.good();
}

std::optional<nlohmann::json> read_json(
    const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) {
        return std::nullopt;
    }
    try {
        nlohmann::json value;
        input >> value;
        return value;
    } catch (...) {
        return std::nullopt;
    }
}

bool has_atomic_temporary(const std::filesystem::path& directory,
                          const std::string& destination_name) {
    const std::string prefix = destination_name + ".tmp.";
    std::error_code error;
    for (std::filesystem::directory_iterator it(directory, error), end;
         !error && it != end; it.increment(error)) {
        if (it->path().filename().string().rfind(prefix, 0) == 0) {
            return true;
        }
    }
    return false;
}

bool test_typed_config_load_errors(const std::filesystem::path& base) {
    using Error = yume::facade::config_io::ConfigLoadError;
    std::string detail;
    Error error = Error::None;
    if (!expect(!yume::facade::config_io::load_client(
                    base / "missing-client.json", &detail, &error),
                "missing client config should fail") ||
        !expect(error == Error::NotFound,
                "missing client config should have a typed not-found error")) {
        return false;
    }

    const auto invalid = base / "invalid-client.json";
    std::ofstream output(invalid);
    output << R"({"port":"not-a-number"})";
    output.close();
    error = Error::None;
    if (!expect(!yume::facade::config_io::load_client(
                    invalid, &detail, &error),
                "invalid client config should fail") ||
        !expect(error == Error::Parse,
                "invalid client config should have a typed parse error")) {
        return false;
    }
    return true;
}

bool test_server_bootstrap_config_round_trip(
        const std::filesystem::path& base) {
    yume::server::ServerConfig config;
    config.federation_enable = true;
    config.cluster_bootstrap = true;
    config.federation_identity = "federation.key";
    config.federation_operator_ca = "operator-ca.pem";

    const auto path = base / "bootstrap-yumed.json";
    std::string error;
    if (!expect(yume::facade::config_io::save_server(
                    config, path, &error),
                "facade should save a bootstrap-only server config") ||
        !expect(error.empty(),
                "bootstrap server config save should not report an error")) {
        return false;
    }
    auto loaded = yume::facade::config_io::load_server(path, &error);
    if (!expect(loaded.has_value(),
                "facade should load a bootstrap-only server config") ||
        !expect(loaded && loaded->federation_enable &&
                    loaded->cluster_bootstrap &&
                    loaded->federation_peers.empty(),
                "cluster_bootstrap must survive facade JSON round-trip")) {
        return false;
    }

    const auto has_peer_requirement = [](const auto& report) {
        return std::any_of(
            report.errors.begin(), report.errors.end(),
            [](const std::string& item) {
                return item.rfind("federation_peers:", 0U) == 0U;
            });
    };
    const auto bootstrap_report =
        yume::facade::config_io::validate(config);
    if (!expect(!has_peer_requirement(bootstrap_report),
                "bootstrap-only validation must not require an outbound peer")) {
        return false;
    }
    config.cluster_bootstrap = false;
    if (!expect(
            has_peer_requirement(yume::facade::config_io::validate(config)),
            "non-bootstrap federation must still require an outbound peer")) {
        return false;
    }

    config.federation_peers.push_back(
        R"({"id":"edge","url":"yume://edge.example:443","psk_file":"secrets/edge.psk","carrier_secret_file":"secrets/edge.carrier"})");
    const auto peer_path = base / "peer-yumed.json";
    if (!expect(yume::facade::config_io::save_server(
                    config, peer_path, &error),
                "facade should save federation peers as JSON objects")) {
        return false;
    }
    nlohmann::json saved;
    {
        std::ifstream input(peer_path);
        input >> saved;
    }
    if (!expect(saved["federation_peers"].is_array() &&
                    saved["federation_peers"].size() == 1U &&
                    saved["federation_peers"][0].is_object(),
                "saved federation_peers entries must remain objects")) {
        return false;
    }
    loaded = yume::facade::config_io::load_server(peer_path, &error);
    if (!expect(loaded.has_value() &&
                    loaded->federation_peers.size() == 1U,
                "facade should reload its federated server config")) {
        return false;
    }
    const auto peer = nlohmann::json::parse(loaded->federation_peers.front());
    return expect(
               peer.value("psk_file", "") ==
                   (base / "secrets/edge.psk").string(),
               "peer PSK path must resolve from the config base") &&
           expect(
               peer.value("carrier_secret_file", "") ==
                   (base / "secrets/edge.carrier").string(),
               "peer carrier-secret path must resolve from the config base");
}

bool test_atomic_file_replace_and_cleanup(const std::filesystem::path& base) {
    const auto directory = base / "atomic";
    const auto path = directory / "client.json";
    if (!std::filesystem::create_directory(directory)) {
        return expect(false, "should create atomic-write test directory");
    }
    std::string error;
    if (!expect(yume::runtime::AtomicWriteFile(path, "old", &error),
                "initial atomic write should succeed") ||
        !expect(error.empty(), "successful atomic write should clear error") ||
        !expect(yume::runtime::AtomicWriteFile(path, "replacement", &error),
                "atomic replacement should succeed") ||
        !expect(error.empty(), "successful replacement should clear error")) {
        return false;
    }

    std::ifstream input(path, std::ios::binary);
    const std::string content((std::istreambuf_iterator<char>(input)),
                              std::istreambuf_iterator<char>());
    if (!expect(content == "replacement",
                "atomic replacement should publish complete content") ||
        !expect(!has_atomic_temporary(directory, path.filename().string()),
                "successful atomic replacement should leave no temporary file")) {
        return false;
    }

    const auto removed = directory / "removed.json";
    if (!expect(yume::runtime::AtomicWriteFile(removed, "temporary", &error),
                "durable-remove fixture should be written") ||
        !expect(yume::runtime::DurableRemoveFile(removed, &error),
                "durable remove should succeed") ||
        !expect(error.empty() && !std::filesystem::exists(removed),
                "durable remove should publish absence") ||
        !expect(yume::runtime::DurableRemoveFile(removed, &error),
                "durable remove should be idempotent for a missing file") ||
        !expect(error.empty(),
                "idempotent durable remove should clear stale errors")) {
        return false;
    }

#ifndef _WIN32
    struct stat status {};
    if (!expect(::stat(path.c_str(), &status) == 0,
                "atomic config should be stat-able") ||
        !expect((status.st_mode & 0777) == 0600,
                "atomic config temporary should install owner-only mode")) {
        return false;
    }
#endif

    const auto blocked = base / "blocked-destination";
    if (!std::filesystem::create_directory(blocked)) {
        return expect(false, "should create blocked destination directory");
    }
    std::ofstream marker(blocked / "keep.txt");
    marker << "keep";
    marker.close();
    error.clear();
    if (!expect(!yume::runtime::AtomicWriteFile(blocked, "must-not-land", &error),
                "atomic replacement of a non-empty directory must fail") ||
        !expect(!error.empty(), "failed atomic replacement should report error") ||
        !expect(std::filesystem::is_directory(blocked) &&
                    std::filesystem::exists(blocked / "keep.txt"),
                "failed atomic replacement must preserve destination") ||
        !expect(!has_atomic_temporary(base, blocked.filename().string()),
                "failed atomic replacement should remove its temporary file")) {
        return false;
    }
    return true;
}

bool test_facade_canonical_and_legacy_parse(
    const std::filesystem::path& base) {
    std::string error;
    auto canonical = yume::facade::config_io::parse_client_json(
        R"({
            "server":"config.example",
            "port":9443,
            "identity":"client.key",
            "admin_identity":"admin.key",
            "packet_tun_name":"yume0",
            "threads":7,
            "io_threads":99,
            "tunnels":3,
            "obfs_pad_multiple":64,
            "obfs_jitter_ms":17,
            "udp":true,
            "allow_udp":false,
            "server_in_charge":true,
            "server_in_charge_port":3001,
            "tls_pin":"canonical-pin",
            "tls_pin_sha256":"legacy-pin",
            "non_interactive":true,
            "app_codec":"monero-rpc",
            "codec":"ignored-legacy-codec",
            "app_codec_listen":"[::1]:19090",
            "anonym_pubkey_material_id":"operator-public",
            "anonym_ca_material_id":"operator-ca",
            "auth_key_material_id":"client-auth",
            "tls_ca_material_id":"tls-ca",
            "relay_trust_mode":"pinned",
            "relay_trust_dir":"relay-trust",
            "relay_peer_pins":{
                "peer:client":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            },
            "tls_stealth_enabled":true,
            "tls_stealth_profile":"profile-from-file",
            "tls_fingerprint_log":true,
            "tls_fingerprint_log_path":"fingerprints",
            "tls_fingerprint_verify":true,
            "tls_fingerprint_test_endpoint":"fingerprint.example",
            "outbound_proxy":"socks5://127.0.0.1:9050"
        })",
        base, &error);
    if (!expect(canonical.has_value(), "facade should parse canonical config") ||
        !expect(error.empty(), "canonical facade parse should not report an error")) {
        return false;
    }
    if (!expect(canonical->io_threads == 7,
                "canonical threads must take precedence over io_threads") ||
        !expect(canonical->allow_udp,
                "canonical udp must take precedence over allow_udp") ||
        !expect(canonical->tls_pin_sha256 == "canonical-pin",
                "canonical tls_pin must take precedence") ||
        !expect(canonical->identity == (base / "client.key").string(),
                "identity should resolve relative to the config") ||
        !expect(canonical->admin_identity == (base / "admin.key").string(),
                "admin identity should resolve relative to the config") ||
        !expect(canonical->packet_tun_name == "yume0",
                "packet TUN name should parse") ||
        !expect(canonical->obfs_pad_multiple == 64 &&
                    canonical->obfs_jitter_ms == 17,
                "obfuscation shaping should parse") ||
        !expect(canonical->server_in_charge &&
                    canonical->server_in_charge_port == 3001,
                "server-control settings should parse") ||
        !expect(canonical->non_interactive,
                "non-interactive mode should parse") ||
        !expect(canonical->app_codec == "monero-rpc" &&
                    canonical->app_codec_listen_host == "::1" &&
                    canonical->app_codec_listen_port == 19090,
                "application codec endpoint should parse IPv6") ||
        !expect(canonical->tls_fingerprint_log_path ==
                    (base / "fingerprints").string(),
                "fingerprint path should resolve relative to the config") ||
        !expect(canonical->tls_stealth_profile == "profile-from-file" &&
                    canonical->tls_fingerprint_log &&
                    canonical->tls_fingerprint_verify &&
                    canonical->tls_fingerprint_test_endpoint ==
                        "fingerprint.example",
                "TLS diagnostics settings should parse") ||
        !expect(canonical->anonym_pubkey_material_id == "operator-public" &&
                    canonical->anonym_ca_material_id == "operator-ca" &&
                    canonical->auth_key_material_id == "client-auth" &&
                    canonical->tls_ca_material_id == "tls-ca",
                "secure-material identifiers should parse") ||
        !expect(canonical->relay_trust_mode == "pinned" &&
                    canonical->relay_trust_dir ==
                        (base / "relay-trust").string() &&
                    canonical->relay_peer_pins.at("peer:client") ==
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "relay-v2 trust settings should parse") ||
        !expect(canonical->outbound_proxy_url ==
                    "socks5://127.0.0.1:9050",
                "outbound proxy should parse")) {
        return false;
    }

    auto legacy = yume::facade::config_io::parse_client_json(
        R"({
            "io_threads":5,
            "allow_udp":true,
            "tls_pin_sha256":"legacy-only-pin",
            "codec":"monero-rpc"
        })",
        base, &error);
    return expect(legacy.has_value(), "facade should accept legacy aliases") &&
           expect(legacy->io_threads == 5,
                  "legacy io_threads should remain readable") &&
           expect(legacy->allow_udp,
                  "legacy allow_udp should remain readable") &&
           expect(legacy->tls_pin_sha256 == "legacy-only-pin",
                  "legacy tls_pin_sha256 should remain readable") &&
           expect(legacy->app_codec == "monero-rpc",
                  "legacy codec should remain readable");
}

bool test_facade_rejects_malformed_values(
    const std::filesystem::path& base) {
    std::string error = "stale";
    auto wrong_type = yume::facade::config_io::parse_client_json(
        R"({"server":"example.test","port":"443"})", base, &error);
    if (!expect(!wrong_type.has_value(),
                "facade must reject a wrong-typed client field") ||
        !expect(error.find("port") != std::string::npos,
                "wrong-typed client field should name its key")) {
        return false;
    }
    auto wrong_root = yume::facade::config_io::parse_client_json(
        R"([])", base, &error);
    if (!expect(!wrong_root.has_value(),
                "facade must reject a non-object client config") ||
        !expect(error.find("JSON object") != std::string::npos,
                "non-object client config should report its contract")) {
        return false;
    }
    auto valid = yume::facade::config_io::parse_client_json(
        R"({"server":"example.test"})", base, &error);
    return expect(valid.has_value(),
                  "valid facade config should still parse after an error") &&
           expect(error.empty(),
                  "successful facade parse should clear a stale error");
}

yume::client::ClientConfig make_config() {
    yume::client::ClientConfig config;
    config.server = "saved.example";
    config.port = 9443;
    config.identity = "client.key";
    config.admin_identity = "admin.key";
    config.packet_tun_name = "yume1";
    config.io_threads = 8;
    config.tunnel_count = 2;
    config.obfs_pad_multiple = 32;
    config.obfs_jitter_ms = 9;
    config.allow_udp = true;
    config.server_in_charge = true;
    config.server_in_charge_port = 3002;
    config.anonym_pubkey = "operator.pub";
    config.anonym_pubkey_material_id = "operator-public";
    config.anonym_ca_cert = "operator-ca.crt";
    config.anonym_ca_material_id = "operator-ca";
    config.auth_key_material_id = "client-auth";
    config.tls_ca_cert = "tls-ca.crt";
    config.tls_ca_material_id = "tls-ca";
    config.tls_pin_sha256 = "saved-pin";
    config.relay_trust_mode = "pinned";
    config.relay_trust_dir = "relay-trust";
    config.relay_peer_pins = {{
        "peer:client",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}};
    config.outbound_proxy_url = "socks5://127.0.0.1:9050";
    config.non_interactive = true;
    config.app_codec = "monero-rpc";
    config.app_codec_listen_host = "::1";
    config.app_codec_listen_port = 19091;
    config.tls_stealth_enabled = true;
    config.tls_stealth_profile = "profile-from-saved-file";
    config.tls_fingerprint_log = true;
    config.tls_fingerprint_log_path = "fingerprints";
    config.tls_fingerprint_verify = true;
    config.tls_fingerprint_test_endpoint = "saved-fingerprint.example";
    return config;
}

bool expect_canonical_document(const nlohmann::json& document) {
    return expect(document.value("threads", 0) == 8,
                  "writer should use canonical threads") &&
           expect(document.value("udp", false),
                  "writer should use canonical udp") &&
           expect(document.value("tls_pin", std::string{}) == "saved-pin",
                  "writer should use canonical tls_pin") &&
           expect(!document.contains("io_threads") &&
                      !document.contains("allow_udp") &&
                      !document.contains("tls_pin_sha256"),
                  "writer should omit legacy aliases") &&
           expect(!document.contains("obfs_secret"),
                  "writer must not serialize inline legacy secrets") &&
           expect(document.value("admin_identity", std::string{}) ==
                      "admin.key",
                  "writer should preserve admin identity") &&
           expect(document.value("packet_tun_name", std::string{}) ==
                      "yume1",
                  "writer should preserve packet TUN name") &&
           expect(document.value("obfs_pad_multiple", 0) == 32 &&
                      document.value("obfs_jitter_ms", 0) == 9,
                  "writer should preserve obfuscation shaping") &&
           expect(document.value("app_codec_listen", std::string{}) ==
                      "[::1]:19091",
                  "writer should bracket IPv6 application-codec endpoints") &&
           expect(document.value("tls_stealth_profile", std::string{}) ==
                      "profile-from-saved-file" &&
                      document.value("tls_fingerprint_log", false) &&
                      document.value("tls_fingerprint_verify", false),
                  "writer should preserve TLS diagnostic settings") &&
           expect(document.value("outbound_proxy", std::string{}) ==
                      "socks5://127.0.0.1:9050",
                  "writer should preserve outbound proxy") &&
           expect(document.value("relay_trust_mode", std::string{}) ==
                      "pinned" &&
                      document.value("relay_trust_dir", std::string{}) ==
                      "relay-trust" &&
                      document["relay_peer_pins"].value(
                          "peer:client", std::string{}) ==
                      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                  "writer should preserve relay-v2 trust settings") &&
           expect(document.value("anonym_pubkey_material_id", std::string{}) ==
                      "operator-public" &&
                      document.value("auth_key_material_id", std::string{}) ==
                      "client-auth" &&
                      document.value("tls_ca_material_id", std::string{}) ==
                      "tls-ca",
                  "writer should preserve secure-material identifiers");
}

bool test_facade_save_and_cli_load(const std::filesystem::path& base) {
    const auto path = base / "facade-yume.json";
    auto config = make_config();
    std::string error;
    if (!expect(yume::facade::config_io::save_client(config, path, &error),
                "facade should save client config") ||
        !expect(error.empty(), "facade save should not report an error")) {
        return false;
    }
    auto document = read_json(path);
    if (!expect(document.has_value(), "saved facade config should be JSON") ||
        !expect_canonical_document(*document)) {
        return false;
    }

    yume::client::ParsedArgs args;
    args.config_path = path.string();
    args.config_specified = true;
    yume::client::ClientConfig loaded;
    if (!expect(yume::client::load_client_config_file(
                    args, "", &loaded, &error),
                "CLI should load facade config") ||
        !expect(error.empty(), "valid CLI config load should not report an error")) {
        return false;
    }
    yume::client::apply_cli_config_overrides(args, base.string(), &loaded);
    return expect(loaded.io_threads == 8 && loaded.allow_udp,
                  "CLI should read facade canonical scheduling keys") &&
           expect(loaded.tls_pin_sha256 == "saved-pin",
                  "CLI should read facade canonical TLS pin") &&
           expect(loaded.app_codec_listen_host == "::1" &&
                      loaded.app_codec_listen_port == 19091,
                  "CLI should read bracketed IPv6 codec endpoint") &&
           expect(loaded.tls_stealth_profile == "profile-from-saved-file",
                  "CLI defaults must not override config TLS profile") &&
           expect(loaded.tls_fingerprint_log_path ==
                      (base / "fingerprints").string(),
                  "CLI defaults must not override config fingerprint path") &&
           expect(loaded.tls_fingerprint_test_endpoint ==
                      "saved-fingerprint.example",
                  "CLI defaults must not override config test endpoint") &&
           expect(loaded.auth_key_material_id == "client-auth",
                  "CLI should read secure-material identifiers");
}

bool test_facade_save_surfaces_serialization_failure(
    const std::filesystem::path& base) {
    const auto path = base / "facade-serialization-yume.json";
    const std::string original = "{\n  \"sentinel\": \"preserve\"\n}\n";
    {
        std::ofstream output(path, std::ios::binary);
        output << original;
    }
    auto config = make_config();
    config.server = std::string("invalid-") + static_cast<char>(0xff);
    std::string error;
    if (!expect(!yume::facade::config_io::save_client(
                    config, path, &error),
                "facade must surface JSON serialization failure") ||
        !expect(!error.empty(),
                "facade serialization failure should include a diagnostic")) {
        return false;
    }
    std::ifstream input(path, std::ios::binary);
    const std::string after((std::istreambuf_iterator<char>(input)),
                            std::istreambuf_iterator<char>());
    return expect(after == original,
                  "facade serialization failure must preserve existing bytes") &&
           expect(!has_atomic_temporary(base, path.filename().string()),
                  "facade serialization failure must not leave a temporary");
}

bool test_cli_alias_load_and_canonical_save(
    const std::filesystem::path& base) {
    const auto legacy_path = base / "legacy-yume.json";
    if (!write_json(legacy_path, {
            {"server", "legacy.example"},
            {"io_threads", 5},
            {"allow_udp", true},
            {"tls_pin_sha256", "legacy-pin"},
            {"codec", "monero-rpc"},
        })) {
        return expect(false, "should write legacy client config fixture");
    }
    yume::client::ParsedArgs load_args;
    load_args.config_path = legacy_path.string();
    load_args.config_specified = true;
    yume::client::ClientConfig legacy;
    std::string load_error;
    if (!expect(yume::client::load_client_config_file(
                    load_args, "", &legacy, &load_error),
                "CLI should load legacy aliases") ||
        !expect(load_error.empty(),
                "valid legacy config load should not report an error")) {
        return false;
    }
    if (!expect(legacy.io_threads == 5 && legacy.allow_udp,
                "CLI should accept legacy scheduling aliases") ||
        !expect(legacy.tls_pin_sha256 == "legacy-pin",
                "CLI should accept legacy TLS pin alias") ||
        !expect(legacy.app_codec == "monero-rpc",
                "CLI should accept legacy codec alias")) {
        return false;
    }

    const auto saved_path = base / "cli-yume.json";
    if (!write_json(saved_path, {
            {"io_threads", 99},
            {"allow_udp", false},
            {"tls_pin_sha256", "stale-pin"},
            {"codec", "stale-codec"},
        })) {
        return expect(false, "should write CLI canonicalization fixture");
    }
    yume::client::ParsedArgs save_args;
    save_args.config_path = saved_path.string();
    save_args.save_server = true;
    std::string save_error;
    if (!expect(yume::client::save_client_config_file(
                    save_args, make_config(), &save_error),
                "CLI should save canonical config") ||
        !expect(save_error.empty(),
                "valid CLI config save should not report an error")) {
        return false;
    }
    auto document = read_json(saved_path);
    return expect(document.has_value(), "CLI-saved config should be JSON") &&
           expect_canonical_document(*document) &&
           expect(!document->contains("codec") &&
                      !document->contains("inner_hop") &&
                      !document->contains("hop_interval_ms"),
                  "CLI save should remove retired aliases");
}

// The client key set is closed and shared by both parsers. An unknown key is
// an error rather than silence, because a misspelled security key would
// otherwise parse as "not configured" and the client would connect without
// it. Retired keys name their replacement, and integral fields reject values
// they cannot represent instead of wrapping.
bool test_client_key_set_is_closed(const std::filesystem::path& base) {
    std::string error;
    auto typo = yume::facade::config_io::parse_client_json(
        R"({"server":"example.test","tls_pinn":"deadbeef"})", base, &error);
    if (!expect(!typo.has_value(),
                "facade must reject an unknown client key") ||
        !expect(error.find("tls_pinn") != std::string::npos,
                "unknown-key error should name the key")) {
        return false;
    }
    auto inline_secret = yume::facade::config_io::parse_client_json(
        R"({"server":"example.test","obfs_secret":"00"})", base, &error);
    if (!expect(!inline_secret.has_value(),
                "facade must reject an inline admission secret") ||
        !expect(error.find("obfs_secret_file") != std::string::npos,
                "inline-secret error should name the file key")) {
        return false;
    }
    auto negative_jitter = yume::facade::config_io::parse_client_json(
        R"({"server":"example.test","obfs_jitter_ms":-1})", base, &error);
    if (!expect(!negative_jitter.has_value(),
                "facade must reject a negative obfs_jitter_ms") ||
        !expect(error.find("obfs_jitter_ms") != std::string::npos,
                "range error should name the key")) {
        return false;
    }
    auto wide_pad = yume::facade::config_io::parse_client_json(
        R"({"server":"example.test","obfs_pad_multiple":65792})", base,
        &error);
    if (!expect(!wide_pad.has_value(),
                "facade must reject an obfs_pad_multiple beyond 16 bits")) {
        return false;
    }

    // Representable is not the same as sane. A huge positive jitter passes
    // every type check and then delays every outbound frame, so both parsers
    // carry the same ceiling.
    auto huge_jitter = yume::facade::config_io::parse_client_json(
        R"({"server":"example.test","obfs_jitter_ms":4294967295})", base,
        &error);
    if (!expect(huge_jitter.has_value(),
                "a representable jitter should still parse")) {
        return false;
    }
    if (!expect(!yume::facade::config_io::validate(*huge_jitter).errors.empty(),
                "validate must reject an unbounded obfs_jitter_ms")) {
        return false;
    }

    const auto bound_path = base / "huge-jitter-yume.json";
    if (!write_json(bound_path, {
            {"server", "example.test"},
            {"obfs_jitter_ms", 4294967295U},
        })) {
        return expect(false, "should write huge-jitter fixture");
    }
    {
        yume::client::ParsedArgs bound_args;
        bound_args.config_path = bound_path.string();
        bound_args.config_specified = true;
        yume::client::ClientConfig bound_config;
        error.clear();
        if (!expect(!yume::client::load_client_config_file(
                        bound_args, "", &bound_config, &error),
                    "CLI must reject an unbounded obfs_jitter_ms") ||
            !expect(error.find("obfs_jitter_ms") != std::string::npos,
                    "CLI bound error should name the key")) {
            return false;
        }
    }

    const auto path = base / "unknown-key-yume.json";
    if (!write_json(path, {
            {"server", "example.test"},
            {"tls_pinn", "deadbeef"},
        })) {
        return expect(false, "should write unknown-key client fixture");
    }
    yume::client::ParsedArgs args;
    args.config_path = path.string();
    args.config_specified = true;
    yume::client::ClientConfig config;
    error.clear();
    return expect(!yume::client::load_client_config_file(
                      args, "", &config, &error),
                  "CLI must reject an unknown client key") &&
           expect(error.find("tls_pinn") != std::string::npos,
                  "CLI unknown-key error should name the key");
}

// A member-level failure carries an RFC 6901 pointer so an embedder can point
// at the offending key without parsing the message. Failures that belong to no
// single member carry no pointer, and an empty pointer is a fact rather than a
// missing field.
bool test_parse_reports_json_pointer(const std::filesystem::path& base) {
    std::string error;
    std::string pointer;
    auto typo = yume::facade::config_io::parse_client_json(
        R"({"server":"example.test","tls_pinn":"deadbeef"})", base, &error,
        &pointer);
    if (!expect(!typo.has_value(), "unknown key must be refused") ||
        !expect(pointer == "/tls_pinn",
                "unknown key should report its own pointer")) {
        return false;
    }
    pointer.clear();
    auto bad_type = yume::facade::config_io::parse_client_json(
        R"({"server":"example.test","port":"not-a-number"})", base, &error,
        &pointer);
    if (!expect(!bad_type.has_value(), "a wrong-typed member must be refused") ||
        !expect(pointer == "/port",
                "a wrong-typed member should report its own pointer")) {
        return false;
    }
    pointer.clear();
    auto broken_json = yume::facade::config_io::parse_client_json(
        R"({"server":)", base, &error, &pointer);
    if (!expect(!broken_json.has_value(), "malformed JSON must be refused") ||
        !expect(pointer.empty(),
                "malformed JSON belongs to no member and carries no pointer")) {
        return false;
    }
    pointer.clear();
    auto server_typo = yume::facade::config_io::parse_server_json(
        R"({"listen_port":443,"lisen_address":"0.0.0.0"})", base, &error,
        &pointer);
    return expect(!server_typo.has_value(),
                  "the server key set is closed too") &&
           expect(pointer == "/lisen_address",
                  "an unknown server key should report its own pointer") &&
           expect(error.find("lisen_address") != std::string::npos,
                  "an unknown server key error should name the key");
}

// The server key set is closed for the same reason the client set is, and both
// server parsers must agree. Inline secret material is refused outright.
bool test_server_key_set_is_closed(const std::filesystem::path& base) {
    std::string error;
    auto inline_obfs = yume::facade::config_io::parse_server_json(
        R"({"listen_port":443,"obfs_secret":"00"})", base, &error);
    if (!expect(!inline_obfs.has_value(),
                "facade must reject an inline server admission secret") ||
        !expect(error.find("obfs_secret_file") != std::string::npos,
                "the refusal should name the file key")) {
        return false;
    }
    auto inline_cover = yume::facade::config_io::parse_server_json(
        R"({"listen_port":443,"real_secret":"hunter2"})", base, &error);
    if (!expect(!inline_cover.has_value(),
                "facade must reject an inline cover-backend secret") ||
        !expect(error.find("real_secret_file") != std::string::npos,
                "the refusal should name the file key")) {
        return false;
    }

    // The facade used to drop these on load while validate() still judged
    // them, so a GUI-loaded server was quietly unshaped.
    auto shaping = yume::facade::config_io::parse_server_json(
        R"({"listen_port":443,"obfs_pad_multiple":16,"obfs_jitter_ms":25})",
        base, &error);
    if (!expect(shaping.has_value(), "shaping fields should parse") ||
        !expect(shaping->obfs_pad_multiple == 16 &&
                    shaping->obfs_jitter_ms == 25,
                "shaping fields must reach ServerConfig")) {
        return false;
    }

    // A key the facade parses but never serializes is silent data loss across
    // a GUI load-and-save round trip.
    auto carried = yume::facade::config_io::parse_server_json(
        R"({"listen_port":443,"upstream_response_dir":"/tmp/captures",)"
        R"("upstream_response_ttl":900,"benchmark_enable":true})",
        base, &error);
    if (!expect(carried.has_value(), "capture-replay keys should parse")) {
        return false;
    }
    if (!expect(carried->upstream_response_dir == "/tmp/captures" &&
                    carried->upstream_response_ttl_s == 900 &&
                    carried->benchmark_enable,
                "capture-replay keys must reach ServerConfig")) {
        return false;
    }
    const auto round_trip_path = base / "server-round-trip.json";
    if (!expect(yume::facade::config_io::save_server(
                    *carried, round_trip_path, &error),
                "saving a server config should succeed")) {
        return false;
    }
    std::ifstream saved(round_trip_path);
    const std::string saved_text((std::istreambuf_iterator<char>(saved)),
                                 std::istreambuf_iterator<char>());
    return expect(saved_text.find("upstream_response_dir") != std::string::npos,
                  "the serializer must not drop upstream_response_dir") &&
           expect(saved_text.find("upstream_response_ttl") != std::string::npos,
                  "the serializer must not drop upstream_response_ttl") &&
           expect(saved_text.find("benchmark_enable") != std::string::npos,
                  "the serializer must not drop benchmark_enable");
}

bool test_cli_load_is_transactional(const std::filesystem::path& base) {
    const auto path = base / "invalid-yume.json";
    if (!write_json(path, {
            {"server", "must-not-escape.example"},
            {"port", "not-an-integer"},
        })) {
        return expect(false, "should write invalid client config fixture");
    }

    yume::client::ParsedArgs args;
    args.config_path = path.string();
    args.config_specified = true;
    yume::client::ClientConfig config;
    config.identity = "original.key";
    std::string error;
    if (!expect(!yume::client::load_client_config_file(
                    args, "", &config, &error),
                "CLI must reject a malformed config") ||
        !expect(!error.empty(),
                "malformed CLI config should report an error")) {
        return false;
    }
    if (!expect(config.server.empty() && config.port == 443 &&
                    config.identity == "original.key",
                "failed config load must not expose partial state")) {
        return false;
    }

    const auto float_path = base / "float-yume.json";
    {
        std::ofstream output(float_path);
        output << R"({"port":443.5})";
    }
    args.config_path = float_path.string();
    config.server = "original.example";
    config.port = 9443;
    error.clear();
    return expect(!yume::client::load_client_config_file(
                      args, "", &config, &error),
                  "CLI must reject wrong types even when current values hide them") &&
           expect(config.server == "original.example" && config.port == 9443,
                  "type failure must preserve the complete client config");
}

bool test_cli_save_reports_failure(const std::filesystem::path& base) {
    yume::client::ParsedArgs args;
    args.config_path = (base / "missing" / "yume.json").string();
    args.save_server = true;
    std::string error;
    return expect(!yume::client::save_client_config_file(
                      args, make_config(), &error),
                  "CLI must report a config write failure") &&
           expect(!error.empty(),
                  "failed CLI config save should include a diagnostic");
}

bool test_cli_save_preserves_malformed_existing_config(
    const std::filesystem::path& base) {
    const auto path = base / "malformed-existing-yume.json";
    const std::string malformed = R"({"server":"old.example",)";
    {
        std::ofstream output(path, std::ios::binary);
        output << malformed;
        if (!output) {
            return expect(false,
                          "should write malformed client config fixture");
        }
    }

    yume::client::ParsedArgs args;
    args.config_path = path.string();
    args.save_server = true;
    std::string error;
    if (!expect(!yume::client::save_client_config_file(
                    args, make_config(), &error),
                "CLI must reject a malformed existing config during save") ||
        !expect(!error.empty(),
                "malformed existing config should include a diagnostic")) {
        return false;
    }

    std::ifstream input(path, std::ios::binary);
    const std::string after((std::istreambuf_iterator<char>(input)),
                            std::istreambuf_iterator<char>());
    if (!expect(after == malformed,
                "failed save must preserve malformed existing bytes") ||
        !expect(!has_atomic_temporary(base, path.filename().string()),
                "rejected save must not leave a temporary config")) {
        return false;
    }

    const auto non_object_path = base / "non-object-existing-yume.json";
    if (!write_json(non_object_path, nlohmann::json::array({1, 2, 3}))) {
        return expect(false, "should write non-object client config fixture");
    }
    args.config_path = non_object_path.string();
    error.clear();
    if (!expect(!yume::client::save_client_config_file(
                    args, make_config(), &error),
                "CLI must reject a non-object existing config during save") ||
        !expect(!error.empty(),
                "non-object existing config should include a diagnostic")) {
        return false;
    }
    const auto after_non_object = read_json(non_object_path);
    if (!expect(after_non_object.has_value() &&
                    after_non_object->is_array(),
                "failed save must preserve a non-object existing config")) {
        return false;
    }

    const auto wrong_type_path = base / "wrong-type-existing-yume.json";
    const std::string wrong_type =
        "{\n  \"server\": 7,\n  \"obfuscation\": \"yes\"\n}\n";
    {
        std::ofstream output(wrong_type_path, std::ios::binary);
        output << wrong_type;
    }
    args.config_path = wrong_type_path.string();
    error.clear();
    if (!expect(!yume::client::save_client_config_file(
                    args, make_config(), &error),
                "CLI must reject wrong-typed existing config during save") ||
        !expect(!error.empty(),
                "wrong-typed existing config should include a diagnostic")) {
        return false;
    }
    std::ifstream wrong_type_input(wrong_type_path, std::ios::binary);
    const std::string wrong_type_after(
        (std::istreambuf_iterator<char>(wrong_type_input)),
        std::istreambuf_iterator<char>());
    if (!expect(wrong_type_after == wrong_type,
                "failed save must preserve wrong-typed existing bytes") ||
        !expect(!has_atomic_temporary(
                    base, wrong_type_path.filename().string()),
                "rejected typed save must not leave a temporary config")) {
        return false;
    }

    const auto serialization_path = base / "serialization-yume.json";
    const std::string original = "{\n  \"sentinel\": \"preserve\"\n}\n";
    {
        std::ofstream output(serialization_path, std::ios::binary);
        output << original;
    }
    args.config_path = serialization_path.string();
    auto unserializable = make_config();
    unserializable.server = std::string("invalid-") +
                            static_cast<char>(0xff);
    error.clear();
    if (!expect(!yume::client::save_client_config_file(
                    args, unserializable, &error),
                "CLI must surface JSON serialization failure") ||
        !expect(!error.empty(),
                "serialization failure should include a diagnostic")) {
        return false;
    }
    std::ifstream serialization_input(serialization_path, std::ios::binary);
    const std::string serialization_after(
        (std::istreambuf_iterator<char>(serialization_input)),
        std::istreambuf_iterator<char>());
    return expect(serialization_after == original,
                  "serialization failure must preserve existing bytes") &&
           expect(!has_atomic_temporary(
                      base, serialization_path.filename().string()),
                  "serialization failure must not leave a temporary config");
}

}  // namespace

int main() {
    try {
        const TemporaryDirectory temporary;
        return test_facade_canonical_and_legacy_parse(temporary.path()) &&
                       test_facade_rejects_malformed_values(temporary.path()) &&
                       test_typed_config_load_errors(temporary.path()) &&
                       test_server_bootstrap_config_round_trip(
                           temporary.path()) &&
                       test_atomic_file_replace_and_cleanup(temporary.path()) &&
                       test_facade_save_and_cli_load(temporary.path()) &&
                       test_facade_save_surfaces_serialization_failure(
                           temporary.path()) &&
                       test_cli_alias_load_and_canonical_save(temporary.path()) &&
                       test_client_key_set_is_closed(temporary.path()) &&
                       test_parse_reports_json_pointer(temporary.path()) &&
                       test_server_key_set_is_closed(temporary.path()) &&
                       test_cli_load_is_transactional(temporary.path()) &&
                       test_cli_save_reports_failure(temporary.path()) &&
                       test_cli_save_preserves_malformed_existing_config(
                           temporary.path())
                   ? 0
                   : 1;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
