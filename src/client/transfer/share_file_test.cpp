/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/transfer/share_file.hpp"

#include <nlohmann/json.hpp>

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

namespace {

std::string read_text(const std::filesystem::path& path) {
    std::ifstream input(path);
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

}  // namespace

int main() {
    namespace fs = std::filesystem;
    using namespace yume::share;

    ShareBundle bundle;
    bundle.server_host = "192.0.2.10";
    bundle.server_port = 8443;
    bundle.auth_private_key_pem = "test-private-key";
    bundle.anonym_ca_cert_pem = "operator-ca";
    bundle.tls_ca_cert_pem = "tls-ca";
    bundle.tls_server_name = "edge.example.test";
    bundle.tunnel_count = 3;
    bundle.require_operator_identity = true;
    bundle.obfs_secret = std::string(64, 'a');
    bundle.inner_psk = std::string(64, 'b');

    std::string error;
    assert(encode_share(bundle, std::string(kPasswordMin - 1, 'x'), &error).empty());
    assert(error.find("at least 12") != std::string::npos);

    const std::string password(kPasswordMin, 'x');
    const auto encoded = encode_share(bundle, password, &error);
    assert(!encoded.empty());
    const auto decoded = decode_share(encoded, password, &error);
    assert(decoded.has_value());
    assert(decoded->tls_ca_cert_pem == bundle.tls_ca_cert_pem);
    assert(decoded->tls_server_name == bundle.tls_server_name);
    assert(decoded->tunnel_count == 3);
    assert(decoded->require_operator_identity);

    ShareBundle legacy_bundle;
    legacy_bundle.server_host = "192.0.2.11";
    legacy_bundle.anonym_ca_cert_pem = "combined-legacy-ca";
    const auto legacy_encoded = encode_share(legacy_bundle, password, &error);
    const auto legacy_decoded = decode_share(legacy_encoded, password, &error);
    assert(legacy_decoded.has_value());
    assert(legacy_decoded->tls_ca_cert_pem == legacy_bundle.anonym_ca_cert_pem);

    const auto unique = std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count());
    const fs::path home = fs::temp_directory_path() / ("yume-share-test-" + unique);
    fs::create_directories(home);
#ifdef _WIN32
    _putenv_s("HOME", home.string().c_str());
#else
    assert(::setenv("HOME", home.string().c_str(), 1) == 0);
#endif

    ApplyResult result;
    assert(apply_imported_bundle(*decoded, &result, &error));
    const auto config = nlohmann::json::parse(read_text(result.config_path));
    assert(config.at("tls_ca_cert") == result.tls_ca_path);
    assert(config.at("anonym_ca_cert") == result.anonym_ca_path);
    assert(config.at("tls_server_name") == bundle.tls_server_name);
    assert(config.at("tunnels") == 3);
    assert(config.at("require_anonym") == true);
    assert(read_text(result.tls_ca_path) == bundle.tls_ca_cert_pem);

    std::error_code ignored;
    fs::remove_all(home, ignored);
    return 0;
}
