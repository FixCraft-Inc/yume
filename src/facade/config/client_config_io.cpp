/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "facade/config/config_io.hpp"

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <system_error>

#include <nlohmann/json.hpp>

#include "facade/config/detail.hpp"

namespace yume::facade::config_io {

using nlohmann::json;
using detail::read_opt;
using detail::resolve_config_path;

std::optional<client::ClientConfig> load_client(
    std::filesystem::path const& path, std::string* err) {
    std::ifstream in(path);
    if (!in) {
        if (err) *err = "cannot open " + path.string();
        return std::nullopt;
    }
    json j;
    try {
        in >> j;
    } catch (std::exception const& e) {
        if (err) *err = std::string{"invalid JSON: "} + e.what();
        return std::nullopt;
    }

    client::ClientConfig c;
    read_opt(j, "server", c.server);
    read_opt(j, "port", c.port);
    read_opt(j, "identity", c.identity);
    read_opt(j, "socks_port", c.socks_port);
    read_opt(j, "io_threads", c.io_threads);
    read_opt(j, "obfuscation", c.obfuscation);
    read_opt(j, "obfs_secret", c.obfs_secret);
    read_opt(j, "inner_crypto", c.inner_crypto);
    read_opt(j, "inner_heavy", c.inner_heavy);
    read_opt(j, "inner_hop", c.inner_hop);
    read_opt(j, "hop_interval_ms", c.hop_interval_ms);
    read_opt(j, "allow_udp", c.allow_udp);
    read_opt(j, "allow_local_ip", c.allow_local_ip);
    read_opt(j, "allow_exec", c.allow_exec);
    read_opt(j, "pq_public_key", c.pq_public_key);
    read_opt(j, "allow_embedded_master", c.allow_embedded_master);
    read_opt(j, "anonym_pubkey", c.anonym_pubkey);
    read_opt(j, "anonym_ca_cert", c.anonym_ca_cert);
    read_opt(j, "anonym_ca_material_id", c.anonym_ca_material_id);
    read_opt(j, "anonym_pubkey_material_id", c.anonym_pubkey_material_id);
    read_opt(j, "tls_ca_material_id", c.tls_ca_material_id);
    read_opt(j, "auth_key_material_id", c.auth_key_material_id);
    read_opt(j, "tls_ca_cert", c.tls_ca_cert);
    read_opt(j, "tls_server_name", c.tls_server_name);
    read_opt(j, "tls_pin_sha256", c.tls_pin_sha256);
    read_opt(j, "require_anonym", c.require_anonym);
    read_opt(j, "boring", c.boring);
    read_opt(j, "instance_name", c.instance_name);
    read_opt(j, "preferred_name", c.preferred_name);
    read_opt(j, "preferred_id", c.preferred_id);
    read_opt(j, "relay_mode", c.relay_mode);
    read_opt(j, "allow_inbound_admin", c.allow_inbound_admin);
    read_opt(j, "allow_outbound_admin", c.allow_outbound_admin);
    read_opt(j, "allow_chat", c.allow_chat);
    read_opt(j, "allow_file", c.allow_file);
    read_opt(j, "allow_bytes", c.allow_bytes);
    read_opt(j, "history_enabled", c.history_enabled);
    read_opt(j, "history_dir", c.history_dir);
    read_opt(j, "relay_key_file", c.relay_key_file);
    read_opt(j, "auto_attach_local", c.auto_attach_local);
    read_opt(j, "tls_stealth_enabled", c.tls_stealth_enabled);
    read_opt(j, "tls_stealth_profile", c.tls_stealth_profile);
    read_opt(j, "tls_stealth_rotate", c.tls_stealth_rotate);
    read_opt(j, "tls_stealth_rotation_interval", c.tls_stealth_rotation_interval);
    read_opt(j, "tls_fingerprint_log", c.tls_fingerprint_log);
    read_opt(j, "tls_fingerprint_log_path", c.tls_fingerprint_log_path);
    read_opt(j, "tls_fingerprint_verify", c.tls_fingerprint_verify);
    read_opt(j, "tls_fingerprint_test_endpoint", c.tls_fingerprint_test_endpoint);
    read_opt(j, "self_dpi", c.self_dpi);
    read_opt(j, "outbound_proxy", c.outbound_proxy_url);

    auto const base = path.parent_path();
    resolve_config_path(c.identity, base);
    resolve_config_path(c.pq_public_key, base);
    resolve_config_path(c.anonym_pubkey, base);
    resolve_config_path(c.anonym_ca_cert, base);
    resolve_config_path(c.tls_ca_cert, base);
    resolve_config_path(c.history_dir, base);
    resolve_config_path(c.relay_key_file, base);
    resolve_config_path(c.tls_fingerprint_log_path, base);
    return c;
}

bool save_client(client::ClientConfig const& c,
                 std::filesystem::path const& path,
                 std::string* err) {
    json j = {
        {"server", c.server},
        {"port", c.port},
        {"identity", c.identity},
        {"socks_port", c.socks_port},
        {"io_threads", c.io_threads},
        {"obfuscation", c.obfuscation},
        {"obfs_secret", c.obfs_secret},
        {"inner_crypto", c.inner_crypto},
        {"inner_heavy", c.inner_heavy},
        {"inner_hop", c.inner_hop},
        {"hop_interval_ms", c.hop_interval_ms},
        {"allow_udp", c.allow_udp},
        {"allow_local_ip", c.allow_local_ip},
        {"allow_exec", c.allow_exec},
        {"pq_public_key", c.pq_public_key},
        {"allow_embedded_master", c.allow_embedded_master},
        {"anonym_pubkey", c.anonym_pubkey},
        {"anonym_ca_cert", c.anonym_ca_cert},
        {"anonym_ca_material_id", c.anonym_ca_material_id},
        {"anonym_pubkey_material_id", c.anonym_pubkey_material_id},
        {"tls_ca_material_id", c.tls_ca_material_id},
        {"auth_key_material_id", c.auth_key_material_id},
        {"tls_ca_cert", c.tls_ca_cert},
        {"tls_server_name", c.tls_server_name},
        {"tls_pin_sha256", c.tls_pin_sha256},
        {"require_anonym", c.require_anonym},
        {"boring", c.boring},
        {"instance_name", c.instance_name},
        {"preferred_name", c.preferred_name},
        {"preferred_id", c.preferred_id},
        {"relay_mode", c.relay_mode},
        {"allow_inbound_admin", c.allow_inbound_admin},
        {"allow_outbound_admin", c.allow_outbound_admin},
        {"allow_chat", c.allow_chat},
        {"allow_file", c.allow_file},
        {"allow_bytes", c.allow_bytes},
        {"history_enabled", c.history_enabled},
        {"history_dir", c.history_dir},
        {"relay_key_file", c.relay_key_file},
        {"auto_attach_local", c.auto_attach_local},
        {"tls_stealth_enabled", c.tls_stealth_enabled},
        {"tls_stealth_profile", c.tls_stealth_profile},
        {"tls_stealth_rotate", c.tls_stealth_rotate},
        {"tls_stealth_rotation_interval", c.tls_stealth_rotation_interval},
        {"tls_fingerprint_log", c.tls_fingerprint_log},
        {"tls_fingerprint_log_path", c.tls_fingerprint_log_path},
        {"tls_fingerprint_verify", c.tls_fingerprint_verify},
        {"tls_fingerprint_test_endpoint", c.tls_fingerprint_test_endpoint},
        {"self_dpi", c.self_dpi},
        {"outbound_proxy", c.outbound_proxy_url},
    };

    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    std::ofstream out(path);
    if (!out) {
        if (err) *err = "cannot write " + path.string();
        return false;
    }
    out << j.dump(2);
    return out.good();
}

ValidationReport validate(client::ClientConfig const& c) {
    ValidationReport r;
    if (c.server.empty()) {
        r.errors.emplace_back("server: host is required");
    }
    if (c.port <= 0 || c.port > 65535) {
        r.errors.emplace_back("port: must be 1..65535");
    }
    if (c.socks_port < 0 || c.socks_port > 65535) {
        r.errors.emplace_back("socks_port: must be 0..65535 (0 = auto in GUI)");
    }
    if (!c.tls_stealth_profile.empty()
        && c.tls_stealth_profile != "chrome"
        && c.tls_stealth_profile != "firefox"
        && c.tls_stealth_profile != "safari") {
        r.warnings.emplace_back(
            "tls_stealth_profile: unknown value (expected chrome|firefox|safari)");
    }
    if (c.hop_interval_ms == 0 && c.inner_hop) {
        r.warnings.emplace_back("hop_interval_ms: 0 with hopping enabled");
    }
    return r;
}

}  // namespace yume::facade::config_io
