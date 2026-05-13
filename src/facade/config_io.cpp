/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "facade/config_io.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <system_error>

#include <nlohmann/json.hpp>

namespace yume::facade::config_io {

namespace {

using nlohmann::json;

template <typename T>
void read_opt(json const& j, const char* key, T& dst) {
    auto it = j.find(key);
    if (it != j.end() && !it->is_null()) {
        try {
            dst = it->get<T>();
        } catch (...) {
            // Ignore type mismatch; field keeps its default value.
        }
    }
}

std::filesystem::path home_dir() {
#ifdef _WIN32
    if (const char* p = std::getenv("USERPROFILE")) return p;
    if (const char* p = std::getenv("HOMEDRIVE")) {
        if (const char* h = std::getenv("HOMEPATH")) {
            return std::filesystem::path(p) / h;
        }
    }
    return {};
#else
    if (const char* p = std::getenv("HOME")) return p;
    return {};
#endif
}

std::filesystem::path expand_user_path(std::string const& value) {
    if (value == "~") return home_dir();
    if (value.rfind("~/", 0) == 0 || value.rfind("~\\", 0) == 0) {
        return home_dir() / value.substr(2);
    }
    return std::filesystem::path(value);
}

void resolve_config_path(std::string& value, std::filesystem::path const& base) {
    if (value.empty()) return;
    std::filesystem::path p = expand_user_path(value);
    if (p.is_relative() && !base.empty()) {
        p = base / p;
    }

    std::error_code ec;
    auto abs = std::filesystem::absolute(p, ec);
    if (!ec) p = abs;
    value = p.lexically_normal().string();
}

}  // namespace

std::filesystem::path default_data_dir() {
    return home_dir() / ".yume";
}

std::filesystem::path default_client_config_path() {
    return default_data_dir() / "client.json";
}

std::filesystem::path default_server_config_path() {
    return default_data_dir() / "server.json";
}

// --------------------------------------------------------------------
// ClientConfig
// --------------------------------------------------------------------

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
    read_opt(j, "auth_key_material_id", c.auth_key_material_id);
    read_opt(j, "tls_ca_cert", c.tls_ca_cert);
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
        {"auth_key_material_id", c.auth_key_material_id},
        {"tls_ca_cert", c.tls_ca_cert},
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

// --------------------------------------------------------------------
// ServerConfig
// --------------------------------------------------------------------

std::optional<server::ServerConfig> load_server(
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

    server::ServerConfig s;
    read_opt(j, "listen_port", s.listen_port);
    read_opt(j, "tls_cert", s.tls_cert);
    read_opt(j, "tls_key", s.tls_key);
    read_opt(j, "auth_keys", s.auth_keys);
    read_opt(j, "auth_keys_meta", s.auth_keys_meta);
    read_opt(j, "threads", s.threads);
    read_opt(j, "obfuscation", s.obfuscation);
    read_opt(j, "obfs_secret", s.obfs_secret);
    read_opt(j, "inner_crypto", s.inner_crypto);
    read_opt(j, "inner_heavy", s.inner_heavy);
    read_opt(j, "inner_dual", s.inner_dual);
    read_opt(j, "inner_required", s.inner_required);
    read_opt(j, "inner_hop", s.inner_hop);
    read_opt(j, "hop_interval_ms", s.hop_interval_ms);
    read_opt(j, "reverse_port_min", s.reverse_port_min);
    read_opt(j, "reverse_port_max", s.reverse_port_max);
    read_opt(j, "dns_server", s.dns_server);
    read_opt(j, "pq_private_key", s.pq_private_key);
    read_opt(j, "pq_auto_generate", s.pq_auto_generate);
    read_opt(j, "allow_embedded_master", s.allow_embedded_master);
    read_opt(j, "allow_exec", s.allow_exec);
    read_opt(j, "allow_local_ip", s.allow_local_ip);
    read_opt(j, "control_full", s.control_full);
    read_opt(j, "real_http", s.real_http);
    read_opt(j, "real_index_path", s.real_index_path);
    read_opt(j, "real_secret", s.real_secret);
    read_opt(j, "real_secret_file", s.real_secret_file);
    read_opt(j, "anonym", s.anonym);
    read_opt(j, "anonym_proof_mode", s.anonym_proof_mode);
    read_opt(j, "anonym_api", s.anonym_api);
    read_opt(j, "anonym_token", s.anonym_token);
    read_opt(j, "anonym_ca_key", s.anonym_ca_key);
    read_opt(j, "anonym_ca_cert", s.anonym_ca_cert);
    read_opt(j, "anonym_sub_key", s.anonym_sub_key);
    read_opt(j, "anonym_sub_cert", s.anonym_sub_cert);
    read_opt(j, "server_name", s.server_name);
    read_opt(j, "server_id", s.server_id);
    read_opt(j, "relay_enable", s.relay_enable);
    read_opt(j, "directory_enable", s.directory_enable);
    read_opt(j, "ipc_enable", s.ipc_enable);
    read_opt(j, "ipc_path", s.ipc_path);
    read_opt(j, "federation_enable", s.federation_enable);
    read_opt(j, "federation_peers", s.federation_peers);
    read_opt(j, "operator_keys", s.operator_keys);
    read_opt(j, "operator_keys_meta", s.operator_keys_meta);
    read_opt(j, "boring", s.boring);

    auto const base = path.parent_path();
    resolve_config_path(s.tls_cert, base);
    resolve_config_path(s.tls_key, base);
    resolve_config_path(s.auth_keys, base);
    resolve_config_path(s.pq_private_key, base);
    resolve_config_path(s.real_index_path, base);
    resolve_config_path(s.real_secret_file, base);
    resolve_config_path(s.anonym_ca_key, base);
    resolve_config_path(s.anonym_ca_cert, base);
    resolve_config_path(s.anonym_sub_key, base);
    resolve_config_path(s.anonym_sub_cert, base);
    resolve_config_path(s.ipc_path, base);
    return s;
}

bool save_server(server::ServerConfig const& s,
                 std::filesystem::path const& path,
                 std::string* err) {
    json j = {
        {"listen_port", s.listen_port},
        {"tls_cert", s.tls_cert},
        {"tls_key", s.tls_key},
        {"auth_keys", s.auth_keys},
        {"auth_keys_meta", s.auth_keys_meta},
        {"threads", s.threads},
        {"obfuscation", s.obfuscation},
        {"obfs_secret", s.obfs_secret},
        {"inner_crypto", s.inner_crypto},
        {"inner_heavy", s.inner_heavy},
        {"inner_dual", s.inner_dual},
        {"inner_required", s.inner_required},
        {"inner_hop", s.inner_hop},
        {"hop_interval_ms", s.hop_interval_ms},
        {"reverse_port_min", s.reverse_port_min},
        {"reverse_port_max", s.reverse_port_max},
        {"dns_server", s.dns_server},
        {"pq_private_key", s.pq_private_key},
        {"pq_auto_generate", s.pq_auto_generate},
        {"allow_embedded_master", s.allow_embedded_master},
        {"allow_exec", s.allow_exec},
        {"allow_local_ip", s.allow_local_ip},
        {"control_full", s.control_full},
        {"real_http", s.real_http},
        {"real_index_path", s.real_index_path},
        {"real_secret_file", s.real_secret_file},
        {"anonym", s.anonym},
        {"anonym_proof_mode", s.anonym_proof_mode},
        {"anonym_api", s.anonym_api},
        {"anonym_token", s.anonym_token},
        {"anonym_ca_key", s.anonym_ca_key},
        {"anonym_ca_cert", s.anonym_ca_cert},
        {"anonym_sub_key", s.anonym_sub_key},
        {"anonym_sub_cert", s.anonym_sub_cert},
        {"server_name", s.server_name},
        {"server_id", s.server_id},
        {"relay_enable", s.relay_enable},
        {"directory_enable", s.directory_enable},
        {"ipc_enable", s.ipc_enable},
        {"ipc_path", s.ipc_path},
        {"federation_enable", s.federation_enable},
        {"federation_peers", s.federation_peers},
        {"operator_keys", s.operator_keys},
        {"operator_keys_meta", s.operator_keys_meta},
        {"boring", s.boring},
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

ValidationReport validate(server::ServerConfig const& s) {
    ValidationReport r;
    if (s.listen_port <= 0 || s.listen_port > 65535) {
        r.errors.emplace_back("listen_port: must be 1..65535");
    }
    if (s.tls_cert.empty()) {
        r.errors.emplace_back("tls_cert: TLS certificate path is required");
    }
    if (s.tls_key.empty()) {
        r.errors.emplace_back("tls_key: TLS private key path is required");
    }
    if (s.auth_keys.empty()) {
        r.warnings.emplace_back(
            "auth_keys: no authorized_keys path set; no clients will be able to connect");
    }
    if (s.reverse_port_min > s.reverse_port_max) {
        r.errors.emplace_back(
            "reverse_port_min must be <= reverse_port_max");
    }
    if (s.threads < 0) {
        r.errors.emplace_back("threads: must be >= 0 (0 = auto)");
    }
    return r;
}

}  // namespace yume::facade::config_io
