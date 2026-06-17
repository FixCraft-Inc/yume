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
using detail::resolve_filter_spec_path;

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
    read_opt(j, "robots_deny", s.robots_deny);
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
    read_opt(j, "outbound_proxy", s.outbound_proxy_url);
    read_opt(j, "relay_enable", s.relay_enable);
    read_opt(j, "directory_enable", s.directory_enable);
    read_opt(j, "ipc_enable", s.ipc_enable);
    read_opt(j, "ipc_path", s.ipc_path);
    read_opt(j, "federation_enable", s.federation_enable);
    if (auto it = j.find("federation_peers"); it != j.end() && it->is_array()) {
        for (const auto& peer : *it) {
            if (peer.is_string()) {
                s.federation_peers.push_back(peer.get<std::string>());
            } else if (peer.is_object()) {
                s.federation_peers.push_back(peer.dump());
            }
        }
    }
    read_opt(j, "federation_auth_key", s.federation_auth_key);
    read_opt(j, "federation_anonym_ca", s.federation_anonym_ca);
    read_opt(j, "operator_keys", s.operator_keys);
    read_opt(j, "operator_keys_meta", s.operator_keys_meta);
    read_opt(j, "egress_mbps", s.egress_mbps);
    read_opt(j, "client_filter_mode", s.client_filter_mode);
    read_opt(j, "egress_filter_mode", s.egress_filter_mode);
    read_opt(j, "filter_geolite", s.filter_geolite);
    read_opt(j, "filter_memory_mib", s.filter_memory_mib);
    if (auto it = j.find("filter_lists"); it != j.end() && it->is_array()) {
        for (const auto& item : *it) {
            if (item.is_string()) {
                s.filter_lists.push_back(item.get<std::string>());
            }
        }
    }
    read_opt(j, "packet_egress", s.packet_egress);
    read_opt(j, "packet_tun_name", s.packet_tun_name);
    read_opt(j, "packet_cidr", s.packet_cidr);
    read_opt(j, "packet_mtu", s.packet_mtu);
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
    resolve_config_path(s.federation_auth_key, base);
    resolve_config_path(s.federation_anonym_ca, base);
    resolve_config_path(s.operator_keys, base);
    resolve_config_path(s.operator_keys_meta, base);
    resolve_config_path(s.filter_geolite, base);
    for (auto& spec : s.filter_lists) {
        resolve_filter_spec_path(spec, base);
    }
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
        {"robots_deny", s.robots_deny},
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
        {"outbound_proxy", s.outbound_proxy_url},
        {"relay_enable", s.relay_enable},
        {"directory_enable", s.directory_enable},
        {"ipc_enable", s.ipc_enable},
        {"ipc_path", s.ipc_path},
        {"federation_enable", s.federation_enable},
        {"federation_peers", s.federation_peers},
        {"federation_auth_key", s.federation_auth_key},
        {"federation_anonym_ca", s.federation_anonym_ca},
        {"operator_keys", s.operator_keys},
        {"operator_keys_meta", s.operator_keys_meta},
        {"egress_mbps", s.egress_mbps},
        {"client_filter_mode", s.client_filter_mode},
        {"egress_filter_mode", s.egress_filter_mode},
        {"filter_lists", s.filter_lists},
        {"filter_geolite", s.filter_geolite},
        {"filter_memory_mib", s.filter_memory_mib},
        {"packet_egress", s.packet_egress},
        {"packet_tun_name", s.packet_tun_name},
        {"packet_cidr", s.packet_cidr},
        {"packet_mtu", s.packet_mtu},
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
    auto valid_filter_mode = [](const std::string& value) {
        return value == "blacklist" || value == "denylist" ||
               value == "whitelist" || value == "allowlist";
    };
    if (!valid_filter_mode(s.client_filter_mode)) {
        r.errors.emplace_back("client_filter_mode: expected blacklist or whitelist");
    }
    if (!valid_filter_mode(s.egress_filter_mode)) {
        r.errors.emplace_back("egress_filter_mode: expected blacklist or whitelist");
    }
    for (const auto& spec : s.filter_lists) {
        const auto first = spec.find(':');
        const auto second = first == std::string::npos ? std::string::npos : spec.find(':', first + 1);
        if (first == std::string::npos || second == std::string::npos || second + 1 >= spec.size()) {
            r.errors.emplace_back("filter_lists: expected <client|egress|both>:<allow|deny>:<path>");
            break;
        }
    }
    if (!s.packet_egress.empty() && s.packet_egress != "off" && s.packet_egress != "none" && s.packet_egress != "tun") {
        r.errors.emplace_back("packet_egress: expected tun, off, none, or empty");
    }
    if (!s.packet_egress.empty() && s.packet_egress != "off" && s.packet_egress != "none") {
        if (s.packet_tun_name.empty()) {
            r.errors.emplace_back("packet_tun_name: must not be empty when packet egress is enabled");
        }
        if (s.packet_mtu < 576 || s.packet_mtu > 65535) {
            r.errors.emplace_back("packet_mtu: must be 576..65535");
        }
    }
    if (s.federation_enable) {
        if (s.federation_auth_key.empty()) {
            r.errors.emplace_back("federation_auth_key: required when federation_enable=true");
        }
        if (s.federation_anonym_ca.empty()) {
            r.errors.emplace_back("federation_anonym_ca: required when federation_enable=true");
        }
        if (s.federation_peers.empty()) {
            r.errors.emplace_back("federation_peers: at least one peer is required when federation_enable=true");
        }
    }
    return r;
}

}  // namespace yume::facade::config_io
