/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <initializer_list>
#include <limits>
#include <string>

#include <nlohmann/json.hpp>

namespace yume::server::cli {

// Validate every server-config value whose type is consumed directly by the
// CLI loader. Validation is independent of CLI precedence: an overridden but
// malformed value is still a malformed configuration and must not be hidden.
inline bool validate_server_config_json_types(const nlohmann::json& document,
                                              std::string* error) {
    if (error) error->clear();
    if (!document.is_object()) {
        if (error) *error = "server config root must be a JSON object";
        return false;
    }

    const auto require_all = [&](std::initializer_list<const char*> keys,
                                 const auto& predicate,
                                 const char* expected) {
        for (const char* key : keys) {
            const auto it = document.find(key);
            if (it != document.end() && !predicate(*it)) {
                if (error) {
                    *error = std::string(key) + " must be " + expected;
                }
                return false;
            }
        }
        return true;
    };

    const auto is_int = [](const nlohmann::json& value) {
        if (value.is_number_unsigned()) {
            return value.get<std::uint64_t>() <=
                   static_cast<std::uint64_t>(
                       std::numeric_limits<int>::max());
        }
        if (!value.is_number_integer()) return false;
        const auto parsed = value.get<std::int64_t>();
        return parsed >= std::numeric_limits<int>::min() &&
               parsed <= std::numeric_limits<int>::max();
    };
    const auto is_u32 = [](const nlohmann::json& value) {
        if (value.is_number_unsigned()) {
            return value.get<std::uint64_t>() <=
                   std::numeric_limits<std::uint32_t>::max();
        }
        if (!value.is_number_integer()) return false;
        const auto parsed = value.get<std::int64_t>();
        return parsed >= 0 &&
               static_cast<std::uint64_t>(parsed) <=
                   std::numeric_limits<std::uint32_t>::max();
    };

    if (!require_all(
            {"transport_profile", "listen_address", "dns_server", "tls_cert",
             "tls_key", "auth_keys", "auth_keys_meta", "admin_keys",
             "pq_private_key", "monero_rpc_backend",
             "monero_rpc_backend_host", "real_index_path", "real_root",
             "real_backend", "real_secret", "real_secret_file",
             "obfs_secret_file", "inner_psk_file", "obfs_secret",
             "client_filter_mode", "egress_filter_mode", "filter_geolite",
             "packet_egress", "packet_tun_name", "packet_cidr",
             "upstream_response_dir", "anonym_proof_mode", "anonym_api",
             "anonym_token", "anonym_ca_key", "anonym_ca_cert",
             "anonym_sub_key", "anonym_sub_cert", "server_name", "server_id",
             "outbound_proxy", "ipc_path", "federation_identity",
             "federation_operator_ca", "operator_keys", "operator_keys_meta",
             "host_mode", "deny_default", "client_deny_action",
             "exposure_check_hostname", "exposure_check"},
            [](const nlohmann::json& value) { return value.is_string(); },
            "a string")) {
        return false;
    }
    if (!require_all(
            {"obfuscation", "inner_crypto", "inner_dual", "inner_required",
             "allow_exec", "allow_local_ip", "control_full",
             "allow_monero_rpc_codec", "allow_monero_rpc", "real_http",
             "robots_deny", "benchmark_enable", "boring", "anonym",
             "relay_enable", "directory_enable", "ipc_enable",
             "federation_enable", "cluster_bootstrap",
             "accept_yume_clients"},
            [](const nlohmann::json& value) { return value.is_boolean(); },
            "a boolean")) {
        return false;
    }
    if (!require_all(
            {"listen_port", "reverse_port_min", "reverse_port_max", "threads",
             "monero_rpc_backend_port"},
            is_int, "an integer representable as int")) {
        return false;
    }
    if (!require_all(
            {"obfs_pad_multiple", "obfs_jitter_ms",
             "tls_handshake_timeout_ms", "max_sessions",
             "bulk_key_max_sessions", "rekey_window", "accept_rate_limit",
             "egress_mbps", "filter_memory_mib", "packet_mtu",
             "upstream_response_ttl"},
            is_u32, "an integer in 0..4294967295")) {
        return false;
    }
    if (!require_all(
            {"codec_allow", "allow_codecs", "allow_services",
             "preauth_services", "filter_lists", "federation_peers", "routes",
             "listeners"},
            [](const nlohmann::json& value) { return value.is_array(); },
            "an array")) {
        return false;
    }

    for (const char* key : {"codec_allow", "allow_codecs", "allow_services",
                            "preauth_services", "filter_lists"}) {
        const auto it = document.find(key);
        if (it == document.end()) continue;
        for (const auto& entry : *it) {
            if (!entry.is_string()) {
                if (error) {
                    *error = std::string(key) + " entries must be strings";
                }
                return false;
            }
        }
    }
    if (const auto peers = document.find("federation_peers");
        peers != document.end()) {
        for (const auto& peer : *peers) {
            if (!peer.is_object()) {
                if (error) {
                    *error = "federation_peers entries must be objects";
                }
                return false;
            }
        }
    }
    if (const auto custom = document.find("security_custom");
        custom != document.end() && !custom->is_object()) {
        if (error) *error = "security_custom must be a JSON object";
        return false;
    }
    if (const auto mode = document.find("security_mode");
        mode != document.end() && !mode->is_string()) {
        if (error) *error = "security_mode must be a string";
        return false;
    }
    return true;
}

}  // namespace yume::server::cli
