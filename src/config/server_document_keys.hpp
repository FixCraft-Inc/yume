/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */
#pragma once

#include <array>
#include <optional>
#include <string_view>

#include <nlohmann/json.hpp>

#include "config/document_error.hpp"
#include "config/document_keys.hpp"

namespace yume::config {

// The closed key set of a transport-v2 server configuration document.
//
// Two parsers read the same file: the CLI loader in
// server/cli/config_load.cpp and the facade parser in
// facade/config/server_config_io.cpp, which the GUI uses. Both must agree on
// what a key means and both must refuse a key they do not know, for the same
// reason the client set is closed: a misspelled key reads as "leave the
// default", and several of these defaults are security decisions.
//
// "security_mode" and "security_custom" are written by
// config/ratchet_profile_json.hpp on behalf of both parsers.
inline constexpr auto kServerDocumentKeys = std::to_array<std::string_view>({
    "accept_rate_limit",
    "accept_yume_clients",
    "admin_keys",
    "allow_codecs",
    "allow_embedded_master",
    "allow_exec",
    "allow_local_ip",
    "allow_monero_rpc_codec",
    "allow_services",
    "anonym",
    "anonym_api",
    "anonym_ca_cert",
    "anonym_ca_key",
    "anonym_proof_mode",
    "anonym_sub_cert",
    "anonym_sub_key",
    "anonym_token_file",
    "auth_keys",
    "auth_keys_meta",
    "benchmark_enable",
    "boring",
    "bulk_key_max_sessions",
    "client_deny_action",
    "client_filter_mode",
    "cluster_bootstrap",
    "control_full",
    "directory_enable",
    "dns_server",
    "egress_filter_mode",
    "egress_mbps",
    "exposure_check_hostname",
    "federation_enable",
    "federation_identity",
    "federation_operator_ca",
    "federation_peers",
    "filter_geolite",
    "filter_lists",
    "filter_memory_mib",
    "host_mode",
    "inner_crypto",
    "inner_psk_file",
    "ipc_enable",
    "ipc_path",
    "listen_address",
    "listen_port",
    "listeners",
    "max_sessions",
    "monero_rpc_backend_host",
    "monero_rpc_backend_port",
    "obfs_jitter_ms",
    "obfs_pad_multiple",
    "obfs_secret_file",
    "obfuscation",
    "operator_keys",
    "operator_keys_meta",
    "outbound_proxy",
    "packet_cidr",
    "packet_egress",
    "packet_mtu",
    "packet_tun_name",
    "pq_auto_generate",
    "pq_private_key",
    "preauth_services",
    "real_backend",
    "real_http",
    "real_index_path",
    "real_root",
    "real_secret_file",
    "rekey_window",
    "relay_enable",
    "reverse_port_max",
    "reverse_port_min",
    "robots_deny",
    "role",
    "routes",
    "security_custom",
    "security_mode",
    "server_id",
    "server_name",
    "threads",
    "tls_cert",
    "tls_handshake_timeout_ms",
    "tls_key",
    "transport_profile",
    "upstream_response_dir",
    "upstream_response_ttl",
});

// Keys that were accepted by an earlier development wire. See
// yume::config::RetiredDocumentKey for the contract.
inline constexpr auto kRetiredServerKeys = std::to_array<RetiredDocumentKey>({
    {"anonym_token",
     "inline operator proof tokens are refused; store the token in an "
     "owner-only file and set anonym_token_file"},
    {"obfs_secret",
     "inline admission secrets are refused; store the secret in an "
     "owner-only file and set obfs_secret_file"},
    {"real_secret",
     "inline cover-backend secrets are refused; store the secret in an "
     "owner-only file and set real_secret_file, or leave both unset to have "
     "one generated"},
});

// Returns the first key-set problem in a server document, or nullopt when
// every key is known and current.
inline std::optional<DocumentError> server_document_key_error(
    const nlohmann::json& document) {
    return document_key_error(document, kServerDocumentKeys,
                              kRetiredServerKeys, "server");
}

}  // namespace yume::config
