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

// The closed key set of a transport-v2 client configuration document.
//
// Two parsers read the same file: the CLI parser in
// client/cli/config/config.cpp and the facade parser in
// facade/config/client_config_io.cpp, which the GUI and the C ABI use. Both
// must agree on what a key means, and both must refuse a key they do not
// know. This header sits below both parsers so there is exactly one place to
// add a key.
//
// "display_name" is written by the facade for profile listings and read by
// facade/config/profiles.cpp, not by either configuration parser. "role" is
// the C ABI dialect selector (docs/ABI.md): the ABI reads it before handing
// the same document to this parser, so a file may carry it.
inline constexpr auto kClientDocumentKeys = std::to_array<std::string_view>({
    "accept_monitoring",
    "admin_identity",
    "allow_bytes",
    "allow_chat",
    "allow_embedded_master",
    "allow_exec",
    "allow_file",
    "allow_inbound_admin",
    "allow_local_ip",
    "allow_outbound_admin",
    "allow_udp",
    "anonym_ca_cert",
    "anonym_ca_material_id",
    "anonym_pubkey",
    "anonym_pubkey_material_id",
    "app_codec",
    "app_codec_listen",
    "app_codec_listen_host",
    "app_codec_listen_port",
    "auth_key_material_id",
    "auto_attach_local",
    "boring",
    "codec",
    "display_name",
    "history_dir",
    "history_enabled",
    "identity",
    "inner_crypto",
    "inner_psk_file",
    "instance_name",
    "io_threads",
    "non_interactive",
    "obfs_jitter_ms",
    "obfs_pad_multiple",
    "obfs_secret_file",
    "obfuscation",
    "outbound_proxy",
    "packet_tun_name",
    "port",
    "pq_public_key",
    "preferred_id",
    "preferred_name",
    "rekey_window",
    "relay_key_file",
    "relay_mode",
    "relay_peer_pins",
    "relay_receive_dir",
    "relay_trust_dir",
    "relay_trust_mode",
    "require_anonym",
    "role",
    "security_custom",
    "security_mode",
    "self_dpi",
    "server",
    "server_in_charge",
    "server_in_charge_port",
    "service_streams_only",
    "socks_bind",
    "socks_port",
    "threads",
    "tls_backend",
    "tls_ca_cert",
    "tls_ca_material_id",
    "tls_fingerprint_log",
    "tls_fingerprint_log_path",
    "tls_fingerprint_test_endpoint",
    "tls_fingerprint_verify",
    "tls_helper_path",
    "tls_pin",
    "tls_pin_sha256",
    "tls_server_name",
    "tls_stealth_enabled",
    "tls_stealth_profile",
    "transport_profile",
    "tunnels",
    "udp",
});

// Keys that were accepted by an earlier development wire. See
// yume::config::RetiredDocumentKey for the contract.
inline constexpr auto kRetiredClientKeys = std::to_array<RetiredDocumentKey>({
    {"obfs_secret",
     "inline admission secrets are refused; store the secret in an "
     "owner-only file and set obfs_secret_file"},
    {"tls_stealth_rotate",
     "TLS profile rotation was removed; one immutable transport profile "
     "is used"},
    {"tls_stealth_rotation_interval",
     "TLS profile rotation was removed; one immutable transport profile "
     "is used"},
});

// Returns the first key-set problem in a client document, or nullopt when
// every key is known and current.
inline std::optional<DocumentError> client_document_key_error(
    const nlohmann::json& document) {
    return document_key_error(document, kClientDocumentKeys,
                              kRetiredClientKeys, "client");
}

}  // namespace yume::config
