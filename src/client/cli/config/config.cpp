/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/config/config.hpp"

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>

#include <nlohmann/json.hpp>

#include "config/ratchet_profile_json.hpp"
#include "core/security/ratchet.hpp"
#include "core/runtime/atomic_file.hpp"
#include "client/cli/connect/cert.hpp"
#include "client/cli/config/platform.hpp"
#include "core/app_codec/builtin/monero_rpc.hpp"
#include "core/app_codec/codec.hpp"
#include "util.hpp"
#include "util_json.hpp"

namespace yume::client {

namespace {

bool path_exists_noexcept(const std::filesystem::path& path) noexcept {
    std::error_code ec;
    return std::filesystem::exists(path, ec);
}

std::string format_endpoint_spec(std::string_view host, int port) {
    std::string endpoint;
    if (host.find(':') != std::string_view::npos) {
        endpoint = "[" + std::string(host) + "]";
    } else {
        endpoint = std::string(host);
    }
    endpoint += ":" + std::to_string(port);
    return endpoint;
}

bool validate_client_config_json_types(const nlohmann::json& document,
                                       std::string* error) {
    if (error) error->clear();
    if (!document.is_object()) {
        if (error) *error = "client config root must be a JSON object";
        return false;
    }
    const auto require_all = [&](std::initializer_list<const char*> keys,
                                 const auto& predicate,
                                 const char* expected) {
        for (const char* key : keys) {
            const auto it = document.find(key);
            if (it != document.end() && !predicate(*it)) {
                if (error) *error = std::string(key) + " must be " + expected;
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
            {"server", "identity", "admin_identity", "socks_bind",
             "packet_tun_name", "obfs_secret_file", "inner_psk_file",
             "obfs_secret", "pq_public_key", "anonym_pubkey",
             "anonym_pubkey_material_id", "anonym_ca_cert",
             "anonym_ca_material_id", "auth_key_material_id",
             "tls_ca_cert", "tls_ca_material_id", "tls_server_name",
             "tls_pin", "tls_pin_sha256", "transport_profile",
             "tls_backend", "tls_helper_path", "outbound_proxy",
             "instance_name", "preferred_name", "preferred_id",
             "relay_mode", "relay_trust_mode", "relay_trust_dir",
             "history_dir", "relay_receive_dir", "relay_key_file",
             "app_codec", "codec", "app_codec_listen",
             "app_codec_listen_host", "tls_stealth_profile",
             "tls_fingerprint_log_path", "tls_fingerprint_test_endpoint",
             "security_mode"},
            [](const nlohmann::json& value) { return value.is_string(); },
            "a string")) {
        return false;
    }
    if (!require_all(
            {"obfuscation", "inner_crypto", "inner_heavy", "udp",
             "allow_udp", "allow_local_ip", "server_in_charge",
             "allow_exec", "allow_embedded_master", "require_anonym",
             "accept_monitoring", "service_streams_only", "boring",
             "non_interactive", "allow_inbound_admin",
             "allow_outbound_admin", "allow_chat", "allow_file",
             "allow_bytes", "history_enabled", "auto_attach_local",
             "tls_stealth_enabled", "tls_fingerprint_log",
             "tls_fingerprint_verify", "self_dpi"},
            [](const nlohmann::json& value) { return value.is_boolean(); },
            "a boolean")) {
        return false;
    }
    if (!require_all(
            {"port", "socks_port", "threads", "io_threads", "tunnels",
             "server_in_charge_port", "app_codec_listen_port"},
            is_int, "an integer representable as int")) {
        return false;
    }
    if (!require_all({"obfs_jitter_ms"}, is_u32,
                     "an integer in 0..4294967295")) {
        return false;
    }
    const auto pad = document.find("obfs_pad_multiple");
    if (pad != document.end() && (!is_u32(*pad) ||
                                  (pad->is_number_unsigned()
                                       ? pad->get<std::uint64_t>()
                                       : static_cast<std::uint64_t>(
                                             pad->get<std::int64_t>())) > 256)) {
        if (error) *error = "obfs_pad_multiple must be an integer in 0..256";
        return false;
    }
    const auto rekey = document.find("rekey_window");
    if (rekey != document.end() && !is_int(*rekey)) {
        if (error) *error = "rekey_window must be an integer";
        return false;
    }
    const auto pins = document.find("relay_peer_pins");
    if (pins != document.end()) {
        if (!pins->is_object()) {
            if (error) *error = "relay_peer_pins must be a JSON object";
            return false;
        }
        for (auto it = pins->begin(); it != pins->end(); ++it) {
            if (!it.value().is_string()) {
                if (error) *error = "relay_peer_pins values must be strings";
                return false;
            }
        }
    }
    const auto custom = document.find("security_custom");
    if (custom != document.end() && !custom->is_object()) {
        if (error) *error = "security_custom must be a JSON object";
        return false;
    }
    try {
        (void)yume::config::ParseSecurityProfile(document);
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
    return true;
}

std::uint32_t json_non_negative_u32(const nlohmann::json& document,
                                    const char* key) {
    const auto& value = document.at(key);
    if (value.is_number_unsigned()) {
        return static_cast<std::uint32_t>(value.get<std::uint64_t>());
    }
    return static_cast<std::uint32_t>(value.get<std::int64_t>());
}

}  // namespace

void resolve_config_path(ParsedArgs* args, const std::string& exe_dir) {
    if (!args) {
        return;
    }
    args->config_path = util::expand_user(args->config_path);
    if (args->config_specified || exe_dir.empty()) {
        return;
    }
    std::filesystem::path cfg_path(args->config_path);
    if (path_exists_noexcept(cfg_path)) {
        return;
    }
    std::filesystem::path cand = std::filesystem::path(exe_dir) / cfg_path;
    if (path_exists_noexcept(cand)) {
        args->config_path = cand.string();
    }
}

bool load_client_config_file(const ParsedArgs& args,
                             const std::string& exe_dir,
                             ClientConfig* out_cfg,
                             std::string* error) {
    if (error) error->clear();
    if (!out_cfg) {
        if (error) *error = "client config output is null";
        return false;
    }
    if (!args.config_specified && !path_exists_noexcept(args.config_path)) {
        return true;
    }

    ClientConfig candidate = *out_cfg;
    ClientConfig* const cfg = &candidate;
    try {
        std::error_code ec;
        std::string config_dir;
        auto cfg_abs = std::filesystem::absolute(args.config_path, ec);
        if (!ec) {
            config_dir = cfg_abs.parent_path().string();
        } else {
            config_dir = std::filesystem::path(args.config_path).parent_path().string();
        }
        auto resolve_cfg_path = [&](const std::string& value) {
            return util::resolve_path(value, config_dir, exe_dir);
        };
        auto json = util::read_json_config(args.config_path);
        std::string validation_error;
        if (!validate_client_config_json_types(json, &validation_error)) {
            throw std::runtime_error(validation_error);
        }
        if (json.contains("tls_stealth_rotate") ||
            json.contains("tls_stealth_rotation_interval")) {
            throw std::runtime_error(
                "TLS profile rotation keys were removed in YUME 0.2.0-dev6");
        }
        if (json.contains("server") && cfg->server.empty()) {
            cfg->server = json["server"].get<std::string>();
        }
        if (json.contains("port") && cfg->port == 443) {
            cfg->port = json["port"].get<int>();
        }
        if (json.contains("identity") && cfg->identity.empty()) {
            cfg->identity = resolve_cfg_path(json["identity"].get<std::string>());
        }
        if (json.contains("admin_identity") && cfg->admin_identity.empty()) {
            cfg->admin_identity = resolve_cfg_path(
                json["admin_identity"].get<std::string>());
        }
        if (json.contains("socks_port") && !args.socks_port_override && cfg->socks_port == 0) {
            cfg->socks_port = json["socks_port"].get<int>();
        }
        if (json.contains("socks_bind") && !args.socks_port_override) {
            cfg->socks_bind_host = json["socks_bind"].get<std::string>();
        }
        if (json.contains("packet_tun_name") && !args.packet_tun_override) {
            cfg->packet_tun_name = json["packet_tun_name"].get<std::string>();
        }
        const char* threads_key = json.contains("threads")
            ? "threads"
            : (json.contains("io_threads") ? "io_threads" : nullptr);
        if (threads_key && cfg->io_threads == 0 && !args.io_threads_override) {
            cfg->io_threads = json[threads_key].get<int>();
        }
        if (json.contains("tunnels") && !args.tunnel_count_override) {
            cfg->tunnel_count = json["tunnels"].get<int>();
        }
        if (json.contains("obfuscation") && !args.obfuscation_override) {
            cfg->obfuscation = json["obfuscation"].get<bool>();
        }
        if (json.contains("obfs_secret_file") && !args.obfs_secret_file_override) {
            cfg->obfs_secret_file = resolve_cfg_path(
                json["obfs_secret_file"].get<std::string>());
        }
        if (json.contains("inner_psk_file") && !args.inner_psk_file_override) {
            cfg->inner_psk_file = resolve_cfg_path(
                json["inner_psk_file"].get<std::string>());
        }
        if (json.contains("obfs_secret")) {
            cfg->obfs_secret = json["obfs_secret"].get<std::string>();
        }
        if (json.contains("obfs_pad_multiple") && !args.obfs_pad_multiple_override) {
            cfg->obfs_pad_multiple = static_cast<std::uint16_t>(
                json_non_negative_u32(json, "obfs_pad_multiple"));
        }
        if (json.contains("obfs_jitter_ms") && !args.obfs_jitter_ms_override) {
            cfg->obfs_jitter_ms =
                json_non_negative_u32(json, "obfs_jitter_ms");
        }
        if (json.contains("inner_crypto") && !args.inner_crypto_override) {
            cfg->inner_crypto = json["inner_crypto"].get<bool>();
        }
        if (json.contains("inner_heavy")) {
            cfg->inner_heavy = json["inner_heavy"].get<bool>();
        }
        if (json.contains("rekey_window") && !args.rekey_window_override) {
            const int window = json["rekey_window"].get<int>();
            if (window < ratchet::kMinRekeyWindow ||
                window > ratchet::kMaxRekeyWindow) {
                throw std::runtime_error("rekey_window must be in 1..64");
            }
            cfg->rekey_window = static_cast<std::uint16_t>(window);
        }
        cfg->security_profile = yume::config::ParseSecurityProfile(
            json, cfg->security_profile);
        const char* udp_key = json.contains("udp")
            ? "udp"
            : (json.contains("allow_udp") ? "allow_udp" : nullptr);
        if (udp_key && !args.udp_override) {
            cfg->allow_udp = json[udp_key].get<bool>();
        }
        if (json.contains("allow_local_ip") && !args.allow_local_ip_override) {
            cfg->allow_local_ip = json["allow_local_ip"].get<bool>();
        }
        if (json.contains("server_in_charge") && !args.server_in_charge_override) {
            cfg->server_in_charge = json["server_in_charge"].get<bool>();
        }
        if (json.contains("server_in_charge_port") && !args.server_in_charge_port_override) {
            cfg->server_in_charge_port = json["server_in_charge_port"].get<int>();
        }
        if (json.contains("allow_exec") && !args.allow_exec_override) {
            cfg->allow_exec = json["allow_exec"].get<bool>();
        }
        if (json.contains("pq_public_key") && cfg->pq_public_key.empty()) {
            cfg->pq_public_key = resolve_cfg_path(json["pq_public_key"].get<std::string>());
        }
        if (json.contains("allow_embedded_master") &&
            !args.allow_embedded_master_override) {
            cfg->allow_embedded_master =
                json["allow_embedded_master"].get<bool>();
        }
        if (json.contains("anonym_pubkey") && cfg->anonym_pubkey.empty()) {
            cfg->anonym_pubkey = resolve_cfg_path(json["anonym_pubkey"].get<std::string>());
        }
        if (json.contains("anonym_pubkey_material_id")) {
            cfg->anonym_pubkey_material_id =
                json["anonym_pubkey_material_id"].get<std::string>();
        }
        if (json.contains("anonym_ca_cert")) {
            cfg->anonym_ca_cert = resolve_cfg_path(json["anonym_ca_cert"].get<std::string>());
        }
        if (json.contains("anonym_ca_material_id")) {
            cfg->anonym_ca_material_id =
                json["anonym_ca_material_id"].get<std::string>();
        }
        if (json.contains("auth_key_material_id")) {
            cfg->auth_key_material_id =
                json["auth_key_material_id"].get<std::string>();
        }
        if (json.contains("tls_ca_cert") && cfg->tls_ca_cert.empty()) {
            cfg->tls_ca_cert = resolve_cfg_path(json["tls_ca_cert"].get<std::string>());
        }
        if (json.contains("tls_ca_material_id")) {
            cfg->tls_ca_material_id =
                json["tls_ca_material_id"].get<std::string>();
        }
        if (json.contains("tls_server_name") && cfg->tls_server_name.empty()) {
            cfg->tls_server_name = json["tls_server_name"].get<std::string>();
        }
        const char* tls_pin_key = json.contains("tls_pin")
            ? "tls_pin"
            : (json.contains("tls_pin_sha256") ? "tls_pin_sha256" : nullptr);
        if (tls_pin_key && cfg->tls_pin_sha256.empty()) {
            cfg->tls_pin_sha256 = json[tls_pin_key].get<std::string>();
        }
        if (json.contains("transport_profile")) {
            cfg->transport_profile = json["transport_profile"].get<std::string>();
        }
        if (json.contains("tls_backend")) {
            cfg->tls_backend = json["tls_backend"].get<std::string>();
        }
        if (json.contains("tls_helper_path")) {
            cfg->tls_helper_path = resolve_cfg_path(
                json["tls_helper_path"].get<std::string>());
        }
        if (json.contains("outbound_proxy") && !args.outbound_proxy_override) {
            cfg->outbound_proxy_url = json["outbound_proxy"].get<std::string>();
        }
        if (json.contains("require_anonym")) {
            cfg->require_anonym = json["require_anonym"].get<bool>();
        }
        if (json.contains("accept_monitoring")) {
            cfg->accept_monitoring = json["accept_monitoring"].get<bool>();
        }
        if (json.contains("service_streams_only")) {
            cfg->service_streams_only = json["service_streams_only"].get<bool>();
        }
        if (json.contains("boring") && !args.boring_override) {
            cfg->boring = json["boring"].get<bool>();
        }
        if (json.contains("non_interactive")) {
            cfg->non_interactive = json["non_interactive"].get<bool>();
        }
        if (json.contains("instance_name") && cfg->instance_name.empty()) {
            cfg->instance_name = json["instance_name"].get<std::string>();
        }
        if (json.contains("preferred_name") && cfg->preferred_name.empty()) {
            cfg->preferred_name = json["preferred_name"].get<std::string>();
        }
        if (json.contains("preferred_id") && cfg->preferred_id.empty()) {
            cfg->preferred_id = json["preferred_id"].get<std::string>();
        }
        if (json.contains("relay_mode")) {
            cfg->relay_mode = json["relay_mode"].get<std::string>();
        }
        if (json.contains("relay_trust_mode") &&
            !args.relay_trust_mode_override) {
            cfg->relay_trust_mode =
                json["relay_trust_mode"].get<std::string>();
        }
        if (json.contains("relay_trust_dir") &&
            !args.relay_trust_dir_override) {
            cfg->relay_trust_dir = resolve_cfg_path(
                json["relay_trust_dir"].get<std::string>());
        }
        if (json.contains("relay_peer_pins")) {
            const auto& pins = json["relay_peer_pins"];
            if (!pins.is_object()) {
                throw std::runtime_error(
                    "relay_peer_pins must be a JSON object");
            }
            for (auto it = pins.begin(); it != pins.end(); ++it) {
                if (!it.value().is_string()) {
                    throw std::runtime_error(
                        "relay_peer_pins values must be strings");
                }
                cfg->relay_peer_pins[it.key()] =
                    it.value().get<std::string>();
            }
        }
        if (json.contains("allow_inbound_admin") && !args.allow_inbound_admin_override) {
            cfg->allow_inbound_admin = json["allow_inbound_admin"].get<bool>();
        }
        if (json.contains("allow_outbound_admin") && !args.allow_outbound_admin_override) {
            cfg->allow_outbound_admin = json["allow_outbound_admin"].get<bool>();
        }
        if (json.contains("allow_chat") && !args.allow_chat_override) {
            cfg->allow_chat = json["allow_chat"].get<bool>();
        }
        if (json.contains("allow_file") && !args.allow_file_override) {
            cfg->allow_file = json["allow_file"].get<bool>();
        }
        if (json.contains("allow_bytes") && !args.allow_bytes_override) {
            cfg->allow_bytes = json["allow_bytes"].get<bool>();
        }
        if (json.contains("history_enabled") && !args.history_override) {
            cfg->history_enabled = json["history_enabled"].get<bool>();
        }
        if (json.contains("history_dir") && cfg->history_dir.empty()) {
            cfg->history_dir = resolve_cfg_path(json["history_dir"].get<std::string>());
        }
        if (json.contains("relay_receive_dir") &&
            cfg->relay_receive_dir.empty()) {
            cfg->relay_receive_dir = resolve_cfg_path(
                json["relay_receive_dir"].get<std::string>());
        }
        if (json.contains("relay_key_file") && cfg->relay_key_file.empty()) {
            cfg->relay_key_file = resolve_cfg_path(json["relay_key_file"].get<std::string>());
        }
        if (json.contains("auto_attach_local")) {
            cfg->auto_attach_local = json["auto_attach_local"].get<bool>();
        }
        if (json.contains("app_codec") && !args.app_codec_override) {
            cfg->app_codec = json["app_codec"].get<std::string>();
        } else if (json.contains("codec") && !args.app_codec_override) {
            cfg->app_codec = json["codec"].get<std::string>();
        }
        if (json.contains("app_codec_listen") && !args.app_codec_listen_override) {
            std::string parse_error;
            auto ep = app_codec::parse_endpoint_spec(json["app_codec_listen"].get<std::string>(),
                                                     app_codec::builtin::kMoneroRpcDefaultHost,
                                                     app_codec::builtin::kMoneroRpcDefaultPort,
                                                     &parse_error);
            if (ep.has_value()) {
                cfg->app_codec_listen_host = ep->host;
                cfg->app_codec_listen_port = ep->port;
            } else {
                util::log_error("app_codec_listen: " + parse_error);
                cfg->app_codec_listen_port = 0;
            }
        }
        if (json.contains("app_codec_listen_host") && !args.app_codec_listen_override) {
            cfg->app_codec_listen_host = json["app_codec_listen_host"].get<std::string>();
        }
        if (json.contains("app_codec_listen_port") && !args.app_codec_listen_override) {
            cfg->app_codec_listen_port = json["app_codec_listen_port"].get<int>();
        }
        if (json.contains("tls_stealth_enabled") && !args.tls_stealth_override) {
            cfg->tls_stealth_enabled = json["tls_stealth_enabled"].get<bool>();
        }
        if (json.contains("tls_stealth_profile") &&
            !args.tls_stealth_profile_override) {
            cfg->tls_stealth_profile =
                json["tls_stealth_profile"].get<std::string>();
        }
        if (json.contains("tls_fingerprint_log") &&
            !args.tls_fingerprint_log_override) {
            cfg->tls_fingerprint_log = json["tls_fingerprint_log"].get<bool>();
        }
        if (json.contains("tls_fingerprint_log_path") &&
            !args.tls_fingerprint_log_path_override) {
            cfg->tls_fingerprint_log_path = resolve_cfg_path(
                json["tls_fingerprint_log_path"].get<std::string>());
        }
        if (json.contains("tls_fingerprint_verify") &&
            !args.tls_fingerprint_verify_override) {
            cfg->tls_fingerprint_verify =
                json["tls_fingerprint_verify"].get<bool>();
        }
        if (json.contains("tls_fingerprint_test_endpoint") &&
            !args.tls_fingerprint_test_endpoint_override) {
            cfg->tls_fingerprint_test_endpoint =
                json["tls_fingerprint_test_endpoint"].get<std::string>();
        }
        if (json.contains("self_dpi") && !args.self_dpi_override) {
            cfg->self_dpi = json["self_dpi"].get<bool>();
        }
    } catch (const std::exception& ex) {
        if (error) *error = std::string("config load failed: ") + ex.what();
        return false;
    }
    *out_cfg = std::move(candidate);
    return true;
}

void apply_cli_config_overrides(const ParsedArgs& args,
                                const std::string& cli_cwd,
                                ClientConfig* cfg) {
    if (!cfg) {
        return;
    }
    auto resolve_cli_path = [&](const std::string& value) {
        return util::resolve_path(value, cli_cwd, "");
    };

    if (!args.server.empty()) {
        cfg->server = args.server;
    }
    if (args.port > 0) {
        cfg->port = args.port;
    }
    if (!args.admin_identity.empty()) {
        cfg->admin_identity = resolve_cli_path(args.admin_identity);
    }
    if (!args.identity.empty()) {
        cfg->identity = resolve_cli_path(args.identity);
    }
    if (args.socks_port_override) {
        cfg->socks_bind_host = args.socks_bind_host;
        cfg->socks_port = args.socks_port;
    }
    if (args.packet_tun_override) {
        cfg->packet_tun_name = args.packet_tun_name;
    }
    if (args.io_threads != 0 || args.io_threads_override) {
        cfg->io_threads = args.io_threads;
    }
    if (args.tunnel_count > 0 || args.tunnel_count_override) {
        cfg->tunnel_count = args.tunnel_count;
    }
    if (cfg->tunnel_count < 1) {
        cfg->tunnel_count = 1;
    }
    if (cfg->tunnel_count > 16) {
        // Per-tunnel TLS state and authentication handshake
        // aren't free; 16 is the empirical sweet spot above which the
        // server-side rate limiter (default 100 accepts/s) starts to
        // drop handshakes anyway. Clamp loudly rather than crash much
        // later with cryptic accept failures.
        util::log_warn("--tunnels " + std::to_string(cfg->tunnel_count) +
                       " exceeds the 16-tunnel cap; clamping to 16");
        cfg->tunnel_count = 16;
    }
    if (args.obfuscation_override) {
        cfg->obfuscation = args.obfuscation;
    }
    if (args.obfs_secret_file_override) {
        cfg->obfs_secret_file = resolve_cli_path(args.obfs_secret_file);
    }
    if (args.inner_psk_file_override) {
        cfg->inner_psk_file = resolve_cli_path(args.inner_psk_file);
    }
    if (args.obfs_pad_multiple_override) {
        cfg->obfs_pad_multiple = args.obfs_pad_multiple;
    }
    if (args.obfs_jitter_ms_override) {
        cfg->obfs_jitter_ms = args.obfs_jitter_ms;
    }
    if (args.inner_crypto_override) {
        cfg->inner_crypto = args.inner_crypto;
    }
    if (args.inner_crypto) {
        cfg->inner_heavy = args.inner_heavy;
    }
    if (args.rekey_window_override) {
        cfg->rekey_window = ratchet::ClampRekeyWindow(
            static_cast<std::uint32_t>(args.rekey_window));
    }
    if (!args.pq_public_key.empty()) {
        cfg->pq_public_key = resolve_cli_path(args.pq_public_key);
    }
    if (args.allow_embedded_master_override) {
        cfg->allow_embedded_master = args.allow_embedded_master;
    }
    if (!args.anonym_ca_cert.empty()) {
        cfg->anonym_ca_cert = resolve_cli_path(args.anonym_ca_cert);
    }
    if (!args.tls_ca_cert.empty()) {
        cfg->tls_ca_cert = resolve_cli_path(args.tls_ca_cert);
    }
    if (!args.tls_server_name.empty()) {
        cfg->tls_server_name = args.tls_server_name;
    }
    if (!args.tls_pin_sha256.empty()) {
        cfg->tls_pin_sha256 = args.tls_pin_sha256;
    }
    if (args.outbound_proxy_override) {
        cfg->outbound_proxy_url = args.outbound_proxy_url;
    }
    if (args.require_anonym) {
        cfg->require_anonym = true;
    }
    if (args.udp_override) {
        cfg->allow_udp = args.use_udp;
    }
    if (args.allow_local_ip_override) {
        cfg->allow_local_ip = args.allow_local_ip;
    }
    if (args.server_in_charge_override) {
        cfg->server_in_charge = args.server_in_charge;
    }
    if (args.server_in_charge_port_override) {
        cfg->server_in_charge_port = args.server_in_charge_port;
    }
    if (!args.preferred_name.empty()) {
        cfg->preferred_name = args.preferred_name;
    }
    if (!args.preferred_id.empty()) {
        cfg->preferred_id = args.preferred_id;
    }
    if (args.relay_mode_override) {
        cfg->relay_mode = args.relay_mode;
    }
    if (args.relay_trust_mode_override) {
        cfg->relay_trust_mode = args.relay_trust_mode;
    }
    if (args.relay_trust_dir_override) {
        cfg->relay_trust_dir = resolve_cli_path(args.relay_trust_dir);
    }
    for (const auto& pin : args.relay_peer_pins) {
        const auto separator = pin.find('=');
        cfg->relay_peer_pins[pin.substr(0, separator)] =
            pin.substr(separator + 1);
    }
    if (args.accept_monitoring) {
        cfg->accept_monitoring = true;
    }
    if (args.service_streams_only) {
        cfg->service_streams_only = true;
    }
    if (args.allow_inbound_admin_override) {
        cfg->allow_inbound_admin = args.allow_inbound_admin;
    }
    if (args.allow_outbound_admin_override) {
        cfg->allow_outbound_admin = args.allow_outbound_admin;
    }
    if (args.allow_chat_override) {
        cfg->allow_chat = args.allow_chat;
    }
    if (args.allow_file_override) {
        cfg->allow_file = args.allow_file;
    }
    if (args.allow_bytes_override) {
        cfg->allow_bytes = args.allow_bytes;
    }
    if (!args.history_dir.empty()) {
        cfg->history_dir = resolve_cli_path(args.history_dir);
    }
    if (!args.relay_receive_dir.empty()) {
        cfg->relay_receive_dir = resolve_cli_path(args.relay_receive_dir);
    }
    if (!args.relay_key_file.empty()) {
        cfg->relay_key_file = resolve_cli_path(args.relay_key_file);
    }
    if (args.history_override) {
        cfg->history_enabled = args.history_enabled;
    }
    if (!args.instance_name.empty()) {
        cfg->instance_name = args.instance_name;
    }
    if (args.app_codec_override) {
        cfg->app_codec = args.app_codec;
    }
    if (args.app_codec_listen_override) {
        std::string parse_error;
        auto ep = app_codec::parse_endpoint_spec(args.app_codec_listen,
                                                 app_codec::builtin::kMoneroRpcDefaultHost,
                                                 app_codec::builtin::kMoneroRpcDefaultPort,
                                                 &parse_error);
        if (ep.has_value()) {
            cfg->app_codec_listen_host = ep->host;
            cfg->app_codec_listen_port = ep->port;
        } else {
            util::log_warn("--codec-listen ignored: " + parse_error);
            cfg->app_codec_listen_port = 0;
        }
    }
    if (args.allow_exec_override) {
        cfg->allow_exec = args.allow_exec;
    }
    if (args.boring_override) {
        cfg->boring = args.boring;
    }
    if (args.non_interactive) {
        cfg->non_interactive = true;
    }
    if (args.tls_stealth_override) {
        cfg->tls_stealth_enabled = args.tls_stealth;
    }
    if (args.tls_stealth_profile_override) {
        cfg->tls_stealth_profile = args.tls_stealth_profile;
    }
    if (!args.transport_profile.empty()) {
        cfg->transport_profile = args.transport_profile;
    }
    if (!args.tls_backend.empty()) {
        cfg->tls_backend = args.tls_backend;
    }
    if (!args.tls_helper_path.empty()) {
        cfg->tls_helper_path = args.tls_helper_path;
    }
    if (args.tls_fingerprint_log_override) {
        cfg->tls_fingerprint_log = args.tls_fingerprint_log;
    }
    if (args.tls_fingerprint_log_path_override) {
        cfg->tls_fingerprint_log_path = args.tls_fingerprint_log_path;
    }
    if (args.tls_fingerprint_verify_override) {
        cfg->tls_fingerprint_verify = args.tls_fingerprint_verify;
    }
    if (args.tls_fingerprint_test_endpoint_override) {
        cfg->tls_fingerprint_test_endpoint = args.tls_fingerprint_test_endpoint;
    }
    if (args.self_dpi_override) {
        cfg->self_dpi = args.self_dpi;
    }
}

void normalize_client_config_after_overrides(ParsedArgs* args, ClientConfig* cfg) {
    if (!args || !cfg) {
        return;
    }
#if defined(_WIN32) || defined(__APPLE__)
    if (cfg->tls_ca_cert.empty() && !cfg->anonym_ca_cert.empty()) {
        cfg->tls_ca_cert = cfg->anonym_ca_cert;
    }
#endif
    if (args->bench) {
        if (!args->bench_chunk_kib_override) {
            args->bench_chunk_kib = static_cast<int>(
                util::relay_read_buf_size() / 1024U);
        }
        if (args->bench_full) {
            if (!args->bench_mib_override) {
                args->bench_mib = 1024;
            }
            if (!args->bench_streams_override) {
                args->bench_streams = 64;
            }
            if (!args->bench_direction_override) {
                args->bench_direction = "both";
            }
        }
        if (args->bench_mib <= 0) {
            args->bench_mib = 256;
        }
        if (args->bench_mib > 16384) {
            args->bench_mib = 16384;
        }
        if (args->bench_chunk_kib <= 0) {
            args->bench_chunk_kib = 64;
        }
        if (args->bench_chunk_kib > 256) {
            args->bench_chunk_kib = 256;
        }
        if (args->bench_streams <= 0) {
            args->bench_streams = 1;
        }
        if (args->bench_streams > 240) {
            args->bench_streams = 240;
        }
        if (!args->socks_port_override) {
            cfg->socks_port = 0;
            cfg->socks_bind_host.clear();
        }
        if (!args->server_in_charge_override) {
            cfg->server_in_charge = false;
            cfg->server_in_charge_port = 0;
        }
    }
    if (cfg->history_dir.empty()) {
        const char* xdg = std::getenv("XDG_CONFIG_HOME");
        const char* home = std::getenv("HOME");
        std::filesystem::path base = (xdg && *xdg)
            ? std::filesystem::path(xdg)
            : ((home && *home) ? std::filesystem::path(home) : std::filesystem::path("."));
        cfg->history_dir = ((home && *home) ? (base / ".yume" / "history") : (base / "history")).string();
    }
    if (cfg->relay_receive_dir.empty()) {
        const std::filesystem::path history_path(cfg->history_dir);
        const auto parent = history_path.has_parent_path()
            ? history_path.parent_path() : std::filesystem::path(".");
        cfg->relay_receive_dir = (parent / "received").string();
    }
    if (cfg->relay_trust_dir.empty()) {
        const std::filesystem::path history_path(cfg->history_dir);
        const auto parent = history_path.has_parent_path()
            ? history_path.parent_path() : std::filesystem::path(".");
        cfg->relay_trust_dir = (parent / "relay-trust").string();
    }
    if (cfg->relay_mode != "trusted") {
        cfg->relay_mode = "untrusted";
    }
    if (!cfg->app_codec.empty()) {
        cfg->app_codec = app_codec::canonical_codec_id(cfg->app_codec);
    }
}

void discover_default_pq_public_key(const char* argv0, ClientConfig* cfg) {
    if (!cfg || !cfg->inner_crypto || !cfg->pq_public_key.empty()) {
        return;
    }
    std::error_code ec;
    std::filesystem::path runtime_dir = std::filesystem::current_path(ec);
    std::filesystem::path exe_path_dir;
    std::filesystem::path user_cfg_dir;
    std::string self_path = get_self_path(argv0);
    if (!self_path.empty()) {
        exe_path_dir = std::filesystem::path(self_path).parent_path();
    }
    if (const char* home = std::getenv("HOME"); home && *home) {
        user_cfg_dir = std::filesystem::path(home) / ".yume";
    }
    auto try_set = [&](const std::filesystem::path& base) {
        if (!cfg->pq_public_key.empty() || base.empty()) {
            return;
        }
        std::filesystem::path cand = base / "pq_public.key";
        if (file_exists(cand.string())) {
            cfg->pq_public_key = cand.string();
        }
    };
    try_set(user_cfg_dir);
    try_set(runtime_dir);
    try_set(exe_path_dir);
    if (!cfg->pq_public_key.empty()) {
        util::log_info("using discovered pq_public_key: " + cfg->pq_public_key);
    }
}

bool save_client_config_file(const ParsedArgs& args,
                             const ClientConfig& cfg,
                             std::string* error) {
    if (error) error->clear();
    if (!args.save_server || cfg.server.empty()) {
        return true;
    }
    nlohmann::json json = nlohmann::json::object();
    const std::filesystem::path config_path(args.config_path);
    std::error_code exists_error;
    const bool config_exists = std::filesystem::exists(config_path, exists_error);
    if (exists_error) {
        if (error) {
            *error = "cannot inspect existing client config '" +
                     config_path.string() + "': " + exists_error.message();
        }
        return false;
    }
    if (config_exists) {
        std::ifstream in(config_path);
        if (!in) {
            if (error) {
                *error = "cannot read existing client config '" +
                         config_path.string() + "'";
            }
            return false;
        }
        try {
            in >> json;
        } catch (const std::exception& ex) {
            if (error) {
                *error = "cannot parse existing client config '" +
                         config_path.string() + "': " + ex.what();
            }
            return false;
        }
        if (in.bad()) {
            if (error) {
                *error = "cannot finish reading existing client config '" +
                         config_path.string() + "'";
            }
            return false;
        }
        if (!json.is_object()) {
            if (error) {
                *error = "existing client config root must be a JSON object: '" +
                         config_path.string() + "'";
            }
            return false;
        }
        if (json.contains("tls_stealth_rotate") ||
            json.contains("tls_stealth_rotation_interval")) {
            if (error) {
                *error = "existing client config is not usable: TLS profile "
                         "rotation keys were removed in YUME 0.2.0-dev6";
            }
            return false;
        }
        std::string validation_error;
        if (!validate_client_config_json_types(json, &validation_error)) {
            if (error) {
                *error = "existing client config is not usable: " +
                         validation_error;
            }
            return false;
        }
    }
    // Normalize files written by older facade/CLI versions. Canonical keys
    // below win on read; removing aliases also prevents inline 1.x secrets or
    // retired ratchet/profile controls from surviving a save operation.
    json.erase("io_threads");
    json.erase("allow_udp");
    json.erase("tls_pin_sha256");
    json.erase("codec");
    json.erase("obfs_secret");
    json.erase("inner_hop");
    json.erase("hop_interval_ms");
    json.erase("tls_stealth_rotate");
    json.erase("tls_stealth_rotation_interval");
    json["server"] = cfg.server;
    if (cfg.port > 0) json["port"] = cfg.port;
    if (!cfg.identity.empty()) json["identity"] = cfg.identity;
    if (!cfg.admin_identity.empty()) json["admin_identity"] = cfg.admin_identity;
    if (cfg.socks_port > 0) json["socks_port"] = cfg.socks_port;
    if (!cfg.socks_bind_host.empty()) json["socks_bind"] = cfg.socks_bind_host;
    if (!cfg.packet_tun_name.empty()) json["packet_tun_name"] = cfg.packet_tun_name;
    if (cfg.io_threads != 0) json["threads"] = cfg.io_threads;
    if (cfg.tunnel_count > 1) json["tunnels"] = cfg.tunnel_count;
    json["obfuscation"] = cfg.obfuscation;
    if (!cfg.obfs_secret_file.empty()) json["obfs_secret_file"] = cfg.obfs_secret_file;
    if (!cfg.inner_psk_file.empty()) json["inner_psk_file"] = cfg.inner_psk_file;
    if (cfg.obfs_pad_multiple > 0) json["obfs_pad_multiple"] = cfg.obfs_pad_multiple;
    if (cfg.obfs_jitter_ms > 0) json["obfs_jitter_ms"] = cfg.obfs_jitter_ms;
    json["inner_crypto"] = cfg.inner_crypto;
    json["inner_heavy"] = cfg.inner_heavy;
    json["rekey_window"] = cfg.rekey_window;
    yume::config::WriteSecurityProfile(json, cfg.security_profile);
    json["udp"] = cfg.allow_udp;
    json["allow_local_ip"] = cfg.allow_local_ip;
    json["server_in_charge"] = cfg.server_in_charge;
    if (cfg.server_in_charge_port > 0) json["server_in_charge_port"] = cfg.server_in_charge_port;
    json["allow_exec"] = cfg.allow_exec;
    if (!cfg.pq_public_key.empty()) json["pq_public_key"] = cfg.pq_public_key;
    json["allow_embedded_master"] = cfg.allow_embedded_master;
    if (!cfg.anonym_pubkey.empty()) json["anonym_pubkey"] = cfg.anonym_pubkey;
    if (!cfg.anonym_pubkey_material_id.empty()) {
        json["anonym_pubkey_material_id"] = cfg.anonym_pubkey_material_id;
    }
    if (!cfg.anonym_ca_cert.empty()) json["anonym_ca_cert"] = cfg.anonym_ca_cert;
    if (!cfg.anonym_ca_material_id.empty()) {
        json["anonym_ca_material_id"] = cfg.anonym_ca_material_id;
    }
    if (!cfg.auth_key_material_id.empty()) {
        json["auth_key_material_id"] = cfg.auth_key_material_id;
    }
    if (!cfg.tls_ca_cert.empty()) json["tls_ca_cert"] = cfg.tls_ca_cert;
    if (!cfg.tls_ca_material_id.empty()) {
        json["tls_ca_material_id"] = cfg.tls_ca_material_id;
    }
    if (!cfg.tls_server_name.empty()) json["tls_server_name"] = cfg.tls_server_name;
    if (!cfg.tls_pin_sha256.empty()) json["tls_pin"] = cfg.tls_pin_sha256;
    json["transport_profile"] = cfg.transport_profile;
    json["tls_backend"] = cfg.tls_backend;
    if (!cfg.tls_helper_path.empty()) json["tls_helper_path"] = cfg.tls_helper_path;
    if (!cfg.outbound_proxy_url.empty()) {
        json["outbound_proxy"] = cfg.outbound_proxy_url;
    } else {
        json.erase("outbound_proxy");
    }
    json["require_anonym"] = cfg.require_anonym;
    json["accept_monitoring"] = cfg.accept_monitoring;
    json["service_streams_only"] = cfg.service_streams_only;
    json["boring"] = cfg.boring;
    json["non_interactive"] = cfg.non_interactive;
    json["instance_name"] = cfg.instance_name;
    json["preferred_name"] = cfg.preferred_name;
    json["preferred_id"] = cfg.preferred_id;
    json["relay_mode"] = cfg.relay_mode;
    json["relay_trust_mode"] = cfg.relay_trust_mode;
    if (!cfg.relay_trust_dir.empty()) {
        json["relay_trust_dir"] = cfg.relay_trust_dir;
    }
    json["relay_peer_pins"] = cfg.relay_peer_pins;
    json["allow_inbound_admin"] = cfg.allow_inbound_admin;
    json["allow_outbound_admin"] = cfg.allow_outbound_admin;
    json["allow_chat"] = cfg.allow_chat;
    json["allow_file"] = cfg.allow_file;
    json["allow_bytes"] = cfg.allow_bytes;
    json["history_enabled"] = cfg.history_enabled;
    if (!cfg.history_dir.empty()) json["history_dir"] = cfg.history_dir;
    if (!cfg.relay_receive_dir.empty()) {
        json["relay_receive_dir"] = cfg.relay_receive_dir;
    }
    if (!cfg.relay_key_file.empty()) json["relay_key_file"] = cfg.relay_key_file;
    json["auto_attach_local"] = cfg.auto_attach_local;
    if (!cfg.app_codec.empty()) {
        json["app_codec"] = cfg.app_codec;
        json["app_codec_listen"] = format_endpoint_spec(
            cfg.app_codec_listen_host, cfg.app_codec_listen_port);
    } else {
        json.erase("app_codec");
        json.erase("app_codec_listen");
    }
    json["tls_stealth_enabled"] = cfg.tls_stealth_enabled;
    json["tls_stealth_profile"] = cfg.tls_stealth_profile;
    json["tls_fingerprint_log"] = cfg.tls_fingerprint_log;
    if (!cfg.tls_fingerprint_log_path.empty()) {
        json["tls_fingerprint_log_path"] = cfg.tls_fingerprint_log_path;
    } else {
        json.erase("tls_fingerprint_log_path");
    }
    json["tls_fingerprint_verify"] = cfg.tls_fingerprint_verify;
    json["tls_fingerprint_test_endpoint"] =
        cfg.tls_fingerprint_test_endpoint;
    json["self_dpi"] = cfg.self_dpi;
    std::string serialized;
    try {
        serialized = json.dump(2);
    } catch (const std::exception& ex) {
        if (error) {
            *error = "cannot serialize client config: " +
                     std::string(ex.what());
        }
        return false;
    }
    return yume::runtime::AtomicWriteFile(
        config_path, serialized, error);
}

}  // namespace yume::client
