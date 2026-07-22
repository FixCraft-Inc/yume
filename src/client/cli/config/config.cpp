/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/config/config.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <system_error>

#include <nlohmann/json.hpp>

#include "client/cli/connect/cert.hpp"
#include "client/cli/config/platform.hpp"
#include "core/app_codec/builtin/monero_rpc.hpp"
#include "core/app_codec/codec.hpp"
#include "util.hpp"

namespace yume::client {

namespace {

bool path_exists_noexcept(const std::filesystem::path& path) noexcept {
    std::error_code ec;
    return std::filesystem::exists(path, ec);
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

void load_client_config_file(const ParsedArgs& args,
                             const std::string& exe_dir,
                             ClientConfig* cfg) {
    if (!cfg || (!args.config_specified && !path_exists_noexcept(args.config_path))) {
        return;
    }

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
        if (json.contains("server") && cfg->server.empty()) {
            cfg->server = json["server"].get<std::string>();
        }
        if (json.contains("port") && cfg->port == 443) {
            cfg->port = json["port"].get<int>();
        }
        if (json.contains("identity") && cfg->identity.empty()) {
            cfg->identity = resolve_cfg_path(json["identity"].get<std::string>());
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
        if (json.contains("threads") && cfg->io_threads == 0 && !args.io_threads_override) {
            cfg->io_threads = json["threads"].get<int>();
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
            int v = json["obfs_pad_multiple"].get<int>();
            if (v < 0) v = 0;
            if (v > 256) v = 256;
            cfg->obfs_pad_multiple = static_cast<std::uint16_t>(v);
        }
        if (json.contains("obfs_jitter_ms") && !args.obfs_jitter_ms_override) {
            int v = json["obfs_jitter_ms"].get<int>();
            if (v < 0) v = 0;
            cfg->obfs_jitter_ms = static_cast<std::uint32_t>(v);
        }
        if (json.contains("inner_crypto") && !args.inner_crypto_override) {
            cfg->inner_crypto = json["inner_crypto"].get<bool>();
        }
        if (json.contains("inner_heavy")) {
            cfg->inner_heavy = json["inner_heavy"].get<bool>();
        }
        if (json.contains("inner_hop")) {
            cfg->inner_hop = json["inner_hop"].get<bool>();
        }
        if (json.contains("hop_interval_ms")) {
            cfg->hop_interval_ms = static_cast<std::uint32_t>(json["hop_interval_ms"].get<int>());
        }
        if (json.contains("udp") && !args.udp_override) {
            cfg->allow_udp = json["udp"].get<bool>();
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
        if (json.contains("use_embedded_master") && !args.allow_embedded_master_override) {
            cfg->allow_embedded_master = json["use_embedded_master"].get<bool>();
        }
        if (json.contains("anonym_pubkey") && cfg->anonym_pubkey.empty()) {
            cfg->anonym_pubkey = resolve_cfg_path(json["anonym_pubkey"].get<std::string>());
        }
        if (json.contains("anonym_ca_cert")) {
            cfg->anonym_ca_cert = resolve_cfg_path(json["anonym_ca_cert"].get<std::string>());
        }
        if (json.contains("tls_ca_cert") && cfg->tls_ca_cert.empty()) {
            cfg->tls_ca_cert = resolve_cfg_path(json["tls_ca_cert"].get<std::string>());
        }
        if (json.contains("tls_server_name") && cfg->tls_server_name.empty()) {
            cfg->tls_server_name = json["tls_server_name"].get<std::string>();
        }
        if (json.contains("tls_pin") && cfg->tls_pin_sha256.empty()) {
            cfg->tls_pin_sha256 = json["tls_pin"].get<std::string>();
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
        if (json.contains("self_dpi") && !args.self_dpi_override) {
            cfg->self_dpi = json["self_dpi"].get<bool>();
        }
    } catch (const std::exception& ex) {
        util::log_warn(std::string("config load failed: ") + ex.what());
    }
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
        // Per-tunnel TLS state, auth handshake, and key-hopping timer
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
    if (args.inner_hop_override) {
        cfg->inner_hop = args.inner_hop;
    }
    if (args.hop_interval_override) {
        cfg->hop_interval_ms = args.hop_interval_ms;
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
    if (!args.relay_mode.empty()) {
        cfg->relay_mode = args.relay_mode;
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
    if (!args.tls_stealth_profile.empty()) {
        cfg->tls_stealth_profile = args.tls_stealth_profile;
    }
    if (args.tls_stealth_rotate) {
        cfg->tls_stealth_rotate = true;
    }
    if (args.tls_stealth_rotation_interval > 0) {
        cfg->tls_stealth_rotation_interval = args.tls_stealth_rotation_interval;
    }
    if (args.tls_fingerprint_log) {
        cfg->tls_fingerprint_log = true;
    }
    if (!args.tls_fingerprint_log_path.empty()) {
        cfg->tls_fingerprint_log_path = args.tls_fingerprint_log_path;
    }
    if (args.tls_fingerprint_verify) {
        cfg->tls_fingerprint_verify = true;
    }
    if (!args.tls_fingerprint_test_endpoint.empty()) {
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
    if (cfg->inner_hop && !cfg->inner_crypto) {
        cfg->inner_crypto = true;
    }
    if (!cfg->inner_crypto) {
        cfg->inner_hop = false;
    }
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
    if (cfg->hop_interval_ms > 0) {
        if (cfg->hop_interval_ms < 250) {
            cfg->hop_interval_ms = 250;
        } else if (cfg->hop_interval_ms > 1000) {
            cfg->hop_interval_ms = 1000;
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

void save_client_config_file(const ParsedArgs& args, const ClientConfig& cfg) {
    if (!args.save_server || cfg.server.empty()) {
        return;
    }
    nlohmann::json json;
    std::ifstream in(args.config_path);
    if (in) {
        try {
            in >> json;
        } catch (...) {
            json = nlohmann::json::object();
        }
    } else {
        json = nlohmann::json::object();
    }
    json["server"] = cfg.server;
    if (cfg.port > 0) json["port"] = cfg.port;
    if (!cfg.identity.empty()) json["identity"] = cfg.identity;
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
    json["inner_hop"] = cfg.inner_hop;
    json["hop_interval_ms"] = cfg.hop_interval_ms;
    json["udp"] = cfg.allow_udp;
    json["allow_local_ip"] = cfg.allow_local_ip;
    json["server_in_charge"] = cfg.server_in_charge;
    if (cfg.server_in_charge_port > 0) json["server_in_charge_port"] = cfg.server_in_charge_port;
    json["allow_exec"] = cfg.allow_exec;
    if (!cfg.pq_public_key.empty()) json["pq_public_key"] = cfg.pq_public_key;
    json["use_embedded_master"] = cfg.allow_embedded_master;
    if (!cfg.anonym_ca_cert.empty()) json["anonym_ca_cert"] = cfg.anonym_ca_cert;
    if (!cfg.tls_ca_cert.empty()) json["tls_ca_cert"] = cfg.tls_ca_cert;
    if (!cfg.tls_server_name.empty()) json["tls_server_name"] = cfg.tls_server_name;
    if (!cfg.tls_pin_sha256.empty()) json["tls_pin"] = cfg.tls_pin_sha256;
    json["require_anonym"] = cfg.require_anonym;
    json["accept_monitoring"] = cfg.accept_monitoring;
    json["service_streams_only"] = cfg.service_streams_only;
    json["boring"] = cfg.boring;
    json["non_interactive"] = cfg.non_interactive;
    json["instance_name"] = cfg.instance_name;
    json["preferred_name"] = cfg.preferred_name;
    json["preferred_id"] = cfg.preferred_id;
    json["relay_mode"] = cfg.relay_mode;
    json["allow_inbound_admin"] = cfg.allow_inbound_admin;
    json["allow_outbound_admin"] = cfg.allow_outbound_admin;
    json["allow_chat"] = cfg.allow_chat;
    json["allow_file"] = cfg.allow_file;
    json["allow_bytes"] = cfg.allow_bytes;
    json["history_enabled"] = cfg.history_enabled;
    if (!cfg.history_dir.empty()) json["history_dir"] = cfg.history_dir;
    if (!cfg.relay_key_file.empty()) json["relay_key_file"] = cfg.relay_key_file;
    json["auto_attach_local"] = cfg.auto_attach_local;
    if (!cfg.app_codec.empty()) {
        json["app_codec"] = cfg.app_codec;
        json["app_codec_listen"] = cfg.app_codec_listen_host + ":" +
                                   std::to_string(cfg.app_codec_listen_port);
    }
    json["self_dpi"] = cfg.self_dpi;
    std::ofstream out(args.config_path);
    if (out) {
        out << json.dump(2);
    }
}

}  // namespace yume::client
