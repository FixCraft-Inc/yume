/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/cli/config.hpp"

#include <filesystem>
#include <fstream>

#include <nlohmann/json.hpp>

#include "util.hpp"

namespace yume::client {

void resolve_config_path(ParsedArgs* args, const std::string& exe_dir) {
    if (!args) {
        return;
    }
    args->config_path = util::expand_user(args->config_path);
    if (args->config_specified || exe_dir.empty()) {
        return;
    }
    std::filesystem::path cfg_path(args->config_path);
    if (std::filesystem::exists(cfg_path)) {
        return;
    }
    std::filesystem::path cand = std::filesystem::path(exe_dir) / cfg_path;
    if (std::filesystem::exists(cand)) {
        args->config_path = cand.string();
    }
}

void load_client_config_file(const ParsedArgs& args,
                             const std::string& exe_dir,
                             ClientConfig* cfg) {
    if (!cfg || (!args.config_specified && !std::filesystem::exists(args.config_path))) {
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
        if (json.contains("threads") && cfg->io_threads == 0 && !args.io_threads_override) {
            cfg->io_threads = json["threads"].get<int>();
        }
        if (json.contains("tunnels") && !args.tunnel_count_override) {
            cfg->tunnel_count = json["tunnels"].get<int>();
        }
        if (json.contains("obfuscation") && !args.obfuscation_override) {
            cfg->obfuscation = json["obfuscation"].get<bool>();
        }
        if (json.contains("obfs_secret") && !args.obfs_secret_override) {
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
        if (json.contains("tls_pin") && cfg->tls_pin_sha256.empty()) {
            cfg->tls_pin_sha256 = json["tls_pin"].get<std::string>();
        }
        if (json.contains("outbound_proxy") && !args.outbound_proxy_override) {
            cfg->outbound_proxy_url = json["outbound_proxy"].get<std::string>();
        }
        if (json.contains("require_anonym")) {
            cfg->require_anonym = json["require_anonym"].get<bool>();
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
        if (json.contains("self_dpi") && !args.self_dpi_override) {
            cfg->self_dpi = json["self_dpi"].get<bool>();
        }
    } catch (const std::exception& ex) {
        util::log_warn(std::string("config load failed: ") + ex.what());
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
    if (cfg.io_threads != 0) json["threads"] = cfg.io_threads;
    if (cfg.tunnel_count > 1) json["tunnels"] = cfg.tunnel_count;
    json["obfuscation"] = cfg.obfuscation;
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
    if (!cfg.tls_pin_sha256.empty()) json["tls_pin"] = cfg.tls_pin_sha256;
    json["require_anonym"] = cfg.require_anonym;
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
    json["self_dpi"] = cfg.self_dpi;
    std::ofstream out(args.config_path);
    if (out) {
        out << json.dump(2);
    }
}

}  // namespace yume::client
