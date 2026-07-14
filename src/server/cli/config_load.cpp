/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/config_load.hpp"

#include <cstdint>
#include <exception>
#include <filesystem>
#include <string>

#include <nlohmann/json.hpp>

#include "server/cli/misc.hpp"
#include "core/app_codec/codec.hpp"
#include "server/config/config.hpp"
#include "server/config/json_values.hpp"
#include "server/host/host_routes.hpp"
#include "util.hpp"

namespace yume::server_cli {
namespace {

std::uint32_t json_non_negative_u32(const nlohmann::json& json, const char* key) {
    int v = json[key].get<int>();
    if (v < 0) {
        v = 0;
    }
    return static_cast<std::uint32_t>(v);
}

std::uint16_t json_obfs_pad_multiple(const nlohmann::json& json) {
    int v = json["obfs_pad_multiple"].get<int>();
    if (v < 0) {
        v = 0;
    }
    if (v > 256) {
        v = 256;
    }
    return static_cast<std::uint16_t>(v);
}

void resolve_server_config_paths(yume::server::ServerConfig& cfg,
                                 const ServerConfigLoadContext& context) {
    auto resolve_cfg_path = [&](const std::string& value) {
        return yume::util::resolve_path(value, context.config_dir, context.exe_dir);
    };

    if (!cfg.tls_cert.empty()) {
        cfg.tls_cert = resolve_cfg_path(cfg.tls_cert);
    }
    if (!cfg.tls_key.empty()) {
        cfg.tls_key = resolve_cfg_path(cfg.tls_key);
    }
    if (!cfg.auth_keys.empty()) {
        cfg.auth_keys = resolve_cfg_path(cfg.auth_keys);
    }
    if (!cfg.auth_keys_meta.empty()) {
        cfg.auth_keys_meta = resolve_cfg_path(cfg.auth_keys_meta);
    }
    if (!cfg.pq_private_key.empty()) {
        cfg.pq_private_key = resolve_cfg_path(cfg.pq_private_key);
    }
    if (!cfg.real_index_path.empty()) {
        cfg.real_index_path = resolve_cfg_path(cfg.real_index_path);
    }
    if (!cfg.real_secret_file.empty()) {
        cfg.real_secret_file = resolve_cfg_path(cfg.real_secret_file);
    }
    if (!cfg.anonym_ca_key.empty()) {
        cfg.anonym_ca_key = resolve_cfg_path(cfg.anonym_ca_key);
    }
    if (!cfg.anonym_ca_cert.empty()) {
        cfg.anonym_ca_cert = resolve_cfg_path(cfg.anonym_ca_cert);
    }
    if (!cfg.anonym_sub_key.empty()) {
        cfg.anonym_sub_key = resolve_cfg_path(cfg.anonym_sub_key);
    }
    if (!cfg.anonym_sub_cert.empty()) {
        cfg.anonym_sub_cert = resolve_cfg_path(cfg.anonym_sub_cert);
    }
    if (!cfg.operator_keys.empty()) {
        cfg.operator_keys = resolve_cfg_path(cfg.operator_keys);
    }
    if (!cfg.operator_keys_meta.empty()) {
        cfg.operator_keys_meta = resolve_cfg_path(cfg.operator_keys_meta);
    }
    if (!cfg.federation_auth_key.empty()) {
        cfg.federation_auth_key = resolve_cfg_path(cfg.federation_auth_key);
    }
    if (!cfg.federation_anonym_ca.empty()) {
        cfg.federation_anonym_ca = resolve_cfg_path(cfg.federation_anonym_ca);
    }
    if (!cfg.filter_geolite.empty()) {
        cfg.filter_geolite = resolve_cfg_path(cfg.filter_geolite);
    }
    for (auto& spec : cfg.filter_lists) {
        spec = resolve_filter_list_spec_path(spec, context.config_dir, context.exe_dir);
    }
}

}  // namespace

bool load_server_config_file_and_resolve_paths(yume::server::ServerConfig& cfg,
                                               ServerConfigLoadContext& context,
                                               const ServerConfigOverrides& overrides) {
    context.config_path = yume::util::expand_user(context.config_path);
    if (!context.config_specified && !context.exe_dir.empty()) {
        std::filesystem::path cfg_path(context.config_path);
        if (!std::filesystem::exists(cfg_path)) {
            std::filesystem::path candidate = std::filesystem::path(context.exe_dir) / cfg_path;
            if (std::filesystem::exists(candidate)) {
                context.config_path = candidate.string();
            }
        }
    }

    if (context.config_specified || std::filesystem::exists(context.config_path)) {
        std::error_code ec;
        auto cfg_abs = std::filesystem::absolute(context.config_path, ec);
        if (!ec) {
            context.config_dir = cfg_abs.parent_path().string();
        } else {
            context.config_dir = std::filesystem::path(context.config_path).parent_path().string();
        }
    }

    auto resolve_cfg_path = [&](const std::string& value) {
        return yume::util::resolve_path(value, context.config_dir, context.exe_dir);
    };

    if (context.config_specified || std::filesystem::exists(context.config_path)) {
        try {
            auto json = yume::util::read_json_config(context.config_path);
            if (json.contains("listen_port") && cfg.listen_port == 443) {
                cfg.listen_port = json["listen_port"].get<int>();
            }
            if (json.contains("reverse_port_min") &&
                cfg.reverse_port_min == yume::policy::kReversePortMinDefault) {
                cfg.reverse_port_min = json["reverse_port_min"].get<int>();
            }
            if (json.contains("reverse_port_max") &&
                cfg.reverse_port_max == yume::policy::kReversePortMaxDefault) {
                cfg.reverse_port_max = json["reverse_port_max"].get<int>();
            }
            if (json.contains("dns_server") && cfg.dns_server.empty()) {
                cfg.dns_server = json["dns_server"].get<std::string>();
            }
            if (json.contains("tls_cert") && cfg.tls_cert.empty()) {
                cfg.tls_cert = resolve_cfg_path(json["tls_cert"].get<std::string>());
            }
            if (json.contains("tls_key") && cfg.tls_key.empty()) {
                cfg.tls_key = resolve_cfg_path(json["tls_key"].get<std::string>());
            }
            if (json.contains("auth_keys") && cfg.auth_keys.empty()) {
                cfg.auth_keys = resolve_cfg_path(json["auth_keys"].get<std::string>());
            }
            if (json.contains("auth_keys_meta") && cfg.auth_keys_meta.empty()) {
                cfg.auth_keys_meta = resolve_cfg_path(json["auth_keys_meta"].get<std::string>());
            }
            if (json.contains("threads") && cfg.threads == 0) {
                cfg.threads = json["threads"].get<int>();
            }
            if (json.contains("obfuscation") && !overrides.obfuscation) {
                cfg.obfuscation = json["obfuscation"].get<bool>();
            }
            if (json.contains("inner_crypto") && !overrides.inner_crypto) {
                cfg.inner_crypto = json["inner_crypto"].get<bool>();
            }
            if (json.contains("inner_dual") && !overrides.inner_dual) {
                cfg.inner_dual = json["inner_dual"].get<bool>();
            }
            if (json.contains("inner_required") && !overrides.inner_required) {
                cfg.inner_required = json["inner_required"].get<bool>();
            }
            if (json.contains("inner_hop") && !overrides.inner_hop) {
                cfg.inner_hop = json["inner_hop"].get<bool>();
            }
            if (json.contains("hop_interval_ms") && !overrides.hop_interval) {
                cfg.hop_interval_ms = static_cast<std::uint32_t>(json["hop_interval_ms"].get<int>());
            }
            if (json.contains("argon2_memory_budget_kib") &&
                !overrides.argon2_memory_budget) {
                cfg.argon2_memory_budget_kib =
                    yume::server::json_positive_u32(
                        json, "argon2_memory_budget_kib");
            }
            if (json.contains("argon2_max_jobs") && !overrides.argon2_max_jobs) {
                cfg.argon2_max_jobs =
                    yume::server::json_positive_u32(json, "argon2_max_jobs");
            }
            if (json.contains("inner_heavy")) {
                cfg.inner_heavy = json["inner_heavy"].get<bool>();
            }
            if (json.contains("pq_private_key") && cfg.pq_private_key.empty()) {
                cfg.pq_private_key = resolve_cfg_path(json["pq_private_key"].get<std::string>());
            }
            if (json.contains("pq_auto_generate") && !overrides.pq_auto_generate) {
                cfg.pq_auto_generate = json["pq_auto_generate"].get<bool>();
            }
            if (json.contains("use_embedded_master") && !overrides.allow_embedded_master) {
                cfg.allow_embedded_master = json["use_embedded_master"].get<bool>();
            }
            if (json.contains("allow_exec") && !cfg.allow_exec) {
                cfg.allow_exec = json["allow_exec"].get<bool>();
            }
            if (json.contains("allow_local_ip")) {
                cfg.allow_local_ip = json["allow_local_ip"].get<bool>();
            }
            if (json.contains("control_full")) {
                cfg.control_full = json["control_full"].get<bool>();
            }
            if (json.contains("allow_monero_rpc_codec")) {
                cfg.allow_monero_rpc_codec = json["allow_monero_rpc_codec"].get<bool>();
                if (cfg.allow_monero_rpc_codec) {
                    yume::app_codec::add_codec_unique(&cfg.allowed_codecs, yume::app_codec::kMoneroRpcCodecId);
                }
            } else if (json.contains("allow_monero_rpc")) {
                cfg.allow_monero_rpc_codec = json["allow_monero_rpc"].get<bool>();
                if (cfg.allow_monero_rpc_codec) {
                    yume::app_codec::add_codec_unique(&cfg.allowed_codecs, yume::app_codec::kMoneroRpcCodecId);
                }
            }
            const auto read_codec_allow = [&](const char* key) -> bool {
                if (!json.contains(key)) {
                    return true;
                }
                if (!json[key].is_array()) {
                    yume::util::log_error(std::string(key) + " must be an array");
                    return false;
                }
                for (const auto& item : json[key]) {
                    if (!item.is_string()) {
                        yume::util::log_error(std::string(key) + " entries must be strings");
                        return false;
                    }
                    const std::string codec = yume::app_codec::canonical_codec_id(item.get<std::string>());
                    if (!yume::app_codec::is_supported_codec(codec)) {
                        yume::util::log_error(std::string("unsupported application codec in ") + key + ": " + codec);
                        return false;
                    }
                    yume::app_codec::add_codec_unique(&cfg.allowed_codecs, codec);
                    if (codec == std::string(yume::app_codec::kMoneroRpcCodecId)) {
                        cfg.allow_monero_rpc_codec = true;
                    }
                }
                return true;
            };
            if (!read_codec_allow("codec_allow") || !read_codec_allow("allow_codecs")) {
                return false;
            }
            if (json.contains("allow_services")) {
                if (!json["allow_services"].is_array()) {
                    yume::util::log_error("allow_services must be an array");
                    return false;
                }
                for (const auto& item : json["allow_services"]) {
                    if (!item.is_string()) {
                        yume::util::log_error("allow_services entries must be strings");
                        return false;
                    }
                    cfg.allowed_services.push_back(item.get<std::string>());
                }
            }
            if (json.contains("monero_rpc_backend")) {
                std::string parse_error;
                auto ep = yume::app_codec::parse_endpoint_spec(json["monero_rpc_backend"].get<std::string>(),
                                                               yume::app_codec::kMoneroRpcDefaultHost,
                                                               yume::app_codec::kMoneroRpcDefaultPort,
                                                               &parse_error);
                if (ep.has_value()) {
                    cfg.monero_rpc_backend_host = ep->host;
                    cfg.monero_rpc_backend_port = ep->port;
                } else {
                    yume::util::log_error("monero_rpc_backend: " + parse_error);
                    return false;
                }
            }
            if (json.contains("monero_rpc_backend_host")) {
                cfg.monero_rpc_backend_host = json["monero_rpc_backend_host"].get<std::string>();
            }
            if (json.contains("monero_rpc_backend_port")) {
                cfg.monero_rpc_backend_port = json["monero_rpc_backend_port"].get<int>();
            }
            if (json.contains("real_http") && !cfg.real_http) {
                cfg.real_http = json["real_http"].get<bool>();
            }
            if (json.contains("real_index_path") && cfg.real_index_path.empty()) {
                cfg.real_index_path = resolve_cfg_path(json["real_index_path"].get<std::string>());
            }
            if (json.contains("real_secret") && cfg.real_secret.empty()) {
                cfg.real_secret = json["real_secret"].get<std::string>();
            }
            if (json.contains("real_secret_file") && cfg.real_secret_file.empty()) {
                cfg.real_secret_file = resolve_cfg_path(json["real_secret_file"].get<std::string>());
            }
            if (json.contains("obfs_secret") && cfg.obfs_secret.empty()) {
                cfg.obfs_secret = json["obfs_secret"].get<std::string>();
            }
            if (json.contains("obfs_pad_multiple") && cfg.obfs_pad_multiple == 0) {
                cfg.obfs_pad_multiple = json_obfs_pad_multiple(json);
            }
            if (json.contains("obfs_jitter_ms") && cfg.obfs_jitter_ms == 0) {
                cfg.obfs_jitter_ms = json_non_negative_u32(json, "obfs_jitter_ms");
            }
            if (json.contains("tls_handshake_timeout_ms") && !overrides.tls_handshake_timeout) {
                cfg.tls_handshake_timeout_ms = json_non_negative_u32(json, "tls_handshake_timeout_ms");
            }
            if (json.contains("max_sessions") && !overrides.max_sessions) {
                cfg.max_sessions = json_non_negative_u32(json, "max_sessions");
            }
            if (json.contains("accept_rate_limit") && !overrides.accept_rate_limit) {
                cfg.accept_rate_limit = json_non_negative_u32(json, "accept_rate_limit");
            }
            if (json.contains("egress_mbps") && !overrides.egress_mbps) {
                cfg.egress_mbps = json_non_negative_u32(json, "egress_mbps");
            }
            if (json.contains("robots_deny") && !cfg.robots_deny) {
                cfg.robots_deny = json["robots_deny"].get<bool>();
            }
            if (json.contains("client_filter_mode") && !overrides.client_filter_mode) {
                cfg.client_filter_mode = json["client_filter_mode"].get<std::string>();
            }
            if (json.contains("egress_filter_mode") && !overrides.egress_filter_mode) {
                cfg.egress_filter_mode = json["egress_filter_mode"].get<std::string>();
            }
            if (json.contains("filter_memory_mib") && !overrides.filter_memory_mib) {
                cfg.filter_memory_mib = json_non_negative_u32(json, "filter_memory_mib");
            }
            if (json.contains("filter_geolite") && !overrides.filter_geolite) {
                cfg.filter_geolite = resolve_cfg_path(json["filter_geolite"].get<std::string>());
            }
            if (json.contains("filter_lists") && json["filter_lists"].is_array()) {
                for (const auto& item : json["filter_lists"]) {
                    if (item.is_string()) {
                        cfg.filter_lists.push_back(
                            resolve_filter_list_spec_path(item.get<std::string>(),
                                                          context.config_dir,
                                                          context.exe_dir));
                    }
                }
            }
            if (json.contains("packet_egress") && !overrides.packet_egress) {
                cfg.packet_egress = json["packet_egress"].get<std::string>();
            }
            if (json.contains("packet_tun_name") && !overrides.packet_tun_name) {
                cfg.packet_tun_name = json["packet_tun_name"].get<std::string>();
            }
            if (json.contains("packet_cidr") && !overrides.packet_cidr) {
                cfg.packet_cidr = json["packet_cidr"].get<std::string>();
            }
            if (json.contains("packet_mtu") && !overrides.packet_mtu) {
                cfg.packet_mtu = json_non_negative_u32(json, "packet_mtu");
            }
            if (json.contains("benchmark_enable") && !cfg.benchmark_enable) {
                cfg.benchmark_enable = json["benchmark_enable"].get<bool>();
            }
            if (json.contains("upstream_response_dir") && cfg.upstream_response_dir.empty()) {
                cfg.upstream_response_dir = resolve_cfg_path(json["upstream_response_dir"].get<std::string>());
            }
            if (json.contains("upstream_response_ttl") && cfg.upstream_response_ttl_s == 0) {
                cfg.upstream_response_ttl_s = json_non_negative_u32(json, "upstream_response_ttl");
            }
            if (json.contains("boring")) {
                cfg.boring = json["boring"].get<bool>();
            }
            if (json.contains("anonym") && !overrides.anonym) {
                cfg.anonym = json["anonym"].get<bool>();
            }
            if (json.contains("anonym_proof_mode") && !overrides.anonym_proof_mode) {
                cfg.anonym_proof_mode = json["anonym_proof_mode"].get<std::string>();
            }
            if (json.contains("anonym_api") && cfg.anonym_api.empty()) {
                cfg.anonym_api = json["anonym_api"].get<std::string>();
            }
            if (json.contains("anonym_token") && cfg.anonym_token.empty()) {
                cfg.anonym_token = json["anonym_token"].get<std::string>();
            }
            if (json.contains("anonym_ca_key") && cfg.anonym_ca_key.empty()) {
                cfg.anonym_ca_key = resolve_cfg_path(json["anonym_ca_key"].get<std::string>());
            }
            if (json.contains("anonym_ca_cert") && cfg.anonym_ca_cert.empty()) {
                cfg.anonym_ca_cert = resolve_cfg_path(json["anonym_ca_cert"].get<std::string>());
            }
            if (json.contains("anonym_sub_key") && cfg.anonym_sub_key.empty()) {
                cfg.anonym_sub_key = resolve_cfg_path(json["anonym_sub_key"].get<std::string>());
            }
            if (json.contains("anonym_sub_cert") && cfg.anonym_sub_cert.empty()) {
                cfg.anonym_sub_cert = resolve_cfg_path(json["anonym_sub_cert"].get<std::string>());
            }
            if (json.contains("server_name") && cfg.server_name.empty()) {
                cfg.server_name = json["server_name"].get<std::string>();
            }
            if (json.contains("server_id") && cfg.server_id.empty()) {
                cfg.server_id = json["server_id"].get<std::string>();
            }
            if (json.contains("outbound_proxy") && cfg.outbound_proxy_url.empty()) {
                cfg.outbound_proxy_url = json["outbound_proxy"].get<std::string>();
            }
            if (json.contains("relay_enable") && !overrides.relay_enable) {
                cfg.relay_enable = json["relay_enable"].get<bool>();
            }
            if (json.contains("directory_enable") && !overrides.directory_enable) {
                cfg.directory_enable = json["directory_enable"].get<bool>();
            }
            if (json.contains("ipc_enable")) {
                cfg.ipc_enable = json["ipc_enable"].get<bool>();
            }
            if (json.contains("ipc_path") && cfg.ipc_path.empty()) {
                cfg.ipc_path = resolve_cfg_path(json["ipc_path"].get<std::string>());
            }
            if (json.contains("federation_enable") && !cfg.federation_enable) {
                cfg.federation_enable = json["federation_enable"].get<bool>();
            }
            if (json.contains("federation_peers") && cfg.federation_peers.empty()) {
                for (const auto& peer : json["federation_peers"]) {
                    cfg.federation_peers.push_back(peer.dump());
                }
            }
            if (json.contains("federation_auth_key") && cfg.federation_auth_key.empty()) {
                cfg.federation_auth_key = resolve_cfg_path(json["federation_auth_key"].get<std::string>());
            }
            if (json.contains("federation_anonym_ca") && cfg.federation_anonym_ca.empty()) {
                cfg.federation_anonym_ca = resolve_cfg_path(json["federation_anonym_ca"].get<std::string>());
            }
            if (json.contains("operator_keys") && cfg.operator_keys.empty()) {
                cfg.operator_keys = resolve_cfg_path(json["operator_keys"].get<std::string>());
            }
            if (json.contains("operator_keys_meta") && cfg.operator_keys_meta.empty()) {
                cfg.operator_keys_meta = resolve_cfg_path(json["operator_keys_meta"].get<std::string>());
            }
            if (json.contains("host_mode") && !overrides.host_mode) {
                auto mode = yume::server::host::parse_host_mode(json["host_mode"].get<std::string>());
                if (mode.has_value()) {
                    cfg.host_mode = *mode;
                    if (*mode == yume::server::host::HostMode::Private &&
                        !json.contains("accept_yume_clients") &&
                        !overrides.accept_yume_clients) {
                        cfg.accept_yume_clients = false;
                    }
                } else {
                    yume::util::log_error("host_mode must be off, private, or relay");
                    return false;
                }
            }
            if (json.contains("accept_yume_clients") && !overrides.accept_yume_clients) {
                cfg.accept_yume_clients = json["accept_yume_clients"].get<bool>();
            }
            if (json.contains("deny_default") && !overrides.client_deny_action) {
                auto action = yume::server::host::parse_deny_action(json["deny_default"].get<std::string>());
                if (action.has_value()) {
                    cfg.client_deny_action = *action;
                } else {
                    yume::util::log_error("deny_default must be close, reset, or drop");
                    return false;
                }
            }
            if (json.contains("client_deny_action") && !overrides.client_deny_action) {
                auto action = yume::server::host::parse_deny_action(json["client_deny_action"].get<std::string>());
                if (action.has_value()) {
                    cfg.client_deny_action = *action;
                } else {
                    yume::util::log_error("client_deny_action must be close, reset, or drop");
                    return false;
                }
            }
            if (json.contains("exposure_check_hostname") && !overrides.exposure_check_hostname) {
                cfg.exposure_check_hostname = json["exposure_check_hostname"].get<std::string>();
            }
            if (json.contains("exposure_check") && !overrides.exposure_check_hostname) {
                cfg.exposure_check_hostname = json["exposure_check"].get<std::string>();
            }
            if (json.contains("routes")) {
                std::string route_error;
                if (!yume::server::host::HostRouteTable::parse_routes_json(json["routes"],
                                                                           &cfg.host_routes,
                                                                           &route_error)) {
                    yume::util::log_error("routes: " + route_error);
                    return false;
                }
            }
            if (json.contains("listeners")) {
                std::string listener_error;
                if (!yume::server::host::HostRouteTable::parse_listeners_json(json["listeners"],
                                                                              &cfg.extra_listeners,
                                                                              &listener_error)) {
                    yume::util::log_error("listeners: " + listener_error);
                    return false;
                }
            }
        } catch (const std::exception& ex) {
            yume::util::log_error(std::string("config load failed: ") + ex.what());
            return false;
        }
    }

    resolve_server_config_paths(cfg, context);
    return true;
}

}  // namespace yume::server_cli
