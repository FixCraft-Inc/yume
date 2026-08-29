/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/config/config_io.hpp"

#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#include <nlohmann/json.hpp>

#include <boost/asio/ip/address.hpp>

#include "facade/config/detail.hpp"
#include "facade/config/keys.hpp"
#include "config/ratchet_profile_json.hpp"
#include "core/app_codec/builtin/monero_rpc.hpp"
#include "core/app_codec/codec.hpp"
#include "core/runtime/atomic_file.hpp"
#include "core/version.hpp"
#include "server/config/json_values.hpp"
#include "server/host/host_routes.hpp"
#include "server/host/host_types.hpp"

namespace yume::facade::config_io {

using nlohmann::json;
using detail::read_opt;
using detail::resolve_config_path;
using detail::resolve_filter_spec_path;
namespace cfg_key = keys;

namespace {

server::ServerConfig server_from_json(json const& j, std::filesystem::path const& base) {
    if (!j.is_object()) {
        throw std::runtime_error("config root must be a JSON object");
    }
    server::ServerConfig s;
    read_opt(j, cfg_key::transport_profile, s.transport_profile);
    read_opt(j, cfg_key::listen_address, s.listen_address);
    read_opt(j, cfg_key::listen_port, s.listen_port);
    read_opt(j, cfg_key::tls_cert, s.tls_cert);
    read_opt(j, cfg_key::tls_key, s.tls_key);
    read_opt(j, cfg_key::auth_keys, s.auth_keys);
    read_opt(j, cfg_key::auth_keys_meta, s.auth_keys_meta);
    read_opt(j, cfg_key::admin_keys, s.admin_keys);
    read_opt(j, cfg_key::threads, s.threads);
    read_opt(j, cfg_key::tls_handshake_timeout_ms, s.tls_handshake_timeout_ms);
    read_opt(j, cfg_key::max_sessions, s.max_sessions);
    read_opt(j, cfg_key::accept_rate_limit, s.accept_rate_limit);
    read_opt(j, cfg_key::obfuscation, s.obfuscation);
    read_opt(j, cfg_key::obfs_secret, s.obfs_secret);
    read_opt(j, cfg_key::obfs_secret_file, s.obfs_secret_file);
    read_opt(j, cfg_key::inner_psk_file, s.inner_psk_file);
    read_opt(j, cfg_key::inner_crypto, s.inner_crypto);
    read_opt(j, cfg_key::inner_heavy, s.inner_heavy);
    read_opt(j, cfg_key::inner_dual, s.inner_dual);
    read_opt(j, cfg_key::inner_required, s.inner_required);
    read_opt(j, cfg_key::rekey_window, s.rekey_window);
    s.security_profile = yume::config::ParseSecurityProfile(
        j, s.security_profile);
    read_opt(j, cfg_key::reverse_port_min, s.reverse_port_min);
    read_opt(j, cfg_key::reverse_port_max, s.reverse_port_max);
    read_opt(j, cfg_key::dns_server, s.dns_server);
    read_opt(j, cfg_key::pq_private_key, s.pq_private_key);
    read_opt(j, cfg_key::pq_auto_generate, s.pq_auto_generate);
    read_opt(j, cfg_key::allow_embedded_master, s.allow_embedded_master);
    read_opt(j, cfg_key::allow_exec, s.allow_exec);
    read_opt(j, cfg_key::allow_local_ip, s.allow_local_ip);
    read_opt(j, cfg_key::control_full, s.control_full);
    read_opt(j, cfg_key::allow_services, s.allowed_services);
    read_opt(j, cfg_key::preauth_services, s.preauth_services);
    if (j.contains(cfg_key::allow_monero_rpc_codec)) {
        s.allow_monero_rpc_codec = j[cfg_key::allow_monero_rpc_codec].get<bool>();
        if (s.allow_monero_rpc_codec) {
            yume::app_codec::add_codec_unique(&s.allowed_codecs,
                                              yume::app_codec::builtin::kMoneroRpcCodecId);
        }
    } else if (j.contains(cfg_key::allow_monero_rpc)) {
        s.allow_monero_rpc_codec = j[cfg_key::allow_monero_rpc].get<bool>();
        if (s.allow_monero_rpc_codec) {
            yume::app_codec::add_codec_unique(&s.allowed_codecs,
                                              yume::app_codec::builtin::kMoneroRpcCodecId);
        }
    }
    auto const read_codec_allow = [&](char const* key) {
        auto it = j.find(key);
        if (it == j.end()) return;
        if (!it->is_array()) {
            throw std::runtime_error(std::string(key) + " must be an array");
        }
        for (auto const& item : *it) {
            if (!item.is_string()) {
                throw std::runtime_error(
                    std::string(key) + " entries must be strings");
            }
            auto const codec = yume::app_codec::canonical_codec_id(item.get<std::string>());
            if (!yume::app_codec::is_supported_codec(codec)) {
                throw std::runtime_error(
                    std::string("unsupported application codec in ") +
                    key + ": " + codec);
            }
            yume::app_codec::add_codec_unique(&s.allowed_codecs, codec);
            if (codec == std::string(yume::app_codec::builtin::kMoneroRpcCodecId)) {
                s.allow_monero_rpc_codec = true;
            }
        }
    };
    read_codec_allow(cfg_key::codec_allow);
    read_codec_allow(cfg_key::allow_codecs);
    if (j.contains(cfg_key::monero_rpc_backend)) {
        std::string parse_error;
        auto ep = yume::app_codec::parse_endpoint_spec(
            j[cfg_key::monero_rpc_backend].get<std::string>(),
            yume::app_codec::builtin::kMoneroRpcDefaultHost,
            yume::app_codec::builtin::kMoneroRpcDefaultPort,
            &parse_error);
        if (ep.has_value()) {
            s.monero_rpc_backend_host = ep->host;
            s.monero_rpc_backend_port = ep->port;
        } else {
            throw std::runtime_error("monero_rpc_backend: " + parse_error);
        }
    }
    read_opt(j, cfg_key::monero_rpc_backend_host, s.monero_rpc_backend_host);
    read_opt(j, cfg_key::monero_rpc_backend_port, s.monero_rpc_backend_port);
    read_opt(j, cfg_key::real_http, s.real_http);
    read_opt(j, cfg_key::robots_deny, s.robots_deny);
    read_opt(j, cfg_key::real_index_path, s.real_index_path);
    read_opt(j, cfg_key::real_root, s.real_root);
    read_opt(j, cfg_key::real_backend, s.real_backend);
    read_opt(j, cfg_key::real_secret, s.real_secret);
    read_opt(j, cfg_key::real_secret_file, s.real_secret_file);
    read_opt(j, cfg_key::anonym, s.anonym);
    read_opt(j, cfg_key::anonym_proof_mode, s.anonym_proof_mode);
    read_opt(j, cfg_key::anonym_api, s.anonym_api);
    read_opt(j, cfg_key::anonym_token, s.anonym_token);
    read_opt(j, cfg_key::anonym_ca_key, s.anonym_ca_key);
    read_opt(j, cfg_key::anonym_ca_cert, s.anonym_ca_cert);
    read_opt(j, cfg_key::anonym_sub_key, s.anonym_sub_key);
    read_opt(j, cfg_key::anonym_sub_cert, s.anonym_sub_cert);
    read_opt(j, cfg_key::server_name, s.server_name);
    read_opt(j, cfg_key::server_id, s.server_id);
    read_opt(j, cfg_key::outbound_proxy, s.outbound_proxy_url);
    read_opt(j, cfg_key::relay_enable, s.relay_enable);
    read_opt(j, cfg_key::directory_enable, s.directory_enable);
    read_opt(j, cfg_key::ipc_enable, s.ipc_enable);
    read_opt(j, cfg_key::ipc_path, s.ipc_path);
    read_opt(j, cfg_key::federation_enable, s.federation_enable);
    read_opt(j, cfg_key::cluster_bootstrap, s.cluster_bootstrap);
    if (auto it = j.find(cfg_key::federation_peers); it != j.end()) {
        if (!it->is_array()) {
            throw std::runtime_error("federation_peers must be an array");
        }
        for (const auto& peer : *it) {
            if (!peer.is_object()) {
                throw std::runtime_error(
                    "federation_peers entries must be objects");
            }
            json resolved = peer;
            for (const char* key : {"psk_file", "carrier_secret_file"}) {
                const auto value = resolved.find(key);
                if (value == resolved.end()) continue;
                if (!value->is_string()) {
                    throw std::runtime_error(
                        std::string("federation_peers[].") + key +
                        " must be a string");
                }
                std::string path = value->get<std::string>();
                resolve_config_path(path, base);
                *value = std::move(path);
            }
            s.federation_peers.push_back(resolved.dump());
        }
    }
    read_opt(j, cfg_key::federation_identity, s.federation_identity);
    read_opt(j, cfg_key::federation_operator_ca, s.federation_operator_ca);
    read_opt(j, cfg_key::operator_keys, s.operator_keys);
    read_opt(j, cfg_key::operator_keys_meta, s.operator_keys_meta);
    read_opt(j, cfg_key::egress_mbps, s.egress_mbps);
    read_opt(j, cfg_key::bulk_key_max_sessions, s.bulk_key_max_sessions);
    read_opt(j, cfg_key::client_filter_mode, s.client_filter_mode);
    read_opt(j, cfg_key::egress_filter_mode, s.egress_filter_mode);
    read_opt(j, cfg_key::filter_geolite, s.filter_geolite);
    read_opt(j, cfg_key::filter_memory_mib, s.filter_memory_mib);
    read_opt(j, cfg_key::filter_lists, s.filter_lists);
    read_opt(j, cfg_key::packet_egress, s.packet_egress);
    read_opt(j, cfg_key::packet_tun_name, s.packet_tun_name);
    read_opt(j, cfg_key::packet_cidr, s.packet_cidr);
    read_opt(j, cfg_key::packet_mtu, s.packet_mtu);
    read_opt(j, cfg_key::boring, s.boring);
    if (j.contains(cfg_key::host_mode)) {
        auto mode = yume::server::host::parse_host_mode(j[cfg_key::host_mode].get<std::string>());
        if (mode.has_value()) {
            s.host_mode = *mode;
            if (*mode == yume::server::host::HostMode::Private && !j.contains(cfg_key::accept_yume_clients)) {
                s.accept_yume_clients = false;
            }
        } else {
            throw std::runtime_error("host_mode must be off, private, or relay");
        }
    }
    read_opt(j, cfg_key::accept_yume_clients, s.accept_yume_clients);
    if (j.contains(cfg_key::deny_default)) {
        auto action = yume::server::host::parse_deny_action(j[cfg_key::deny_default].get<std::string>());
        if (action.has_value()) {
            s.client_deny_action = *action;
        } else {
            throw std::runtime_error("deny_default must be close, reset, or drop");
        }
    }
    if (j.contains(cfg_key::client_deny_action)) {
        auto action = yume::server::host::parse_deny_action(j[cfg_key::client_deny_action].get<std::string>());
        if (action.has_value()) {
            s.client_deny_action = *action;
        } else {
            throw std::runtime_error("client_deny_action must be close, reset, or drop");
        }
    }
    read_opt(j, cfg_key::exposure_check_hostname, s.exposure_check_hostname);
    if (j.contains(cfg_key::exposure_check) && s.exposure_check_hostname.empty()) {
        s.exposure_check_hostname = j[cfg_key::exposure_check].get<std::string>();
    }
    if (j.contains(cfg_key::routes)) {
        std::string route_error;
        if (!yume::server::host::HostRouteTable::parse_routes_json(j[cfg_key::routes],
                                                                   &s.host_routes,
                                                                   &route_error)) {
            throw std::runtime_error("routes: " + route_error);
        }
    }
    if (j.contains(cfg_key::listeners)) {
        std::string listener_error;
        if (!yume::server::host::HostRouteTable::parse_listeners_json(j[cfg_key::listeners],
                                                                      &s.extra_listeners,
                                                                      &listener_error)) {
            throw std::runtime_error("listeners: " + listener_error);
        }
    }

    resolve_config_path(s.tls_cert, base);
    resolve_config_path(s.tls_key, base);
    resolve_config_path(s.auth_keys, base);
    resolve_config_path(s.admin_keys, base);
    resolve_config_path(s.pq_private_key, base);
    resolve_config_path(s.real_index_path, base);
    resolve_config_path(s.real_root, base);
    resolve_config_path(s.obfs_secret_file, base);
    resolve_config_path(s.inner_psk_file, base);
    resolve_config_path(s.real_secret_file, base);
    resolve_config_path(s.anonym_ca_key, base);
    resolve_config_path(s.anonym_ca_cert, base);
    resolve_config_path(s.anonym_sub_key, base);
    resolve_config_path(s.anonym_sub_cert, base);
    resolve_config_path(s.ipc_path, base);
    resolve_config_path(s.federation_identity, base);
    resolve_config_path(s.federation_operator_ca, base);
    resolve_config_path(s.operator_keys, base);
    resolve_config_path(s.operator_keys_meta, base);
    resolve_config_path(s.filter_geolite, base);
    for (auto& spec : s.filter_lists) {
        resolve_filter_spec_path(spec, base);
    }
    return s;
}

}  // namespace

std::optional<server::ServerConfig> load_server(
    std::filesystem::path const& path,
    std::string* err,
    ConfigLoadError* load_error) {
    if (err) err->clear();
    if (load_error) *load_error = ConfigLoadError::None;
    errno = 0;
    std::ifstream in(path);
    if (!in) {
        const int open_errno = errno;
        if (err) *err = "cannot open " + path.string();
        if (load_error) {
            *load_error = ConfigOpenErrorFromErrno(open_errno);
        }
        return std::nullopt;
    }
    json j;
    try {
        in >> j;
    } catch (std::exception const& e) {
        if (err) *err = std::string{"invalid JSON: "} + e.what();
        if (load_error) *load_error = ConfigLoadError::Parse;
        return std::nullopt;
    }

    try {
        return server_from_json(j, path.parent_path());
    } catch (std::exception const& e) {
        if (err) *err = e.what();
        if (load_error) *load_error = ConfigLoadError::Parse;
        return std::nullopt;
    }
}

std::optional<server::ServerConfig> parse_server_json(
    std::string_view text,
    std::filesystem::path const& base_dir,
    std::string* err) {
    if (err) err->clear();
    json j;
    try {
        j = json::parse(text.begin(), text.end());
    } catch (std::exception const& e) {
        if (err) *err = std::string{"invalid JSON: "} + e.what();
        return std::nullopt;
    }
    try {
        return server_from_json(j, base_dir);
    } catch (std::exception const& e) {
        if (err) *err = e.what();
        return std::nullopt;
    }
}

bool save_server(server::ServerConfig const& s,
                 std::filesystem::path const& path,
                 std::string* err) {
    if (err) err->clear();
    json federation_peers = json::array();
    try {
        for (const auto& encoded : s.federation_peers) {
            auto peer = json::parse(encoded);
            if (!peer.is_object()) {
                throw std::runtime_error(
                    "federation_peers entries must encode objects");
            }
            federation_peers.push_back(std::move(peer));
        }
    } catch (const std::exception& ex) {
        if (err) {
            *err = std::string("cannot serialize federation_peers: ") +
                   ex.what();
        }
        return false;
    }
    json j = {
        {cfg_key::listen_address, s.listen_address},
        {cfg_key::transport_profile, s.transport_profile},
        {cfg_key::listen_port, s.listen_port},
        {cfg_key::tls_cert, s.tls_cert},
        {cfg_key::tls_key, s.tls_key},
        {cfg_key::auth_keys, s.auth_keys},
        {cfg_key::auth_keys_meta, s.auth_keys_meta},
        {cfg_key::admin_keys, s.admin_keys},
        {cfg_key::threads, s.threads},
        {cfg_key::tls_handshake_timeout_ms, s.tls_handshake_timeout_ms},
        {cfg_key::max_sessions, s.max_sessions},
        {cfg_key::accept_rate_limit, s.accept_rate_limit},
        {cfg_key::obfuscation, s.obfuscation},
        {cfg_key::obfs_secret_file, s.obfs_secret_file},
        {cfg_key::inner_psk_file, s.inner_psk_file},
        {cfg_key::inner_crypto, s.inner_crypto},
        {cfg_key::inner_heavy, s.inner_heavy},
        {cfg_key::inner_dual, s.inner_dual},
        {cfg_key::inner_required, s.inner_required},
        {cfg_key::rekey_window, s.rekey_window},
        {cfg_key::reverse_port_min, s.reverse_port_min},
        {cfg_key::reverse_port_max, s.reverse_port_max},
        {cfg_key::dns_server, s.dns_server},
        {cfg_key::pq_private_key, s.pq_private_key},
        {cfg_key::pq_auto_generate, s.pq_auto_generate},
        {cfg_key::allow_embedded_master, s.allow_embedded_master},
        {cfg_key::allow_exec, s.allow_exec},
        {cfg_key::allow_local_ip, s.allow_local_ip},
        {cfg_key::control_full, s.control_full},
        {cfg_key::allow_codecs, s.allowed_codecs},
        {cfg_key::allow_services, s.allowed_services},
        {cfg_key::preauth_services, s.preauth_services},
        {cfg_key::allow_monero_rpc_codec, s.allow_monero_rpc_codec},
        {cfg_key::monero_rpc_backend_host, s.monero_rpc_backend_host},
        {cfg_key::monero_rpc_backend_port, s.monero_rpc_backend_port},
        {cfg_key::real_http, s.real_http},
        {cfg_key::robots_deny, s.robots_deny},
        {cfg_key::real_index_path, s.real_index_path},
        {cfg_key::real_root, s.real_root},
        {cfg_key::real_backend, s.real_backend},
        {cfg_key::real_secret_file, s.real_secret_file},
        {cfg_key::anonym, s.anonym},
        {cfg_key::anonym_proof_mode, s.anonym_proof_mode},
        {cfg_key::anonym_api, s.anonym_api},
        {cfg_key::anonym_token, s.anonym_token},
        {cfg_key::anonym_ca_key, s.anonym_ca_key},
        {cfg_key::anonym_ca_cert, s.anonym_ca_cert},
        {cfg_key::anonym_sub_key, s.anonym_sub_key},
        {cfg_key::anonym_sub_cert, s.anonym_sub_cert},
        {cfg_key::server_name, s.server_name},
        {cfg_key::server_id, s.server_id},
        {cfg_key::outbound_proxy, s.outbound_proxy_url},
        {cfg_key::relay_enable, s.relay_enable},
        {cfg_key::directory_enable, s.directory_enable},
        {cfg_key::ipc_enable, s.ipc_enable},
        {cfg_key::ipc_path, s.ipc_path},
        {cfg_key::federation_enable, s.federation_enable},
        {cfg_key::cluster_bootstrap, s.cluster_bootstrap},
        {cfg_key::federation_peers, std::move(federation_peers)},
        {cfg_key::federation_identity, s.federation_identity},
        {cfg_key::federation_operator_ca, s.federation_operator_ca},
        {cfg_key::operator_keys, s.operator_keys},
        {cfg_key::operator_keys_meta, s.operator_keys_meta},
        {cfg_key::egress_mbps, s.egress_mbps},
        {cfg_key::bulk_key_max_sessions, s.bulk_key_max_sessions},
        {cfg_key::client_filter_mode, s.client_filter_mode},
        {cfg_key::egress_filter_mode, s.egress_filter_mode},
        {cfg_key::filter_lists, s.filter_lists},
        {cfg_key::filter_geolite, s.filter_geolite},
        {cfg_key::filter_memory_mib, s.filter_memory_mib},
        {cfg_key::packet_egress, s.packet_egress},
        {cfg_key::packet_tun_name, s.packet_tun_name},
        {cfg_key::packet_cidr, s.packet_cidr},
        {cfg_key::packet_mtu, s.packet_mtu},
        {cfg_key::boring, s.boring},
        {cfg_key::host_mode, yume::server::host::to_string(s.host_mode)},
        {cfg_key::accept_yume_clients, s.accept_yume_clients},
        {cfg_key::client_deny_action, yume::server::host::to_string(s.client_deny_action)},
        {cfg_key::exposure_check_hostname, s.exposure_check_hostname},
    };
    yume::config::WriteSecurityProfile(j, s.security_profile);
    json routes = json::array();
    for (const auto& route : s.host_routes) {
        routes.push_back({
            {"sni", route.sni},
            {"host", route.host},
            {"path_prefix", route.path_prefix},
            {"backend", route.backend},
        });
    }
    if (!routes.empty()) {
        j[cfg_key::routes] = routes;
    }
    json listeners = json::array();
    for (const auto& listener : s.extra_listeners) {
        std::string bind = listener.bind_address;
        if (!bind.empty()) {
            if (bind.find(':') != std::string::npos && bind.front() != '[') {
                bind = "[" + bind + "]";
            }
            bind += ":";
        }
        bind += std::to_string(listener.bind_port);
        listeners.push_back({
            {"bind", bind},
            {"mode", yume::server::host::to_string(listener.mode)},
            {"backend", listener.backend},
        });
    }
    if (!listeners.empty()) {
        j[cfg_key::listeners] = listeners;
    }

    return yume::runtime::AtomicWriteFile(
        path, j.dump(2), err,
        yume::runtime::ParentDirectoryPolicy::Create);
}

ValidationReport validate(server::ServerConfig const& s) {
    ValidationReport r;
    if (s.transport_profile != yume::kTransportProfile) {
        r.errors.emplace_back(
            "transport_profile: must be " +
            std::string(yume::kTransportProfile));
    }
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
    // prepare_v2_security_config() refuses to start without these three, so a
    // report that omits them lets a consumer enable "Start" on a config that
    // cannot possibly run. Mirror the runtime's admission here.
    if (s.obfs_secret_file.empty()) {
        r.errors.emplace_back(
            "obfs_secret_file: required; YUME 2.0 does not accept an inline "
            "obfs_secret");
    }
    if (s.inner_psk_file.empty()) {
        r.errors.emplace_back("inner_psk_file: required");
    }
    if (!s.obfs_secret.empty()) {
        r.errors.emplace_back(
            "obfs_secret: inline secrets are refused; use obfs_secret_file");
    }
    if (s.real_backend.empty()) {
        r.errors.emplace_back(
            "real_backend: required; expected "
            "loopback://<loopback-ip-literal>:<port>");
    } else if (!yume::server::host::parse_loopback_backend(s.real_backend)
                    .has_value()) {
        r.errors.emplace_back(
            "real_backend: must be loopback://<loopback-ip-literal>:<port>");
    }
    if (!s.obfuscation || !s.inner_crypto) {
        r.errors.emplace_back(
            "obfuscation/inner_crypto: mandatory in " +
            std::string(yume::kVersion) + "; both must be enabled");
    }
    if (s.obfs_pad_multiple != 0 || s.obfs_jitter_ms != 0) {
        r.errors.emplace_back(
            "obfs_pad_multiple/obfs_jitter_ms: the Chrome profile capture "
            "contains neither; both must be 0");
    }
    if (s.reverse_port_min > s.reverse_port_max) {
        r.errors.emplace_back(
            "reverse_port_min must be <= reverse_port_max");
    }
    if (s.threads < 0 || s.threads > 256) {
        r.errors.emplace_back("threads: must be in 0..256 (0 = auto)");
    }
    if (s.bulk_key_max_sessions == 0 || s.bulk_key_max_sessions > 65535) {
        r.errors.emplace_back("bulk_key_max_sessions: must be in 1..65535");
    }
    if (s.rekey_window < yume::ratchet::kMinRekeyWindow ||
        s.rekey_window > yume::ratchet::kMaxRekeyWindow) {
        r.errors.emplace_back("rekey_window: must be in 1..64");
    }
    if (!yume::ratchet::ResolveSecurityProfile(
             s.security_profile).has_value()) {
        r.errors.emplace_back(
            "security_profile: ultimate requires valid custom limits");
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
        if (s.federation_identity.empty()) {
            r.errors.emplace_back("federation_identity: required when federation_enable=true");
        }
        if (s.federation_operator_ca.empty()) {
            r.errors.emplace_back("federation_operator_ca: required when federation_enable=true");
        }
        if (s.federation_peers.empty() && !s.cluster_bootstrap) {
            r.errors.emplace_back(
                "federation_peers: at least one peer is required when "
                "federation_enable=true unless cluster_bootstrap=true");
        }
    }
    if (s.cluster_bootstrap && !s.federation_enable) {
        r.errors.emplace_back(
            "cluster_bootstrap: requires federation_enable=true");
    }
    if (s.host_mode == yume::server::host::HostMode::Off &&
        (!s.host_routes.empty() || !s.extra_listeners.empty())) {
        r.errors.emplace_back("host_mode: routes/listeners require private or relay");
    }
    if (s.host_mode == yume::server::host::HostMode::Private && s.accept_yume_clients) {
        r.errors.emplace_back("host_mode private requires accept_yume_clients=false");
    }
    if (s.host_mode == yume::server::host::HostMode::Relay && !s.accept_yume_clients) {
        r.errors.emplace_back("host_mode relay requires accept_yume_clients=true");
    }
    for (const auto& route : s.host_routes) {
        std::string error;
        if (!yume::server::host::backend_is_loopback_only(route.backend, &error)) {
            r.errors.emplace_back("routes.backend: " + error);
            break;
        }
    }
    for (const auto& listener : s.extra_listeners) {
        if (listener.bind_port < 1 || listener.bind_port > 65535) {
            r.errors.emplace_back("listeners.bind: port must be 1..65535");
            break;
        }
        if (!listener.bind_address.empty()) {
            boost::system::error_code ec;
            boost::asio::ip::make_address(listener.bind_address, ec);
            if (ec) {
                r.errors.emplace_back("listeners.bind: address must be an IP literal");
                break;
            }
        }
        if (listener.backend.empty()) {
            r.errors.emplace_back("listeners.backend: required");
            break;
        }
        std::string error;
        if (!yume::server::host::backend_is_loopback_only(listener.backend, &error)) {
            r.errors.emplace_back("listeners.backend: " + error);
            break;
        }
    }
    return r;
}

}  // namespace yume::facade::config_io
