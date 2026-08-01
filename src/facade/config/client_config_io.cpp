/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/config/config_io.hpp"

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

#include <boost/asio/ip/address.hpp>
#include <nlohmann/json.hpp>

#include "core/version.hpp"
#include "core/stealth/http_profile.hpp"
#include "config/ratchet_profile_json.hpp"
#include "facade/config/detail.hpp"
#include "facade/config/keys.hpp"

namespace yume::facade::config_io {

using nlohmann::json;
using detail::read_opt;
using detail::resolve_config_path;
namespace cfg_key = keys;

namespace {

client::ClientConfig client_from_json(json const& j, std::filesystem::path const& base) {
    client::ClientConfig c;
    read_opt(j, cfg_key::server, c.server);
    read_opt(j, cfg_key::port, c.port);
    read_opt(j, cfg_key::identity, c.identity);
    read_opt(j, cfg_key::socks_bind, c.socks_bind_host);
    read_opt(j, cfg_key::socks_port, c.socks_port);
    read_opt(j, cfg_key::io_threads, c.io_threads);
    read_opt(j, cfg_key::tunnels, c.tunnel_count);
    read_opt(j, cfg_key::obfuscation, c.obfuscation);
    read_opt(j, cfg_key::obfs_secret, c.obfs_secret);
    read_opt(j, cfg_key::obfs_secret_file, c.obfs_secret_file);
    read_opt(j, cfg_key::inner_psk_file, c.inner_psk_file);
    read_opt(j, cfg_key::inner_crypto, c.inner_crypto);
    read_opt(j, cfg_key::inner_heavy, c.inner_heavy);
    read_opt(j, cfg_key::inner_hop, c.inner_hop);
    read_opt(j, cfg_key::hop_interval_ms, c.hop_interval_ms);
    read_opt(j, cfg_key::rekey_window, c.rekey_window);
    c.security_profile = yume::config::ParseSecurityProfile(
        j, c.security_profile);
    read_opt(j, cfg_key::allow_udp, c.allow_udp);
    read_opt(j, cfg_key::allow_local_ip, c.allow_local_ip);
    read_opt(j, cfg_key::allow_exec, c.allow_exec);
    read_opt(j, cfg_key::pq_public_key, c.pq_public_key);
    read_opt(j, cfg_key::allow_embedded_master, c.allow_embedded_master);
    read_opt(j, cfg_key::anonym_pubkey, c.anonym_pubkey);
    read_opt(j, cfg_key::anonym_ca_cert, c.anonym_ca_cert);
    read_opt(j, cfg_key::anonym_ca_material_id, c.anonym_ca_material_id);
    read_opt(j, cfg_key::anonym_pubkey_material_id, c.anonym_pubkey_material_id);
    read_opt(j, cfg_key::tls_ca_material_id, c.tls_ca_material_id);
    read_opt(j, cfg_key::auth_key_material_id, c.auth_key_material_id);
    read_opt(j, cfg_key::tls_ca_cert, c.tls_ca_cert);
    read_opt(j, cfg_key::tls_server_name, c.tls_server_name);
    read_opt(j, cfg_key::tls_pin_sha256, c.tls_pin_sha256);
    read_opt(j, cfg_key::transport_profile, c.transport_profile);
    read_opt(j, cfg_key::tls_backend, c.tls_backend);
    read_opt(j, cfg_key::tls_helper_path, c.tls_helper_path);
    read_opt(j, cfg_key::require_anonym, c.require_anonym);
    read_opt(j, cfg_key::accept_monitoring, c.accept_monitoring);
    read_opt(j, cfg_key::service_streams_only, c.service_streams_only);
    read_opt(j, cfg_key::boring, c.boring);
    read_opt(j, cfg_key::instance_name, c.instance_name);
    read_opt(j, cfg_key::preferred_name, c.preferred_name);
    read_opt(j, cfg_key::preferred_id, c.preferred_id);
    read_opt(j, cfg_key::relay_mode, c.relay_mode);
    read_opt(j, cfg_key::allow_inbound_admin, c.allow_inbound_admin);
    read_opt(j, cfg_key::allow_outbound_admin, c.allow_outbound_admin);
    read_opt(j, cfg_key::allow_chat, c.allow_chat);
    read_opt(j, cfg_key::allow_file, c.allow_file);
    read_opt(j, cfg_key::allow_bytes, c.allow_bytes);
    read_opt(j, cfg_key::history_enabled, c.history_enabled);
    read_opt(j, cfg_key::history_dir, c.history_dir);
    read_opt(j, cfg_key::relay_key_file, c.relay_key_file);
    read_opt(j, cfg_key::auto_attach_local, c.auto_attach_local);
    read_opt(j, cfg_key::tls_stealth_enabled, c.tls_stealth_enabled);
    read_opt(j, cfg_key::tls_stealth_profile, c.tls_stealth_profile);
    if (j.contains(cfg_key::tls_stealth_rotate) ||
        j.contains(cfg_key::tls_stealth_rotation_interval)) {
        throw std::runtime_error(
            "TLS profile rotation keys were removed in YUME 2.0-dev6");
    }
    read_opt(j, cfg_key::tls_fingerprint_log, c.tls_fingerprint_log);
    read_opt(j, cfg_key::tls_fingerprint_log_path, c.tls_fingerprint_log_path);
    read_opt(j, cfg_key::tls_fingerprint_verify, c.tls_fingerprint_verify);
    read_opt(j, cfg_key::tls_fingerprint_test_endpoint, c.tls_fingerprint_test_endpoint);
    read_opt(j, cfg_key::self_dpi, c.self_dpi);
    read_opt(j, cfg_key::outbound_proxy, c.outbound_proxy_url);

    resolve_config_path(c.identity, base);
    resolve_config_path(c.obfs_secret_file, base);
    resolve_config_path(c.inner_psk_file, base);
    resolve_config_path(c.pq_public_key, base);
    resolve_config_path(c.anonym_pubkey, base);
    resolve_config_path(c.anonym_ca_cert, base);
    resolve_config_path(c.tls_ca_cert, base);
    resolve_config_path(c.tls_helper_path, base);
    resolve_config_path(c.history_dir, base);
    resolve_config_path(c.relay_key_file, base);
    resolve_config_path(c.tls_fingerprint_log_path, base);
    return c;
}

}  // namespace

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

    try {
        return client_from_json(j, path.parent_path());
    } catch (std::exception const& e) {
        if (err) *err = e.what();
        return std::nullopt;
    }
}

std::optional<client::ClientConfig> parse_client_json(
    std::string_view text,
    std::filesystem::path const& base_dir,
    std::string* err) {
    json j;
    try {
        j = json::parse(text.begin(), text.end());
    } catch (std::exception const& e) {
        if (err) *err = std::string{"invalid JSON: "} + e.what();
        return std::nullopt;
    }
    try {
        return client_from_json(j, base_dir);
    } catch (std::exception const& e) {
        if (err) *err = e.what();
        return std::nullopt;
    }
}

bool save_client(client::ClientConfig const& c,
                 std::filesystem::path const& path,
                 std::string* err) {
    json j = {
        {cfg_key::server, c.server},
        {cfg_key::port, c.port},
        {cfg_key::identity, c.identity},
        {cfg_key::socks_bind, c.socks_bind_host},
        {cfg_key::socks_port, c.socks_port},
        {cfg_key::io_threads, c.io_threads},
        {cfg_key::tunnels, c.tunnel_count},
        {cfg_key::obfuscation, c.obfuscation},
        {cfg_key::obfs_secret, c.obfs_secret},
        {cfg_key::obfs_secret_file, c.obfs_secret_file},
        {cfg_key::inner_psk_file, c.inner_psk_file},
        {cfg_key::inner_crypto, c.inner_crypto},
        {cfg_key::inner_heavy, c.inner_heavy},
        {cfg_key::inner_hop, c.inner_hop},
        {cfg_key::hop_interval_ms, c.hop_interval_ms},
        {cfg_key::rekey_window, c.rekey_window},
        {cfg_key::allow_udp, c.allow_udp},
        {cfg_key::allow_local_ip, c.allow_local_ip},
        {cfg_key::allow_exec, c.allow_exec},
        {cfg_key::pq_public_key, c.pq_public_key},
        {cfg_key::allow_embedded_master, c.allow_embedded_master},
        {cfg_key::anonym_pubkey, c.anonym_pubkey},
        {cfg_key::anonym_ca_cert, c.anonym_ca_cert},
        {cfg_key::anonym_ca_material_id, c.anonym_ca_material_id},
        {cfg_key::anonym_pubkey_material_id, c.anonym_pubkey_material_id},
        {cfg_key::tls_ca_material_id, c.tls_ca_material_id},
        {cfg_key::auth_key_material_id, c.auth_key_material_id},
        {cfg_key::tls_ca_cert, c.tls_ca_cert},
        {cfg_key::tls_server_name, c.tls_server_name},
        {cfg_key::tls_pin_sha256, c.tls_pin_sha256},
        {cfg_key::transport_profile, c.transport_profile},
        {cfg_key::tls_backend, c.tls_backend},
        {cfg_key::tls_helper_path, c.tls_helper_path},
        {cfg_key::require_anonym, c.require_anonym},
        {cfg_key::accept_monitoring, c.accept_monitoring},
        {cfg_key::service_streams_only, c.service_streams_only},
        {cfg_key::boring, c.boring},
        {cfg_key::instance_name, c.instance_name},
        {cfg_key::preferred_name, c.preferred_name},
        {cfg_key::preferred_id, c.preferred_id},
        {cfg_key::relay_mode, c.relay_mode},
        {cfg_key::allow_inbound_admin, c.allow_inbound_admin},
        {cfg_key::allow_outbound_admin, c.allow_outbound_admin},
        {cfg_key::allow_chat, c.allow_chat},
        {cfg_key::allow_file, c.allow_file},
        {cfg_key::allow_bytes, c.allow_bytes},
        {cfg_key::history_enabled, c.history_enabled},
        {cfg_key::history_dir, c.history_dir},
        {cfg_key::relay_key_file, c.relay_key_file},
        {cfg_key::auto_attach_local, c.auto_attach_local},
        {cfg_key::tls_stealth_enabled, c.tls_stealth_enabled},
        {cfg_key::tls_stealth_profile, c.tls_stealth_profile},
        {cfg_key::tls_fingerprint_log, c.tls_fingerprint_log},
        {cfg_key::tls_fingerprint_log_path, c.tls_fingerprint_log_path},
        {cfg_key::tls_fingerprint_verify, c.tls_fingerprint_verify},
        {cfg_key::tls_fingerprint_test_endpoint, c.tls_fingerprint_test_endpoint},
        {cfg_key::self_dpi, c.self_dpi},
        {cfg_key::outbound_proxy, c.outbound_proxy_url},
    };
    yume::config::WriteSecurityProfile(j, c.security_profile);

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
    if (c.tunnel_count < 1 || c.tunnel_count > 16) {
        r.errors.emplace_back("tunnels: must be 1..16");
    }
    if (c.rekey_window < yume::ratchet::kMinRekeyWindow ||
        c.rekey_window > yume::ratchet::kMaxRekeyWindow) {
        r.errors.emplace_back("rekey_window: must be in 1..64");
    }
    if (!yume::ratchet::ResolveSecurityProfile(
             c.security_profile).has_value()) {
        r.errors.emplace_back(
            "security_profile: ultimate requires valid custom limits");
    }
    if (!c.socks_bind_host.empty()) {
        boost::system::error_code ec;
        boost::asio::ip::make_address(c.socks_bind_host, ec);
        if (ec) {
            r.errors.emplace_back("socks_bind: address must be an IP literal");
        }
    }
    if (!c.tls_stealth_enabled ||
        !yume::http_profile::transport_client_supported(c.tls_stealth_profile)) {
        r.errors.emplace_back(
            "tls_stealth_profile: no complete fixture exists in this build");
    }
    if (c.transport_profile != yume::kTransportProfile) {
        r.errors.emplace_back(
            "transport_profile: must be " +
            std::string(yume::kTransportProfile));
    }
    if (c.tls_backend != "chrome151" &&
        c.tls_backend != "openssl-diagnostic") {
        r.errors.emplace_back(
            "tls_backend: must be chrome151 or openssl-diagnostic");
    }
    if (c.tls_backend == "chrome151" && c.tunnel_count != 1) {
        r.errors.emplace_back(
            "tunnels: chrome151 currently supports exactly one outer tunnel");
    }
    if (!c.inner_crypto) {
        r.errors.emplace_back(
            "inner_crypto: mandatory in " + std::string(yume::kVersion));
    }
    if (c.require_anonym && c.accept_monitoring) {
        r.errors.emplace_back(
            "accept_monitoring: cannot be enabled when operator identity proof is required");
    }
    return r;
}

}  // namespace yume::facade::config_io
