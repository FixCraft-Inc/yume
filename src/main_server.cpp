/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <utility>
#include <ctime>
#include <thread>
#include <vector>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cerrno>
#include <mutex>
#include <cctype>
#include <cstdlib>
#include <cstring>
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#elif defined(__APPLE__)
#include <sys/stat.h>
#include <unistd.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif
#include "server/srv_help.hpp"
#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

#include "core/http_profile.hpp"
#include "core/inner_crypto.hpp"
#include "core/runtime_policy.hpp"
#include "core/tls_fingerprint.hpp"
#include "core/tls_stealth.hpp"
#include "core/version.hpp"
#include "server/manager.hpp"
#include "server/auth.hpp"
#include "server/ip_filter.hpp"
#include "server/server_anonym_cli.hpp"
#include "server/server_cluster_cli.hpp"
#include "server/server_key_cli.hpp"
#include "server/local_runtime.hpp"
#include "server/server_local_cli.hpp"
#include "server/server_misc_cli.hpp"
#include "server/server_runtime_prep.hpp"
#include "util.hpp"

namespace {
constexpr const char kDefaultSecretPath[] = "./.secrets/html_secret";

using yume::server_cli::anonym_local_sign_default;
using yume::server_cli::derive_pq_public_path;
using yume::server_cli::expand_cluster_join_spec;
using yume::server_cli::fetch_anonym_proof;
using yume::server_cli::file_readable;
using yume::server_cli::cert_fingerprint_sha256;
using yume::server_cli::get_self_path;
using yume::server_cli::load_pq_public_b64;
using yume::server_cli::load_or_create_secret;
using yume::server_cli::parse_proof_ts;
using yume::server_cli::prepare_server_runtime_files;
using yume::server_cli::read_file_bytes;
using yume::server_cli::resolve_filter_list_spec_path;
using yume::server_cli::run_server_key_command;
using yume::server_cli::run_server_manager_ui;
using yume::server_cli::ServerKeyCommand;
using yume::server_cli::sha256_hex;
using yume::server_cli::sign_pq_pub_with_key;

bool parse_env_bool(const char* name, bool fallback) {
    const char* raw = std::getenv(name);
    if (!raw || !*raw) {
        return fallback;
    }
    std::string value(raw);
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (value == "1" || value == "true" || value == "yes" || value == "on") {
        return true;
    }
    if (value == "0" || value == "false" || value == "no" || value == "off") {
        return false;
    }
    return fallback;
}

#if !defined(_WIN32)
bool parse_unsigned_env(const char* name, unsigned long* out) {
    if (!out) {
        return false;
    }
    const char* raw = std::getenv(name);
    if (!raw || !*raw) {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    unsigned long value = std::strtoul(raw, &end, 10);
    if (errno != 0 || !end || *end != '\0') {
        return false;
    }
    *out = value;
    return true;
}

bool sudo_drop_target(uid_t* uid, gid_t* gid) {
    unsigned long raw_uid = 0;
    unsigned long raw_gid = 0;
    if (!parse_unsigned_env("SUDO_UID", &raw_uid) ||
        !parse_unsigned_env("SUDO_GID", &raw_gid) ||
        raw_uid == 0) {
        return false;
    }
    if (uid) {
        *uid = static_cast<uid_t>(raw_uid);
    }
    if (gid) {
        *gid = static_cast<gid_t>(raw_gid);
    }
    return true;
}

void repair_drop_target_file(const std::filesystem::path& path,
                             uid_t uid,
                             gid_t gid,
                             mode_t mode,
                             const char* label) {
    if (path.empty()) {
        return;
    }
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return;
    }
    if (::chown(path.c_str(), uid, gid) != 0) {
        yume::util::log_warn(std::string("failed to chown ") + label + " for privilege drop: " +
                             path.string() + " (" + std::strerror(errno) + ")");
    }
    if (::chmod(path.c_str(), mode) != 0) {
        yume::util::log_warn(std::string("failed to chmod ") + label + " for privilege drop: " +
                             path.string() + " (" + std::strerror(errno) + ")");
    }
}

void repair_pq_key_ownership_for_drop(const yume::server::ServerConfig& cfg, bool keep_root) {
    if (keep_root || cfg.pq_private_key.empty() || ::geteuid() != 0) {
        return;
    }

    uid_t uid = 0;
    gid_t gid = 0;
    if (!sudo_drop_target(&uid, &gid)) {
        return;
    }

    std::filesystem::path priv_path(cfg.pq_private_key);
    std::filesystem::path pub_path(derive_pq_public_path(cfg.pq_private_key));
    std::filesystem::path key_dir = priv_path.parent_path();
    if (!key_dir.empty()) {
        repair_drop_target_file(key_dir, uid, gid, 0700, "PQ key directory");
    }
    repair_drop_target_file(priv_path, uid, gid, 0600, "PQ private key");
    repair_drop_target_file(pub_path, uid, gid, 0644, "PQ public key");
}
#endif
}  // namespace

int main(int argc, char** argv) {
    yume::util::init_logging();

    yume::server::ServerConfig cfg;
    std::string cli_cwd;
    {
        std::error_code ec;
        auto cwd = std::filesystem::current_path(ec);
        if (!ec) {
            cli_cwd = cwd.string();
        }
    }
    auto resolve_cli_path = [&](const std::string& value) {
        return yume::util::resolve_path(value, cli_cwd, "");
    };
    std::string config_path = "config/yumed.json";
    bool config_specified = false;
    ServerKeyCommand key_command;
    bool inner_heavy_override = false;
    bool inner_heavy_value = true;
    bool inner_crypto_override = false;
    bool inner_dual_override = false;
    bool inner_required_override = false;
    bool inner_hop_override = false;
    bool inner_hop_value = true;
    bool hop_interval_override = false;
    bool anonym_override = false;
    bool anonym_proof_mode_override = false;
    bool pq_auto_generate_override = false;
    bool allow_embedded_master_override = false;
    // Track whether operator explicitly set the new hardening knobs so
    // the --public-node defaults don't overwrite them.
    bool tls_handshake_timeout_override = false;
    bool max_sessions_override = false;
    bool accept_rate_limit_override = false;
    bool egress_mbps_override = false;
    bool client_filter_mode_override = false;
    bool egress_filter_mode_override = false;
    bool filter_geolite_override = false;
    bool filter_memory_mib_override = false;
    bool packet_egress_override = false;
    bool packet_tun_name_override = false;
    bool packet_cidr_override = false;
    bool packet_mtu_override = false;
    bool relay_enable_override = false;
    bool directory_enable_override = false;
    bool attach_local = false;
    bool keep_root = false;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "completion" || arg == "--completion") && i + 1 < argc) {
            std::string shell = argv[++i];
            if (shell == "bash") {
                print_bash_completion();
                return 0;
            }
            yume::util::log_error("unsupported completion shell: " + shell);
            return 1;
        }
        if (arg == "--help" || arg == "-h") {
            print_help();
            return 0;
        }
        if (arg == "--version") {
            print_version();
            return 0;
        }
        if (arg == "--credits") {
            print_credits();
            return 0;
        }
        if (arg == "--config" && i + 1 < argc) {
            config_path = argv[++i];
            config_specified = true;
        } else if (arg == "--listen" && i + 1 < argc) {
            // Two forms:
            //   --listen 443           → bind 0.0.0.0:443 (legacy)
            //   --listen 1.2.3.4:443   → bind specifically to that IP
            //   --listen [::1]:443     → IPv6 with bracket syntax
            //   --listen [::]:443      → IPv6 any
            std::string raw = argv[++i];
            std::string addr_part;
            std::string port_part;
            if (!raw.empty() && raw.front() == '[') {
                // [addr]:port form
                auto rbr = raw.find(']');
                if (rbr == std::string::npos || rbr + 2 > raw.size() || raw[rbr + 1] != ':') {
                    yume::util::log_error("--listen: bracket form must be [addr]:port");
                    return 1;
                }
                addr_part = raw.substr(1, rbr - 1);
                port_part = raw.substr(rbr + 2);
            } else {
                auto colon = raw.rfind(':');
                if (colon == std::string::npos) {
                    // Port-only legacy form
                    port_part = raw;
                } else {
                    addr_part = raw.substr(0, colon);
                    port_part = raw.substr(colon + 1);
                }
            }
            try {
                cfg.listen_port = std::stoi(port_part);
            } catch (const std::exception&) {
                yume::util::log_error("--listen: cannot parse port '" + port_part + "'");
                return 1;
            }
            if (cfg.listen_port < 1 || cfg.listen_port > 65535) {
                yume::util::log_error("--listen: port out of range 1..65535: " + port_part);
                return 1;
            }
            cfg.listen_address = addr_part;
        } else if (arg == "--reverse-port-min" && i + 1 < argc) {
            cfg.reverse_port_min = std::stoi(argv[++i]);
        } else if (arg == "--reverse-port-max" && i + 1 < argc) {
            cfg.reverse_port_max = std::stoi(argv[++i]);
        } else if (arg == "--dns-server" && i + 1 < argc) {
            cfg.dns_server = argv[++i];
        } else if (arg == "--proxy" && i + 1 < argc) {
            cfg.outbound_proxy_url = argv[++i];
        } else if ((arg == "--cert" || arg == "--tls_cert") && i + 1 < argc) {
            cfg.tls_cert = resolve_cli_path(argv[++i]);
        } else if ((arg == "--key" || arg == "--tls_key") && i + 1 < argc) {
            cfg.tls_key = resolve_cli_path(argv[++i]);
        } else if (arg == "--auth-keys" && i + 1 < argc) {
            cfg.auth_keys = resolve_cli_path(argv[++i]);
        } else if (arg == "--threads" && i + 1 < argc) {
            cfg.threads = std::stoi(argv[++i]);
        } else if (arg == "--obfs") {
            cfg.obfuscation = true;
        } else if (arg == "--no-obfs") {
            cfg.obfuscation = false;
        } else if (arg == "--obfs-secret" && i + 1 < argc) {
            cfg.obfs_secret = argv[++i];
        } else if (arg == "--obfs-pad-multiple" && i + 1 < argc) {
            int parsed = std::atoi(argv[++i]);
            if (parsed < 0) parsed = 0;
            if (parsed > 256) parsed = 256;
            cfg.obfs_pad_multiple = static_cast<std::uint16_t>(parsed);
        } else if (arg == "--obfs-jitter-ms" && i + 1 < argc) {
            int parsed = std::atoi(argv[++i]);
            if (parsed < 0) parsed = 0;
            cfg.obfs_jitter_ms = static_cast<std::uint32_t>(parsed);
        } else if (arg == "--tls-handshake-timeout-ms" && i + 1 < argc) {
            int parsed = std::atoi(argv[++i]);
            if (parsed < 0) parsed = 0;
            cfg.tls_handshake_timeout_ms = static_cast<std::uint32_t>(parsed);
            tls_handshake_timeout_override = true;
        } else if (arg == "--max-sessions" && i + 1 < argc) {
            int parsed = std::atoi(argv[++i]);
            if (parsed < 0) parsed = 0;
            cfg.max_sessions = static_cast<std::uint32_t>(parsed);
            max_sessions_override = true;
        } else if (arg == "--accept-rate-limit" && i + 1 < argc) {
            int parsed = std::atoi(argv[++i]);
            if (parsed < 0) parsed = 0;
            cfg.accept_rate_limit = static_cast<std::uint32_t>(parsed);
            accept_rate_limit_override = true;
        } else if (arg == "--egress-mbps" && i + 1 < argc) {
            int parsed = std::atoi(argv[++i]);
            if (parsed < 0) parsed = 0;
            cfg.egress_mbps = static_cast<std::uint32_t>(parsed);
            egress_mbps_override = true;
        } else if (arg == "--filter-list" && i + 1 < argc) {
            cfg.filter_lists.push_back(resolve_filter_list_spec_path(argv[++i], cli_cwd, ""));
        } else if (arg == "--filter-geolite" && i + 1 < argc) {
            cfg.filter_geolite = resolve_cli_path(argv[++i]);
            filter_geolite_override = true;
        } else if (arg == "--filter-memory-mib" && i + 1 < argc) {
            int parsed = std::atoi(argv[++i]);
            if (parsed < 0) parsed = 0;
            cfg.filter_memory_mib = static_cast<std::uint32_t>(parsed);
            filter_memory_mib_override = true;
        } else if (arg == "--client-filter-mode" && i + 1 < argc) {
            cfg.client_filter_mode = argv[++i];
            client_filter_mode_override = true;
        } else if (arg == "--egress-filter-mode" && i + 1 < argc) {
            cfg.egress_filter_mode = argv[++i];
            egress_filter_mode_override = true;
        } else if (arg == "--packet-egress" && i + 1 < argc) {
            cfg.packet_egress = argv[++i];
            packet_egress_override = true;
        } else if (arg == "--packet-tun-name" && i + 1 < argc) {
            cfg.packet_tun_name = argv[++i];
            packet_tun_name_override = true;
        } else if (arg == "--packet-cidr" && i + 1 < argc) {
            cfg.packet_cidr = argv[++i];
            packet_cidr_override = true;
        } else if (arg == "--packet-mtu" && i + 1 < argc) {
            int parsed = std::atoi(argv[++i]);
            if (parsed < 0) parsed = 0;
            cfg.packet_mtu = static_cast<std::uint32_t>(parsed);
            packet_mtu_override = true;
        } else if (arg == "--bench") {
            cfg.benchmark_enable = true;
        } else if (arg == "--inner") {
            yume::util::log_warn("--inner is deprecated; use --inner-heavy or --inner-light");
            cfg.inner_crypto = true;
            inner_crypto_override = true;
            inner_heavy_override = true;
            inner_heavy_value = true;
        } else if (arg == "--no-inner") {
            cfg.inner_crypto = false;
            cfg.inner_dual = false;
            cfg.inner_required = false;
            cfg.inner_hop = false;
            inner_crypto_override = true;
            inner_dual_override = true;
            inner_required_override = true;
            inner_hop_override = true;
            inner_hop_value = false;
        } else if (arg == "--inner-heavy") {
            cfg.inner_crypto = true;
            inner_crypto_override = true;
            inner_heavy_override = true;
            inner_heavy_value = true;
        } else if (arg == "--inner-light") {
            cfg.inner_crypto = true;
            inner_crypto_override = true;
            inner_heavy_override = true;
            inner_heavy_value = false;
        } else if (arg == "--inner-dual") {
            cfg.inner_crypto = true;
            cfg.inner_dual = true;
            inner_crypto_override = true;
            inner_dual_override = true;
        } else if (arg == "--inner-required") {
            cfg.inner_crypto = true;
            cfg.inner_required = true;
            inner_crypto_override = true;
            inner_required_override = true;
        } else if (arg == "--hop") {
            cfg.inner_hop = true;
            inner_hop_override = true;
            inner_hop_value = true;
        } else if (arg == "--no-hop") {
            cfg.inner_hop = false;
            inner_hop_override = true;
            inner_hop_value = false;
        } else if (arg == "--hop-interval" && i + 1 < argc) {
            cfg.hop_interval_ms = static_cast<std::uint32_t>(std::stoul(argv[++i]));
            hop_interval_override = true;
        } else if (arg == "--pq-key" && i + 1 < argc) {
            cfg.pq_private_key = resolve_cli_path(argv[++i]);
            inner_crypto_override = true;
        } else if (arg == "--pq-auto-generate") {
            cfg.pq_auto_generate = true;
            pq_auto_generate_override = true;
        } else if (arg == "--use-embedded-master") {
            cfg.allow_embedded_master = true;
            allow_embedded_master_override = true;
        } else if (arg == "--no-embedded-master") {
            cfg.allow_embedded_master = false;
            allow_embedded_master_override = true;
        } else if (arg == "--allow-exec") {
            cfg.allow_exec = true;
        } else if (arg == "--allow-local-ip") {
            cfg.allow_local_ip = true;
        } else if (arg == "--control-full") {
            cfg.control_full = true;
        } else if (arg == "--real") {
            cfg.real_http = true;
        } else if (arg == "--robots-deny") {
            cfg.robots_deny = true;
        } else if (arg == "--real-index" && i + 1 < argc) {
            cfg.real_index_path = resolve_cli_path(argv[++i]);
        } else if (arg == "--real-secret" && i + 1 < argc) {
            cfg.real_secret = argv[++i];
        } else if (arg == "--real-secret-file" && i + 1 < argc) {
            cfg.real_secret_file = resolve_cli_path(argv[++i]);
        } else if (arg == "--anonym") {
            cfg.anonym = true;
            anonym_override = true;
        } else if (arg == "--anonym-proof-mode" && i + 1 < argc) {
            cfg.anonym_proof_mode = argv[++i];
            anonym_proof_mode_override = true;
        } else if (arg == "--anonym-api" && i + 1 < argc) {
            cfg.anonym_api = argv[++i];
        } else if (arg == "--anonym-token" && i + 1 < argc) {
            cfg.anonym_token = argv[++i];
        } else if (arg == "--anonym-ca-key" && i + 1 < argc) {
            cfg.anonym_ca_key = resolve_cli_path(argv[++i]);
        } else if (arg == "--anonym-ca-cert" && i + 1 < argc) {
            cfg.anonym_ca_cert = resolve_cli_path(argv[++i]);
        } else if (arg == "--anonym-sub-key" && i + 1 < argc) {
            cfg.anonym_sub_key = resolve_cli_path(argv[++i]);
        } else if (arg == "--anonym-sub-cert" && i + 1 < argc) {
            cfg.anonym_sub_cert = resolve_cli_path(argv[++i]);
        } else if (arg == "--server-name" && i + 1 < argc) {
            cfg.server_name = argv[++i];
        } else if (arg == "--server-id" && i + 1 < argc) {
            cfg.server_id = argv[++i];
        } else if (arg == "--relay-enable") {
            cfg.relay_enable = true;
            relay_enable_override = true;
        } else if (arg == "--relay-disable") {
            cfg.relay_enable = false;
            relay_enable_override = true;
        } else if (arg == "--directory-enable") {
            cfg.directory_enable = true;
            directory_enable_override = true;
        } else if (arg == "--directory-disable") {
            cfg.directory_enable = false;
            directory_enable_override = true;
        } else if (arg == "--allow-remote-server-admin") {
            yume::util::log_warn("--allow-remote-server-admin was never wired to a check; flag removed (ignored)");
        } else if (arg == "--operator-keys" && i + 1 < argc) {
            cfg.operator_keys = resolve_cli_path(argv[++i]);
        } else if (arg == "--federation-enable") {
            cfg.federation_enable = true;
        } else if (arg == "--federation-auth-key" && i + 1 < argc) {
            cfg.federation_auth_key = resolve_cli_path(argv[++i]);
        } else if (arg == "--federation-anonym-ca" && i + 1 < argc) {
            cfg.federation_anonym_ca = resolve_cli_path(argv[++i]);
        } else if (arg == "--peer" && i + 1 < argc) {
            cfg.federation_peers.push_back(argv[++i]);
        } else if (arg == "--cluster-join" && i + 1 < argc) {
            const std::string spec = argv[++i];
            try {
                cfg.federation_peers.push_back(expand_cluster_join_spec(spec));
            } catch (const std::exception& ex) {
                yume::util::log_error(ex.what());
                return 1;
            }
            cfg.federation_enable = true;
        } else if (arg == "--cluster-bootstrap") {
            cfg.federation_enable = true;
            cfg.cluster_bootstrap = true;
        } else if (arg == "--public-node") {
            cfg.public_node = true;
        } else if (arg == "--hide-in-the-crowd" && i + 1 < argc) {
            cfg.http_profile = argv[++i];
        } else if (arg == "--upstream-response" && i + 1 < argc) {
            cfg.upstream_response_file = resolve_cli_path(argv[++i]);
        } else if (arg == "--upstream-response-dir" && i + 1 < argc) {
            cfg.upstream_response_dir = resolve_cli_path(argv[++i]);
        } else if (arg == "--upstream-response-ttl" && i + 1 < argc) {
            int parsed = std::atoi(argv[++i]);
            if (parsed < 0) parsed = 0;
            cfg.upstream_response_ttl_s = static_cast<std::uint32_t>(parsed);
        } else if (arg == "--attach-local") {
            attach_local = true;
        } else if (arg == "--root") {
            keep_root = true;
        } else if (arg == "--keys-add" && i + 1 < argc) {
            key_command.add = argv[++i];
        } else if (arg == "--keys-remove" && i + 1 < argc) {
            key_command.remove = argv[++i];
        } else if (arg == "--keys-alias" && i + 2 < argc) {
            key_command.alias = argv[++i];
            key_command.alias_value = argv[++i];
        } else if (arg == "--keys-list") {
            key_command.list = true;
        } else if (arg == "--keys-gen" && i + 1 < argc) {
            key_command.generate_prefix = argv[++i];
        } else if (arg == "--keys-gen-add") {
            key_command.generate_and_add = true;
        } else if (arg == "--ui") {
            key_command.ui = true;
        } else if (arg == "--boring") {
            cfg.boring = true;
        } else if (arg == "--timing") {
            yume::util::set_timing_enabled(true);
        } else {
            yume::util::log_error("unknown or incomplete option: " + arg);
            return 1;
        }
    }
    std::string exe_dir;
    {
        std::string self_path = get_self_path(argv[0]);
        if (!self_path.empty()) {
            exe_dir = std::filesystem::path(self_path).parent_path().string();
        }
    }
    config_path = yume::util::expand_user(config_path);
    if (!config_specified && !exe_dir.empty()) {
        std::filesystem::path cfg_path(config_path);
        if (!std::filesystem::exists(cfg_path)) {
            std::filesystem::path cand = std::filesystem::path(exe_dir) / cfg_path;
            if (std::filesystem::exists(cand)) {
                config_path = cand.string();
            }
        }
    }
    std::string config_dir;
    if (config_specified || std::filesystem::exists(config_path)) {
        std::error_code ec;
        auto cfg_abs = std::filesystem::absolute(config_path, ec);
        if (!ec) {
            config_dir = cfg_abs.parent_path().string();
        } else {
            config_dir = std::filesystem::path(config_path).parent_path().string();
        }
    }
    auto resolve_cfg_path = [&](const std::string& value) {
        return yume::util::resolve_path(value, config_dir, exe_dir);
    };

    if (config_specified || std::filesystem::exists(config_path)) {
        try {
            auto json = yume::util::read_json_config(config_path);
            if (json.contains("listen_port")) {
                if (cfg.listen_port == 443) {
                    cfg.listen_port = json["listen_port"].get<int>();
                }
            }
            if (json.contains("reverse_port_min")) {
                if (cfg.reverse_port_min == yume::policy::kReversePortMinDefault) {
                    cfg.reverse_port_min = json["reverse_port_min"].get<int>();
                }
            }
            if (json.contains("reverse_port_max")) {
                if (cfg.reverse_port_max == yume::policy::kReversePortMaxDefault) {
                    cfg.reverse_port_max = json["reverse_port_max"].get<int>();
                }
            }
            if (json.contains("dns_server")) {
                if (cfg.dns_server.empty()) {
                    cfg.dns_server = json["dns_server"].get<std::string>();
                }
            }
            if (json.contains("tls_cert")) {
                if (cfg.tls_cert.empty()) {
                    cfg.tls_cert = resolve_cfg_path(json["tls_cert"].get<std::string>());
                }
            }
            if (json.contains("tls_key")) {
                if (cfg.tls_key.empty()) {
                    cfg.tls_key = resolve_cfg_path(json["tls_key"].get<std::string>());
                }
            }
            if (json.contains("auth_keys")) {
                if (cfg.auth_keys.empty()) {
                    cfg.auth_keys = resolve_cfg_path(json["auth_keys"].get<std::string>());
                }
            }
            if (json.contains("threads")) {
                if (cfg.threads == 0) {
                    cfg.threads = json["threads"].get<int>();
                }
            }
            if (json.contains("obfuscation")) {
                if (!cfg.obfuscation) {
                    cfg.obfuscation = json["obfuscation"].get<bool>();
                }
            }
            if (json.contains("inner_crypto")) {
                if (!inner_crypto_override) {
                    cfg.inner_crypto = json["inner_crypto"].get<bool>();
                }
            }
            if (json.contains("inner_dual")) {
                if (!inner_dual_override) {
                    cfg.inner_dual = json["inner_dual"].get<bool>();
                }
            }
            if (json.contains("inner_required")) {
                if (!inner_required_override) {
                    cfg.inner_required = json["inner_required"].get<bool>();
                }
            }
            if (json.contains("inner_hop")) {
                if (!inner_hop_override) {
                    cfg.inner_hop = json["inner_hop"].get<bool>();
                }
            }
            if (json.contains("hop_interval_ms")) {
                if (!hop_interval_override) {
                    cfg.hop_interval_ms = static_cast<std::uint32_t>(json["hop_interval_ms"].get<int>());
                }
            }
            if (json.contains("inner_heavy")) {
                cfg.inner_heavy = json["inner_heavy"].get<bool>();
            }
            if (json.contains("pq_private_key")) {
                if (cfg.pq_private_key.empty()) {
                    cfg.pq_private_key = resolve_cfg_path(json["pq_private_key"].get<std::string>());
                }
            }
            if (json.contains("pq_auto_generate")) {
                if (!pq_auto_generate_override) {
                    cfg.pq_auto_generate = json["pq_auto_generate"].get<bool>();
                }
            }
            if (json.contains("use_embedded_master")) {
                if (!allow_embedded_master_override) {
                    cfg.allow_embedded_master = json["use_embedded_master"].get<bool>();
                }
            }
            if (json.contains("allow_exec")) {
                if (!cfg.allow_exec) {
                    cfg.allow_exec = json["allow_exec"].get<bool>();
                }
            }
            if (json.contains("allow_local_ip")) {
                cfg.allow_local_ip = json["allow_local_ip"].get<bool>();
            }
            if (json.contains("control_full")) {
                cfg.control_full = json["control_full"].get<bool>();
            }
            if (json.contains("real_http")) {
                if (!cfg.real_http) {
                    cfg.real_http = json["real_http"].get<bool>();
                }
            }
            if (json.contains("real_index_path")) {
                if (cfg.real_index_path.empty()) {
                    cfg.real_index_path = resolve_cfg_path(json["real_index_path"].get<std::string>());
                }
            }
            if (json.contains("real_secret")) {
                if (cfg.real_secret.empty()) {
                    cfg.real_secret = json["real_secret"].get<std::string>();
                }
            }
            if (json.contains("real_secret_file")) {
                if (cfg.real_secret_file.empty()) {
                    cfg.real_secret_file = resolve_cfg_path(json["real_secret_file"].get<std::string>());
                }
            }
            if (json.contains("obfs_secret")) {
                if (cfg.obfs_secret.empty()) {
                    cfg.obfs_secret = json["obfs_secret"].get<std::string>();
                }
            }
            if (json.contains("obfs_pad_multiple") && cfg.obfs_pad_multiple == 0) {
                int v = json["obfs_pad_multiple"].get<int>();
                if (v < 0) v = 0;
                if (v > 256) v = 256;
                cfg.obfs_pad_multiple = static_cast<std::uint16_t>(v);
            }
            if (json.contains("obfs_jitter_ms") && cfg.obfs_jitter_ms == 0) {
                int v = json["obfs_jitter_ms"].get<int>();
                if (v < 0) v = 0;
                cfg.obfs_jitter_ms = static_cast<std::uint32_t>(v);
            }
            if (json.contains("tls_handshake_timeout_ms") && !tls_handshake_timeout_override) {
                int v = json["tls_handshake_timeout_ms"].get<int>();
                if (v < 0) v = 0;
                cfg.tls_handshake_timeout_ms = static_cast<std::uint32_t>(v);
            }
            if (json.contains("max_sessions") && !max_sessions_override) {
                int v = json["max_sessions"].get<int>();
                if (v < 0) v = 0;
                cfg.max_sessions = static_cast<std::uint32_t>(v);
            }
            if (json.contains("accept_rate_limit") && !accept_rate_limit_override) {
                int v = json["accept_rate_limit"].get<int>();
                if (v < 0) v = 0;
                cfg.accept_rate_limit = static_cast<std::uint32_t>(v);
            }
            if (json.contains("egress_mbps") && !egress_mbps_override) {
                int v = json["egress_mbps"].get<int>();
                if (v < 0) v = 0;
                cfg.egress_mbps = static_cast<std::uint32_t>(v);
            }
            if (json.contains("robots_deny") && !cfg.robots_deny) {
                cfg.robots_deny = json["robots_deny"].get<bool>();
            }
            if (json.contains("client_filter_mode") && !client_filter_mode_override) {
                cfg.client_filter_mode = json["client_filter_mode"].get<std::string>();
            }
            if (json.contains("egress_filter_mode") && !egress_filter_mode_override) {
                cfg.egress_filter_mode = json["egress_filter_mode"].get<std::string>();
            }
            if (json.contains("filter_memory_mib") && !filter_memory_mib_override) {
                int v = json["filter_memory_mib"].get<int>();
                if (v < 0) v = 0;
                cfg.filter_memory_mib = static_cast<std::uint32_t>(v);
            }
            if (json.contains("filter_geolite") && !filter_geolite_override) {
                cfg.filter_geolite = resolve_cfg_path(json["filter_geolite"].get<std::string>());
            }
            if (json.contains("filter_lists") && json["filter_lists"].is_array()) {
                for (const auto& item : json["filter_lists"]) {
                    if (item.is_string()) {
                        cfg.filter_lists.push_back(
                            resolve_filter_list_spec_path(item.get<std::string>(), config_dir, exe_dir));
                    }
                }
            }
            if (json.contains("packet_egress") && !packet_egress_override) {
                cfg.packet_egress = json["packet_egress"].get<std::string>();
            }
            if (json.contains("packet_tun_name") && !packet_tun_name_override) {
                cfg.packet_tun_name = json["packet_tun_name"].get<std::string>();
            }
            if (json.contains("packet_cidr") && !packet_cidr_override) {
                cfg.packet_cidr = json["packet_cidr"].get<std::string>();
            }
            if (json.contains("packet_mtu") && !packet_mtu_override) {
                int v = json["packet_mtu"].get<int>();
                if (v < 0) v = 0;
                cfg.packet_mtu = static_cast<std::uint32_t>(v);
            }
            if (json.contains("benchmark_enable") && !cfg.benchmark_enable) {
                cfg.benchmark_enable = json["benchmark_enable"].get<bool>();
            }
            if (json.contains("upstream_response_dir") && cfg.upstream_response_dir.empty()) {
                cfg.upstream_response_dir = resolve_cfg_path(json["upstream_response_dir"].get<std::string>());
            }
            if (json.contains("upstream_response_ttl") && cfg.upstream_response_ttl_s == 0) {
                int v = json["upstream_response_ttl"].get<int>();
                if (v < 0) v = 0;
                cfg.upstream_response_ttl_s = static_cast<std::uint32_t>(v);
            }
            if (json.contains("boring")) {
                cfg.boring = json["boring"].get<bool>();
            }
            if (json.contains("anonym")) {
                if (!anonym_override) {
                    cfg.anonym = json["anonym"].get<bool>();
                }
            }
            if (json.contains("anonym_proof_mode") && !anonym_proof_mode_override) {
                cfg.anonym_proof_mode = json["anonym_proof_mode"].get<std::string>();
            }
            if (json.contains("anonym_api")) {
                if (cfg.anonym_api.empty()) {
                    cfg.anonym_api = json["anonym_api"].get<std::string>();
                }
            }
            if (json.contains("anonym_token")) {
                if (cfg.anonym_token.empty()) {
                    cfg.anonym_token = json["anonym_token"].get<std::string>();
                }
            }
            if (json.contains("anonym_ca_key")) {
                if (cfg.anonym_ca_key.empty()) {
                    cfg.anonym_ca_key = resolve_cfg_path(json["anonym_ca_key"].get<std::string>());
                }
            }
            if (json.contains("anonym_ca_cert")) {
                if (cfg.anonym_ca_cert.empty()) {
                    cfg.anonym_ca_cert = resolve_cfg_path(json["anonym_ca_cert"].get<std::string>());
                }
            }
            if (json.contains("anonym_sub_key")) {
                if (cfg.anonym_sub_key.empty()) {
                    cfg.anonym_sub_key = resolve_cfg_path(json["anonym_sub_key"].get<std::string>());
                }
            }
            if (json.contains("anonym_sub_cert")) {
                if (cfg.anonym_sub_cert.empty()) {
                    cfg.anonym_sub_cert = resolve_cfg_path(json["anonym_sub_cert"].get<std::string>());
                }
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
            if (json.contains("relay_enable") && !relay_enable_override) {
                cfg.relay_enable = json["relay_enable"].get<bool>();
            }
            if (json.contains("directory_enable") && !directory_enable_override) {
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
        } catch (const std::exception& ex) {
            yume::util::log_error(std::string("config load failed: ") + ex.what());
            return 1;
        }
    }
    if (!cfg.tls_cert.empty()) {
        cfg.tls_cert = resolve_cfg_path(cfg.tls_cert);
    }
    if (!cfg.tls_key.empty()) {
        cfg.tls_key = resolve_cfg_path(cfg.tls_key);
    }
    if (!cfg.auth_keys.empty()) {
        cfg.auth_keys = resolve_cfg_path(cfg.auth_keys);
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
        spec = resolve_filter_list_spec_path(spec, config_dir, exe_dir);
    }
    if (cfg.dns_server.empty()) {
        const char* dns_env = std::getenv("YUME_DNS_SERVER");
        if (dns_env && *dns_env) {
            cfg.dns_server = dns_env;
        }
    }
    if (!cfg.dns_server.empty()) {
        yume::util::log_info("server outbound DNS override: " + cfg.dns_server);
    }
#if !defined(_WIN32)
    if (cfg.dns_server.empty() && !std::filesystem::exists("/etc/resolv.conf")) {
        yume::util::log_warn(
            "/etc/resolv.conf is missing; server-side DNS may be slow. "
            "Use --dns-server 1.1.1.1 or set YUME_DNS_SERVER=1.1.1.1 to bypass system DNS.");
    }
#endif
    if (inner_heavy_override) {
        cfg.inner_heavy = inner_heavy_value;
    }
    if (cfg.inner_dual || cfg.inner_required) {
        cfg.inner_crypto = true;
    }
    if (inner_hop_override) {
        cfg.inner_hop = inner_hop_value;
    }
    if (cfg.inner_hop) {
        cfg.inner_crypto = true;
        cfg.inner_required = true;
        if (cfg.hop_interval_ms == 0) {
            cfg.hop_interval_ms = 500;
        }
    }
    if (cfg.hop_interval_ms > 0) {
        if (cfg.hop_interval_ms < 250) {
            cfg.hop_interval_ms = 250;
        } else if (cfg.hop_interval_ms > 1000) {
            cfg.hop_interval_ms = 1000;
        }
    }
    cfg.reverse_port_min = std::clamp(cfg.reverse_port_min, 1, 65535);
    cfg.reverse_port_max = std::clamp(cfg.reverse_port_max, 1, 65535);
    if (cfg.reverse_port_min > cfg.reverse_port_max) {
        std::swap(cfg.reverse_port_min, cfg.reverse_port_max);
        yume::util::log_warn("reverse_port_min > reverse_port_max; swapped values");
    }
    cfg.anonym_proof_mode = yume::policy::normalize_anonym_proof_mode(cfg.anonym_proof_mode);

#if !YUME_FEATURE_EXEC
    if (cfg.allow_exec) {
        yume::util::log_warn(
            "--allow-exec ignored: build was configured without -DYUME_FEATURE_EXEC=ON; "
            "rebuild with that option to enable server-side command execution");
    }
#endif
#if !YUME_FEATURE_LAN_BRIDGE
    if (cfg.allow_local_ip) {
        yume::util::log_warn(
            "--allow-local-ip ignored: build was configured without -DYUME_FEATURE_LAN_BRIDGE=ON; "
            "rebuild with that option to enable LAN/private-IP bridging");
    }
#endif
#if !YUME_FEATURE_FULL_CONTROL
    if (cfg.control_full) {
        yume::util::log_warn(
            "--control-full ignored: build was configured without -DYUME_FEATURE_FULL_CONTROL=ON; "
            "rebuild with that option to enable unrestricted address bridging");
    }
#endif
    if ((cfg.allow_exec || cfg.allow_local_ip || cfg.control_full) && cfg.auth_keys_meta.empty()) {
        yume::util::log_warn(
            "dangerous server feature enabled but no auth_keys_meta is configured; "
            "no key will inherit these permissions until you create the meta file and grant per-key access "
            "(see docs/PERMISSIONS.md)");
    }
    if (cfg.federation_enable &&
        (cfg.federation_auth_key.empty() || cfg.federation_anonym_ca.empty())) {
        yume::util::log_error("federation requires --federation-auth-key and --federation-anonym-ca");
        return 1;
    }
    if (cfg.federation_enable && !cfg.cluster_bootstrap && cfg.federation_peers.empty()) {
        yume::util::log_error("federation requires at least one --peer or --cluster-join; pass --cluster-bootstrap if this node is a cluster entry point");
        return 1;
    }

    if (!cfg.http_profile.empty()) {
        if (!yume::http_profile::server(cfg.http_profile).has_value()) {
            std::string supported;
            for (const auto& n : yume::http_profile::server_names()) {
                if (!supported.empty()) supported += ", ";
                supported += n;
            }
            yume::util::log_error("--hide-in-the-crowd: unknown server profile '" + cfg.http_profile +
                                  "'. Supported: " + supported);
            return 1;
        }
    }
    if (!yume::server::IpFilter::parse_mode(cfg.client_filter_mode).has_value()) {
        yume::util::log_error("--client-filter-mode must be blacklist or whitelist");
        return 1;
    }
    if (!yume::server::IpFilter::parse_mode(cfg.egress_filter_mode).has_value()) {
        yume::util::log_error("--egress-filter-mode must be blacklist or whitelist");
        return 1;
    }
    for (const auto& spec : cfg.filter_lists) {
        std::string parse_error;
        if (!yume::server::IpFilter::parse_list_spec(spec, &parse_error).has_value()) {
            yume::util::log_error("--filter-list " + spec + ": " + parse_error);
            return 1;
        }
    }
    if (!cfg.packet_egress.empty() && cfg.packet_egress != "off" && cfg.packet_egress != "none") {
        if (cfg.packet_egress != "tun") {
            yume::util::log_error("--packet-egress supports only 'tun' in v1");
            return 1;
        }
        if (cfg.packet_tun_name.empty()) {
            yume::util::log_error("--packet-tun-name must not be empty");
            return 1;
        }
        if (cfg.packet_mtu < 576 || cfg.packet_mtu > 65535) {
            yume::util::log_error("--packet-mtu must be in range 576..65535");
            return 1;
        }
        yume::util::log_info("packet-native egress requested: tun=" + cfg.packet_tun_name +
                             " cidr=" + cfg.packet_cidr +
                             " mtu=" + std::to_string(cfg.packet_mtu) +
                             ". The TUN address/NAT must be prepared by the operator before startup.");
    }

    if (!cfg.upstream_response_file.empty()) {
        // Load the captured response once at startup. Normalise lone
        // \n into \r\n so operators who captured with `curl -i` (which
        // strips the on-wire \r) still produce valid HTTP wire bytes
        // when we replay. Already-\r\n stays unchanged.
        std::ifstream in(cfg.upstream_response_file, std::ios::binary);
        if (!in) {
            yume::util::log_error("--upstream-response: cannot open " + cfg.upstream_response_file);
            return 1;
        }
        std::stringstream ss; ss << in.rdbuf();
        std::string raw = ss.str();
        std::string normalized;
        normalized.reserve(raw.size() + raw.size() / 16);
        for (std::size_t i = 0; i < raw.size(); ++i) {
            char c = raw[i];
            if (c == '\n' && (i == 0 || raw[i - 1] != '\r')) {
                normalized += '\r';
            }
            normalized += c;
        }
        if (normalized.rfind("HTTP/1.", 0) != 0) {
            yume::util::log_error("--upstream-response: " + cfg.upstream_response_file +
                                  " does not start with 'HTTP/1.' — expected a captured HTTP/1.x response");
            return 1;
        }
        cfg.upstream_response_bytes = std::move(normalized);
        yume::util::log_info("--upstream-response: loaded " +
                             std::to_string(cfg.upstream_response_bytes.size()) +
                             " bytes from " + cfg.upstream_response_file +
                             " (replayed verbatim to non-yume probes)");
    }

    if (!cfg.upstream_response_dir.empty()) {
        namespace fs = std::filesystem;
        std::error_code ec;
        if (!fs::is_directory(cfg.upstream_response_dir, ec)) {
            yume::util::log_error("--upstream-response-dir: " + cfg.upstream_response_dir +
                                  " is not a directory");
            return 1;
        }
        if (!cfg.upstream_response_file.empty()) {
            yume::util::log_warn("--upstream-response-dir overrides --upstream-response " +
                                 cfg.upstream_response_file + " (single-file capture will be ignored)");
        }
    }

    if (cfg.obfs_pad_multiple > 0) {
        yume::util::log_info("--obfs-pad-multiple " + std::to_string(cfg.obfs_pad_multiple) +
                             ": every outbound frame payload is padded to a multiple of this size. " +
                             "Connecting clients MUST run a yume build that knows kFlagPadded (>= 1.0 post-padding); " +
                             "older clients will fail to parse the stream.");
    }
    if (cfg.obfs_jitter_ms > 0) {
        yume::util::log_info("--obfs-jitter-ms " + std::to_string(cfg.obfs_jitter_ms) +
                             ": each batched write is deferred by 0.." +
                             std::to_string(cfg.obfs_jitter_ms) +
                             " ms. Adds latency, breaks the constant-cadence ML signature.");
    }

    if (cfg.public_node) {
        // --public-node: hardening preset for an internet-facing yumed.
        // Refuses flags that expose dangerous capabilities and requires
        // explicit auth setup. The existing silent-downgrade warnings
        // for --allow-local-ip / --control-full become hard errors here
        // so operators can't accidentally ship a "public" node that
        // also tries to bridge to LAN or expose full address control.
        if (cfg.http_profile.empty()) {
            cfg.http_profile = "nginx";
            yume::util::log_info("--public-node: defaulting --hide-in-the-crowd to 'nginx' (pass --hide-in-the-crowd <profile> to override)");
        }
        // --public-node hardening defaults. Each respects an explicit
        // operator override (CLI flag or JSON config); only fills in
        // the safe-by-default value when the operator left it at 0.
        if (!tls_handshake_timeout_override && cfg.tls_handshake_timeout_ms == 0) {
            cfg.tls_handshake_timeout_ms = 10000;
            yume::util::log_info("--public-node: defaulting --tls-handshake-timeout-ms to 10000 (pass --tls-handshake-timeout-ms 0 to disable)");
        }
        if (!max_sessions_override && cfg.max_sessions == 0) {
            cfg.max_sessions = 4096;
            yume::util::log_info("--public-node: defaulting --max-sessions to 4096 (pass --max-sessions <N> to override; 0 = unlimited)");
        }
        if (!accept_rate_limit_override && cfg.accept_rate_limit == 0) {
            cfg.accept_rate_limit = 100;
            yume::util::log_info("--public-node: defaulting --accept-rate-limit to 100/s (pass --accept-rate-limit <N> to override; 0 = unlimited)");
        }
        // Refuse to bind to a private / loopback / link-local address
        // when the operator declared this is an internet-facing node.
        // Empty listen_address = "bind any" (0.0.0.0) which is the
        // operator's clear intent to be internet-facing, so it's
        // allowed. Only explicit addr binds are checked.
        if (!cfg.listen_address.empty()) {
            boost::system::error_code addr_ec;
            auto addr = boost::asio::ip::make_address(cfg.listen_address, addr_ec);
            if (addr_ec) {
                yume::util::log_error("--public-node: --listen address '" +
                                      cfg.listen_address + "' does not parse: " +
                                      addr_ec.message());
                return 1;
            }
            bool refuse = false;
            std::string reason;
            if (addr.is_loopback()) {
                refuse = true; reason = "loopback (127.0.0.0/8 or ::1)";
            } else if (addr.is_unspecified()) {
                // 0.0.0.0 / :: are the explicit "any" forms — allowed,
                // operator just wrote them out longhand.
            } else if (addr.is_v4()) {
                const auto v4 = addr.to_v4();
                const auto bytes = v4.to_bytes();
                const uint32_t ip = (uint32_t(bytes[0]) << 24) | (uint32_t(bytes[1]) << 16) |
                                    (uint32_t(bytes[2]) << 8)  |  uint32_t(bytes[3]);
                // RFC 1918 ranges + link-local (169.254/16) + CGNAT
                // (100.64/10). Public CGNAT addresses can legitimately
                // back internet-facing services in some ISP setups,
                // but the typical case is a misconfigured edge router;
                // err on the side of refusing.
                if ((ip & 0xFF000000u) == 0x0A000000u)  { refuse = true; reason = "RFC 1918 (10.0.0.0/8)"; }
                if ((ip & 0xFFF00000u) == 0xAC100000u)  { refuse = true; reason = "RFC 1918 (172.16.0.0/12)"; }
                if ((ip & 0xFFFF0000u) == 0xC0A80000u)  { refuse = true; reason = "RFC 1918 (192.168.0.0/16)"; }
                if ((ip & 0xFFFF0000u) == 0xA9FE0000u)  { refuse = true; reason = "link-local (169.254.0.0/16)"; }
                if ((ip & 0xFFC00000u) == 0x64400000u)  { refuse = true; reason = "CGNAT (100.64.0.0/10)"; }
            } else if (addr.is_v6()) {
                const auto v6 = addr.to_v6();
                if (v6.is_link_local()) {
                    refuse = true; reason = "IPv6 link-local (fe80::/10)";
                }
                // ULA fc00::/7 — bytes[0] in {0xFC, 0xFD}.
                const auto bytes = v6.to_bytes();
                if ((bytes[0] & 0xFE) == 0xFC) {
                    refuse = true; reason = "IPv6 ULA (fc00::/7)";
                }
            }
            if (refuse) {
                yume::util::log_error("--public-node: refusing to bind --listen " +
                                      cfg.listen_address + " (" + reason +
                                      "). A public node must not bind to a private/loopback range. "
                                      "Either drop --public-node, or set --listen to a public address (or just the port).");
                return 1;
            }
            yume::util::log_info("--public-node: --listen " + cfg.listen_address +
                                 " passes private-range check");
        }
#ifndef _WIN32
        // Lock the process umask to 0077 BEFORE anything writes a
        // file or creates a directory. Subsequent secret-key writes
        // (PQ keypair under ./.secrets), IPC socket creates, config
        // dirs etc all inherit owner-only mode so other local users
        // can't read them. Set unconditionally under --public-node;
        // no override knob — operators who want world-readable
        // secret files on a public-facing host should reconsider.
        const mode_t prior = umask(0077);
        yume::util::log_info(
            std::string("--public-node: process umask set to 0077 (was 0") +
            std::to_string(prior >> 6 & 7) +
            std::to_string(prior >> 3 & 7) +
            std::to_string(prior & 7) +
            "); subsequent secret files and IPC socket will be 0600/0700");
#endif
        std::vector<std::string> violations;
        if (cfg.allow_exec) {
            violations.emplace_back("--allow-exec is forbidden by --public-node (server-side exec on a public node is a remote-shell hole)");
        }
        if (cfg.allow_local_ip) {
            violations.emplace_back("--allow-local-ip is forbidden by --public-node (LAN bridging from a public endpoint exposes the host's private network)");
        }
        if (cfg.control_full) {
            violations.emplace_back("--control-full is forbidden by --public-node (unrestricted address bridging from a public endpoint is a relay hole)");
        }
        if (!cfg.inner_crypto) {
            violations.emplace_back("--no-inner is forbidden by --public-node (inner crypto is the only post-handshake confidentiality; a public node MUST require it)");
        }
        if (cfg.auth_keys.empty()) {
            violations.emplace_back("--public-node requires --auth-keys to be set (otherwise the daemon accepts no clients, or worse, accepts everyone if you later loosen this)");
        }
        if (!violations.empty()) {
            yume::util::log_error("--public-node violations:");
            for (const auto& v : violations) {
                yume::util::log_error("  - " + v);
            }
            return 1;
        }
        yume::util::log_info("--public-node active; the following protections are enforced at startup:");
        yume::util::log_info("  - dangerous capability flags (--allow-exec / --allow-local-ip / --control-full) are rejected");
        yume::util::log_info("  - inner crypto required (no plaintext transport)");
        yume::util::log_info("  - --auth-keys required (no anonymous-relay accidents)");
        yume::util::log_info("  - Argon2 caps locked to safe defaults (env vars can only RAISE, never lower)");
        yume::util::log_info("  - private-IP bind refusal (--listen explicit-addr in RFC 1918 / loopback / link-local / ULA → startup error)");
        yume::util::log_info("  - TLS handshake deadline (--tls-handshake-timeout-ms; default 10s, slow-loris guard)");
        yume::util::log_info("  - accept-side rate-limit + max-concurrent-session cap (--accept-rate-limit 100/s, --max-sessions 4096)");
        yume::util::log_info("  - process umask locked to 0077 (secret files + IPC socket land at 0600/0700)");
    }

    auto require_readable = [&](const char* label, const std::string& path) {
        if (path.empty()) {
            return true;
        }
        if (!file_readable(path)) {
            yume::util::log_error(std::string(label) + " not found: " + path);
            return false;
        }
        return true;
    };

    const bool key_management_only = key_command.ui || key_command.has_action();

    if (!key_management_only) {
        if (!require_readable("tls_cert", cfg.tls_cert)) {
            return 1;
        }
        if (!require_readable("tls_key", cfg.tls_key)) {
            return 1;
        }
        if (!require_readable("auth_keys", cfg.auth_keys)) {
            return 1;
        }
        if (!require_readable("pq_private_key", cfg.pq_private_key)) {
            return 1;
        }
        if (!require_readable("real_index_path", cfg.real_index_path)) {
            return 1;
        }
        if (!require_readable("real_secret_file", cfg.real_secret_file)) {
            return 1;
        }
        if (!require_readable("anonym_ca_key", cfg.anonym_ca_key)) {
            return 1;
        }
        if (!require_readable("anonym_ca_cert", cfg.anonym_ca_cert)) {
            return 1;
        }
        if (!require_readable("anonym_sub_key", cfg.anonym_sub_key)) {
            return 1;
        }
        if (!require_readable("anonym_sub_cert", cfg.anonym_sub_cert)) {
            return 1;
        }
        if (!require_readable("federation_auth_key", cfg.federation_auth_key)) {
            return 1;
        }
        if (!require_readable("federation_anonym_ca", cfg.federation_anonym_ca)) {
            return 1;
        }
    }

    if (key_command.ui) {
        auto result = run_server_manager_ui(cfg, key_command);
        if (result.handled) {
            return result.exit_code;
        }
    }

    if (prepare_server_runtime_files(cfg, argv[0], key_command.has_action()) != 0) {
        return 1;
    }

    if (key_command.has_action()) {
        auto result = run_server_key_command(cfg, key_command);
        if (result.handled) {
            return result.exit_code;
        }
    }

    if (!cfg.inner_crypto) {
        if (cfg.boring) {
            yume::util::log_warn("Security warning: BASEFWX / PQ disabled");
        } else {
            yume::util::log_warn("🔓⛓️‍💥 YOUR SECURITY IS SUFFERING BECAUSE YOU HAVE DISABLED: BASEFWX / PQ");
        }
    } else if (cfg.allow_embedded_master && cfg.pq_private_key.empty()) {
        yume::util::log_warn("using embedded BaseFWX master PQ key fallback (explicitly enabled)");
    } else if (cfg.allow_embedded_master) {
        yume::util::log_warn(
            "embedded BaseFWX master PQ keypair enabled; connection security depends on basefwx-bundled keys "
            "(disable with --no-embedded-master if you also provide --pq-key)");
    }

    if (cfg.anonym && cfg.anonym_ca_key.empty() && !cfg.anonym_ca_cert.empty()) {
        yume::util::log_warn("anonym_ca_cert set but anonym_ca_key is missing; no CA signature will be produced");
    }
    if (cfg.anonym && !cfg.anonym_ca_key.empty() && cfg.anonym_ca_cert.empty()) {
        yume::util::log_warn("anonym_ca_key set but anonym_ca_cert is missing; clients cannot verify CA signature");
    }
    if (cfg.anonym && !cfg.anonym_sub_key.empty() && cfg.anonym_sub_cert.empty()) {
        yume::util::log_warn("anonym_sub_key set but anonym_sub_cert is missing; sub signature cannot be used");
    }
    if (cfg.anonym && cfg.anonym_sub_key.empty() && !cfg.anonym_sub_cert.empty()) {
        yume::util::log_warn("anonym_sub_cert set but anonym_sub_key is missing; no sub signature will be produced");
    }
    if (cfg.anonym && yume::policy::anonym_proof_mode_requires_remote(cfg.anonym_proof_mode) && cfg.anonym_api.empty()) {
        yume::util::log_warn("anonym proof mode is fixcraft but anonym_api is not set");
    }
    if (cfg.anonym && yume::policy::anonym_proof_mode_requires_local(cfg.anonym_proof_mode) &&
        cfg.anonym_ca_key.empty() && cfg.anonym_sub_key.empty()) {
        yume::util::log_warn("anonym proof mode is local but no anonym_ca_key or anonym_sub_key is configured");
    }
    if (!cfg.anonym && (!cfg.anonym_sub_key.empty() || !cfg.anonym_sub_cert.empty())) {
        yume::util::log_warn(
            "anonym_sub_key/anonym_sub_cert are set but --anonym is disabled; server mode is normal "
            "and anonym proof mode is OFF. Add --anonym if clients require anonym proof");
    }
    if (cfg.listen_port != 443 && !cfg.anonym) {
        yume::util::log_warn("WARNING: running on a port other than 443 reduces stealth and defeats HTTPS disguise.");
    }
    const std::string effective_inner_mode =
        !cfg.inner_crypto ? "off"
        : cfg.inner_dual ? "dual"
        : cfg.inner_heavy ? "heavy"
        : "light";
    const std::string hop_state =
        cfg.inner_hop ? "on (" + std::to_string(cfg.hop_interval_ms) + "ms)"
                      : "off";
    yume::util::log_info("effective inner mode: " + effective_inner_mode +
                         "; hopping: " + hop_state +
                         "; required: " + (cfg.inner_required ? "yes" : "no"));
    if (cfg.benchmark_enable) {
        yume::util::log_info("authenticated benchmark endpoint enabled for yume --bench");
    }

    // TLS JA3 self-check: generate our own ClientHello via in-memory
    // BIO, compute JA3, compare against the per-profile baseline. Catches
    // silent drift when OpenSSL is upgraded between builds — if the
    // observed JA3 stops matching any known browser cluster the daemon
    // logs loudly so operators see it on the next restart.
    {
        // Baselines captured 2026-05 on the build-host build
        // (OpenSSL 3.5, Debian 13). Each is the MD5 of the
        // standard JA3 string produced by compute_self_fingerprint
        // for that profile against the current registry data. A
        // future OpenSSL upgrade or profile-data edit that changes
        // these will fire a "DRIFT" warning at every startup, which
        // is exactly what we want — silent drift away from a known
        // browser cluster is the failure mode the self-check exists
        // to catch.
        struct Baseline { yume::tls_fingerprint::BrowserProfile profile; const char* name; const char* expected_ja3; };
        constexpr Baseline kBaselines[] = {
            {yume::tls_fingerprint::BrowserProfile::CHROME_135,  "chrome",  "51dc1deffb716cb50b5b0e5449c4e28f"},
            {yume::tls_fingerprint::BrowserProfile::FIREFOX_126, "firefox", "b2f1f8aa44e9d9510358e21055e2a3c2"},
            {yume::tls_fingerprint::BrowserProfile::SAFARI_17,   "safari",  "96244ebd33ea0991b081300f27a9a6b3"},
        };
        for (const auto& b : kBaselines) {
            auto self = yume::tls_stealth::compute_self_fingerprint(b.profile);
            if (!self.has_value()) {
                yume::util::log_warn(std::string("ja3 self-check ") + b.name + ": could not generate ClientHello");
                continue;
            }
            const std::string& got = self->ja3_hash;
            if (*b.expected_ja3 == '\0') {
                yume::util::log_info(std::string("ja3 self-check ") + b.name + ": " + got +
                                     " (no pinned baseline — record this hash if it should be pinned)");
            } else if (got == b.expected_ja3) {
                yume::util::log_info(std::string("ja3 self-check ") + b.name + ": " + got + " (matches baseline)");
            } else {
                yume::util::log_warn(std::string("ja3 self-check ") + b.name +
                                     ": DRIFT — observed " + got +
                                     " vs pinned " + b.expected_ja3 +
                                     ". OpenSSL extension order may have changed; verify the JA3 still falls in the browser cluster before publishing.");
            }
        }
    }

    if (cfg.real_http) {
        if (cfg.real_secret.empty()) {
            const std::string secret_path = cfg.real_secret_file.empty() ? kDefaultSecretPath : cfg.real_secret_file;
            try {
                cfg.real_secret = load_or_create_secret(secret_path);
            } catch (const std::exception& ex) {
                yume::util::log_error(std::string("failed to load real_secret: ") + ex.what());
                return 1;
            }
        }
    }

    std::atomic<long long> anonym_last_ts{0};
    const char* anonym_local_sign_env = std::getenv("YUME_ANONYM_LOCAL_SIGN");
    const bool anonym_local_sign =
        parse_env_bool("YUME_ANONYM_LOCAL_SIGN", anonym_local_sign_default());

    if (cfg.anonym) {
        if (!anonym_local_sign && (!cfg.anonym_ca_key.empty() || !cfg.anonym_sub_key.empty())) {
            if (anonym_local_sign_env && *anonym_local_sign_env) {
                yume::util::log_warn("anonym local signing is disabled by YUME_ANONYM_LOCAL_SIGN=0");
            } else {
                yume::util::log_warn("anonym local signing is disabled by default on this build/platform (set YUME_ANONYM_LOCAL_SIGN=1 to force)");
            }
        }
        try {
            std::string self_path = get_self_path(argv[0]);
            if (self_path.empty()) {
                throw std::runtime_error("failed to locate executable path");
            }
            std::string bin = read_file_bytes(self_path);
            cfg.anonym_hash = sha256_hex(bin);
            if (!cfg.tls_cert.empty()) {
                cfg.anonym_certfp = cert_fingerprint_sha256(cfg.tls_cert);
            }
            std::string pq_public_path;
            if (cfg.inner_crypto && !cfg.pq_private_key.empty()) {
                pq_public_path = derive_pq_public_path(cfg.pq_private_key);
            }
            std::string pq_sign_key = !cfg.anonym_sub_key.empty() ? cfg.anonym_sub_key : cfg.anonym_ca_key;
            auto proof = fetch_anonym_proof(cfg.anonym_hash, cfg.anonym_certfp, cfg.anonym_proof_mode, cfg.anonym_api,
                                            cfg.anonym_token, cfg.anonym_ca_key,
                                            cfg.anonym_sub_key, cfg.anonym_sub_cert,
                                            pq_public_path, pq_sign_key, anonym_local_sign,
                                            cfg.outbound_proxy_url);
            cfg.anonym_sig = proof.sig;
            cfg.anonym_ts = proof.ts;
            cfg.anonym_nonce = proof.nonce;
            cfg.anonym_proof_mode = proof.proof_policy;
            cfg.anonym_proof_sources = proof.proof_sources;
            cfg.anonym_ca_sig = proof.ca_sig;
            cfg.anonym_ca_alg = proof.ca_alg;
            cfg.anonym_sub_sig = proof.sub_sig;
            cfg.anonym_sub_alg = proof.sub_alg;
            cfg.anonym_sub_cert_b64 = proof.sub_cert_b64;
            cfg.pq_pub_b64 = proof.pq_pub_b64;
            cfg.pq_sig = proof.pq_sig;
            cfg.pq_alg = proof.pq_alg;
            anonym_last_ts.store(parse_proof_ts(proof.ts, static_cast<long long>(std::time(nullptr))),
                                 std::memory_order_relaxed);
        } catch (const std::exception& ex) {
            std::cerr << "\033[1;31mANONYM PROOF FAILED: " << ex.what() << "\033[0m\n";
            return 1;
        }
        yume::util::set_logging_enabled(false);
        std::cerr << "\033[1;33mANONYM MODE ACTIVE: client metadata logging disabled\033[0m\n";
    }
    if (!cfg.anonym) {
        if (cfg.anonym_certfp.empty() && !cfg.tls_cert.empty()) {
            try {
                cfg.anonym_certfp = cert_fingerprint_sha256(cfg.tls_cert);
            } catch (const std::exception& ex) {
                yume::util::log_warn(std::string("failed to compute cert fingerprint for PQ signing: ") + ex.what());
            }
        }
        std::string pq_public_path;
        if (cfg.inner_crypto && !cfg.pq_private_key.empty()) {
            pq_public_path = derive_pq_public_path(cfg.pq_private_key);
        }
        if (!pq_public_path.empty() && cfg.pq_pub_b64.empty()) {
            std::string pq_pub_b64;
            if (load_pq_public_b64(pq_public_path, &pq_pub_b64)) {
                cfg.pq_pub_b64 = pq_pub_b64;
                std::string pq_sign_key;
                if (!cfg.anonym_sub_key.empty() && !cfg.anonym_sub_cert.empty()) {
                    pq_sign_key = cfg.anonym_sub_key;
                    if (cfg.anonym_sub_cert_b64.empty()) {
                        try {
                            std::string sub_pem = read_file_bytes(cfg.anonym_sub_cert);
                            cfg.anonym_sub_cert_b64 = yume::util::base64_encode(sub_pem);
                        } catch (const std::exception& ex) {
                            yume::util::log_warn(std::string("failed to read anonym_sub_cert: ") + ex.what());
                        }
                    }
                }
                if (pq_sign_key.empty() && !cfg.anonym_ca_key.empty()) {
                    pq_sign_key = cfg.anonym_ca_key;
                }
                if (cfg.anonym_certfp.empty()) {
                    yume::util::log_warn("PQ OTA disabled: TLS cert fingerprint missing");
                } else if (pq_sign_key.empty()) {
                    yume::util::log_warn("PQ OTA disabled: anonym_sub_key/anonym_ca_key not set");
                } else if (!sign_pq_pub_with_key(pq_pub_b64, cfg.anonym_certfp, pq_sign_key,
                                                 &cfg.pq_sig, &cfg.pq_alg)) {
                    yume::util::log_warn("PQ OTA disabled: pq public key signing failed");
                }
            } else {
                yume::util::log_warn("PQ public key not readable; OTA PQ disabled");
            }
        }
    }

    const std::string local_instance_key = yume::server_cli::effective_server_instance_key(cfg, config_path);
    const std::string local_runtime_path = cfg.ipc_path.empty()
        ? yume::server::LocalRuntime::socket_path_for(local_instance_key)
        : cfg.ipc_path;
    const bool local_runtime_exists =
        cfg.ipc_enable && yume::server::LocalRuntime::available(local_runtime_path);
    if (cfg.ipc_enable && local_runtime_exists) {
        const bool should_attach = attach_local || yume::server_cli::prompt_attach_existing("yumed");
        if (should_attach) {
            return yume::server_cli::run_local_server_attach(
                local_runtime_path,
                !yume::server_cli::stdin_is_tty());
        }
        yume::util::log_error("yumed is already running for this instance; use --attach-local to interact with it");
        return 1;
    } else if (attach_local) {
        yume::util::log_error("no running yumed instance was found for this configuration");
        return 1;
    }

    unsigned int hw = std::thread::hardware_concurrency();
    int threads = cfg.threads > 0 ? cfg.threads : static_cast<int>(hw > 0 ? hw : 1);
    boost::asio::io_context io(threads);
    yume::server::Manager manager(io, cfg);
    std::atomic<bool> stop_refresh{false};
    std::mutex refresh_mu;
    std::condition_variable refresh_cv;
    std::thread refresh_thread;
    auto local_runtime = std::make_shared<yume::server::LocalRuntime>(
        local_runtime_path,
        &manager,
        [&]() {
            manager.stop();
            io.stop();
            stop_refresh.store(true);
            refresh_cv.notify_all();
        });
    if (cfg.anonym) {
        refresh_thread = std::thread([&manager, &cfg, &stop_refresh, &anonym_last_ts, &refresh_mu, &refresh_cv, anonym_local_sign]() {
            auto compute_delay = [&]() -> int {
                const long long now = static_cast<long long>(std::time(nullptr));
                const long long last = anonym_last_ts.load(std::memory_order_relaxed);
                if (last <= 0) {
                    return yume::policy::kAnonymRefreshMinSeconds;
                }
                const long long age = now - last;
                const long long target = static_cast<long long>(
                    yume::policy::kAnonymProofWindowSeconds - yume::policy::kAnonymRefreshLeadSeconds);
                long long delay = target - age;
                if (delay < yume::policy::kAnonymRefreshMinSeconds) {
                    delay = yume::policy::kAnonymRefreshMinSeconds;
                }
                if (delay > yume::policy::kAnonymRefreshSeconds) {
                    delay = yume::policy::kAnonymRefreshSeconds;
                }
                return static_cast<int>(delay);
            };

            while (!stop_refresh.load()) {
                const int delay_s = compute_delay();
                std::unique_lock<std::mutex> lock(refresh_mu);
                if (refresh_cv.wait_for(lock, std::chrono::seconds(delay_s), [&stop_refresh]() {
                        return stop_refresh.load();
                    })) {
                    break;
                }
                lock.unlock();
                try {
                    std::string pq_public_path;
                    if (cfg.inner_crypto && !cfg.pq_private_key.empty()) {
                        pq_public_path = derive_pq_public_path(cfg.pq_private_key);
                    }
                    std::string pq_sign_key = !cfg.anonym_sub_key.empty() ? cfg.anonym_sub_key : cfg.anonym_ca_key;
                    auto proof = fetch_anonym_proof(cfg.anonym_hash, cfg.anonym_certfp, cfg.anonym_proof_mode, cfg.anonym_api,
                                                    cfg.anonym_token, cfg.anonym_ca_key,
                                                    cfg.anonym_sub_key, cfg.anonym_sub_cert,
                                                    pq_public_path, pq_sign_key, anonym_local_sign,
                                                    cfg.outbound_proxy_url);
                    cfg.anonym_ts = proof.ts;
                    manager.update_anonym_proof(proof.hash, proof.sig, proof.ts, proof.nonce,
                                                proof.certfp, proof.proof_policy, proof.proof_sources,
                                                proof.ca_sig, proof.ca_alg,
                                                proof.sub_sig, proof.sub_alg, proof.sub_cert_b64,
                                                proof.pq_pub_b64, proof.pq_sig, proof.pq_alg);
                    anonym_last_ts.store(parse_proof_ts(proof.ts, static_cast<long long>(std::time(nullptr))),
                                         std::memory_order_relaxed);
                } catch (const std::exception& ex) {
                    std::cerr << "\033[1;33mANONYM REFRESH FAILED: " << ex.what() << "\033[0m\n";
                    anonym_last_ts.store(0, std::memory_order_relaxed);
                }
            }
        });
    }

    std::atomic<bool> shutting_down{false};
    yume::util::install_signal_handlers([&](int sig) {
        if (sig == SIGTERM) {
            shutting_down.store(true);
        }
        if (shutting_down.exchange(true)) {
            std::cerr << "\033[1;31mforce exit requested\033[0m\n";
            std::_Exit(1);
        }
        if (yume::util::is_logging_enabled()) {
            yume::util::log_info("Stopping...");
        } else {
            std::cerr << "\033[1;33mStopping...\033[0m\n";
        }
        local_runtime->stop();
        manager.stop();
        stop_refresh.store(true);
        refresh_cv.notify_all();
        std::thread([&io]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(1500));
            io.stop();
        }).detach();
    });

#if !defined(_WIN32)
    repair_pq_key_ownership_for_drop(cfg, keep_root);
#endif

    try {
        std::string ipc_error;
        if (cfg.ipc_enable && !local_runtime->start(&ipc_error)) {
            yume::util::log_warn("local attach disabled: " + ipc_error);
        }
        manager.start();
        if (!keep_root) {
            std::string drop_error;
            std::string drop_summary;
            if (!yume::util::drop_privileges(&drop_error, &drop_summary)) {
                throw std::runtime_error("failed to drop privileges: " + drop_error);
            }
            if (!drop_summary.empty()) {
                if (yume::util::is_logging_enabled()) {
                    yume::util::log_info(drop_summary);
                } else {
                    std::cerr << "\033[1;33mPrivileges dropped after bind/listen\033[0m\n";
                }
            }
        }
    } catch (const std::exception& ex) {
        local_runtime->stop();
        manager.stop();
        if (yume::util::is_logging_enabled()) {
            yume::util::log_error(std::string("server start failed: ") + ex.what());
        } else {
            std::cerr << "\033[1;31mserver start failed: " << ex.what() << "\033[0m\n";
        }
        stop_refresh.store(true);
        refresh_cv.notify_all();
        if (refresh_thread.joinable()) {
            refresh_thread.join();
        }
        return 1;
    }

    std::vector<std::thread> workers;
    workers.reserve(static_cast<size_t>(threads));
    for (int i = 0; i < threads; ++i) {
        workers.emplace_back([&]() { io.run(); });
    }
    for (auto& t : workers) {
        t.join();
    }
    stop_refresh.store(true);
    refresh_cv.notify_all();
    if (refresh_thread.joinable()) {
        refresh_thread.join();
    }
    local_runtime->stop();

    return 0;
}
