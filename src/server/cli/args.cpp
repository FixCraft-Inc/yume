/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/args.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <string>
#include <string_view>

#include "core/app_codec/codec.hpp"
#include "server/cli/cluster.hpp"
#include "server/cli/help.hpp"
#include "server/cli/misc.hpp"
#include "server/cli/numeric_parse.hpp"
#include "server/config/config.hpp"
#include "server/host/host_types.hpp"
#include "util.hpp"

namespace yume::server_cli {
namespace {

bool parse_non_negative_u32(const char* raw, const char* option, std::uint32_t* out) {
    if (raw && parse_u32_strict(raw, out)) {
        return true;
    }
    yume::util::log_error(std::string(option) + ": expected an unsigned 32-bit integer");
    return false;
}

bool parse_positive_u32(const char* raw, const char* option, std::uint32_t* out) {
    if (raw && parse_u32_strict(raw, out) && *out > 0) {
        return true;
    }
    yume::util::log_error(std::string(option) + ": expected a positive unsigned 32-bit integer");
    return false;
}

bool parse_port(const char* raw, const char* option, int* out) {
    int value = 0;
    if (!raw || !parse_int_strict(raw, &value) || value < 1 || value > 65535) {
        yume::util::log_error(std::string(option) + ": port must be 1..65535");
        return false;
    }
    *out = value;
    return true;
}

bool parse_listen_spec(const std::string& raw, yume::server::ServerConfig& cfg) {
    std::string addr_part;
    std::string port_part;
    if (!raw.empty() && raw.front() == '[') {
        const auto rbr = raw.find(']');
        if (rbr == std::string::npos || rbr + 2 > raw.size() || raw[rbr + 1] != ':') {
            yume::util::log_error("--listen: bracket form must be [addr]:port");
            return false;
        }
        addr_part = raw.substr(1, rbr - 1);
        port_part = raw.substr(rbr + 2);
    } else {
        const auto colon = raw.rfind(':');
        if (colon == std::string::npos) {
            port_part = raw;
        } else {
            addr_part = raw.substr(0, colon);
            port_part = raw.substr(colon + 1);
        }
    }
    if (!parse_port(port_part.c_str(), "--listen", &cfg.listen_port)) {
        return false;
    }
    cfg.listen_address = addr_part;
    return true;
}

bool parse_obfs_pad_multiple(const char* raw, std::uint16_t* out) {
    std::uint32_t parsed = 0;
    if (!parse_non_negative_u32(raw, "--obfs-pad-multiple", &parsed)) {
        return false;
    }
    *out = static_cast<std::uint16_t>(std::min<std::uint32_t>(parsed, 256));
    return true;
}

}  // namespace

bool parse_server_cli_args(int argc,
                           char** argv,
                           const std::string& cli_cwd,
                           yume::server::ServerConfig& cfg,
                           ServerCliParseResult* out) {
    if (!out) {
        return false;
    }
    ServerCliParseResult result;
    auto resolve_cli_path = [&](const std::string& value) {
        return yume::util::resolve_path(value, cli_cwd, "");
    };

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "completion" || arg == "--completion") && i + 1 < argc) {
            std::string shell = argv[++i];
            if (shell == "bash") {
                print_bash_completion();
                result.handled = true;
                result.exit_code = 0;
                *out = result;
                return true;
            }
            yume::util::log_error("unsupported completion shell: " + shell);
            result.handled = true;
            result.exit_code = 1;
            *out = result;
            return true;
        }
        if (arg == "--help" || arg == "-h") {
            print_help();
            result.handled = true;
            result.exit_code = 0;
            *out = result;
            return true;
        }
        if (arg == "--version") {
            print_version();
            result.handled = true;
            result.exit_code = 0;
            *out = result;
            return true;
        }
        if (arg == "--credits") {
            print_credits();
            result.handled = true;
            result.exit_code = 0;
            *out = result;
            return true;
        }
        if (arg == "--config" && i + 1 < argc) {
            result.config_context.config_path = argv[++i];
            result.config_context.config_specified = true;
        } else if (arg == "--listen" && i + 1 < argc) {
            if (!parse_listen_spec(argv[++i], cfg)) {
                return false;
            }
        } else if (arg == "--reverse-port-min" && i + 1 < argc) {
            if (!parse_port(argv[++i], "--reverse-port-min", &cfg.reverse_port_min)) return false;
        } else if (arg == "--reverse-port-max" && i + 1 < argc) {
            if (!parse_port(argv[++i], "--reverse-port-max", &cfg.reverse_port_max)) return false;
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
        } else if (arg == "--auth-keys-meta" && i + 1 < argc) {
            cfg.auth_keys_meta = resolve_cli_path(argv[++i]);
        } else if (arg == "--threads" && i + 1 < argc) {
            if (!parse_int_strict(argv[++i], &cfg.threads) || cfg.threads < 0) {
                yume::util::log_error("--threads: expected a non-negative integer");
                return false;
            }
        } else if (arg == "--obfs") {
            cfg.obfuscation = true;
            result.config_overrides.obfuscation = true;
        } else if (arg == "--no-obfs") {
            cfg.obfuscation = false;
            result.config_overrides.obfuscation = true;
        } else if (arg == "--obfs-secret" && i + 1 < argc) {
            cfg.obfs_secret = argv[++i];
        } else if (arg == "--obfs-pad-multiple" && i + 1 < argc) {
            if (!parse_obfs_pad_multiple(argv[++i], &cfg.obfs_pad_multiple)) return false;
        } else if (arg == "--obfs-jitter-ms" && i + 1 < argc) {
            if (!parse_non_negative_u32(argv[++i], "--obfs-jitter-ms", &cfg.obfs_jitter_ms)) return false;
        } else if (arg == "--tls-handshake-timeout-ms" && i + 1 < argc) {
            if (!parse_non_negative_u32(argv[++i], "--tls-handshake-timeout-ms", &cfg.tls_handshake_timeout_ms)) return false;
            result.config_overrides.tls_handshake_timeout = true;
        } else if (arg == "--max-sessions" && i + 1 < argc) {
            if (!parse_non_negative_u32(argv[++i], "--max-sessions", &cfg.max_sessions)) return false;
            result.config_overrides.max_sessions = true;
        } else if (arg == "--accept-rate-limit" && i + 1 < argc) {
            if (!parse_non_negative_u32(argv[++i], "--accept-rate-limit", &cfg.accept_rate_limit)) return false;
            result.config_overrides.accept_rate_limit = true;
        } else if (arg == "--egress-mbps" && i + 1 < argc) {
            if (!parse_non_negative_u32(argv[++i], "--egress-mbps", &cfg.egress_mbps)) return false;
            result.config_overrides.egress_mbps = true;
        } else if (arg == "--filter-list" && i + 1 < argc) {
            cfg.filter_lists.push_back(resolve_filter_list_spec_path(argv[++i], cli_cwd, ""));
        } else if (arg == "--filter-geolite" && i + 1 < argc) {
            cfg.filter_geolite = resolve_cli_path(argv[++i]);
            result.config_overrides.filter_geolite = true;
        } else if (arg == "--filter-memory-mib" && i + 1 < argc) {
            if (!parse_non_negative_u32(argv[++i], "--filter-memory-mib", &cfg.filter_memory_mib)) return false;
            result.config_overrides.filter_memory_mib = true;
        } else if (arg == "--client-filter-mode" && i + 1 < argc) {
            cfg.client_filter_mode = argv[++i];
            result.config_overrides.client_filter_mode = true;
        } else if (arg == "--egress-filter-mode" && i + 1 < argc) {
            cfg.egress_filter_mode = argv[++i];
            result.config_overrides.egress_filter_mode = true;
        } else if (arg == "--packet-egress" && i + 1 < argc) {
            cfg.packet_egress = argv[++i];
            result.config_overrides.packet_egress = true;
        } else if (arg == "--packet-tun-name" && i + 1 < argc) {
            cfg.packet_tun_name = argv[++i];
            result.config_overrides.packet_tun_name = true;
        } else if (arg == "--packet-cidr" && i + 1 < argc) {
            cfg.packet_cidr = argv[++i];
            result.config_overrides.packet_cidr = true;
        } else if (arg == "--packet-mtu" && i + 1 < argc) {
            if (!parse_non_negative_u32(argv[++i], "--packet-mtu", &cfg.packet_mtu)) return false;
            result.config_overrides.packet_mtu = true;
        } else if (arg == "--bench" || arg == "--fullbench" || arg == "--full-bench") {
            cfg.benchmark_enable = true;
        } else if (arg == "--inner") {
            yume::util::log_warn("--inner is deprecated; use --inner-heavy or --inner-light");
            cfg.inner_crypto = true;
            result.config_overrides.inner_crypto = true;
            result.inner_heavy_override = true;
            result.inner_heavy_value = true;
        } else if (arg == "--no-inner") {
            cfg.inner_crypto = false;
            cfg.inner_dual = false;
            cfg.inner_required = false;
            cfg.inner_hop = false;
            result.config_overrides.inner_crypto = true;
            result.config_overrides.inner_dual = true;
            result.config_overrides.inner_required = true;
            result.config_overrides.inner_hop = true;
            result.inner_hop_override = true;
            result.inner_hop_value = false;
        } else if (arg == "--inner-heavy") {
            cfg.inner_crypto = true;
            result.config_overrides.inner_crypto = true;
            result.inner_heavy_override = true;
            result.inner_heavy_value = true;
        } else if (arg == "--inner-light") {
            cfg.inner_crypto = true;
            result.config_overrides.inner_crypto = true;
            result.inner_heavy_override = true;
            result.inner_heavy_value = false;
        } else if (arg == "--inner-dual") {
            cfg.inner_crypto = true;
            cfg.inner_dual = true;
            result.config_overrides.inner_crypto = true;
            result.config_overrides.inner_dual = true;
        } else if (arg == "--inner-required") {
            cfg.inner_crypto = true;
            cfg.inner_required = true;
            result.config_overrides.inner_crypto = true;
            result.config_overrides.inner_required = true;
        } else if (arg == "--hop") {
            cfg.inner_hop = true;
            result.config_overrides.inner_hop = true;
            result.inner_hop_override = true;
            result.inner_hop_value = true;
        } else if (arg == "--no-hop") {
            cfg.inner_hop = false;
            result.config_overrides.inner_hop = true;
            result.inner_hop_override = true;
            result.inner_hop_value = false;
        } else if (arg == "--hop-interval" && i + 1 < argc) {
            if (!parse_non_negative_u32(argv[++i], "--hop-interval", &cfg.hop_interval_ms)) return false;
            result.config_overrides.hop_interval = true;
        } else if (arg == "--argon2-memory-budget-kib" && i + 1 < argc) {
            if (!parse_positive_u32(argv[++i], "--argon2-memory-budget-kib",
                                    &cfg.argon2_memory_budget_kib)) return false;
            result.config_overrides.argon2_memory_budget = true;
        } else if (arg == "--argon2-max-jobs" && i + 1 < argc) {
            if (!parse_positive_u32(argv[++i], "--argon2-max-jobs",
                                    &cfg.argon2_max_jobs)) return false;
            result.config_overrides.argon2_max_jobs = true;
        } else if (arg == "--pq-key" && i + 1 < argc) {
            cfg.pq_private_key = resolve_cli_path(argv[++i]);
            result.config_overrides.inner_crypto = true;
        } else if (arg == "--pq-auto-generate") {
            cfg.pq_auto_generate = true;
            result.config_overrides.pq_auto_generate = true;
        } else if (arg == "--use-embedded-master") {
            cfg.allow_embedded_master = true;
            result.config_overrides.allow_embedded_master = true;
        } else if (arg == "--no-embedded-master") {
            cfg.allow_embedded_master = false;
            result.config_overrides.allow_embedded_master = true;
        } else if (arg == "--allow-exec") {
            cfg.allow_exec = true;
        } else if (arg == "--allow-local-ip") {
            cfg.allow_local_ip = true;
        } else if (arg == "--control-full") {
            cfg.control_full = true;
        } else if ((arg == "--codec-allow" || arg == "--allow-codec") && i + 1 < argc) {
            const std::string codec = yume::app_codec::canonical_codec_id(argv[++i]);
            if (!yume::app_codec::is_supported_codec(codec)) {
                yume::util::log_error("unsupported application codec for " + arg + ": " + codec);
                return false;
            }
            yume::app_codec::add_codec_unique(&cfg.allowed_codecs, codec);
            if (codec == std::string(yume::app_codec::kMoneroRpcCodecId)) {
                cfg.allow_monero_rpc_codec = true;
            }
        } else if (arg == "--allow-monero-rpc") {
            cfg.allow_monero_rpc_codec = true;
            yume::app_codec::add_codec_unique(&cfg.allowed_codecs, yume::app_codec::kMoneroRpcCodecId);
        } else if (arg == "--service-allow" && i + 1 < argc) {
            std::string service = argv[++i];
            if (service.empty()) {
                yume::util::log_error("--service-allow requires a non-empty service name");
                return false;
            }
            cfg.allowed_services.push_back(std::move(service));
        } else if (arg == "--monero-rpc-backend" && i + 1 < argc) {
            std::string parse_error;
            auto ep = yume::app_codec::parse_endpoint_spec(
                argv[++i],
                yume::app_codec::kMoneroRpcDefaultHost,
                yume::app_codec::kMoneroRpcDefaultPort,
                &parse_error);
            if (!ep.has_value()) {
                yume::util::log_error("--monero-rpc-backend: " + parse_error);
                return false;
            }
            cfg.monero_rpc_backend_host = ep->host;
            cfg.monero_rpc_backend_port = ep->port;
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
            result.config_overrides.anonym = true;
        } else if (arg == "--anonym-proof-mode" && i + 1 < argc) {
            cfg.anonym_proof_mode = argv[++i];
            result.config_overrides.anonym_proof_mode = true;
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
            result.config_overrides.relay_enable = true;
        } else if (arg == "--relay-disable") {
            cfg.relay_enable = false;
            result.config_overrides.relay_enable = true;
        } else if (arg == "--directory-enable") {
            cfg.directory_enable = true;
            result.config_overrides.directory_enable = true;
        } else if (arg == "--directory-disable") {
            cfg.directory_enable = false;
            result.config_overrides.directory_enable = true;
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
                return false;
            }
            cfg.federation_enable = true;
        } else if (arg == "--cluster-bootstrap") {
            cfg.federation_enable = true;
            cfg.cluster_bootstrap = true;
        } else if (arg == "--public-node") {
            cfg.public_node = true;
        } else if (arg == "--host-mode" && i + 1 < argc) {
            auto mode = yume::server::host::parse_host_mode(argv[++i]);
            if (!mode.has_value()) {
                yume::util::log_error("--host-mode must be off, private, or relay");
                return false;
            }
            cfg.host_mode = *mode;
            result.config_overrides.host_mode = true;
            if (*mode == yume::server::host::HostMode::Private &&
                !result.config_overrides.accept_yume_clients) {
                cfg.accept_yume_clients = false;
            }
        } else if (arg == "--accept-yume-clients") {
            cfg.accept_yume_clients = true;
            result.config_overrides.accept_yume_clients = true;
        } else if (arg == "--no-yume-clients") {
            cfg.accept_yume_clients = false;
            result.config_overrides.accept_yume_clients = true;
        } else if ((arg == "--client-deny-action" || arg == "--deny-default") && i + 1 < argc) {
            auto action = yume::server::host::parse_deny_action(argv[++i]);
            if (!action.has_value()) {
                yume::util::log_error("--client-deny-action must be close, reset, or drop");
                return false;
            }
            cfg.client_deny_action = *action;
            result.config_overrides.client_deny_action = true;
        } else if (arg == "--exposure-check" && i + 1 < argc) {
            cfg.exposure_check_hostname = argv[++i];
            result.config_overrides.exposure_check_hostname = true;
        } else if (arg == "--hide-in-the-crowd" && i + 1 < argc) {
            cfg.http_profile = argv[++i];
        } else if (arg == "--upstream-response" && i + 1 < argc) {
            cfg.upstream_response_file = resolve_cli_path(argv[++i]);
        } else if (arg == "--upstream-response-dir" && i + 1 < argc) {
            cfg.upstream_response_dir = resolve_cli_path(argv[++i]);
        } else if (arg == "--upstream-response-ttl" && i + 1 < argc) {
            if (!parse_non_negative_u32(argv[++i], "--upstream-response-ttl",
                                        &cfg.upstream_response_ttl_s)) return false;
        } else if (arg == "--attach-local") {
            result.attach_local = true;
        } else if (arg == "--root") {
            result.keep_root = true;
        } else if (arg == "--keys-add" && i + 1 < argc) {
            result.key_command.add = argv[++i];
        } else if (arg == "--keys-remove" && i + 1 < argc) {
            result.key_command.remove = argv[++i];
        } else if (arg == "--keys-alias" && i + 2 < argc) {
            result.key_command.alias = argv[++i];
            result.key_command.alias_value = argv[++i];
        } else if (arg == "--keys-list") {
            result.key_command.list = true;
        } else if (arg == "--keys-gen" && i + 1 < argc) {
            result.key_command.generate_prefix = argv[++i];
        } else if (arg == "--keys-gen-add") {
            result.key_command.generate_and_add = true;
        } else if (arg == "--ui") {
            result.key_command.ui = true;
        } else if (arg == "--boring") {
            cfg.boring = true;
        } else if (arg == "--timing") {
            yume::util::set_timing_enabled(true);
        } else {
            yume::util::log_error("unknown or incomplete option: " + arg);
            return false;
        }
    }

    *out = result;
    return true;
}

}  // namespace yume::server_cli
