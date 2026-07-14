/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/startup_checks.hpp"

#include "core/stealth/http_profile.hpp"
#include "core/app_codec/codec.hpp"
#include "core/protocol/runtime_policy.hpp"
#include "core/stealth/tls_fingerprint.hpp"
#include "core/stealth/tls_stealth.hpp"
#include "server/cli/key.hpp"
#include "server/config/config.hpp"
#include "server/filter/ip_filter.hpp"
#include "server/host/host_types.hpp"
#include "util.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/ip/address.hpp>

#if !defined(_WIN32)
#include <sys/stat.h>
#endif

namespace yume::server_cli {
namespace {

bool require_readable(const char* label, const std::string& path) {
    if (path.empty()) {
        return true;
    }
    if (!file_readable(path)) {
        yume::util::log_error(std::string(label) + " not found: " + path);
        return false;
    }
    return true;
}

bool validate_required_files(const yume::server::ServerConfig& cfg, bool key_management_only) {
    if (key_management_only) {
        return true;
    }
    return require_readable("tls_cert", cfg.tls_cert) &&
           require_readable("tls_key", cfg.tls_key) &&
           require_readable("auth_keys", cfg.auth_keys) &&
           require_readable("pq_private_key", cfg.pq_private_key) &&
           require_readable("real_index_path", cfg.real_index_path) &&
           require_readable("real_secret_file", cfg.real_secret_file) &&
           require_readable("anonym_ca_key", cfg.anonym_ca_key) &&
           require_readable("anonym_ca_cert", cfg.anonym_ca_cert) &&
           require_readable("anonym_sub_key", cfg.anonym_sub_key) &&
           require_readable("anonym_sub_cert", cfg.anonym_sub_cert) &&
           require_readable("federation_auth_key", cfg.federation_auth_key) &&
           require_readable("federation_anonym_ca", cfg.federation_anonym_ca);
}

bool validate_http_profile(const yume::server::ServerConfig& cfg) {
    if (cfg.http_profile.empty()) {
        return true;
    }
    if (yume::http_profile::server(cfg.http_profile).has_value()) {
        return true;
    }
    std::string supported;
    for (const auto& n : yume::http_profile::server_names()) {
        if (!supported.empty()) {
            supported += ", ";
        }
        supported += n;
    }
    yume::util::log_error("--hide-in-the-crowd: unknown server profile '" + cfg.http_profile +
                          "'. Supported: " + supported);
    return false;
}

bool validate_filters(const yume::server::ServerConfig& cfg) {
    if (!yume::server::IpFilter::parse_mode(cfg.client_filter_mode).has_value()) {
        yume::util::log_error("--client-filter-mode must be blacklist or whitelist");
        return false;
    }
    if (!yume::server::IpFilter::parse_mode(cfg.egress_filter_mode).has_value()) {
        yume::util::log_error("--egress-filter-mode must be blacklist or whitelist");
        return false;
    }
    for (const auto& spec : cfg.filter_lists) {
        std::string parse_error;
        if (!yume::server::IpFilter::parse_list_spec(spec, &parse_error).has_value()) {
            yume::util::log_error("--filter-list " + spec + ": " + parse_error);
            return false;
        }
    }
    return true;
}

bool validate_packet_egress(const yume::server::ServerConfig& cfg) {
    if (cfg.packet_egress.empty() || cfg.packet_egress == "off" || cfg.packet_egress == "none") {
        return true;
    }
    if (cfg.packet_egress != "tun") {
        yume::util::log_error("--packet-egress supports only 'tun' in v1");
        return false;
    }
    if (cfg.packet_tun_name.empty()) {
        yume::util::log_error("--packet-tun-name must not be empty");
        return false;
    }
    if (cfg.packet_mtu < 576 || cfg.packet_mtu > 65535) {
        yume::util::log_error("--packet-mtu must be in range 576..65535");
        return false;
    }
    yume::util::log_info("packet-native egress requested: tun=" + cfg.packet_tun_name +
                         " cidr=" + cfg.packet_cidr +
                         " mtu=" + std::to_string(cfg.packet_mtu) +
                         ". The TUN address/NAT must be prepared by the operator before startup.");
    return true;
}

bool validate_app_codecs(const yume::server::ServerConfig& cfg) {
    if (cfg.allowed_codecs.empty()) {
        return true;
    }
    for (const auto& codec_id : cfg.allowed_codecs) {
        auto codec = yume::app_codec::builtin_codec(codec_id);
        if (!codec.has_value()) {
            yume::util::log_error("unsupported application codec enabled: " + codec_id);
            return false;
        }
        if (codec->id == std::string(yume::app_codec::kMoneroRpcCodecId)) {
            if (!yume::app_codec::is_loopback_host_literal(cfg.monero_rpc_backend_host)) {
                yume::util::log_error("monero-rpc codec backend must be a loopback IP literal, got " +
                                      cfg.monero_rpc_backend_host);
                return false;
            }
            if (cfg.monero_rpc_backend_port < 1 || cfg.monero_rpc_backend_port > 65535) {
                yume::util::log_error("monero-rpc codec backend port must be 1..65535");
                return false;
            }
            yume::util::log_info("application codec enabled: " + codec->id + " -> " +
                                 cfg.monero_rpc_backend_host + ":" +
                                 std::to_string(cfg.monero_rpc_backend_port) +
                                 " (per-key " + codec->permission_key + " or allow_codecs is still required)");
        } else {
            yume::util::log_info("application codec enabled: " + codec->id);
        }
    }
    return true;
}

bool validate_host_controller(const yume::server::ServerConfig& cfg) {
    if (cfg.host_mode == yume::server::host::HostMode::Off &&
        (!cfg.host_routes.empty() || !cfg.extra_listeners.empty())) {
        yume::util::log_error("routes/listeners require host_mode private or relay");
        return false;
    }
    for (const auto& route : cfg.host_routes) {
        std::string error;
        if (!yume::server::host::backend_is_loopback_only(route.backend, &error)) {
            yume::util::log_error("host route backend invalid: " + error);
            return false;
        }
    }
    for (const auto& listener : cfg.extra_listeners) {
        if (listener.bind_port < 1 || listener.bind_port > 65535) {
            yume::util::log_error("extra listener bind port out of range");
            return false;
        }
        if (!listener.bind_address.empty()) {
            boost::system::error_code addr_ec;
            boost::asio::ip::make_address(listener.bind_address, addr_ec);
            if (addr_ec) {
                yume::util::log_error("extra listener bind address must be an IP literal: " +
                                      listener.bind_address);
                return false;
            }
        }
        if (listener.backend.empty()) {
            yume::util::log_error("extra listener requires backend");
            return false;
        }
        std::string error;
        if (!yume::server::host::backend_is_loopback_only(listener.backend, &error)) {
            yume::util::log_error("extra listener backend invalid: " + error);
            return false;
        }
    }
    if (cfg.host_mode == yume::server::host::HostMode::Private && cfg.accept_yume_clients) {
        yume::util::log_error("host_mode private requires accept_yume_clients=false; use host_mode relay for YUME clients");
        return false;
    }
    if (cfg.host_mode == yume::server::host::HostMode::Relay && !cfg.accept_yume_clients) {
        yume::util::log_error("host_mode relay requires accept_yume_clients=true");
        return false;
    }
    return true;
}

bool load_upstream_response(yume::server::ServerConfig& cfg) {
    if (cfg.upstream_response_file.empty()) {
        return true;
    }

    // Load the captured response once at startup. Normalise lone \n into
    // \r\n so operators who captured with `curl -i` still produce valid
    // HTTP wire bytes when we replay. Already-\r\n stays unchanged.
    std::ifstream in(cfg.upstream_response_file, std::ios::binary);
    if (!in) {
        yume::util::log_error("--upstream-response: cannot open " + cfg.upstream_response_file);
        return false;
    }
    std::stringstream ss;
    ss << in.rdbuf();
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
        return false;
    }
    cfg.upstream_response_bytes = std::move(normalized);
    yume::util::log_info("--upstream-response: loaded " +
                         std::to_string(cfg.upstream_response_bytes.size()) +
                         " bytes from " + cfg.upstream_response_file +
                         " (replayed verbatim to non-yume probes)");
    return true;
}

bool validate_upstream_response_dir(const yume::server::ServerConfig& cfg) {
    if (cfg.upstream_response_dir.empty()) {
        return true;
    }
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::is_directory(cfg.upstream_response_dir, ec)) {
        yume::util::log_error("--upstream-response-dir: " + cfg.upstream_response_dir +
                              " is not a directory");
        return false;
    }
    if (!cfg.upstream_response_file.empty()) {
        yume::util::log_warn("--upstream-response-dir overrides --upstream-response " +
                             cfg.upstream_response_file + " (single-file capture will be ignored)");
    }
    return true;
}

bool private_public_node_bind(const boost::asio::ip::address& addr, std::string* reason) {
    if (addr.is_loopback()) {
        if (reason) {
            *reason = "loopback (127.0.0.0/8 or ::1)";
        }
        return true;
    }
    if (addr.is_unspecified()) {
        return false;
    }
    if (addr.is_v4()) {
        const auto bytes = addr.to_v4().to_bytes();
        const uint32_t ip = (uint32_t(bytes[0]) << 24) | (uint32_t(bytes[1]) << 16) |
                            (uint32_t(bytes[2]) << 8) | uint32_t(bytes[3]);
        if ((ip & 0xFF000000u) == 0x0A000000u) {
            if (reason) *reason = "RFC 1918 (10.0.0.0/8)";
            return true;
        }
        if ((ip & 0xFFF00000u) == 0xAC100000u) {
            if (reason) *reason = "RFC 1918 (172.16.0.0/12)";
            return true;
        }
        if ((ip & 0xFFFF0000u) == 0xC0A80000u) {
            if (reason) *reason = "RFC 1918 (192.168.0.0/16)";
            return true;
        }
        if ((ip & 0xFFFF0000u) == 0xA9FE0000u) {
            if (reason) *reason = "link-local (169.254.0.0/16)";
            return true;
        }
        if ((ip & 0xFFC00000u) == 0x64400000u) {
            if (reason) *reason = "CGNAT (100.64.0.0/10)";
            return true;
        }
        return false;
    }
    const auto v6 = addr.to_v6();
    if (v6.is_link_local()) {
        if (reason) {
            *reason = "IPv6 link-local (fe80::/10)";
        }
        return true;
    }
    const auto bytes = v6.to_bytes();
    if ((bytes[0] & 0xFE) == 0xFC) {
        if (reason) {
            *reason = "IPv6 ULA (fc00::/7)";
        }
        return true;
    }
    return false;
}

bool apply_public_node_defaults(yume::server::ServerConfig& cfg,
                                const StartupCheckOptions& options) {
    if (!cfg.public_node) {
        return true;
    }

    // --public-node is the internet-facing preset: disguise defaults,
    // stricter bind checks, and hard failures for dangerous capabilities.
    if (cfg.http_profile.empty()) {
        cfg.http_profile = "nginx";
        yume::util::log_info("--public-node: defaulting --hide-in-the-crowd to 'nginx' (pass --hide-in-the-crowd <profile> to override)");
    }
    if (!options.tls_handshake_timeout_overridden && cfg.tls_handshake_timeout_ms == 0) {
        cfg.tls_handshake_timeout_ms = 10000;
        yume::util::log_info("--public-node: defaulting --tls-handshake-timeout-ms to 10000 (pass --tls-handshake-timeout-ms 0 to disable)");
    }
    if (!options.max_sessions_overridden && cfg.max_sessions == 0) {
        cfg.max_sessions = 4096;
        yume::util::log_info("--public-node: defaulting --max-sessions to 4096 (pass --max-sessions <N> to override; 0 = unlimited)");
    }
    if (!options.accept_rate_limit_overridden && cfg.accept_rate_limit == 0) {
        cfg.accept_rate_limit = 100;
        yume::util::log_info("--public-node: defaulting --accept-rate-limit to 100/s (pass --accept-rate-limit <N> to override; 0 = unlimited)");
    }

    if (!cfg.listen_address.empty()) {
        boost::system::error_code addr_ec;
        auto addr = boost::asio::ip::make_address(cfg.listen_address, addr_ec);
        if (addr_ec) {
            yume::util::log_error("--public-node: --listen address '" +
                                  cfg.listen_address + "' does not parse: " +
                                  addr_ec.message());
            return false;
        }
        std::string reason;
        if (private_public_node_bind(addr, &reason)) {
            yume::util::log_error("--public-node: refusing to bind --listen " +
                                  cfg.listen_address + " (" + reason +
                                  "). A public node must not bind to a private/loopback range. "
                                  "Either drop --public-node, or set --listen to a public address (or just the port).");
            return false;
        }
        yume::util::log_info("--public-node: --listen " + cfg.listen_address +
                             " passes private-range check");
    }

#ifndef _WIN32
    const mode_t prior = umask(0077);
    yume::util::log_info(
        std::string("--public-node: process umask set to 0077 (was 0") +
        std::to_string(prior >> 6 & 7) +
        std::to_string(prior >> 3 & 7) +
        std::to_string(prior & 7) +
        "); subsequent secret files and IPC socket will be 0600/0700");
#endif

    std::vector<std::string> violations;
    if (!cfg.obfuscation) {
        violations.emplace_back("--no-obfs is forbidden by --public-node (the HTTP/2 carrier must be the outer visible layer)");
    }
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
    if (!cfg.inner_required) {
        violations.emplace_back("--public-node requires --inner-required (clients without inner crypto must be rejected)");
    }
    if (cfg.auth_keys.empty()) {
        violations.emplace_back("--public-node requires --auth-keys to be set (otherwise the daemon accepts no clients, or worse, accepts everyone if you later loosen this)");
    }
    if (!violations.empty()) {
        yume::util::log_error("--public-node violations:");
        for (const auto& v : violations) {
            yume::util::log_error("  - " + v);
        }
        return false;
    }
    yume::util::log_info("--public-node active; the following protections are enforced at startup:");
    yume::util::log_info("  - HTTP/2 carrier obfuscation required (--no-obfs rejected)");
    yume::util::log_info("  - dangerous capability flags (--allow-exec / --allow-local-ip / --control-full) are rejected");
    yume::util::log_info("  - inner crypto required (no plaintext transport)");
    yume::util::log_info("  - --auth-keys required (no anonymous-relay accidents)");
    yume::util::log_info("  - Argon2 has per-derivation caps plus bounded aggregate memory/jobs");
    yume::util::log_info("  - private-IP bind refusal (--listen explicit-addr in RFC 1918 / loopback / link-local / ULA → startup error)");
    yume::util::log_info("  - TLS handshake deadline (--tls-handshake-timeout-ms; default 10s, slow-loris guard)");
    yume::util::log_info("  - accept-side rate-limit + max-concurrent-session cap (--accept-rate-limit 100/s, --max-sessions 4096)");
    yume::util::log_info("  - process umask locked to 0077 (secret files + IPC socket land at 0600/0700)");
    return true;
}

void log_obfs_tuning(const yume::server::ServerConfig& cfg) {
    if (cfg.obfs_pad_multiple > 0) {
        yume::util::log_info("--obfs-pad-multiple " + std::to_string(cfg.obfs_pad_multiple) +
                             ": every outbound frame payload is padded to a multiple of this size. "
                             "Connecting clients MUST run a yume build that knows kFlagPadded (>= 1.0 post-padding); "
                             "older clients will fail to parse the stream.");
    }
    if (cfg.obfs_jitter_ms > 0) {
        yume::util::log_info("--obfs-jitter-ms " + std::to_string(cfg.obfs_jitter_ms) +
                             ": each batched write is deferred by 0.." +
                             std::to_string(cfg.obfs_jitter_ms) +
                             " ms. Adds latency, breaks the constant-cadence ML signature.");
    }
}

void log_security_warnings(const yume::server::ServerConfig& cfg) {
    if (!cfg.obfuscation) {
        yume::util::log_warn("Security warning: HTTP/2 carrier obfuscation disabled; AUTH starts directly after TLS.");
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
}

void log_effective_startup_summary(const yume::server::ServerConfig& cfg) {
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
    yume::util::log_info("Argon2 admission: aggregate-memory-kib=" +
                         std::to_string(cfg.argon2_memory_budget_kib) +
                         "; max-jobs=" + std::to_string(cfg.argon2_max_jobs));
    yume::util::log_info("effective carrier: " +
                         std::string(cfg.obfuscation ? "http2-obfs" : "raw-tls") +
                         "; server disguise: " +
                         (cfg.http_profile.empty() ? std::string("yumed") : cfg.http_profile));
    if (cfg.benchmark_enable) {
        yume::util::log_info("authenticated benchmark endpoint enabled for yume --bench");
    }
}

void run_ja3_self_check() {
    // Baselines captured 2026-05 on the build-host build (OpenSSL 3.5,
    // Debian 13). Drift here means a dependency/profile edit may have
    // changed the daemon's browser-cluster fingerprint.
    struct Baseline {
        yume::tls_fingerprint::BrowserProfile profile;
        const char* name;
        const char* expected_ja3;
    };
    constexpr Baseline kBaselines[] = {
        {yume::tls_fingerprint::BrowserProfile::CHROME_131, "chrome", "51dc1deffb716cb50b5b0e5449c4e28f"},
        {yume::tls_fingerprint::BrowserProfile::FIREFOX_126, "firefox", "b2f1f8aa44e9d9510358e21055e2a3c2"},
        {yume::tls_fingerprint::BrowserProfile::SAFARI_18, "safari", "96244ebd33ea0991b081300f27a9a6b3"},
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

bool load_real_http_secret(yume::server::ServerConfig& cfg, const std::string& default_secret_path) {
    if (!cfg.real_http || !cfg.real_secret.empty()) {
        return true;
    }
    const std::string secret_path = cfg.real_secret_file.empty() ? default_secret_path : cfg.real_secret_file;
    try {
        cfg.real_secret = load_or_create_secret(secret_path);
    } catch (const std::exception& ex) {
        yume::util::log_error(std::string("failed to load real_secret: ") + ex.what());
        return false;
    }
    return true;
}

}  // namespace

bool prepare_server_startup_config(yume::server::ServerConfig& cfg,
                                   const StartupCheckOptions& options) {
    if (cfg.argon2_memory_budget_kib == 0 || cfg.argon2_max_jobs == 0) {
        yume::util::log_error(
            "Argon2 admission limits must be positive; use "
            "--argon2-memory-budget-kib and --argon2-max-jobs");
        return false;
    }
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
    if ((cfg.allow_exec || cfg.allow_local_ip || cfg.control_full ||
         !cfg.allowed_codecs.empty() || !cfg.allowed_services.empty()) &&
        cfg.auth_keys_meta.empty()) {
        yume::util::log_warn(
            "privileged server feature enabled but no auth_keys_meta is configured; "
            "no key will inherit these permissions until you create the meta file and grant per-key access "
            "(see docs/PERMISSIONS.md)");
    }
    if (cfg.federation_enable &&
        (cfg.federation_auth_key.empty() || cfg.federation_anonym_ca.empty())) {
        yume::util::log_error("federation requires --federation-auth-key and --federation-anonym-ca");
        return false;
    }
    if (cfg.federation_enable && !cfg.cluster_bootstrap && cfg.federation_peers.empty()) {
        yume::util::log_error("federation requires at least one --peer or --cluster-join; pass --cluster-bootstrap if this node is a cluster entry point");
        return false;
    }

    if (!validate_http_profile(cfg) ||
        !validate_filters(cfg) ||
        !validate_packet_egress(cfg) ||
        !validate_app_codecs(cfg) ||
        !validate_host_controller(cfg) ||
        !load_upstream_response(cfg) ||
        !validate_upstream_response_dir(cfg)) {
        return false;
    }
    log_obfs_tuning(cfg);

    if (!apply_public_node_defaults(cfg, options)) {
        return false;
    }
    if (!validate_required_files(cfg, options.key_management_only)) {
        return false;
    }
    if (options.key_management_only) {
        return true;
    }

    log_security_warnings(cfg);
    log_effective_startup_summary(cfg);
    run_ja3_self_check();
    return load_real_http_secret(cfg, options.default_secret_path);
}

}  // namespace yume::server_cli
