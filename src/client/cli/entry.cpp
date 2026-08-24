/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/entry.hpp"
#include "client/cli/display/anonym_proof.hpp"
#include "client/cli/config/args.hpp"
#include "client/cli/connect/auth.hpp"
#include "client/cli/commands/attach.hpp"
#include "client/cli/commands/connected_session.hpp"
#include "client/cli/connect/capabilities.hpp"
#include "client/cli/display/help.hpp"
#include "client/cli/connect/cert.hpp"
#include "client/cli/config/config.hpp"
#include "client/cli/connect/diagnostics.hpp"
#include "client/cli/config/files.hpp"
#include "client/cli/config/input.hpp"
#include "client/cli/connect/io.hpp"
#include "client/cli/connect/outer_carrier_capture.hpp"
#include "client/cli/config/platform.hpp"
#include "client/cli/commands/proxy.hpp"
#include "client/cli/commands/io_runtime.hpp"
#include "client/cli/parse/endpoints.hpp"
#include "client/cli/connect/server_info.hpp"
#include "client/cli/commands/share.hpp"
#include "client/cli/display/status.hpp"

#include <algorithm>
#include <iostream>
#include <functional>
#include <memory>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string_view>
#include <cctype>
#include <cstdint>
#include <utility>
#include <filesystem>
#include <chrono>
#include <cstdlib>
#include <thread>
#include <boost/asio/ip/address.hpp>
#if !defined(_WIN32)
#include <unistd.h>
#endif
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
#endif
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/ssl.h>

#include "client/runtime/local_runtime.hpp"
#include "client/proxy/outbound_proxy.hpp"
#include "client/relay/secret.hpp"
#include "client/relay/runtime.hpp"
#include "client/transport/tunnel.hpp"
#include "client/transport/chrome_tls_helper.hpp"
#include "core/app_codec/codec.hpp"
#include "core/security/crypto.hpp"
#include "core/security/channel_binding.hpp"
#include "core/stealth/http_profile.hpp"
#include "core/stealth/cover_profile.hpp"
#include "core/security/inner_crypto.hpp"
#include "core/stealth/obfs.hpp"
#include "core/protocol/protocol.hpp"
#include "core/protocol/protocol_stream.hpp"
#include "core/protocol/runtime_policy.hpp"
#include "core/stealth/tls_fingerprint.hpp"
#include "core/stealth/tls_stealth.hpp"
#include "core/stealth/tls_metrics.hpp"
#include "util.hpp"
#if defined(YUME_HAS_SELFTEST) && YUME_HAS_SELFTEST
#include "tools/selftest/runner.hpp"
#endif
#include <nlohmann/json.hpp>

namespace yume::client {

namespace {

constexpr const char kDefaultAnonymCaCertPath[] = "";

std::vector<std::uint8_t> parse_sha256_hex(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    if (value.size() != 64) {
        throw std::runtime_error("TLS pin must contain 64 lowercase hexadecimal characters");
    }
    auto nibble = [](char character) -> std::uint8_t {
        if (character >= '0' && character <= '9') {
            return static_cast<std::uint8_t>(character - '0');
        }
        if (character >= 'a' && character <= 'f') {
            return static_cast<std::uint8_t>(character - 'a' + 10);
        }
        throw std::runtime_error(
            "TLS pin must contain 64 lowercase hexadecimal characters");
    };
    std::vector<std::uint8_t> decoded(32);
    for (std::size_t index = 0; index < decoded.size(); ++index) {
        decoded[index] = static_cast<std::uint8_t>(
            (nibble(value[index * 2U]) << 4U) |
            nibble(value[index * 2U + 1U]));
    }
    return decoded;
}

std::string join_items(const std::vector<std::string>& items) {
    std::string out;
    for (std::size_t i = 0; i < items.size(); ++i) {
        if (i > 0) {
            out += (i + 1 == items.size()) ? " and " : ", ";
        }
        out += items[i];
    }
    return out;
}

int run_local_benchmark(const char* argv0, const ParsedArgs& args) {
#if defined(YUME_HAS_SELFTEST) && YUME_HAS_SELFTEST
    std::vector<std::string> local_args;
    local_args.emplace_back((argv0 && *argv0) ? argv0 : "yume");
    local_args.emplace_back(args.local_benchmark_full ? "--full" : "--quick");
    local_args.insert(local_args.end(), args.local_benchmark_args.begin(), args.local_benchmark_args.end());

    std::vector<char*> raw;
    raw.reserve(local_args.size() + 1);
    for (auto& item : local_args) {
        raw.push_back(item.data());
    }
    raw.push_back(nullptr);

    return yume::tools::selftest::run_cli(static_cast<int>(local_args.size()), raw.data());
#else
    (void)argv0;
    (void)args;
    util::log_error("--full-bench is a local device benchmark, but this yume binary was built without it. "
                    "Rebuild with ./ezbuild.sh --selftest or CMake -DYUME_BUILD_SELFTEST=ON.");
    return 1;
#endif
}

// ----------------------------------------------------------------------
// run_parsed() phases
// ----------------------------------------------------------------------
// run_parsed() was a single ~1350-line function mixing argument triage,
// profile installation, config resolution, transport/TLS selection, endpoint
// validation, mode selection and security-posture enforcement. Each phase
// below owns one of those decisions.
//
// The shared convention is a std::optional<int> return: nullopt means "phase
// passed, keep going", a value means "this phase is terminal, return that exit
// code". That preserves the original early-return control flow exactly rather
// than reordering checks, which matters because several of these emit
// user-visible errors in a specific order.

// Resolve and install the effective client HTTP profile. Preference order:
//   1. --hide-in-the-crowd <name> (explicit; must be a registered profile)
//   2. --profile <name> (the transport fixture registry also supplies its
//      TLS fingerprint and HTTP-layer UA)
//   3. the pinned default fixture (currently Chrome)
std::optional<int> apply_client_http_profile(const ParsedArgs& args) {
    std::string ua_profile;
    if (!args.http_profile.empty()) {
        auto p = yume::http_profile::transport_client(args.http_profile);
        if (!p.has_value()) {
            std::string supported;
            for (const auto& n : yume::http_profile::transport_client_names()) {
                if (!supported.empty()) supported += ", ";
                supported += n;
            }
            util::log_error("--hide-in-the-crowd: unknown client profile '" + args.http_profile +
                            "'. Supported: " + supported);
            return 1;
        }
        ua_profile = p->name;
        yume::http_profile::require_pinned_client_ua(p->user_agent);
    } else if (!args.tls_stealth_profile.empty()) {
        auto p = yume::http_profile::transport_client(args.tls_stealth_profile);
        if (p.has_value()) {
            ua_profile = p->name;
            yume::http_profile::require_pinned_client_ua(p->user_agent);
        }
    }
    if (!ua_profile.empty() && args.timing) {
        util::log_info("hide-in-the-crowd: active client profile = " + ua_profile);
    }
    return std::nullopt;
}

// One-shot modes that never load a client config or open a connection.
// Import in particular must dispatch as early as possible so no irrelevant
// default config is loaded first (which could prompt the user or attempt a
// local-runtime attach).
std::optional<int> handle_informational_modes(const ParsedArgs& args,
                                              const std::string& executable_arg) {
    if (args.completion) {
        if (args.completion_shell == "bash") {
            print_bash_completion();
            return 0;
        }
        util::log_error("unsupported completion shell: " + args.completion_shell);
        return 1;
    }
    if (args.share_import) {
        return run_import_share(args.share_path, args.share_password_stdin);
    }
    if (args.proxycmd) {
        const int socks_port = args.socks_port > 0 ? args.socks_port : 1080;
        return run_proxycmd(args.dest_host, args.dest_port, socks_port);
    }
    if (args.help) {
        print_help();
        return 0;
    }
    if (args.version) {
        print_version();
        return 0;
    }
    if (args.credits) {
        print_credits();
        return 0;
    }
    if (args.local_benchmark) {
        return run_local_benchmark(executable_arg.c_str(), args);
    }
    return std::nullopt;
}

// Transport profile and TLS backend admission. YUME 2.0 accepts exactly one
// transport profile and two backends; there is deliberately no silent stealth
// fallback between them.
std::optional<int> validate_transport_and_tls(const ClientConfig& cfg,
                                              const std::string& helper_tls_backend) {
    if (cfg.transport_profile != yume::kTransportProfile) {
        util::log_error(
            "YUME 0.2.0-dev6 requires transport_profile " +
            std::string(yume::kTransportProfile));
        return 1;
    }
    if (cfg.tls_backend != helper_tls_backend &&
        cfg.tls_backend != "openssl-diagnostic") {
        util::log_error(
            "tls_backend must be " + helper_tls_backend +
            " or openssl-diagnostic");
        return 1;
    }
    try {
        (void)parse_sha256_hex(cfg.tls_pin_sha256);
    } catch (const std::exception& error) {
        util::log_error(error.what());
        return 1;
    }
    if (cfg.tls_backend == helper_tls_backend) {
#if !defined(__linux__)
        util::log_error("tls_backend chrome151 currently supports Linux desktop only");
        return 1;
#elif !YUME_HAS_CHROME_TLS_HELPER
        util::log_error(
            "this build does not include the Chrome 151 TLS helper; rebuild with "
            "-DYUME_BUILD_CHROME_TLS_HELPER=ON or explicitly select "
            "tls_backend openssl-diagnostic");
        return 1;
#endif
        if (cfg.tunnel_count != 1) {
            util::log_error(
                "tls_backend chrome151 currently supports exactly one outer tunnel");
            return 1;
        }
        if (cfg.tls_fingerprint_verify) {
            util::log_error(
                "--tls-fingerprint-verify uses an unrelated OpenSSL probe and "
                "cannot verify the Chrome helper; use scripts/yume_tls_wire.py "
                "against the helper's emitted ClientHello");
            return 1;
        }
        if (cfg.tls_fingerprint_log) {
            util::log_warn(
                "legacy TLS fingerprint logging cannot observe the Chrome "
                "helper and will be skipped");
        }
    } else {
        util::log_warn(
            "TLS backend openssl-diagnostic is not Chrome ClientHello parity; "
            "there is no silent stealth fallback");
    }
    return std::nullopt;
}

bool valid_relay_endpoint_id(std::string_view value) {
    return !value.empty() && value.size() <= 255 &&
        std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return std::isalnum(c) != 0 || c == '-' || c == '_' ||
                   c == '.' || c == ':';
        });
}

bool normalize_relay_fingerprint(std::string* value) {
    if (!value || value->size() != 64 ||
        !std::all_of(value->begin(), value->end(), [](unsigned char c) {
            return std::isxdigit(c) != 0;
        })) {
        return false;
    }
    std::transform(value->begin(), value->end(), value->begin(),
                   [](unsigned char c) {
                       return static_cast<char>(std::tolower(c));
                   });
    return true;
}

// Mandatory 2.0 security posture. These are refusals, not warnings:
// carrier-off / inner-off / literal-secret configurations are rejected
// outright, and the two secret files are loaded and validated here so a bad
// file fails before any connection is attempted.
std::optional<int> validate_security_posture(ClientConfig& cfg) {
    if (cfg.relay_trust_mode != "tofu" &&
        cfg.relay_trust_mode != "pinned") {
        util::log_error("relay_trust_mode must be tofu or pinned");
        return 1;
    }
    if (cfg.relay_trust_dir.empty()) {
        util::log_error("relay_trust_dir must not be empty");
        return 1;
    }
    for (auto& [endpoint_id, fingerprint] : cfg.relay_peer_pins) {
        if (!valid_relay_endpoint_id(endpoint_id)) {
            util::log_error(
                "relay_peer_pins contains an invalid endpoint id: " +
                endpoint_id);
            return 1;
        }
        if (!normalize_relay_fingerprint(&fingerprint)) {
            util::log_error(
                "relay_peer_pins fingerprint for " + endpoint_id +
                " must be exactly 64 hexadecimal characters");
            return 1;
        }
    }
    if (!require_file("identity", cfg.identity)) {
        return 1;
    }
    if (!require_file("tls_ca_cert", cfg.tls_ca_cert)) {
        return 1;
    }
    if (!require_file("anonym_ca_cert", cfg.anonym_ca_cert)) {
        return 1;
    }
    if (!require_file("anonym_pubkey", cfg.anonym_pubkey)) {
        return 1;
    }
    if (!cfg.obfs_secret.empty()) {
        util::log_error(
            "literal obfs_secret is not accepted by YUME 2.0; use --obfs-secret-file");
        return 1;
    }
    if (cfg.obfs_secret_file.empty() || cfg.inner_psk_file.empty()) {
        util::log_error(
            "YUME 2.0 requires --obfs-secret-file and --inner-psk-file");
        return 1;
    }
    if (!cfg.obfuscation || !cfg.inner_crypto) {
        util::log_error(
            "YUME 2.0 requires the H2 carrier and mandatory inner encryption; "
            "carrier-off / inner-off configuration is not accepted");
        return 1;
    }
    if (cfg.obfs_pad_multiple != 0 || cfg.obfs_jitter_ms != 0) {
        util::log_error(
            "YUME 2.0 Chrome profile rejects configured obfs padding/jitter; "
            "the committed capture contains neither");
        return 1;
    }
    std::string profile_name = cfg.tls_stealth_profile;
    std::transform(profile_name.begin(), profile_name.end(), profile_name.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (!cfg.tls_stealth_enabled ||
        !yume::http_profile::transport_client_supported(profile_name)) {
        util::log_error(
            "YUME 2.0 requires TLS stealth and a complete transport profile fixture");
        return 1;
    }
    try {
        cfg.obfs_secret_material = std::make_shared<security::Secret32>(
            security::LoadSecretFile32(cfg.obfs_secret_file));
        cfg.inner_psk_material = std::make_shared<security::Secret32>(
            security::LoadSecretFile32(cfg.inner_psk_file));
    } catch (const std::exception& ex) {
        util::log_error(std::string("YUME 2.0 secret-file validation failed: ") + ex.what());
        return 1;
    }
    return std::nullopt;
}

}  // namespace

void Cli::set_runtime_ready_callback(RuntimeReadyCallback cb) {
    runtime_ready_callback_ = std::move(cb);
}

void Cli::set_runtime_active_callback(RuntimeActiveCallback cb) {
    runtime_active_callback_ = std::move(cb);
}

void Cli::set_external_stop_flag(std::shared_ptr<std::atomic<bool>> stop_flag) {
    external_stop_flag_ = std::move(stop_flag);
}

int Cli::run_config(ClientConfig cfg) {
    config_override_ = std::move(cfg);
    ParsedArgs args;
    args.non_interactive = true;
    args.boring = true;
    args.boring_override = true;
    args.keep_root = true;
    args.service_streams_only = true;
    return run_parsed(std::move(args), "yume");
}

int Cli::run(int argc, char** argv) {
    ParsedArgs args = parse_args(argc, argv);
    const std::string executable_arg =
        argc > 0 && argv && argv[0] ? argv[0] : "yume";
    return run_parsed(std::move(args), executable_arg);
}

int Cli::run_parsed(ParsedArgs args, std::string executable_arg) {
    util::init_logging();

    if (!args.parse_error.empty()) {
        util::log_error(args.parse_error);
        return 1;
    }
    const bool explicit_http_profile = !args.http_profile.empty();
    if (args.local_benchmark && args.bench) {
        util::log_error("--full-bench is local-only; use --bench-full for the authenticated endpoint long profile");
        return 1;
    }
    if (args.timing) {
        if constexpr (diagnostics::kTimingCompiledIn) {
            diagnostics::set_timing_enabled(true);
        } else {
            util::log_warn(
                "--timing is unavailable in production builds; use an "
                "ezbuild --dev, RelWithDebInfo, or Debug binary");
        }
    }

    if (auto code = apply_client_http_profile(args)) {
        return *code;
    }
    if (auto code = handle_informational_modes(args, executable_arg)) {
        return *code;
    }
    std::string cli_cwd;
    {
        std::error_code ec;
        auto cwd = std::filesystem::current_path(ec);
        if (!ec) {
            cli_cwd = cwd.string();
        }
    }
    std::string exe_dir;
    {
        std::string self_path = get_self_path(executable_arg.c_str());
        if (!self_path.empty()) {
            exe_dir = std::filesystem::path(self_path).parent_path().string();
        }
    }
    // In-process/API callers already supplied a parsed config and must not
    // probe the desktop default relative path. On Android that path can map
    // into SELinux-protected configfs; even desktop probes use the nonthrowing
    // error-code form in resolve_config_path().
    if (!config_override_.has_value()) {
        resolve_config_path(&args, exe_dir);
    }
    ClientConfig cfg;
    if (file_exists(kDefaultAnonymCaCertPath)) {
        cfg.anonym_ca_cert = kDefaultAnonymCaCertPath;
    }

    int reverse_listen_port = 0;
    std::string reverse_bind_host;
    std::string reverse_host;
    int reverse_port = 0;
    bool use_reverse = false;
    bool reverse_server_in_charge_auto = false;
    bool reverse_server_in_charge_manual = false;
    int reverse_auto_min_port = yume::policy::kReversePortMinDefault;
    int reverse_auto_max_port = yume::policy::kReversePortMaxDefault;
    if (!args.ssh_R.empty()) {
        SshForwardSpec spec;
        std::string parse_error;
        if (!parse_ssh_forward(args.ssh_R, spec, &parse_error)) {
            util::log_error("invalid -R syntax: " + parse_error);
            return 1;
        }
        reverse_bind_host = std::move(spec.bind_host);
        reverse_listen_port = spec.listen_port;
        reverse_host = std::move(spec.target_host);
        reverse_port = spec.target_port;
        use_reverse = true;
    }
    if (!args.ssh_L.empty()) {
        SshForwardSpec spec;
        std::string parse_error;
        if (!parse_ssh_forward(args.ssh_L, spec, &parse_error)) {
            util::log_error("invalid -L syntax: " + parse_error);
            return 1;
        }
        args.lbind_host = std::move(spec.bind_host);
        args.lport = spec.listen_port;
        args.rhost = std::move(spec.target_host);
        args.rport = spec.target_port;
    }

    if (config_override_.has_value()) {
        cfg = std::move(*config_override_);
        config_override_.reset();
        if (cfg.anonym_ca_cert.empty() && file_exists(kDefaultAnonymCaCertPath)) {
            cfg.anonym_ca_cert = kDefaultAnonymCaCertPath;
        }
    } else {
        std::string config_error;
        if (!load_client_config_file(args, exe_dir, &cfg, &config_error)) {
            util::log_error(config_error.empty()
                                ? "client config load failed"
                                : config_error);
            return 1;
        }
    }
    apply_cli_config_overrides(args, cli_cwd, &cfg);
    for (auto& secondary_identity : args.secondary_identities) {
        secondary_identity = util::resolve_path(secondary_identity, cli_cwd, "");
    }
    normalize_client_config_after_overrides(&args, &cfg);
    if (cfg.allow_exec) {
        util::log_error(
            "allow_exec=true is unavailable: inbound remote command "
            "execution is disabled until child processes have bounded "
            "shutdown support");
        return 1;
    }
    const std::string helper_tls_backend(
        yume::cover_profile::active().tls_backend);
    if (auto code = validate_transport_and_tls(cfg, helper_tls_backend)) {
        return *code;
    }
#if !defined(__linux__)
    if (!cfg.packet_tun_name.empty()) {
        util::log_error("--packet-tun is supported only on Linux");
        return 1;
    }
#endif
    if (cfg.socks_port < 0 || cfg.socks_port > 65535) {
        util::log_error("SOCKS5 port must be 0..65535");
        return 1;
    }
    if (!cfg.socks_bind_host.empty()) {
        boost::system::error_code ec;
        boost::asio::ip::make_address(cfg.socks_bind_host, ec);
        if (ec) {
            util::log_error("SOCKS5 bind address must be an IP literal");
            return 1;
        }
    }
    if (!cfg.app_codec.empty()) {
        if (!app_codec::is_supported_codec(cfg.app_codec)) {
            util::log_error("unsupported application codec: " + cfg.app_codec);
            return 1;
        }
        if (!app_codec::is_loopback_host_literal(cfg.app_codec_listen_host)) {
            util::log_error("application codec listener must be a loopback IP literal");
            return 1;
        }
        if (cfg.app_codec_listen_port < 1 || cfg.app_codec_listen_port > 65535) {
            util::log_error("application codec listen port must be 1..65535");
            return 1;
        }
    }
    if (!use_reverse && cfg.server_in_charge) {
        reverse_server_in_charge_auto = true;
        reverse_host = "127.0.0.1";
        reverse_port = 22;
        use_reverse = true;
        if (args.server_in_charge_min_port > 0) {
            reverse_auto_min_port = args.server_in_charge_min_port;
        }
        if (args.server_in_charge_max_port > 0) {
            reverse_auto_max_port = args.server_in_charge_max_port;
        }
        reverse_auto_min_port = std::clamp(reverse_auto_min_port, 1, 65535);
        reverse_auto_max_port = std::clamp(reverse_auto_max_port, 1, 65535);
        if (reverse_auto_min_port > reverse_auto_max_port) {
            std::swap(reverse_auto_min_port, reverse_auto_max_port);
        }
        if (cfg.server_in_charge_port > 0) {
            if (cfg.server_in_charge_port < yume::policy::kServerInChargeManualMinPort ||
                cfg.server_in_charge_port > yume::policy::kServerInChargeManualMaxPort) {
                util::log_error("--accept-server-control port must be " +
                                std::to_string(yume::policy::kServerInChargeManualMinPort) + "-" +
                                std::to_string(yume::policy::kServerInChargeManualMaxPort));
                return 1;
            }
            reverse_server_in_charge_manual = true;
            reverse_listen_port = cfg.server_in_charge_port;
        } else {
            reverse_listen_port = 0;
        }
    }
    const bool live_status_enabled =
        !cfg.non_interactive &&
        (args.live_status || parse_env_bool("YUME_LIVE_STATUS", false));
    util::set_status_enabled(live_status_enabled);
    if ((args.control_mode || args.list_controlled) && args.server.empty()) {
        cfg.server = "127.0.0.1";
    }
    const bool conflicting_endpoint_mode =
        !args.run_cmd.empty() || args.lport > 0 || cfg.socks_port > 0 ||
        use_reverse || args.control_mode || args.list_controlled ||
        args.directory_mode || !cfg.app_codec.empty() ||
        !args.chat_target.empty() || !args.file_target.empty() ||
        !args.bytes_target.empty() || !args.admin_target.empty() ||
        args.attach_local || args.service_streams_only || args.share_export ||
        !cfg.packet_tun_name.empty();
    if (args.bench && conflicting_endpoint_mode) {
        util::log_error("--bench/--bench-full is a one-shot endpoint mode; do not combine it with SOCKS, forwards, relay, or control modes");
        return 1;
    }
    if (!cfg.packet_tun_name.empty() &&
        (args.bench || !args.run_cmd.empty() || args.lport > 0 ||
         cfg.socks_port > 0 || use_reverse || args.control_mode ||
         args.list_controlled || args.directory_mode || !cfg.app_codec.empty() ||
         !args.chat_target.empty() || !args.file_target.empty() ||
         !args.bytes_target.empty() || !args.admin_target.empty() ||
         args.attach_local || args.service_streams_only)) {
        util::log_error("--packet-tun is an exclusive data-plane mode; do not combine it with SOCKS, forwards, relay, benchmark, or control modes");
        return 1;
    }
    const bool has_active_mode =
        args.bench ||
        !cfg.packet_tun_name.empty() ||
        (!args.run_cmd.empty()) ||
        (args.lport > 0) ||
        (cfg.socks_port > 0) ||
        use_reverse ||
        args.control_mode ||
        args.list_controlled ||
        args.directory_mode ||
        !cfg.app_codec.empty() ||
        !args.chat_target.empty() ||
        !args.file_target.empty() ||
        !args.bytes_target.empty() ||
        !args.admin_target.empty() ||
        args.attach_local ||
        args.service_streams_only ||
        args.share_export;  // export is a one-shot, not a connection
    if (!has_active_mode) {
        util::log_error("no mode selected (use --packet-tun, --full-bench, --quick-bench, --bench, --socks, --monero-rpc, -L, -R, --run, --directory, --chat, --send-file, --send-bytes, --admin-attach, --control, --attach-local, or --service-streams-only)");
        return 1;
    }

    if (!args.secondary_identities.empty()) {
        const bool plain_socks_pool =
            cfg.socks_port > 0 &&
            args.run_cmd.empty() &&
            args.exec_cmd.empty() &&
            args.lport <= 0 &&
            args.rhost.empty() &&
            args.rport <= 0 &&
            !use_reverse &&
            !args.directory_mode &&
            cfg.app_codec.empty() &&
            args.chat_target.empty() &&
            args.file_target.empty() &&
            args.bytes_target.empty() &&
            args.admin_target.empty() &&
            !args.control_mode &&
            !args.service_streams_only &&
            cfg.packet_tun_name.empty() &&
            !args.bench;
        if (!plain_socks_pool) {
            util::log_error(
                "--secondary-auth is valid only for a plain multi-tunnel "
                "SOCKS mode");
            return 1;
        }
        const auto expected = cfg.tunnel_count > 0
            ? static_cast<std::size_t>(cfg.tunnel_count - 1) : 0U;
        if (args.secondary_identities.size() != expected) {
            util::log_error(
                "--tunnels " + std::to_string(cfg.tunnel_count) +
                " requires exactly " + std::to_string(expected) +
                " --secondary-auth values");
            return 1;
        }
        for (std::size_t index = 0;
             index < args.secondary_identities.size(); ++index) {
            if (!require_file(
                    ("secondary identity " + std::to_string(index + 2)).c_str(),
                    args.secondary_identities[index])) {
                return 1;
            }
        }
    }

    if (!args.outer_carrier_evidence.empty()) {
        const OuterCarrierCapturePolicy capture_policy{
            .endpoint_bench = args.bench,
            .full_bench = args.bench_full,
            .bench_mib = args.bench_mib,
            .bench_chunk_kib = args.bench_chunk_kib,
            .bench_streams = args.bench_streams,
            .bench_direction = args.bench_direction,
            .tunnel_count = cfg.tunnel_count,
            .transport_profile = cfg.transport_profile,
            .tls_backend = cfg.tls_backend,
            .required_tls_backend = helper_tls_backend,
            .obfuscation = cfg.obfuscation,
            .non_interactive = cfg.non_interactive,
            .conflicting_mode = conflicting_endpoint_mode,
            .outbound_proxy = !cfg.outbound_proxy_url.empty(),
            .obfs_pad_multiple = cfg.obfs_pad_multiple,
            .obfs_jitter_ms = cfg.obfs_jitter_ms,
        };
        const std::string policy_error =
            ValidateOuterCarrierCapturePolicy(capture_policy);
        if (!policy_error.empty()) {
            util::log_error(policy_error);
            return 1;
        }
    }

    if (args.bench) {
        std::vector<std::string> missing;
        if (cfg.server.empty()) {
            missing.emplace_back("--server <host>");
        }
        if (cfg.identity.empty() || !file_exists(cfg.identity)) {
            missing.emplace_back("--auth <identity-key>");
        }
        if (!missing.empty()) {
            const std::string flag = args.bench_full ? "--bench-full" : "--bench";
            util::log_error(flag + " needs " + join_items(missing) +
                            ". The server must also be running yumed with --bench enabled.");
            return 1;
        }
    }
    if (auto code = validate_security_posture(cfg)) {
        return *code;
    }

    if (cfg.port != 443) {
        util::log_warn("using non-443 server port; HTTPS disguise is weaker");
    }

#if !YUME_USE_BASEFWX
    if (cfg.inner_crypto) {
        warn_security_disabled("PQ", cfg.boring);
        cfg.inner_crypto = false;
    }
#endif

    // Export uses the fully-loaded ClientConfig — runs after JSON +
    // CLI overrides have been merged, but before the local-runtime
    // attach check so an in-flight `yume` daemon doesn't get in the
    // way of a backup.
    if (args.share_export) {
        return run_export_share(args.share_path, cfg, args.share_password_stdin);
    }

    std::string save_error;
    if (!save_client_config_file(args, cfg, &save_error)) {
        util::log_error(save_error.empty()
                            ? "client config save failed"
                            : save_error);
        return 1;
    }

    if (args.exec_cmd.size() && !args.control_mode) {
        util::log_error("--exec requires --control");
        return 1;
    }
    if (args.control_mode && args.control_id.empty()) {
        util::log_error("--control requires --id");
        return 1;
    }
    if (cfg.server.empty() || cfg.identity.empty()) {
        util::log_error("--server and --auth (identity) are required");
        print_help();
        return 1;
    }
    const std::string local_instance_key = effective_client_instance_key(cfg, args);
    const std::string local_runtime_path = yume::client::LocalRuntime::socket_path_for(local_instance_key);
    const bool local_runtime_exists = yume::client::LocalRuntime::available(local_runtime_path);
    if (local_runtime_exists) {
        const bool interactive_attach =
            cfg.auto_attach_local && !cfg.non_interactive && is_tty_stdin() && prompt_attach_existing("yume");
        const bool should_attach = args.attach_local || interactive_attach;
        if (should_attach) {
            return run_local_client_attach(local_runtime_path, args, cfg);
        }
        util::log_error("yume is already running for this instance; use --attach-local to interact with it");
        return 1;
    } else if (args.attach_local) {
        util::log_error("no running yume instance was found for this configuration");
        return 1;
    }
    if (!args.keep_root) {
        std::string drop_error;
        std::string drop_summary;
        if (!util::drop_privileges(&drop_error, &drop_summary)) {
            util::log_error("failed to drop privileges: " + drop_error);
            return 1;
        }
        if (!drop_summary.empty()) {
            util::log_info(drop_summary);
        }
    }
    std::unique_ptr<OuterCarrierCapture> outer_carrier_capture;
    if (!args.outer_carrier_evidence.empty()) {
        std::string capture_error;
        outer_carrier_capture = OuterCarrierCapture::Reserve(
            args.outer_carrier_evidence, &capture_error);
        if (!outer_carrier_capture) {
            util::log_error(capture_error.empty()
                                ? "cannot reserve outer-carrier evidence"
                                : capture_error);
            return 1;
        }
    }
    const auto outer_carrier_trace = outer_carrier_capture
        ? outer_carrier_capture->trace()
        : std::shared_ptr<obfs::OuterCarrierTrace>{};
    RuntimeStopController stop_controller(args.bench);
    // Embedded runtimes have an explicit cancellation flag and must not
    // replace the embedding process's SIGINT/SIGTERM policy. Standalone CLI
    // ownership remains process-global and is scoped to stop_controller.
    if (!external_stop_flag_) {
        stop_controller.install_signal_handler();
    }
    auto external_stop_requested = [this]() {
        return external_stop_flag_ &&
               external_stop_flag_->load(std::memory_order_acquire);
    };
    auto should_stop = [&]() {
        if (!stop_controller.stop_requested() && !external_stop_requested()) {
            return false;
        }
        stop_controller.announce_stopping();
        return true;
    };
    const StopPredicate io_should_stop = [&]() {
        return stop_controller.stop_requested() || external_stop_requested();
    };
    int attempt = 0;
    bool pq_warned = false;
    bool verified_once = false;
    std::set<tls_fingerprint::BrowserProfile> tls_verification_attempted;
    std::map<tls_fingerprint::BrowserProfile, tls_fingerprint::FingerprintData>
        verified_tls_fingerprints;
    for (;;) {
        if (should_stop()) {
            return 130;
        }
        bool summary_once = false;
        std::function<std::string()> status_block_builder;
        try {
            boost::asio::io_context io(resolve_io_threads(cfg.io_threads));
            struct ActiveRuntimeGuard {
                std::function<void()> cleanup;
                ~ActiveRuntimeGuard() {
                    if (cleanup) {
                        cleanup();
                    }
                }
            } active_runtime_guard{[&stop_controller]() { stop_controller.clear_active(); }};
            
            std::unique_ptr<boost::asio::ssl::context> owned_ctx;
            boost::asio::ssl::context* ctx = nullptr;
            tls_fingerprint::BrowserProfile active_tls_profile = tls_fingerprint::BrowserProfile::UNKNOWN;
            if (cfg.tls_stealth_enabled) {
                if (cfg.tls_fingerprint_log) {
                    tls_metrics::MetricsManager::instance().initialize(cfg.tls_fingerprint_log_path);
                }

                const auto transport_profile =
                    yume::http_profile::transport_client(cfg.tls_stealth_profile);
                if (!transport_profile) {
                    throw std::runtime_error("configured transport profile fixture is unavailable");
                }
                tls_fingerprint::BrowserProfile profile = transport_profile->tls_profile;
                active_tls_profile = profile;
                if (!explicit_http_profile) {
                    if (auto selected = yume::http_profile::transport_client_for_tls_profile(profile)) {
                        yume::http_profile::require_pinned_client_ua(selected->user_agent);
                    }
                }

                tls_stealth::StealthConfig stealth_config;
                stealth_config.enabled = true;
                stealth_config.target_profile = profile;
                stealth_config.log_fingerprints = cfg.tls_fingerprint_log;
                stealth_config.log_file_path = cfg.tls_fingerprint_log_path;
                stealth_config.verify_with_external_api =
                    cfg.tls_backend == "openssl-diagnostic" &&
                    cfg.tls_fingerprint_verify;
                stealth_config.test_endpoint = cfg.tls_fingerprint_test_endpoint;

                tls_stealth::StealthManager::instance().initialize(stealth_config);

                ctx = &tls_stealth::StealthManager::instance().get_context().get_context();
            } else {
                owned_ctx = std::make_unique<boost::asio::ssl::context>(obfs::create_client_context());
                ctx = owned_ctx.get();
            }

            if (cfg.obfuscation) {
                obfs::configure_alpn(*ctx, false, true);
            }

            ctx->set_verify_mode(boost::asio::ssl::verify_peer);
            ctx->set_default_verify_paths();
            if (!cfg.tls_ca_cert.empty()) {
                ctx->load_verify_file(cfg.tls_ca_cert);
            }

            outbound_proxy::Config proxy_cfg;
            if (!cfg.outbound_proxy_url.empty()) {
                std::string parse_err;
                if (!outbound_proxy::parse_proxy_url(cfg.outbound_proxy_url, proxy_cfg, &parse_err)) {
                    throw std::runtime_error("outbound proxy: " + parse_err);
                }
            }
            const bool via_proxy = proxy_cfg.type == outbound_proxy::Type::Socks5;
            const std::string& tls_name = effective_tls_server_name(cfg);

            boost::asio::ip::tcp::socket connected_socket(io);

            if (via_proxy) {
                // Hand the hostname to the proxy verbatim — Tor needs
                // ATYP_DOMAIN to route .onion, and even for normal hosts
                // we want DNS to happen on the proxy side, never locally.
                util::log_info("client.connect: proxying through " +
                               proxy_cfg.host + ":" + std::to_string(proxy_cfg.port) +
                               " to " + cfg.server + ":" + std::to_string(cfg.port));
                diagnostics::Stopwatch connect_timer(YUME_TIMING_ENABLED());
                auto dr = outbound_proxy::socks5_dial(
                    connected_socket, io, proxy_cfg,
                    cfg.server, cfg.port, kConnectTimeout,
                    cfg.socket_protect, io_should_stop);
                if (dr.cancelled) {
                    throw std::runtime_error("connection cancelled");
                }
                if (dr.timed_out) {
                    throw std::runtime_error("server offline, proxy timed out");
                }
                if (!dr.ok) {
                    throw std::runtime_error(dr.error.empty() ? "outbound proxy failed"
                                                              : "outbound proxy: " + dr.error);
                }
                YUME_TIMING_LOG("client.connect",
                                 "proxy",
                                 "ms=" + std::to_string(
                                     connect_timer.elapsed_ns() / 1'000'000U) +
                                     " proxy=" + proxy_cfg.host + ":" +
                                     std::to_string(proxy_cfg.port) +
                                     " host=" + cfg.server +
                                     " port=" + std::to_string(cfg.port));
            } else {
                boost::asio::ip::tcp::resolver resolver(io);
                boost::asio::ip::tcp::resolver::results_type endpoints;
                diagnostics::Stopwatch resolve_timer(YUME_TIMING_ENABLED());
                const auto resolve_result = resolve_with_timeout(
                    resolver, io, cfg.server, std::to_string(cfg.port),
                    kConnectTimeout, io_should_stop);
                if (resolve_result.cancelled) {
                    throw std::runtime_error("DNS resolution cancelled");
                }
                if (resolve_result.timed_out) {
                    throw std::runtime_error(
                        "server offline, could not reach endpoint (DNS resolution timeout)");
                }
                if (resolve_result.ec) {
                    throw std::runtime_error(
                        "server offline, could not reach endpoint (DNS resolution failed: " +
                        resolve_result.ec.message() + ")");
                }
                endpoints = resolve_result.endpoints;
                std::size_t endpoint_count = 0;
                for (const auto& endpoint : endpoints) {
                    (void)endpoint;
                    ++endpoint_count;
                }
                YUME_TIMING_LOG("client.connect",
                                 "resolve",
                                 "ms=" + std::to_string(
                                     resolve_timer.elapsed_ns() / 1'000'000U) +
                                     " endpoints=" + std::to_string(endpoint_count) +
                                     " host=" + cfg.server +
                                     " port=" + std::to_string(cfg.port));
                diagnostics::Stopwatch connect_timer(YUME_TIMING_ENABLED());
                try {
                    auto cr = connect_with_timeout(
                        connected_socket, endpoints, io, kConnectTimeout,
                        cfg.socket_protect, io_should_stop);
                    if (cr.cancelled) {
                        throw std::runtime_error("connection cancelled");
                    }
                    if (cr.timed_out) {
                        throw std::runtime_error("server offline, could not reach endpoint (connect timeout)");
                    }
                    if (cr.ec) {
                        throw boost::system::system_error(cr.ec);
                    }
                } catch (const boost::system::system_error& ex) {
                    auto code = ex.code();
                    if (code == boost::asio::error::connection_refused ||
                        code == boost::asio::error::host_unreachable ||
                        code == boost::asio::error::network_unreachable ||
                        code == boost::asio::error::timed_out ||
                        code == boost::asio::error::network_down) {
                        throw std::runtime_error("server offline, could not reach endpoint");
                    }
                    throw std::runtime_error("server offline, could not reach endpoint (" + std::string(ex.what()) + ")");
                }
                YUME_TIMING_LOG("client.connect",
                                 "tcp",
                                 "ms=" + std::to_string(
                                     connect_timer.elapsed_ns() / 1'000'000U) +
                                     " host=" + cfg.server +
                                     " port=" + std::to_string(cfg.port));
            }
            boost::system::error_code keep_ec;
            connected_socket.set_option(boost::asio::socket_base::keep_alive(true), keep_ec);
            if (keep_ec) {
                util::log_warn(std::string("keepalive set failed: ") + keep_ec.message());
            }
            // This is the tunnel socket: buffers stay with the kernel so TCP
            // window autotuning can grow into the path's bandwidth-delay
            // product. Pinning either buffer sets SOCK_{RCV,SND}BUF_LOCK on
            // Linux and freezes the window for the connection's lifetime.
            // See server/session/session.cpp for the measurement.
            boost::system::error_code nodelay_ec;
            connected_socket.set_option(boost::asio::ip::tcp::no_delay(true), nodelay_ec);
            
            auto handshake_start = std::chrono::steady_clock::now();
            std::unique_ptr<ClientTransportStream> stream_owner;
            if (cfg.tls_backend == helper_tls_backend) {
                ChromeTlsHelperOptions helper_options;
                helper_options.helper_path = cfg.tls_helper_path.empty()
                    ? DiscoverChromeTlsHelper(
                          get_self_path(executable_arg.c_str()))
                    : std::filesystem::path(cfg.tls_helper_path);
                helper_options.server_name = tls_name;
                helper_options.ca_path = cfg.tls_ca_cert;
                helper_options.leaf_pin = parse_sha256_hex(cfg.tls_pin_sha256);
                helper_options.handshake_timeout = kHandshakeTimeout;
                helper_options.should_stop = io_should_stop;
                stream_owner = std::make_unique<ClientTransportStream>(
                    LaunchChromeTlsHelper(
                        io, std::move(connected_socket), helper_options));
            } else {
                ClientTransportStream::OpenSslStream tls_stream(
                    std::move(connected_socket), *ctx);
                SSL_set_tlsext_host_name(
                    tls_stream.native_handle(), tls_name.c_str());
                SSL_set1_host(tls_stream.native_handle(), tls_name.c_str());
                const auto handshake = handshake_with_timeout(
                    tls_stream, io, kHandshakeTimeout, io_should_stop);
                if (handshake.cancelled) {
                    throw std::runtime_error("TLS handshake cancelled");
                }
                if (handshake.timed_out) {
                    throw std::runtime_error("TLS handshake failed: timeout");
                }
                if (handshake.ec) {
                    const long verify_result =
                        SSL_get_verify_result(tls_stream.native_handle());
                    const std::string detail =
                        describe_verify_result(verify_result, tls_name);
                    const std::string ssl_detail = describe_openssl_error();
                    std::string message =
                        "TLS handshake failed: " + handshake.ec.message();
                    if (!detail.empty()) {
                        message += " (" + detail + ")";
                    }
                    if (!ssl_detail.empty()) {
                        message += " [" + ssl_detail + "]";
                    }
                    throw std::runtime_error(message);
                }
                const std::string fingerprint = get_peer_cert_fingerprint(
                    nullptr, tls_stream.native_handle());
                if (!cfg.tls_pin_sha256.empty() &&
                    (fingerprint.empty() || fingerprint != cfg.tls_pin_sha256)) {
                    throw std::runtime_error("TLS pin mismatch");
                }
                TlsConnectionMetadata metadata;
                metadata.alpn = obfs::selected_alpn(tls_stream.native_handle());
                metadata.leaf_fingerprint_sha256 = fingerprint;
                metadata.exporter =
                    security::ExportChannelBinding(tls_stream.native_handle());
                stream_owner = std::make_unique<ClientTransportStream>(
                    std::move(tls_stream));
                stream_owner->set_metadata(std::move(metadata));
            }
            ClientTransportStream& stream = *stream_owner;
            auto handshake_end = std::chrono::steady_clock::now();
            auto handshake_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                handshake_end - handshake_start);
            YUME_TIMING_LOG("client.connect",
                                 "tls",
                                 "ms=" + std::to_string(handshake_duration.count()) +
                                     " host=" + cfg.server +
                                     (tls_name == cfg.server ? "" : " tls_name=" + tls_name) +
                                     " port=" + std::to_string(cfg.port));
            
            const std::string server_tls_fingerprint_sha256 =
                stream.metadata().leaf_fingerprint_sha256;

            tls_fingerprint::FingerprintData fingerprint_for_metrics;
            if (cfg.tls_stealth_enabled &&
                cfg.tls_backend == "openssl-diagnostic") {
                if (cfg.tls_fingerprint_verify &&
                    tls_verification_attempted.insert(active_tls_profile).second) {
                    auto verification = tls_stealth::evaluate_tls_fingerprint(
                        cfg.tls_fingerprint_test_endpoint,
                        443,
                        active_tls_profile);
                    if (verification.success) {
                        verified_tls_fingerprints[active_tls_profile] =
                            verification.detected_fingerprint;
                        util::log_info("TLS fingerprint verified via " + cfg.tls_fingerprint_test_endpoint
                            + ": JA3=" + verification.ja3_from_server
                            + " JA4=" + verification.ja4_from_server);
                        if (!verification.matches_target_profile) {
                            const std::string observed_profile =
                                tls_fingerprint::browser_profile_name(verification.detected_fingerprint.matched_profile);
                            util::log_warn("TLS fingerprint mismatch: expected "
                                + tls_fingerprint::browser_profile_name(active_tls_profile)
                                + ", observed " + observed_profile);
                        }
                    } else {
                        util::log_warn("TLS fingerprint verification failed: " + verification.error_message);
                    }
                }

                if (auto verified = verified_tls_fingerprints.find(active_tls_profile);
                    verified != verified_tls_fingerprints.end()) {
                    fingerprint_for_metrics = verified->second;
                } else if (auto profile_info = tls_fingerprint::get_browser_profile_info(active_tls_profile);
                           profile_info.has_value()) {
                    fingerprint_for_metrics.ja3_hash = profile_info->ja3_hash;
                    fingerprint_for_metrics.ja4_hash = profile_info->ja4_hash;
                    fingerprint_for_metrics.alpn_protocols = profile_info->alpn_protocols;
                    fingerprint_for_metrics.ja3_components.tls_version = profile_info->tls_version;
                    fingerprint_for_metrics.ja3_components.cipher_suites = profile_info->cipher_suites;
                    fingerprint_for_metrics.ja3_components.extensions = profile_info->extensions;
                    fingerprint_for_metrics.ja3_components.supported_groups = profile_info->supported_groups;
                    fingerprint_for_metrics.ja3_components.ec_point_formats = profile_info->ec_point_formats;
                    fingerprint_for_metrics.ja4_components.protocol_version = "t13";
                    fingerprint_for_metrics.ja4_components.sni_present = "d";
                    fingerprint_for_metrics.ja4_components.cipher_count =
                        static_cast<uint8_t>(profile_info->cipher_suites.size());
                    fingerprint_for_metrics.ja4_components.extension_count =
                        static_cast<uint8_t>(profile_info->extensions.size());
                    fingerprint_for_metrics.ja4_components.first_alpn = profile_info->alpn_protocols.empty()
                        ? ""
                        : profile_info->alpn_protocols.front();
                    fingerprint_for_metrics.ja4_components.cipher_suites = profile_info->cipher_suites;
                    fingerprint_for_metrics.ja4_components.extensions = profile_info->extensions;
                    fingerprint_for_metrics.ja4_components.signature_algorithms = profile_info->signature_algorithms;
                    fingerprint_for_metrics.matched_profile = active_tls_profile;
                    fingerprint_for_metrics.matches_known_browser = true;
                    fingerprint_for_metrics.similarity_score = 100.0;
                }
            }

            if (cfg.tls_stealth_enabled && cfg.tls_fingerprint_log &&
                cfg.tls_backend == "openssl-diagnostic") {
                if (cfg.obfuscation) {
                    fingerprint_for_metrics.alpn_protocols = obfs::carrier_alpn_protocols(true);
                    fingerprint_for_metrics.ja4_components.first_alpn = "h2";
                }
                tls_metrics::MetricsManager::instance().record_connection_fingerprint(
                    cfg.server,
                    static_cast<uint16_t>(cfg.port),
                    fingerprint_for_metrics,
                    true,  // stealth_enabled
                    active_tls_profile,
                    true,  // handshake_succeeded
                    static_cast<uint32_t>(handshake_duration.count()),
                    ""     // error_message
                );
            }

            std::vector<uint8_t> prefetched_tls_bytes;
            std::unique_ptr<obfs::H2Carrier> h2_carrier;
            if (cfg.obfuscation) {
                util::log_info("starting HTTPS h2 carrier handshake");
                require_h2_carrier_alpn(stream, tls_name, cfg.port);
                if (outer_carrier_trace) {
                    outer_carrier_trace->SetTlsAlpn(stream.metadata().alpn);
                }
                diagnostics::Stopwatch h2_timer(YUME_TIMING_ENABLED());
                if (!cfg.obfs_secret_material) {
                    throw FatalError("YUME 2.0 admission secret was not loaded");
                }
                perform_h2_carrier_handshake(stream, io, tls_name, cfg.port,
                                             *cfg.obfs_secret_material,
                                             &prefetched_tls_bytes,
                                             &h2_carrier,
                                             outer_carrier_trace,
                                             io_should_stop);
                YUME_TIMING_LOG("client.connect",
                                 "h2_carrier",
                                 "ms=" + std::to_string(
                                     h2_timer.elapsed_ns() / 1'000'000U) +
                                     " prefetched=" + std::to_string(prefetched_tls_bytes.size()));
                util::log_info("HTTPS h2 carrier handshake established");
            }
            emit_self_dpi_report(
                cfg,
                active_tls_profile,
                fingerprint_for_metrics,
                cfg.obfuscation,
                handshake_duration);
            util::log_info("waiting for AUTH challenge");
            diagnostics::Stopwatch auth_challenge_timer(YUME_TIMING_ENABLED());
            protocol::Frame auth_challenge = read_auth_challenge(
                stream,
                io,
                tls_name,
                cfg.port,
                &prefetched_tls_bytes,
                h2_carrier.get(),
                io_should_stop);
            YUME_TIMING_LOG("client.auth",
                             "challenge",
                             "ms=" + std::to_string(
                                 auth_challenge_timer.elapsed_ns() / 1'000'000U) +
                                 " bytes=" + std::to_string(auth_challenge.payload.size()));
            util::log_info("AUTH challenge received");
            std::optional<crypto::Bytes> inner_key;
            std::optional<inner::KdfParams> inner_kdf;
            inner::KdfParams v2_kdf;
            v2_kdf.name = "hkdf";
            inner_kdf = v2_kdf;
            bool inner_disabled_for_session = false;
            bool pq_need_key = false;
            bool pq_not_supported = false;
            std::string inner_disable_reason;
            util::log_info("sending auth response");
            diagnostics::Stopwatch auth_send_timer(YUME_TIMING_ENABLED());
            if (!h2_carrier || !cfg.inner_psk_material) {
                throw FatalError("YUME 2.0 requires H2 carrier and inner PSK");
            }
            const auto ratchet_policy =
                ratchet::ResolveSecurityProfile(cfg.security_profile);
            if (!ratchet_policy.has_value()) {
                throw FatalError("invalid YUME security profile");
            }
            auto v2_ratchet = send_auth_v2_response(
                stream, io, cfg.identity, auth_challenge,
                *cfg.inner_psk_material, stream.take_exporter(),
                *h2_carrier, cfg.rekey_window,
                *ratchet_policy, cfg.admin_identity, io_should_stop);
            YUME_TIMING_LOG("client.auth",
                             "send_response",
                             "ms=" + std::to_string(
                                 auth_send_timer.elapsed_ns() / 1'000'000U));
            util::log_info("auth response sent; waiting for server confirmation");

            protocol::Frame anon_frame;
            auto server_info_timeout = kServerInfoTimeout;
            try {
                diagnostics::Stopwatch server_info_timer(YUME_TIMING_ENABLED());
                anon_frame = h2_carrier
                    ? read_frame_over_h2_with_timeout(
                          stream, io, *h2_carrier, &prefetched_tls_bytes,
                          server_info_timeout, "server info", cfg.server, cfg.port,
                          io_should_stop)
                    : read_frame_with_timeout(stream, io, server_info_timeout,
                                              "server info", cfg.server, cfg.port,
                                              true, &prefetched_tls_bytes,
                                              io_should_stop);
                YUME_TIMING_LOG("client.auth",
                                 "server_info",
                                 "ms=" + std::to_string(
                                     server_info_timer.elapsed_ns() / 1'000'000U) +
                                     " bytes=" + std::to_string(anon_frame.payload.size()));
            } catch (const FatalError&) {
                throw;
            } catch (const std::exception&) {
                throw FatalError("this endpoint is not a yume server (failed to read server info); please check the origin and try again");
            }
            anon_frame = open_auth_ok_v2(*v2_ratchet, anon_frame);
            if (anon_frame.header.type != protocol::ANON) {
                throw FatalError("this endpoint is not a yume server (unexpected response type); please check the origin and try again");
            }
            bool have_anon = false;
            bool verity_ok = false;
            bool fixcraft_ok = false;
            crypto::EVP_PKEY_ptr sub_pub{nullptr, EVP_PKEY_free};
            crypto::EVP_PKEY_ptr ca_pub{nullptr, EVP_PKEY_free};
            bool sub_ok = false;
            bool ca_ok = false;
            std::vector<std::string> announced_proof_sources;
            std::vector<std::string> verified_proof_sources;
            std::vector<std::string> server_capabilities;
            bool have_inner_caps = false;
            bool server_inner_supported = false;
            bool server_inner_required = false;
            bool server_inner_dual = false;
            bool server_inner_active = false;
            std::string server_inner_mode;
            bool server_cap_pq = false;
            bool server_cap_argon2 = false;
            bool server_cap_pbkdf2 = false;
            std::string server_version;
            std::string server_error;
            std::string mode = "normal";
            std::string hash;
            std::string sig;
            std::string ts;
            std::string nonce;
            std::string certfp;
            std::string ca_sig;
            std::string ca_alg;
            std::string sub_sig;
            std::string sub_alg;
            std::string sub_cert_b64;
            try {
                ServerInfoPayload server_info = parse_server_info_payload(anon_frame);
                server_version = std::move(server_info.version);
                server_error = std::move(server_info.error);
                mode = std::move(server_info.mode);
                hash = std::move(server_info.hash);
                sig = std::move(server_info.sig);
                ts = std::move(server_info.ts);
                nonce = std::move(server_info.nonce);
                certfp = std::move(server_info.certfp);
                ca_sig = std::move(server_info.ca_sig);
                ca_alg = std::move(server_info.ca_alg);
                sub_sig = std::move(server_info.sub_sig);
                sub_alg = std::move(server_info.sub_alg);
                sub_cert_b64 = std::move(server_info.sub_cert_b64);
                announced_proof_sources = std::move(server_info.announced_proof_sources);
                server_capabilities = std::move(server_info.capabilities);
                have_inner_caps = server_info.have_inner_caps;
                server_inner_supported = server_info.server_inner_supported;
                server_inner_required = server_info.server_inner_required;
                server_inner_dual = server_info.server_inner_dual;
                server_inner_active = server_info.server_inner_active;
                server_inner_mode = std::move(server_info.server_inner_mode);
                server_cap_pq = server_info.server_cap_pq;
                server_cap_argon2 = server_info.server_cap_argon2;
                server_cap_pbkdf2 = server_info.server_cap_pbkdf2;
            } catch (const nlohmann::json::parse_error&) {
                throw FatalError("this endpoint is not a yume server (invalid server response); please check the origin and try again");
            } catch (const std::exception& ex) {
                throw FatalError("this endpoint is not a yume server (" + std::string(ex.what()) + "); please check the origin and try again");
            }
            if (server_version.empty() || server_version == "UNKNOWN") {
                throw FatalError("this endpoint is not a yume server (no version info); please check the origin and try again");
            }
            auto sanitize_msg = [&](const std::string& msg) {
                if (!cfg.boring) {
                    return msg;
                }
                std::string out;
                out.reserve(msg.size());
                for (unsigned char c : msg) {
                    if (c >= 0x20 && c < 0x7f) {
                        out.push_back(static_cast<char>(c));
                    }
                }
                size_t start = out.find_first_not_of(' ');
                if (start == std::string::npos) {
                    return std::string{};
                }
                size_t end = out.find_last_not_of(' ');
                return out.substr(start, end - start + 1);
            };
            auto print_red = [&](const std::string& msg) {
                std::string out = sanitize_msg(msg);
                if (out.empty()) {
                    return;
                }
                std::cerr << "\033[1;31m" << out << "\033[0m" << std::endl;
            };
            auto print_green = [&](const std::string& msg) {
                std::string out = sanitize_msg(msg);
                if (out.empty()) {
                    return;
                }
                std::cout << "\033[1;32m" << out << "\033[0m" << std::endl;
            };
            if (!server_error.empty()) {
                print_red(server_error);
                if (inner_disabled_for_session &&
                    server_error.find("requires inner") != std::string::npos &&
                    !inner_disable_reason.empty()) {
                    print_red(inner_disable_reason);
                }
                return 1;
            }
            util::log_info("authenticated to server");
            ServerCapabilityInput capability_input;
            capability_input.server_version = server_version;
            capability_input.server_inner_mode = server_inner_mode;
            if (inner_kdf.has_value()) {
                capability_input.inner_kdf_name = inner_kdf->name;
            }
            capability_input.inner_crypto_requested = true;
            capability_input.inner_disabled_for_session = inner_disabled_for_session;
            capability_input.inner_heavy = false;
            capability_input.have_inner_caps = have_inner_caps;
            capability_input.server_inner_supported = server_inner_supported;
            capability_input.server_inner_required = server_inner_required;
            capability_input.server_inner_dual = server_inner_dual;
            capability_input.server_cap_pq = server_cap_pq;
            capability_input.server_cap_argon2 = server_cap_argon2;
            capability_input.server_cap_pbkdf2 = server_cap_pbkdf2;

            ServerCapabilityResult capability = evaluate_server_capabilities(capability_input);
            if (!capability.error.empty()) {
                print_red(capability.error);
                return 1;
            }

            if (mode == "anonym") {
                AnonymProofInput proof_input;
                proof_input.announced_proof_sources = announced_proof_sources;
                proof_input.hash = hash;
                proof_input.sig = sig;
                proof_input.ts = ts;
                proof_input.nonce = nonce;
                proof_input.certfp = certfp;
                proof_input.ca_sig = ca_sig;
                proof_input.sub_sig = sub_sig;
                proof_input.sub_cert_b64 = sub_cert_b64;
                proof_input.anonym_pubkey = cfg.anonym_pubkey;
                proof_input.anonym_ca_cert = cfg.anonym_ca_cert;
                proof_input.peer_cert_fingerprint =
                    stream.metadata().leaf_fingerprint_sha256;
                proof_input.initial_sub_ok = sub_ok;
                proof_input.initial_ca_ok = ca_ok;

                AnonymProofResult proof = verify_anonym_proof(proof_input);
                if (!proof.error_lines.empty()) {
                    for (const auto& line : proof.error_lines) {
                        print_red(line);
                    }
                    return 1;
                }
                fixcraft_ok = proof.fixcraft_ok;
                sub_ok = proof.sub_ok;
                ca_ok = proof.ca_ok;
                if (proof.sub_pub) {
                    sub_pub = std::move(proof.sub_pub);
                }
                if (proof.ca_pub) {
                    ca_pub = std::move(proof.ca_pub);
                }
                verified_proof_sources = std::move(proof.verified_proof_sources);
                if (!proof.operator_ca_subject.empty()) {
                    util::log_info("operator CA subject: " + proof.operator_ca_subject);
                }
                if (!proof.operator_ca_fingerprint_sha256.empty()) {
                    util::log_info("operator CA SHA-256: " + proof.operator_ca_fingerprint_sha256);
                }
                if (!proof.delegated_subject.empty()) {
                    util::log_info("delegated server subject: " + proof.delegated_subject);
                    util::log_info("delegated server issuer: " + proof.delegated_issuer);
                    util::log_info("delegated server serial: " + proof.delegated_serial);
                    util::log_info("delegated server SHA-256: " +
                                   proof.delegated_fingerprint_sha256);
                }
                verity_ok = fixcraft_ok || ca_ok || sub_ok;
                if (!verified_once) {
                    print_green("Operator identity verified by trusted authority");
                    verified_once = true;
                } else {
                    print_green("Operator identity re-verified");
                }
            } else {
                if (cfg.require_anonym) {
                    print_red("CRITICAL ERROR");
                    print_red("SERVER DID NOT PROVIDE REQUIRED OPERATOR IDENTITY PROOF");
                    return 1;
                }
                if (!cfg.accept_monitoring && !args.bench) {
                    print_red("CRITICAL WARNING");
                    print_red("This server operator can observe your traffic metadata.");
                    if (args.non_interactive) {
                        print_red(
                            "Non-interactive clients must set accept_monitoring=true "
                            "or require a server authorized by the selected operator CA.");
                        return 1;
                    }
                    print_red("Type \"I understand the privacy risk\" to continue.");
                    std::string line;
                    std::getline(std::cin, line);
                    auto normalize = [](std::string s) {
                        auto is_space = [](unsigned char ch) { return std::isspace(ch) != 0; };
                        while (!s.empty() && is_space(static_cast<unsigned char>(s.front()))) {
                            s.erase(s.begin());
                        }
                        while (!s.empty() && is_space(static_cast<unsigned char>(s.back()))) {
                            s.pop_back();
                        }
                        std::transform(s.begin(), s.end(), s.begin(),
                                       [](unsigned char ch) { return static_cast<char>(std::toupper(ch)); });
                        return s;
                    };
                    if (normalize(line) != "I UNDERSTAND THE PRIVACY RISK") {
                        return 1;
                    }
                }
            }
            have_anon = true;
            verity_ok = (mode == "anonym") && (fixcraft_ok || ca_ok || sub_ok);
            if (inner_disabled_for_session) {
                if (!pq_warned) {
                    warn_security_disabled("PQ", cfg.boring);
                    if (pq_not_supported) {
                        util::log_warn("PQ not supported in this build; refusing insecure downgrade");
                    } else if (pq_need_key) {
                        util::log_warn("PQ public key not configured; refusing insecure downgrade");
                    }
                    pq_warned = true;
                }
                if (!inner_disable_reason.empty()) {
                    print_red(inner_disable_reason);
                }
                print_red("inner crypto was requested but could not be established; refusing downgraded session");
                return 1;
            }
            if (have_anon && !summary_once) {
                ConnectionStatusSummary summary;
                summary.server = cfg.server;
                if (tls_name != cfg.server) {
                    summary.server += " (tls: " + tls_name + ")";
                }
                summary.version = server_version;
                if (inner_kdf.has_value()) {
                    summary.inner_kdf_name = inner_kdf->name;
                }
                summary.verified_proof_sources = verified_proof_sources;
                summary.obfuscation_enabled = cfg.obfuscation;
                summary.inner_established = v2_ratchet != nullptr;
                summary.inner_heavy = false;
                summary.have_inner_caps = have_inner_caps;
                summary.server_inner_dual = server_inner_dual;
                summary.server_inner_active = server_inner_active;
                summary.verity_applicable = (mode == "anonym");
                summary.verity_ok = verity_ok;
                if (v2_ratchet) {
                    const auto policy = v2_ratchet->outbound_policy();
                    summary.epoch_byte_limit = policy.epoch_byte_limit;
                    summary.epoch_frame_limit = policy.epoch_frame_limit;
                    summary.epoch_active_limit_ms =
                        static_cast<std::uint64_t>(
                            policy.epoch_active_limit.count());
                }
                status_block_builder = make_connection_status_block(std::move(summary));
                if (!live_status_enabled) {
                    // When embedded via facade::InProcClient the GUI
                    // sets silent_ to suppress this banner — the same
                    // information is already surfaced in the GUI's
                    // status panes via the runtime_ready callback +
                    // status() polling.
                    if (!silent_) {
                        std::cout << status_block_builder();
                    }
                } else {
                    util::set_status_line(status_block_builder());
                }
                summary_once = true;
            }

            ConnectedSessionOptions connected_options;
            connected_options.args = &args;
            connected_options.cfg = &cfg;
            connected_options.local_runtime_path = local_runtime_path;
            connected_options.argv0 = executable_arg;
            connected_options.use_reverse = use_reverse;
            connected_options.reverse_server_in_charge_auto = reverse_server_in_charge_auto;
            connected_options.reverse_server_in_charge_manual = reverse_server_in_charge_manual;
            connected_options.reverse_bind_host = reverse_bind_host;
            connected_options.reverse_listen_port = reverse_listen_port;
            connected_options.reverse_host = reverse_host;
            connected_options.reverse_port = reverse_port;
            connected_options.reverse_auto_min_port = reverse_auto_min_port;
            connected_options.reverse_auto_max_port = reverse_auto_max_port;
            connected_options.live_status_enabled = live_status_enabled;
            connected_options.silent = silent_;
            connected_options.have_inner_caps = have_inner_caps;
            connected_options.server_inner_dual = server_inner_dual;
            connected_options.server_inner_active = server_inner_active;
            connected_options.inner_kdf = inner_kdf;
            connected_options.inner_key = inner_key;
            connected_options.ratchet = std::move(v2_ratchet);
            connected_options.h2_carrier = std::move(h2_carrier);
            connected_options.outer_carrier_trace = outer_carrier_trace;
            connected_options.prefetched_carrier_bytes =
                std::move(prefetched_tls_bytes);
            connected_options.server_tls_fingerprint_sha256 =
                server_tls_fingerprint_sha256;
            connected_options.explicit_http_profile = explicit_http_profile;
            connected_options.server_capabilities = std::move(server_capabilities);
            connected_options.status_block_builder = status_block_builder;
            connected_options.should_stop = io_should_stop;
            connected_options.announce_stopping = [&stop_controller]() {
                stop_controller.announce_stopping();
            };
            connected_options.set_active_runtime =
                [this, &stop_controller](boost::asio::io_context* io_ptr,
                                         const std::shared_ptr<Tunnel>& tunnel_ptr,
                                         const std::shared_ptr<RelayRuntime>& relay_ptr,
                                         std::function<void(const std::string&)> disconnect_fn) {
                    auto embedder_disconnect = disconnect_fn;
                    stop_controller.set_active(io_ptr, tunnel_ptr, relay_ptr, std::move(disconnect_fn));
                    if (runtime_active_callback_) {
                        runtime_active_callback_(io_ptr, tunnel_ptr, relay_ptr, std::move(embedder_disconnect));
                    }
                };
            connected_options.take_runtime_ready_callback = [this]() {
                return std::exchange(runtime_ready_callback_, {});
            };

            const int connected_code = run_connected_session(
                io,
                *ctx,
                std::move(stream),
                proxy_cfg,
                std::move(connected_options),
                stop_controller.stop_flag());
            if (outer_carrier_capture) {
                std::string capture_error;
                if (!outer_carrier_capture->Finalize(
                        connected_code == 0, &capture_error)) {
                    util::log_error(
                        capture_error.empty()
                            ? "outer-carrier evidence is incomplete"
                            : capture_error);
                    return connected_code == 0 ? 1 : connected_code;
                }
            }
            return connected_code;
        } catch (const FatalError& ex) {
            if (should_stop()) {
                return 130;
            }
            util::log_error(ex.what());
            return 1;
        } catch (const std::exception& ex) {
            if (should_stop()) {
                return 130;
            }
            if (outer_carrier_capture) {
                util::log_error(
                    std::string("outer-carrier capture failed: ") + ex.what());
                return 1;
            }
            std::shared_ptr<RelayRuntime> relay_ptr = stop_controller.active_relay_runtime();
            if ((args.non_interactive || !relay_ptr) && looks_like_endpoint_down(ex.what())) {
                util::log_error("endpoint appears down (" + cfg.server + ":" +
                                std::to_string(cfg.port) + "): " + ex.what());
                return 1;
            }
            if (args.service_streams_only) {
                util::log_error(std::string("connection failed: ") + ex.what());
                return 1;
            }
            if (relay_ptr) {
                std::string lifecycle_error;
                relay_ptr->notify_error(ex.what(), "connection_failed", &lifecycle_error);
            }
            attempt++;
            int backoff = std::min(30, 1 << std::min(attempt, 5));
            util::log_warn(std::string("connection failed: ") + ex.what());
            util::log_warn("retrying in " + std::to_string(backoff) + "s");
            for (int i = 0; i < backoff * 10; ++i) {
                if (should_stop()) {
                    return 130;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }
}

}  // namespace yume::client
