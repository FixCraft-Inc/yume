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
#include "client/cli/config/platform.hpp"
#include "client/cli/connect/pq_bootstrap.hpp"
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
#include <optional>
#include <stdexcept>
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
#include "core/app_codec/codec.hpp"
#include "core/security/crypto.hpp"
#include "core/stealth/http_profile.hpp"
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
constexpr int kSocketBufferBytes = 2 * 1024 * 1024;

constexpr const char kDefaultAnonymCaCertPath[] = "";

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
    util::log_error("--fullbench is a local device benchmark, but this yume binary was built without it. "
                    "Rebuild with ./ezbuild.sh --selftest or CMake -DYUME_BUILD_SELFTEST=ON.");
    return 1;
#endif
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

int Cli::run(int argc, char** argv) {
    util::init_logging();

    ParsedArgs args = parse_args(argc, argv);
    if (!args.parse_error.empty()) {
        util::log_error(args.parse_error);
        return 1;
    }
    if (args.local_benchmark && args.bench) {
        util::log_error("--fullbench is local-only; use --bench-full for the authenticated endpoint long profile");
        return 1;
    }
    if (args.timing) {
        util::set_timing_enabled(true);
    }

    // Resolve the effective client HTTP profile, then install it.
    // Order of preference:
    //   1. --hide-in-the-crowd <name> (explicit; must be a registered
    //      client profile)
    //   2. --profile <chrome|firefox|safari> (existing flag for the
    //      TLS-layer JA3; we mirror it at the HTTP-layer UA when no
    //      explicit --hide-in-the-crowd was given, so the two stay
    //      consistent)
    //   3. default ("yume", current pre-1.0 behavior)
    {
        std::string ua_profile;
        if (!args.http_profile.empty()) {
            auto p = yume::http_profile::client(args.http_profile);
            if (!p.has_value()) {
                std::string supported;
                for (const auto& n : yume::http_profile::client_names()) {
                    if (!supported.empty()) supported += ", ";
                    supported += n;
                }
                util::log_error("--hide-in-the-crowd: unknown client profile '" + args.http_profile +
                                "'. Supported: " + supported);
                return 1;
            }
            ua_profile = p->name;
            yume::http_profile::set_active_client_ua(p->user_agent);
        } else if (!args.tls_stealth_profile.empty()) {
            auto p = yume::http_profile::client(args.tls_stealth_profile);
            if (p.has_value()) {
                ua_profile = p->name;
                yume::http_profile::set_active_client_ua(p->user_agent);
            }
        }
        if (!ua_profile.empty() && args.timing) {
            util::log_info("hide-in-the-crowd: active client profile = " + ua_profile);
        }
    }
    if (args.completion) {
        if (args.completion_shell == "bash") {
            print_bash_completion();
            return 0;
        }
        util::log_error("unsupported completion shell: " + args.completion_shell);
        return 1;
    }
    // Import is config-less — reads only the share-file. Dispatch as
    // early as possible so we don't load any irrelevant default config
    // first (which could prompt the user, attempt local-runtime
    // attach, etc).
    if (args.share_import) {
        return run_import_share(args.share_path, args.share_password_stdin);
    }
    if (args.proxycmd) {
        int socks_port = args.socks_port > 0 ? args.socks_port : 1080;
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
        return run_local_benchmark(argv[0], args);
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
        std::string self_path = get_self_path(argv[0]);
        if (!self_path.empty()) {
            exe_dir = std::filesystem::path(self_path).parent_path().string();
        }
    }
    resolve_config_path(&args, exe_dir);
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

    load_client_config_file(args, exe_dir, &cfg);
    apply_cli_config_overrides(args, cli_cwd, &cfg);
    normalize_client_config_after_overrides(&args, &cfg);
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
                util::log_error("--server-in-charge port must be " +
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
    if (args.bench &&
        ((!args.run_cmd.empty()) ||
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
         args.share_export)) {
        util::log_error("--bench/--bench-full is a one-shot endpoint mode; do not combine it with SOCKS, forwards, relay, or control modes");
        return 1;
    }
    const bool has_active_mode =
        args.bench ||
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
        util::log_error("no mode selected (use --fullbench, --quickbench, --bench, --socks, --monero-rpc, -L, -R, --run, --directory, --chat, --send-file, --send-bytes, --admin-attach, --control, --attach-local, or --service-streams-only)");
        return 1;
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
    discover_default_pq_public_key(argv[0], &cfg);
    if (args.bench && cfg.inner_crypto && !cfg.pq_public_key.empty() && !file_exists(cfg.pq_public_key)) {
        util::log_warn("configured pq_public_key is missing; benchmark will try signed PQ auto-bootstrap");
        cfg.pq_public_key.clear();
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
    if (!args.bench && !require_file("pq_public_key", cfg.pq_public_key)) {
        return 1;
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

    save_client_config_file(args, cfg);

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
    RuntimeStopController stop_controller(args.bench);
    stop_controller.install_signal_handler();
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
    int attempt = 0;
    bool pq_warned = false;
    bool pq_reconnect_used = false;
    bool verified_once = false;
    bool tls_fingerprint_verification_attempted = false;
    std::optional<tls_fingerprint::FingerprintData> verified_tls_fingerprint;
    for (;;) {
        if (should_stop()) {
            return 130;
        }
        bool summary_once = false;
        std::function<std::string()> status_block_builder;
        try {
            boost::asio::io_context io(resolve_io_threads(cfg.io_threads));
            stop_controller.set_active(&io, nullptr);
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

                tls_fingerprint::BrowserProfile profile = tls_fingerprint::BrowserProfile::CHROME_135;
                std::string profile_lower = cfg.tls_stealth_profile;
                std::transform(profile_lower.begin(), profile_lower.end(), profile_lower.begin(), ::tolower);

                if (profile_lower == "chrome" || profile_lower == "chrome135" || profile_lower == "chrome_135") {
                    profile = tls_fingerprint::BrowserProfile::CHROME_135;
                } else if (profile_lower == "firefox" || profile_lower == "firefox126" || profile_lower == "firefox_126") {
                    profile = tls_fingerprint::BrowserProfile::FIREFOX_126;
                } else if (profile_lower == "safari" || profile_lower == "safari17" || profile_lower == "safari_17") {
                    profile = tls_fingerprint::BrowserProfile::SAFARI_17;
                }
                active_tls_profile = profile;

                tls_stealth::StealthConfig stealth_config;
                stealth_config.enabled = true;
                stealth_config.target_profile = profile;
                stealth_config.rotate_profiles = cfg.tls_stealth_rotate;
                stealth_config.rotation_interval_connections = cfg.tls_stealth_rotation_interval;
                stealth_config.log_fingerprints = cfg.tls_fingerprint_log;
                stealth_config.log_file_path = cfg.tls_fingerprint_log_path;
                stealth_config.verify_with_external_api = cfg.tls_fingerprint_verify;
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

            boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(io, *ctx);

            if (via_proxy) {
                // Hand the hostname to the proxy verbatim — Tor needs
                // ATYP_DOMAIN to route .onion, and even for normal hosts
                // we want DNS to happen on the proxy side, never locally.
                util::log_info("client.connect: proxying through " +
                               proxy_cfg.host + ":" + std::to_string(proxy_cfg.port) +
                               " to " + cfg.server + ":" + std::to_string(cfg.port));
                auto connect_start = std::chrono::steady_clock::now();
                auto dr = outbound_proxy::socks5_dial(
                    stream.next_layer(), io, proxy_cfg,
                    cfg.server, cfg.port, kConnectTimeout);
                if (dr.timed_out) {
                    throw std::runtime_error("server offline, proxy timed out");
                }
                if (!dr.ok) {
                    throw std::runtime_error(dr.error.empty() ? "outbound proxy failed"
                                                              : "outbound proxy: " + dr.error);
                }
                auto connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - connect_start).count();
                util::log_timing("client.connect",
                                 "proxy",
                                 "ms=" + std::to_string(connect_ms) +
                                     " proxy=" + proxy_cfg.host + ":" +
                                     std::to_string(proxy_cfg.port) +
                                     " host=" + cfg.server +
                                     " port=" + std::to_string(cfg.port));
            } else {
                boost::asio::ip::tcp::resolver resolver(io);
                boost::asio::ip::tcp::resolver::results_type endpoints;
                auto resolve_start = std::chrono::steady_clock::now();
                try {
                    endpoints = resolver.resolve(boost::asio::ip::tcp::v4(), cfg.server, std::to_string(cfg.port));
                } catch (const boost::system::system_error& ex) {
                    throw std::runtime_error("server offline, could not reach endpoint (DNS resolution failed: " + std::string(ex.what()) + ")");
                }
                auto resolve_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - resolve_start).count();
                std::size_t endpoint_count = 0;
                for (const auto& endpoint : endpoints) {
                    (void)endpoint;
                    ++endpoint_count;
                }
                util::log_timing("client.connect",
                                 "resolve",
                                 "ms=" + std::to_string(resolve_ms) +
                                     " endpoints=" + std::to_string(endpoint_count) +
                                     " host=" + cfg.server +
                                     " port=" + std::to_string(cfg.port));
                auto connect_start = std::chrono::steady_clock::now();
                try {
                    auto cr = connect_with_timeout(stream.next_layer(), endpoints, io, kConnectTimeout);
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
                auto connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - connect_start).count();
                util::log_timing("client.connect",
                                 "tcp",
                                 "ms=" + std::to_string(connect_ms) +
                                     " host=" + cfg.server +
                                     " port=" + std::to_string(cfg.port));
            }
            boost::system::error_code keep_ec;
            stream.next_layer().set_option(boost::asio::socket_base::keep_alive(true), keep_ec);
            if (keep_ec) {
                util::log_warn(std::string("keepalive set failed: ") + keep_ec.message());
            }
            boost::system::error_code recvbuf_ec;
            stream.next_layer().set_option(boost::asio::socket_base::receive_buffer_size(kSocketBufferBytes), recvbuf_ec);
            boost::system::error_code sendbuf_ec;
            stream.next_layer().set_option(boost::asio::socket_base::send_buffer_size(kSocketBufferBytes), sendbuf_ec);
            boost::system::error_code nodelay_ec;
            stream.next_layer().set_option(boost::asio::ip::tcp::no_delay(true), nodelay_ec);
            SSL_set_tlsext_host_name(stream.native_handle(), tls_name.c_str());
            SSL_set1_host(stream.native_handle(), tls_name.c_str());
            
            auto handshake_start = std::chrono::steady_clock::now();
            boost::system::error_code hs_ec;
            {
                auto hr = handshake_with_timeout(stream, io, kHandshakeTimeout);
                if (hr.timed_out) {
                    throw std::runtime_error("TLS handshake failed: timeout");
                }
                hs_ec = hr.ec;
            }
            auto handshake_end = std::chrono::steady_clock::now();
            auto handshake_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                handshake_end - handshake_start);
            util::log_timing("client.connect",
                                 "tls",
                                 "ms=" + std::to_string(handshake_duration.count()) +
                                     " host=" + cfg.server +
                                     (tls_name == cfg.server ? "" : " tls_name=" + tls_name) +
                                     " port=" + std::to_string(cfg.port));
            
            if (hs_ec) {
                long vr = SSL_get_verify_result(stream.native_handle());
                std::string detail = describe_verify_result(vr, tls_name);
                std::string ssl_detail = describe_openssl_error();
                std::string msg = "TLS handshake failed: " + hs_ec.message();
                if (!detail.empty()) {
                    msg += " (" + detail + ")";
                }
                if (!ssl_detail.empty()) {
                    msg += " [" + ssl_detail + "]";
                }
                throw std::runtime_error(msg);
            }
            const std::string server_tls_fingerprint_sha256 =
                get_peer_cert_fingerprint(nullptr, stream.native_handle());
            if (!cfg.tls_pin_sha256.empty()) {
                if (server_tls_fingerprint_sha256.empty() ||
                    server_tls_fingerprint_sha256 != cfg.tls_pin_sha256) {
                    throw std::runtime_error("TLS pin mismatch");
                }
            }

            tls_fingerprint::FingerprintData fingerprint_for_metrics;
            if (cfg.tls_stealth_enabled) {
                if (cfg.tls_fingerprint_verify && !tls_fingerprint_verification_attempted) {
                    auto verification = tls_stealth::evaluate_tls_fingerprint(
                        cfg.tls_fingerprint_test_endpoint,
                        443,
                        active_tls_profile);
                    tls_fingerprint_verification_attempted = true;
                    if (verification.success) {
                        verified_tls_fingerprint = verification.detected_fingerprint;
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

                if (verified_tls_fingerprint.has_value()) {
                    fingerprint_for_metrics = *verified_tls_fingerprint;
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

            if (cfg.tls_stealth_enabled && cfg.tls_fingerprint_log) {
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
            if (cfg.obfuscation) {
                util::log_info("starting HTTPS h2 carrier handshake");
                require_h2_carrier_alpn(stream, tls_name, cfg.port);
                auto h2_start = std::chrono::steady_clock::now();
                perform_h2_carrier_handshake(stream, io, tls_name, cfg.port,
                                             cfg.obfs_secret, &prefetched_tls_bytes);
                auto h2_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - h2_start).count();
                util::log_timing("client.connect",
                                 "h2_carrier",
                                 "ms=" + std::to_string(h2_ms) +
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
            auto auth_challenge_start = std::chrono::steady_clock::now();
            protocol::Frame auth_challenge = read_auth_challenge(
                stream,
                io,
                tls_name,
                cfg.port,
                &prefetched_tls_bytes);
            auto auth_challenge_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - auth_challenge_start).count();
            util::log_timing("client.auth",
                             "challenge",
                             "ms=" + std::to_string(auth_challenge_ms) +
                                 " bytes=" + std::to_string(auth_challenge.payload.size()));
            util::log_info("AUTH challenge received");
            inner::Argon2Limits server_argon2_limits =
                parse_auth_challenge_argon2_limits(auth_challenge);
            const bool server_advertised_argon2_limits =
                server_argon2_limits.time_max > 0 ||
                server_argon2_limits.memory_max > 0 ||
                server_argon2_limits.parallelism_max > 0;
            if (server_advertised_argon2_limits) {
                util::log_info("server Argon2 caps: " + describe_argon2_limits(server_argon2_limits));
            }

            inner::Config inner_cfg;
            inner_cfg.enabled = cfg.inner_crypto;
            inner_cfg.pq_public_key = cfg.pq_public_key;
            inner_cfg.allow_embedded_master = cfg.allow_embedded_master;
            inner_cfg.argon2_limits = server_argon2_limits;

            std::optional<crypto::Bytes> pq_ciphertext;
            std::optional<crypto::Bytes> pq_salt;
            std::optional<crypto::Bytes> inner_key;
            std::optional<std::string> inner_mode;
            std::optional<bool> inner_hop;
            std::optional<inner::KdfParams> inner_kdf;
            bool inner_disabled_for_session = false;
            bool pq_need_key = false;
            bool pq_not_supported = false;
            std::string inner_disable_reason;
            if (inner_cfg.enabled) {
                try {
                    if (cfg.inner_heavy) {
                        util::log_info("preparing inner crypto (heavy KDF); this can take a few seconds");
                    } else {
                        util::log_info("preparing inner crypto");
                    }
                    auto inner_start = std::chrono::steady_clock::now();
                    auto hs = inner::client_prepare(inner_cfg, cfg.inner_heavy);
                    auto inner_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - inner_start).count();
                    if (!hs.enabled || hs.key.empty()) {
                        throw std::runtime_error("inner crypto init failed");
                    }
                    util::log_timing("client.auth",
                                     "inner_prepare",
                                     "ms=" + std::to_string(inner_ms) +
                                         " mode=" + std::string(cfg.inner_heavy ? "heavy" : "light") +
                                         " kdf=" + (hs.kdf.empty() ? std::string("unknown") : hs.kdf));
                    pq_ciphertext = hs.pq_ciphertext;
                    pq_salt = hs.salt;
                    inner_key = hs.key;
                    inner_mode = cfg.inner_heavy ? std::optional<std::string>("heavy") : std::optional<std::string>("light");
                    if (!hs.kdf.empty()) {
                        inner::KdfParams params;
                        params.name = hs.kdf;
                        params.argon2_time = hs.argon2_time;
                        params.argon2_memory = hs.argon2_memory;
                        params.argon2_parallelism = hs.argon2_parallelism;
                        params.pbkdf2_iters = hs.pbkdf2_iters;
                        inner_kdf = params;
                    }
                    std::string prepared = "inner crypto prepared: mode=" +
                                           std::string(cfg.inner_heavy ? "heavy" : "light") +
                                           ", kdf=" + (hs.kdf.empty() ? std::string("unknown") : hs.kdf);
                    if (hs.kdf == "argon2") {
                        prepared += " time=" + std::to_string(hs.argon2_time) +
                                    " mem=" + std::to_string(hs.argon2_memory) +
                                    " par=" + std::to_string(hs.argon2_parallelism);
                    } else if (hs.kdf == "pbkdf2") {
                        prepared += " iters=" + std::to_string(hs.pbkdf2_iters);
                    }
                    util::log_info(prepared);
                } catch (const std::exception& ex) {
                    std::string msg = ex.what();
                    if (msg.find("PQ public key not configured") != std::string::npos) {
                        pq_need_key = true;
                        inner_disabled_for_session = true;
                        inner_disable_reason =
                            "inner crypto disabled: PQ public key not configured (use --pq-pub, provide pq_public.key, or enable --use-embedded-master)";
                    } else if (msg.find("ML-KEM-768 support is not enabled") != std::string::npos) {
                        pq_not_supported = true;
                        inner_disabled_for_session = true;
                        inner_disable_reason =
                            "inner crypto disabled: PQ not supported in this build (rebuild with liboqs/BaseFWX PQ enabled)";
                    } else {
                        throw;
                    }
                }
            }
            if (pq_ciphertext.has_value()) {
                inner_hop = cfg.inner_hop;
            }

            util::log_info("sending auth response");
            auto auth_send_start = std::chrono::steady_clock::now();
            send_auth_response(stream,
                               cfg.identity,
                               auth_challenge,
                               pq_ciphertext,
                               pq_salt,
                               inner_mode,
                               inner_hop,
                               inner_kdf);
            auto auth_send_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - auth_send_start).count();
            util::log_timing("client.auth",
                             "send_response",
                             "ms=" + std::to_string(auth_send_ms));
            util::log_info("auth response sent; waiting for server confirmation");

            protocol::Frame anon_frame;
            auto server_info_timeout = kServerInfoTimeout;
            if (pq_ciphertext.has_value() && cfg.inner_crypto) {
                server_info_timeout = cfg.inner_heavy ? kServerInfoTimeoutInnerHeavy : kServerInfoTimeoutInner;
            }
            try {
                auto server_info_start = std::chrono::steady_clock::now();
                anon_frame = read_frame_with_timeout(stream, io, server_info_timeout, "server info", cfg.server, cfg.port, true);
                auto server_info_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - server_info_start).count();
                util::log_timing("client.auth",
                                 "server_info",
                                 "ms=" + std::to_string(server_info_ms) +
                                     " bytes=" + std::to_string(anon_frame.payload.size()));
            } catch (const FatalError&) {
                throw;
            } catch (const std::exception&) {
                throw FatalError("this endpoint is not a yume server (failed to read server info); please check the origin and try again");
            }
            if (anon_frame.header.type != protocol::ANON) {
                throw FatalError("this endpoint is not a yume server (unexpected response type); please check the origin and try again");
            }
            bool pq_reconnect = false;
            bool have_anon = false;
            bool verity_ok = false;
            bool fixcraft_ok = false;
            crypto::EVP_PKEY_ptr sub_pub{nullptr, EVP_PKEY_free};
            crypto::EVP_PKEY_ptr ca_pub{nullptr, EVP_PKEY_free};
            bool sub_ok = false;
            bool ca_ok = false;
            std::vector<std::string> announced_proof_sources;
            std::vector<std::string> verified_proof_sources;
            bool have_inner_caps = false;
            bool server_inner_supported = false;
            bool server_inner_required = false;
            bool server_inner_dual = false;
            bool server_inner_active = false;
            std::string server_inner_mode;
            bool server_cap_pq = false;
            bool server_cap_argon2 = false;
            bool server_cap_pbkdf2 = false;
            bool server_hop_enabled = false;
            std::uint32_t server_hop_interval_ms = 0;
            std::int64_t server_time_ms = 0;
            std::string server_version;
            std::string server_error;
            std::string mode = "normal";
            std::uint32_t hop_interval_ms = 0;
            std::int64_t hop_offset_ms = 0;
            bool hop_enabled = false;
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
            std::string pq_pub_b64;
            std::string pq_sig;
            std::string pq_alg;
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
                pq_pub_b64 = std::move(server_info.pq_pub_b64);
                pq_sig = std::move(server_info.pq_sig);
                pq_alg = std::move(server_info.pq_alg);
                announced_proof_sources = std::move(server_info.announced_proof_sources);
                have_inner_caps = server_info.have_inner_caps;
                server_inner_supported = server_info.server_inner_supported;
                server_inner_required = server_info.server_inner_required;
                server_inner_dual = server_info.server_inner_dual;
                server_inner_active = server_info.server_inner_active;
                server_inner_mode = std::move(server_info.server_inner_mode);
                server_cap_pq = server_info.server_cap_pq;
                server_cap_argon2 = server_info.server_cap_argon2;
                server_cap_pbkdf2 = server_info.server_cap_pbkdf2;
                server_hop_enabled = server_info.server_hop_enabled;
                server_hop_interval_ms = server_info.server_hop_interval_ms;
                server_time_ms = server_info.server_time_ms;
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
            bool allow_pq_bootstrap = server_error.empty() ||
                                      server_error.find("requires inner") != std::string::npos ||
                                      server_error.find("pq key") != std::string::npos ||
                                      (cfg.inner_crypto &&
                                       !pq_pub_b64.empty() &&
                                       server_error.find("invalid key") != std::string::npos);
            PqBootstrapInput pq_bootstrap_input;
            pq_bootstrap_input.allow_bootstrap = allow_pq_bootstrap;
            pq_bootstrap_input.inner_crypto_requested = cfg.inner_crypto;
            pq_bootstrap_input.pq_not_supported = pq_not_supported;
            pq_bootstrap_input.pq_need_key = pq_need_key;
            pq_bootstrap_input.pq_pub_b64 = pq_pub_b64;
            pq_bootstrap_input.pq_sig_b64 = pq_sig;
            pq_bootstrap_input.cert_fingerprint = certfp;
            if (allow_pq_bootstrap && !pq_pub_b64.empty() && !certfp.empty() && !pq_sig.empty()) {
                pq_bootstrap_input.peer_cert_fingerprint = get_peer_cert_fingerprint(nullptr, stream.native_handle());
            }
            pq_bootstrap_input.sub_cert_b64 = sub_cert_b64;
            pq_bootstrap_input.anonym_ca_cert = cfg.anonym_ca_cert;

            PqBootstrapState pq_bootstrap_state;
            pq_bootstrap_state.pq_public_key = cfg.pq_public_key;
            pq_bootstrap_state.pq_reconnect = pq_reconnect;
            pq_bootstrap_state.pq_reconnect_used = pq_reconnect_used;
            pq_bootstrap_state.sub_ok = sub_ok;
            pq_bootstrap_state.ca_ok = ca_ok;
            pq_bootstrap_state.sub_pub = std::move(sub_pub);
            pq_bootstrap_state.ca_pub = std::move(ca_pub);
            pq_bootstrap_state = maybe_auto_trust_pq(pq_bootstrap_input, std::move(pq_bootstrap_state));
            cfg.pq_public_key = std::move(pq_bootstrap_state.pq_public_key);
            pq_reconnect = pq_bootstrap_state.pq_reconnect;
            pq_reconnect_used = pq_bootstrap_state.pq_reconnect_used;
            sub_ok = pq_bootstrap_state.sub_ok;
            ca_ok = pq_bootstrap_state.ca_ok;
            sub_pub = std::move(pq_bootstrap_state.sub_pub);
            ca_pub = std::move(pq_bootstrap_state.ca_pub);

            if (!server_error.empty()) {
                if (pq_reconnect) {
                    util::log_info("PQ public key received; reconnecting to enable inner crypto");
                    attempt++;
                    continue;
                }
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
            capability_input.inner_crypto_requested = cfg.inner_crypto;
            capability_input.inner_disabled_for_session = inner_disabled_for_session;
            capability_input.inner_heavy = cfg.inner_heavy;
            capability_input.inner_hop = cfg.inner_hop;
            capability_input.inner_key_established = inner_key.has_value();
            capability_input.have_inner_caps = have_inner_caps;
            capability_input.server_inner_supported = server_inner_supported;
            capability_input.server_inner_required = server_inner_required;
            capability_input.server_inner_dual = server_inner_dual;
            capability_input.server_cap_pq = server_cap_pq;
            capability_input.server_cap_argon2 = server_cap_argon2;
            capability_input.server_cap_pbkdf2 = server_cap_pbkdf2;
            capability_input.server_hop_enabled = server_hop_enabled;
            capability_input.client_hop_interval_ms = cfg.hop_interval_ms;
            capability_input.server_hop_interval_ms = server_hop_interval_ms;
            capability_input.server_time_ms = server_time_ms;

            ServerCapabilityResult capability = evaluate_server_capabilities(capability_input);
            if (!capability.error.empty()) {
                print_red(capability.error);
                return 1;
            }
            hop_interval_ms = capability.hop_interval_ms;
            hop_offset_ms = capability.hop_offset_ms;
            hop_enabled = capability.hop_enabled;

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
                proof_input.peer_cert_fingerprint = get_peer_cert_fingerprint(nullptr, stream.native_handle());
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
                verity_ok = fixcraft_ok || ca_ok || sub_ok;
                if (!verified_once) {
                    print_green("Verified");
                    verified_once = true;
                } else {
                    print_green("Server Verified");
                }
            } else {
                if (cfg.require_anonym) {
                    print_red("CRITICAL ERROR");
                    print_red("SERVER IS NOT IN ANONYM MODE");
                    return 1;
                }
                if (!args.accept_monitoring && !args.bench) {
                    print_red("CRITICAL WARNING");
                    print_red("This server operator can observe your traffic metadata.");
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
            if (pq_reconnect) {
                util::log_info("PQ public key received; reconnecting to enable inner crypto");
                attempt++;
                continue;
            }
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
                summary.hop = {hop_enabled, hop_interval_ms, hop_offset_ms};
                summary.obfuscation_enabled = cfg.obfuscation;
                summary.inner_established = inner_key.has_value();
                summary.inner_heavy = cfg.inner_heavy;
                summary.have_inner_caps = have_inner_caps;
                summary.server_inner_dual = server_inner_dual;
                summary.server_inner_active = server_inner_active;
                summary.verity_ok = verity_ok;
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
                    if (hop_enabled) {
                        util::log_info("live hop updates are disabled; use --live-status (or YUME_LIVE_STATUS=1) to update periodically");
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
            connected_options.argv0 = argv[0] ? argv[0] : "";
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
            connected_options.hop_enabled = hop_enabled;
            connected_options.hop_interval_ms = hop_interval_ms;
            connected_options.hop_offset_ms = hop_offset_ms;
            connected_options.inner_kdf = inner_kdf;
            connected_options.inner_key = inner_key;
            connected_options.server_tls_fingerprint_sha256 =
                server_tls_fingerprint_sha256;
            connected_options.status_block_builder = status_block_builder;
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

            return run_connected_session(
                io,
                *ctx,
                std::move(stream),
                proxy_cfg,
                std::move(connected_options),
                stop_controller.stop_flag());
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
