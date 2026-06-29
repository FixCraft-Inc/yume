/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/config/args.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>

#include "util.hpp"

namespace yume::client {
namespace {

bool parse_int_strict(std::string_view text, int& out) {
    if (text.empty()) {
        return false;
    }
    int value = 0;
    auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc() || ptr != text.data() + text.size()) {
        return false;
    }
    out = value;
    return true;
}

bool parse_u32_strict(std::string_view text, std::uint32_t& out) {
    if (text.empty()) {
        return false;
    }
    unsigned long long value = 0;
    auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc() || ptr != text.data() + text.size()) {
        return false;
    }
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }
    out = static_cast<std::uint32_t>(value);
    return true;
}

bool parse_cluster_spec(const std::string& spec, std::string* host, int* port, std::string* err) {
    if (spec.empty()) {
        if (err) *err = "--cluster argument is empty";
        return false;
    }
    std::string h;
    int p = 443;
    if (spec.front() == '[') {
        auto close = spec.find(']');
        if (close == std::string::npos) {
            if (err) *err = "--cluster: unmatched '[' in " + spec;
            return false;
        }
        h = spec.substr(1, close - 1);
        if (close + 1 < spec.size()) {
            if (spec[close + 1] != ':') {
                if (err) *err = "--cluster: expected ':port' after ']' in " + spec;
                return false;
            }
            try {
                p = std::stoi(spec.substr(close + 2));
            } catch (const std::exception&) {
                if (err) *err = "--cluster: invalid port in " + spec;
                return false;
            }
        }
    } else {
        auto colon = spec.rfind(':');
        if (colon == std::string::npos) {
            h = spec;
        } else {
            h = spec.substr(0, colon);
            try {
                p = std::stoi(spec.substr(colon + 1));
            } catch (const std::exception&) {
                if (err) *err = "--cluster: invalid port in " + spec;
                return false;
            }
        }
    }
    if (h.empty()) {
        if (err) *err = "--cluster: empty host in " + spec;
        return false;
    }
    if (p <= 0 || p > 65535) {
        if (err) *err = "--cluster: port out of range in " + spec;
        return false;
    }
    *host = std::move(h);
    *port = p;
    return true;
}

}  // namespace

ParsedArgs parse_args(int argc, char** argv) {
    ParsedArgs args;
    int i = 1;
    auto take_value = [&](const std::string& flag) -> const char* {
        if (i + 1 >= argc) {
            args.parse_error = "missing value for " + flag;
            return nullptr;
        }
        return argv[++i];
    };
    auto parse_int_value = [&](const std::string& flag, int& out) -> bool {
        const char* raw = take_value(flag);
        if (!raw) {
            return false;
        }
        int parsed = 0;
        if (!parse_int_strict(raw, parsed)) {
            args.parse_error = "invalid integer for " + flag + ": " + raw;
            return false;
        }
        out = parsed;
        return true;
    };
    auto parse_u32_value = [&](const std::string& flag, std::uint32_t& out) -> bool {
        const char* raw = take_value(flag);
        if (!raw) {
            return false;
        }
        std::uint32_t parsed = 0;
        if (!parse_u32_strict(raw, parsed)) {
            args.parse_error = "invalid integer for " + flag + ": " + raw;
            return false;
        }
        out = parsed;
        return true;
    };
    auto pass_local_benchmark_value = [&](const std::string& flag) -> bool {
        const char* raw = take_value(flag);
        if (!raw) {
            return false;
        }
        args.local_benchmark_args.push_back(flag);
        args.local_benchmark_args.emplace_back(raw);
        return true;
    };
    for (; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--") {
            args.non_interactive = true;
        } else if (arg == "completion") {
            const char* shell = take_value("completion");
            if (!shell) {
                return args;
            }
            args.completion = true;
            args.completion_shell = shell;
        } else if (arg == "export") {
            // Share commands still parse normal connection flags on the same command line.
            const char* file = take_value("export");
            if (!file) return args;
            args.share_export = true;
            args.share_path = file;
        } else if (arg == "import") {
            const char* file = take_value("import");
            if (!file) return args;
            args.share_import = true;
            args.share_path = file;
        } else if (arg == "--password-stdin") {
            args.share_password_stdin = true;
        } else if (arg == "--completion") {
            const char* shell = take_value("--completion");
            if (!shell) {
                return args;
            }
            args.completion = true;
            args.completion_shell = shell;
        } else if (arg == "--config") {
            const char* cfg = take_value("--config");
            if (!cfg) {
                return args;
            }
            args.config_path = cfg;
            args.config_specified = true;
        } else if (arg == "--help" || arg == "-h") {
            args.help = true;
        } else if (arg == "--version") {
            args.version = true;
        } else if (arg == "--credits") {
            args.credits = true;
        } else if (arg == "--server") {
            const char* server = take_value("--server");
            if (!server) {
                return args;
            }
            args.server = server;
        } else if (arg == "--hide-in-the-crowd") {
            const char* value = take_value("--hide-in-the-crowd");
            if (!value) {
                return args;
            }
            args.http_profile = value;
        } else if (arg == "--cluster") {
            const char* spec = take_value("--cluster");
            if (!spec) {
                return args;
            }
            std::string host;
            int port = 443;
            std::string err;
            if (!parse_cluster_spec(spec, &host, &port, &err)) {
                args.parse_error = err;
                return args;
            }
            args.server = host;
            args.port = port;
        } else if (arg == "--port") {
            if (!parse_int_value("--port", args.port)) {
                return args;
            }
        } else if (arg == "--auth" || arg == "-i") {
            const char* identity = take_value(arg);
            if (!identity) {
                return args;
            }
            args.identity = identity;
        } else if (arg == "--socks") {
            if (!parse_int_value("--socks", args.socks_port)) {
                return args;
            }
            args.socks_port_override = true;
        } else if (arg == "--bench") {
            args.bench = true;
            args.non_interactive = true;
        } else if (arg == "--bench-full" || arg == "--endpoint-fullbench" || arg == "--endpoint-full-bench") {
            args.bench = true;
            args.bench_full = true;
            args.non_interactive = true;
        } else if (arg == "--fullbench" || arg == "--full-bench" || arg == "--local-fullbench") {
            args.local_benchmark = true;
            args.local_benchmark_full = true;
            args.non_interactive = true;
        } else if (arg == "--quickbench" || arg == "--quick-bench" || arg == "--localbench") {
            args.local_benchmark = true;
            args.local_benchmark_full = false;
            args.non_interactive = true;
        } else if (arg == "--duration-sec" ||
                   arg == "--latency-iters" ||
                   arg == "--bulk-mib" ||
                   arg == "--argon-mem-kib" ||
                   arg == "--argon-parallelism" ||
                   arg == "--streams" ||
                   arg == "--client-threads" ||
                   arg == "--server-threads" ||
                   arg == "--cooldown-ms" ||
                   arg == "--repeat" ||
                   arg == "--repeats" ||
                   arg == "--configs" ||
                   arg == "--json") {
            if (!pass_local_benchmark_value(arg)) {
                return args;
            }
        } else if (arg == "--one-way" ||
                   arg == "--json-stdout" ||
                   arg == "--keep-workdir" ||
                   arg == "--list-configs" ||
                   arg == "--dev" ||
                   arg == "--color" ||
                   arg == "--colour" ||
                   arg == "--no-color" ||
                   arg == "--no-colour") {
            args.local_benchmark_args.push_back(arg);
        } else if (arg == "--bench-mib") {
            if (!parse_int_value("--bench-mib", args.bench_mib)) {
                return args;
            }
            args.bench_mib_override = true;
            args.bench = true;
            args.non_interactive = true;
        } else if (arg == "--bench-chunk-kib") {
            if (!parse_int_value("--bench-chunk-kib", args.bench_chunk_kib)) {
                return args;
            }
            args.bench_chunk_kib_override = true;
            args.bench = true;
            args.non_interactive = true;
        } else if (arg == "--bench-streams") {
            if (!parse_int_value("--bench-streams", args.bench_streams)) {
                return args;
            }
            args.bench_streams_override = true;
            args.bench = true;
            args.non_interactive = true;
        } else if (arg == "--bench-direction") {
            const char* direction = take_value("--bench-direction");
            if (!direction) {
                return args;
            }
            args.bench_direction = direction;
            std::transform(args.bench_direction.begin(), args.bench_direction.end(), args.bench_direction.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (args.bench_direction != "both" &&
                args.bench_direction != "up" &&
                args.bench_direction != "down") {
                args.parse_error = "--bench-direction must be one of: both, up, down";
                return args;
            }
            args.bench = true;
            args.bench_direction_override = true;
            args.non_interactive = true;
        } else if (arg == "--threads") {
            if (!parse_int_value("--threads", args.io_threads)) {
                return args;
            }
            args.io_threads_override = true;
        } else if (arg == "--tunnels") {
            if (!parse_int_value("--tunnels", args.tunnel_count)) {
                return args;
            }
            args.tunnel_count_override = true;
        } else if (arg == "--obfs") {
            args.obfuscation = true;
            args.obfuscation_override = true;
        } else if (arg == "--no-obfs") {
            args.obfuscation = false;
            args.obfuscation_override = true;
        } else if (arg == "--obfs-secret") {
            const char* v = take_value("--obfs-secret");
            if (!v) return args;
            args.obfs_secret = v;
            args.obfs_secret_override = true;
        } else if (arg == "--obfs-pad-multiple") {
            int parsed = 0;
            if (!parse_int_value("--obfs-pad-multiple", parsed)) {
                return args;
            }
            if (parsed < 0) parsed = 0;
            if (parsed > 256) parsed = 256;
            args.obfs_pad_multiple = static_cast<std::uint16_t>(parsed);
            args.obfs_pad_multiple_override = true;
        } else if (arg == "--obfs-jitter-ms") {
            int parsed = 0;
            if (!parse_int_value("--obfs-jitter-ms", parsed)) {
                return args;
            }
            if (parsed < 0) parsed = 0;
            args.obfs_jitter_ms = static_cast<std::uint32_t>(parsed);
            args.obfs_jitter_ms_override = true;
        } else if (arg == "--lport") {
            if (!parse_int_value("--lport", args.lport)) {
                return args;
            }
        } else if (arg == "--rhost") {
            const char* rhost = take_value("--rhost");
            if (!rhost) {
                return args;
            }
            args.rhost = rhost;
        } else if (arg == "--rport") {
            if (!parse_int_value("--rport", args.rport)) {
                return args;
            }
        } else if (arg == "--run" || arg == "-c" || arg == "--cmd") {
            const char* cmd = take_value(arg);
            if (!cmd) {
                return args;
            }
            args.run_cmd = cmd;
        } else if (arg == "--run-ipv4") {
            args.run_ipv4 = true;
        } else if (arg == "--proxycmd") {
            args.proxycmd = true;
        } else if (arg == "--dest") {
            const char* dest = take_value("--dest");
            if (!dest) {
                return args;
            }
            args.dest_host = dest;
        } else if (arg == "--dport") {
            if (!parse_int_value("--dport", args.dest_port)) {
                return args;
            }
        } else if (arg == "--require-anonym" || arg == "--anonym") {
            args.require_anonym = true;
        } else if (arg == "--anonym-ca-cert") {
            const char* cert = take_value("--anonym-ca-cert");
            if (!cert) {
                return args;
            }
            args.anonym_ca_cert = cert;
        } else if (arg == "-L") {
            const char* value = take_value("-L");
            if (!value) {
                return args;
            }
            args.ssh_L = value;
        } else if (arg == "-R") {
            const char* value = take_value("-R");
            if (!value) {
                return args;
            }
            args.ssh_R = value;
        } else if (arg == "--inner") {
            util::log_warn("--inner is deprecated; use --inner-heavy or --inner-light");
            args.inner_crypto = true;
            args.inner_crypto_override = true;
        } else if (arg == "--no-inner") {
            args.inner_crypto = false;
            args.inner_crypto_override = true;
            args.inner_hop = false;
            args.inner_hop_override = true;
        } else if (arg == "--inner-heavy") {
            args.inner_crypto = true;
            args.inner_crypto_override = true;
            args.inner_heavy = true;
        } else if (arg == "--inner-light") {
            args.inner_crypto = true;
            args.inner_crypto_override = true;
            args.inner_heavy = false;
        } else if (arg == "--hop") {
            args.inner_hop = true;
            args.inner_hop_override = true;
        } else if (arg == "--no-hop") {
            args.inner_hop = false;
            args.inner_hop_override = true;
        } else if (arg == "--hop-interval") {
            if (!parse_u32_value("--hop-interval", args.hop_interval_ms)) {
                return args;
            }
            args.hop_interval_override = true;
        } else if (arg == "--udp") {
            args.use_udp = true;
            args.udp_override = true;
        } else if (arg == "--tcp") {
            args.use_udp = false;
            args.udp_override = true;
        } else if (arg == "--allow-local-ip") {
            args.allow_local_ip = true;
            args.allow_local_ip_override = true;
        } else if (arg == "--accept-server-control" || arg == "--server-in-charge") {
            if (arg == "--server-in-charge") {
                util::log_warn("--server-in-charge is deprecated; use --accept-server-control");
            }
            args.server_in_charge = true;
            args.server_in_charge_override = true;
            if (i + 1 < argc) {
                std::string next = argv[i + 1];
                if (!next.empty() && next[0] != '-') {
                    int parsed = 0;
                    if (!parse_int_strict(next, parsed)) {
                        args.parse_error = "invalid integer for --accept-server-control: " + next;
                        return args;
                    }
                    args.server_in_charge_port = parsed;
                    args.server_in_charge_port_override = true;
                    ++i;
                }
            }
        } else if (arg == "--server-in-charge-port") {
            args.server_in_charge = true;
            args.server_in_charge_override = true;
            if (!parse_int_value("--server-in-charge-port", args.server_in_charge_port)) {
                return args;
            }
            args.server_in_charge_port_override = true;
        } else if (arg == "--server-in-charge-min-port") {
            args.server_in_charge = true;
            args.server_in_charge_override = true;
            if (!parse_int_value("--server-in-charge-min-port", args.server_in_charge_min_port)) {
                return args;
            }
        } else if (arg == "--server-in-charge-max-port") {
            args.server_in_charge = true;
            args.server_in_charge_override = true;
            if (!parse_int_value("--server-in-charge-max-port", args.server_in_charge_max_port)) {
                return args;
            }
        } else if (arg == "--allow-exec") {
            args.allow_exec = true;
            args.allow_exec_override = true;
        } else if (arg == "--exec") {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                args.exec_cmd = argv[++i];
            } else {
                args.allow_exec = true;
                args.allow_exec_override = true;
            }
        } else if (arg == "--control") {
            args.control_mode = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                args.control_id = argv[++i];
            }
        } else if (arg == "--id") {
            const char* value = take_value("--id");
            if (!value) {
                return args;
            }
            args.control_id = value;
        } else if (arg == "--list-controlled") {
            args.list_controlled = true;
        } else if (arg == "--name") {
            const char* value = take_value("--name");
            if (!value) {
                return args;
            }
            args.preferred_name = value;
        } else if (arg == "--client-id") {
            const char* value = take_value("--client-id");
            if (!value) {
                return args;
            }
            args.preferred_id = value;
        } else if (arg == "--relay-mode") {
            const char* value = take_value("--relay-mode");
            if (!value) {
                return args;
            }
            args.relay_mode = value;
        } else if (arg == "--allow-inbound-admin") {
            args.allow_inbound_admin = true;
            args.allow_inbound_admin_override = true;
        } else if (arg == "--deny-inbound-admin") {
            args.allow_inbound_admin = false;
            args.allow_inbound_admin_override = true;
        } else if (arg == "--allow-outbound-admin") {
            args.allow_outbound_admin = true;
            args.allow_outbound_admin_override = true;
        } else if (arg == "--deny-outbound-admin") {
            args.allow_outbound_admin = false;
            args.allow_outbound_admin_override = true;
        } else if (arg == "--root") {
            args.keep_root = true;
        } else if (arg == "--allow-chat") {
            args.allow_chat = true;
            args.allow_chat_override = true;
        } else if (arg == "--deny-chat") {
            args.allow_chat = false;
            args.allow_chat_override = true;
        } else if (arg == "--allow-file") {
            args.allow_file = true;
            args.allow_file_override = true;
        } else if (arg == "--deny-file") {
            args.allow_file = false;
            args.allow_file_override = true;
        } else if (arg == "--allow-bytes") {
            args.allow_bytes = true;
            args.allow_bytes_override = true;
        } else if (arg == "--deny-bytes") {
            args.allow_bytes = false;
            args.allow_bytes_override = true;
        } else if (arg == "--history-dir") {
            const char* value = take_value("--history-dir");
            if (!value) {
                return args;
            }
            args.history_dir = value;
            args.history_override = true;
        } else if (arg == "--no-history") {
            args.history_enabled = false;
            args.history_override = true;
        } else if (arg == "--relay-key-file") {
            const char* value = take_value("--relay-key-file");
            if (!value) {
                return args;
            }
            args.relay_key_file = value;
        } else if (arg == "--instance") {
            const char* value = take_value("--instance");
            if (!value) {
                return args;
            }
            args.instance_name = value;
        } else if (arg == "--attach-local") {
            args.attach_local = true;
        } else if (arg == "--codec") {
            const char* value = take_value("--codec");
            if (!value) {
                return args;
            }
            args.app_codec = value;
            args.app_codec_override = true;
        } else if (arg == "--codec-listen") {
            const char* value = take_value("--codec-listen");
            if (!value) {
                return args;
            }
            args.app_codec_listen = value;
            args.app_codec_listen_override = true;
        } else if (arg == "--monero-rpc") {
            args.app_codec = "monero-rpc";
            args.app_codec_override = true;
        } else if (arg == "--monero-rpc-listen") {
            const char* value = take_value("--monero-rpc-listen");
            if (!value) {
                return args;
            }
            args.app_codec = "monero-rpc";
            args.app_codec_override = true;
            args.app_codec_listen = value;
            args.app_codec_listen_override = true;
        } else if (arg == "--chat") {
            const char* value = take_value("--chat");
            if (!value) {
                return args;
            }
            args.chat_target = value;
        } else if (arg == "--send-file") {
            const char* peer = take_value("--send-file");
            if (!peer) {
                return args;
            }
            args.file_target = peer;
            const char* path = take_value("--send-file");
            if (!path) {
                return args;
            }
            args.file_path = path;
        } else if (arg == "--send-bytes") {
            const char* peer = take_value("--send-bytes");
            if (!peer) {
                return args;
            }
            args.bytes_target = peer;
            const char* path = take_value("--send-bytes");
            if (!path) {
                return args;
            }
            args.bytes_path = path;
        } else if (arg == "--directory") {
            args.directory_mode = true;
        } else if (arg == "--admin-attach" || arg == "--server-attach") {
            const char* value = take_value(arg);
            if (!value) {
                return args;
            }
            args.admin_target = value;
        } else if (arg == "--pq-pub") {
            const char* value = take_value("--pq-pub");
            if (!value) {
                return args;
            }
            args.pq_public_key = value;
        } else if (arg == "--use-embedded-master") {
            args.allow_embedded_master = true;
            args.allow_embedded_master_override = true;
        } else if (arg == "--no-embedded-master") {
            args.allow_embedded_master = false;
            args.allow_embedded_master_override = true;
        } else if (arg == "--tls-ca") {
            const char* value = take_value("--tls-ca");
            if (!value) {
                return args;
            }
            args.tls_ca_cert = value;
        } else if (arg == "--tls-name" || arg == "--tls-server-name") {
            const char* value = take_value(arg);
            if (!value) {
                return args;
            }
            args.tls_server_name = value;
        } else if (arg == "--tls-pin") {
            const char* value = take_value("--tls-pin");
            if (!value) {
                return args;
            }
            args.tls_pin_sha256 = value;
        } else if (arg == "--proxy") {
            // socks5://[user[:pass]@]host:port.
            const char* value = take_value("--proxy");
            if (!value) {
                return args;
            }
            args.outbound_proxy_url = value;
            args.outbound_proxy_override = true;
        } else if (arg == "--no-proxy") {
            args.outbound_proxy_url.clear();
            args.outbound_proxy_override = true;
        } else if (arg == "--tor") {
            args.outbound_proxy_url = "socks5://127.0.0.1:9050";
            args.outbound_proxy_override = true;
        } else if (arg == "--no-stealth") {
            args.tls_stealth = false;
            args.tls_stealth_override = true;
        } else if (arg == "--profile") {
            const char* value = take_value("--profile");
            if (!value) {
                return args;
            }
            args.tls_stealth_profile = value;
        } else if (arg == "--tls-stealth-rotate") {
            args.tls_stealth_rotate = true;
        } else if (arg == "--tls-stealth-rotation-interval") {
            if (!parse_u32_value("--tls-stealth-rotation-interval", args.tls_stealth_rotation_interval)) {
                return args;
            }
        } else if (arg == "--tls-fingerprint-log") {
            args.tls_fingerprint_log = true;
        } else if (arg == "--tls-fingerprint-log-path") {
            const char* value = take_value("--tls-fingerprint-log-path");
            if (!value) {
                return args;
            }
            args.tls_fingerprint_log_path = value;
        } else if (arg == "--tls-fingerprint-verify") {
            args.tls_fingerprint_verify = true;
        } else if (arg == "--tls-fingerprint-test-endpoint") {
            const char* value = take_value("--tls-fingerprint-test-endpoint");
            if (!value) {
                return args;
            }
            args.tls_fingerprint_test_endpoint = value;
        } else if (arg == "--self-dpi") {
            args.self_dpi = true;
            args.self_dpi_override = true;
        } else if (arg == "--no-self-dpi") {
            args.self_dpi = false;
            args.self_dpi_override = true;
        } else if (arg == "--accept-monitoring") {
            args.accept_monitoring = true;
        } else if (arg == "--save-server") {
            args.save_server = true;
        } else if (arg == "--boring") {
            args.boring = true;
            args.boring_override = true;
        } else if (arg == "--non-interactive") {
            args.non_interactive = true;
        } else if (arg == "--live-status") {
            args.live_status = true;
        } else if (arg == "--timing") {
            args.timing = true;
        } else {
            args.parse_error = (arg.rfind("-", 0) == 0 ? "unknown option: " : "unknown argument: ") +
                               arg + " (try --help)";
            return args;
        }
    }
    return args;
}

}  // namespace yume::client
