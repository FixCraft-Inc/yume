/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/config/args.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <string_view>
#include <utility>

#include "client/cli/parse/endpoints.hpp"
#include "core/security/ratchet.hpp"
#include "core/stealth/http_profile.hpp"

namespace yume::client {
namespace {

enum class OptionResult {
    Unhandled,
    Handled,
    Error,
};

bool parse_int_strict(std::string_view text, int& out) {
    if (text.empty()) {
        return false;
    }
    int value = 0;
    const auto [ptr, ec] =
        std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc() || ptr != text.data() + text.size()) {
        return false;
    }
    out = value;
    return true;
}

bool valid_sha256_fingerprint(std::string_view value) {
    return value.size() == 64 &&
        std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return std::isxdigit(c) != 0;
        });
}

bool parse_cluster_spec(const std::string& spec,
                        std::string* host,
                        int* port,
                        std::string* error) {
    if (spec.empty()) {
        if (error) *error = "--cluster argument is empty";
        return false;
    }

    std::string parsed_host;
    int parsed_port = 443;
    if (spec.front() == '[') {
        const auto close = spec.find(']');
        if (close == std::string::npos) {
            if (error) *error = "--cluster: unmatched '[' in " + spec;
            return false;
        }
        parsed_host = spec.substr(1, close - 1);
        if (close + 1 < spec.size()) {
            if (spec[close + 1] != ':') {
                if (error) {
                    *error = "--cluster: expected ':port' after ']' in " + spec;
                }
                return false;
            }
            if (!parse_int_strict(spec.substr(close + 2), parsed_port)) {
                if (error) *error = "--cluster: invalid port in " + spec;
                return false;
            }
        }
    } else {
        if (std::count(spec.begin(), spec.end(), ':') > 1) {
            if (error) {
                *error = "--cluster: IPv6 addresses must use [addr]:port syntax";
            }
            return false;
        }
        const auto colon = spec.rfind(':');
        if (colon == std::string::npos) {
            parsed_host = spec;
        } else {
            parsed_host = spec.substr(0, colon);
            if (!parse_int_strict(spec.substr(colon + 1), parsed_port)) {
                if (error) *error = "--cluster: invalid port in " + spec;
                return false;
            }
        }
    }

    if (parsed_host.empty()) {
        if (error) *error = "--cluster: empty host in " + spec;
        return false;
    }
    if (parsed_port <= 0 || parsed_port > 65535) {
        if (error) *error = "--cluster: port out of range in " + spec;
        return false;
    }
    *host = std::move(parsed_host);
    *port = parsed_port;
    return true;
}

class ParseCursor {
public:
    ParseCursor(int argc, char** argv) : argc_(argc), argv_(argv) {}

    bool at_end() const noexcept { return index_ >= argc_; }
    void advance() noexcept { ++index_; }
    std::string current() const { return argv_[index_]; }

    ParsedArgs& args() noexcept { return args_; }
    ParsedArgs take_args() noexcept { return std::move(args_); }

    const char* take_value(std::string_view flag) {
        if (index_ + 1 >= argc_) {
            args_.parse_error = "missing value for " + std::string(flag);
            return nullptr;
        }
        return argv_[++index_];
    }

    bool parse_int_value(std::string_view flag, int& out) {
        const char* raw = take_value(flag);
        if (!raw) {
            return false;
        }
        int parsed = 0;
        if (!parse_int_strict(raw, parsed)) {
            args_.parse_error =
                "invalid integer for " + std::string(flag) + ": " + raw;
            return false;
        }
        out = parsed;
        return true;
    }

    bool pass_local_benchmark_value(const std::string& flag) {
        const char* raw = take_value(flag);
        if (!raw) {
            return false;
        }
        args_.local_benchmark_args.push_back(flag);
        args_.local_benchmark_args.emplace_back(raw);
        return true;
    }

    bool next_is_value() const {
        return index_ + 1 < argc_ && argv_[index_ + 1][0] != '-';
    }

    const char* take_optional_value() {
        return next_is_value() ? argv_[++index_] : nullptr;
    }

private:
    int argc_{0};
    char** argv_{nullptr};
    int index_{1};
    ParsedArgs args_;
};

OptionResult parse_general_option(ParseCursor& cursor, const std::string& arg) {
    auto& args = cursor.args();
    if (arg == "--") {
        args.non_interactive = true;
    } else if (arg == "completion" || arg == "--completion") {
        const char* shell = cursor.take_value(arg);
        if (!shell) return OptionResult::Error;
        args.completion = true;
        args.completion_shell = shell;
    } else if (arg == "export" || arg == "import") {
        const char* path = cursor.take_value(arg);
        if (!path) return OptionResult::Error;
        args.share_export = arg == "export";
        args.share_import = arg == "import";
        args.share_path = path;
    } else if (arg == "--password-stdin") {
        args.share_password_stdin = true;
    } else if (arg == "--config") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        args.config_path = value;
        args.config_specified = true;
    } else if (arg == "--help" || arg == "-h") {
        args.help = true;
    } else if (arg == "--version") {
        args.version = true;
    } else if (arg == "--credits") {
        args.credits = true;
    } else if (arg == "--server") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        args.server = value;
    } else if (arg == "--hide-in-the-crowd") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        if (!http_profile::transport_client_supported(value)) {
            args.parse_error =
                "this YUME build has no complete transport fixture for that profile";
            return OptionResult::Error;
        }
        args.http_profile = value;
    } else if (arg == "--cluster") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        std::string host;
        int port = 443;
        std::string error;
        if (!parse_cluster_spec(value, &host, &port, &error)) {
            args.parse_error = std::move(error);
            return OptionResult::Error;
        }
        args.server = std::move(host);
        args.port = port;
    } else if (arg == "--port") {
        if (!cursor.parse_int_value(arg, args.port)) return OptionResult::Error;
    } else if (arg == "--auth" || arg == "-i") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        args.identity = value;
    } else if (arg == "--secondary-auth") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        args.secondary_identities.emplace_back(value);
    } else if (arg == "--admin-auth") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        args.admin_identity = value;
    } else if (arg == "--socks") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        BindEndpoint endpoint;
        std::string error;
        if (!parse_bind_endpoint(value, endpoint, &error)) {
            args.parse_error = "--socks: " + error;
            return OptionResult::Error;
        }
        args.socks_bind_host = std::move(endpoint.host);
        args.socks_port = endpoint.port;
        args.socks_port_override = true;
    } else if (arg == "--packet-tun") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        args.packet_tun_name = value;
        args.packet_tun_override = true;
        args.non_interactive = true;
    } else {
        return OptionResult::Unhandled;
    }
    return OptionResult::Handled;
}

OptionResult parse_benchmark_option(ParseCursor& cursor, const std::string& arg) {
    auto& args = cursor.args();
    if (arg == "--bench") {
        args.bench = true;
        args.non_interactive = true;
    } else if (arg == "--bench-full") {
        args.bench = true;
        args.bench_full = true;
        args.non_interactive = true;
    } else if (arg == "--full-bench" || arg == "--quick-bench") {
        args.local_benchmark = true;
        args.local_benchmark_full = arg == "--full-bench";
        args.non_interactive = true;
    } else if (arg == "--duration-sec" || arg == "--latency-iters" ||
               arg == "--bulk-mib" || arg == "--streams" ||
               arg == "--client-threads" || arg == "--server-threads" ||
               arg == "--cooldown-ms" || arg == "--repeat" ||
               arg == "--configs" || arg == "--json") {
        if (!cursor.pass_local_benchmark_value(arg)) return OptionResult::Error;
    } else if (arg == "--one-way" || arg == "--json-stdout" ||
               arg == "--keep-workdir" || arg == "--list-configs" ||
               arg == "--dev" || arg == "--color" || arg == "--no-color") {
        args.local_benchmark_args.push_back(arg);
    } else if (arg == "--bench-mib") {
        if (!cursor.parse_int_value(arg, args.bench_mib)) return OptionResult::Error;
        args.bench_mib_override = true;
        args.bench = true;
        args.non_interactive = true;
    } else if (arg == "--bench-chunk-kib") {
        if (!cursor.parse_int_value(arg, args.bench_chunk_kib)) {
            return OptionResult::Error;
        }
        args.bench_chunk_kib_override = true;
        args.bench = true;
        args.non_interactive = true;
    } else if (arg == "--bench-streams") {
        if (!cursor.parse_int_value(arg, args.bench_streams)) {
            return OptionResult::Error;
        }
        args.bench_streams_override = true;
        args.bench = true;
        args.non_interactive = true;
    } else if (arg == "--bench-direction") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        args.bench_direction = value;
        std::transform(args.bench_direction.begin(), args.bench_direction.end(),
                       args.bench_direction.begin(), [](unsigned char c) {
                           return static_cast<char>(std::tolower(c));
                       });
        if (args.bench_direction != "both" && args.bench_direction != "up" &&
            args.bench_direction != "down") {
            args.parse_error =
                "--bench-direction must be one of: both, up, down";
            return OptionResult::Error;
        }
        args.bench = true;
        args.bench_direction_override = true;
        args.non_interactive = true;
    } else if (arg == "--outer-carrier-evidence") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        args.outer_carrier_evidence = value;
        args.non_interactive = true;
    } else if (arg == "--threads") {
        if (!cursor.parse_int_value(arg, args.io_threads)) return OptionResult::Error;
        args.io_threads_override = true;
    } else if (arg == "--tunnels") {
        if (!cursor.parse_int_value(arg, args.tunnel_count)) return OptionResult::Error;
        args.tunnel_count_override = true;
    } else if (arg == "--obfs-secret-file" || arg == "--inner-psk-file") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        if (arg == "--obfs-secret-file") {
            args.obfs_secret_file = value;
            args.obfs_secret_file_override = true;
        } else {
            args.inner_psk_file = value;
            args.inner_psk_file_override = true;
        }
    } else {
        return OptionResult::Unhandled;
    }
    return OptionResult::Handled;
}

OptionResult parse_forwarding_option(ParseCursor& cursor, const std::string& arg) {
    auto& args = cursor.args();
    if (arg == "--lport") {
        if (!cursor.parse_int_value(arg, args.lport)) return OptionResult::Error;
    } else if (arg == "--rhost") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        args.rhost = value;
    } else if (arg == "--rport") {
        if (!cursor.parse_int_value(arg, args.rport)) return OptionResult::Error;
    } else if (arg == "--run" || arg == "-c") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        args.run_cmd = value;
    } else if (arg == "--run-ipv4") {
        args.run_ipv4 = true;
    } else if (arg == "--proxycmd") {
        args.proxycmd = true;
    } else if (arg == "--dest") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        args.dest_host = value;
    } else if (arg == "--dport") {
        if (!cursor.parse_int_value(arg, args.dest_port)) return OptionResult::Error;
    } else if (arg == "--require-operator-identity") {
        args.require_anonym = true;
    } else if (arg == "--operator-ca-cert") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        args.anonym_ca_cert = value;
    } else if (arg == "-L" || arg == "-R") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        (arg == "-L" ? args.ssh_L : args.ssh_R) = value;
    } else if (arg == "--rekey-window") {
        if (!cursor.parse_int_value(arg, args.rekey_window)) return OptionResult::Error;
        if (args.rekey_window < ratchet::kMinRekeyWindow ||
            args.rekey_window > ratchet::kMaxRekeyWindow) {
            args.parse_error =
                "--rekey-window: expected an integer in " +
                std::to_string(ratchet::kMinRekeyWindow) + ".." +
                std::to_string(ratchet::kMaxRekeyWindow);
            return OptionResult::Error;
        }
        args.rekey_window_override = true;
        args.local_benchmark_args.push_back(arg);
        args.local_benchmark_args.push_back(std::to_string(args.rekey_window));
    } else if (arg == "--udp" || arg == "--tcp") {
        args.use_udp = arg == "--udp";
        args.udp_override = true;
    } else if (arg == "--allow-local-ip") {
        args.allow_local_ip = true;
        args.allow_local_ip_override = true;
    } else if (arg == "--accept-server-control") {
        args.server_in_charge = true;
        args.server_in_charge_override = true;
        if (const char* value = cursor.take_optional_value()) {
            int parsed = 0;
            if (!parse_int_strict(value, parsed)) {
                args.parse_error =
                    "invalid integer for --accept-server-control: " +
                    std::string(value);
                return OptionResult::Error;
            }
            args.server_in_charge_port = parsed;
            args.server_in_charge_port_override = true;
        }
    } else if (arg == "--accept-server-control-min-port" ||
               arg == "--accept-server-control-max-port") {
        args.server_in_charge = true;
        args.server_in_charge_override = true;
        int& port = arg == "--accept-server-control-min-port"
            ? args.server_in_charge_min_port
            : args.server_in_charge_max_port;
        if (!cursor.parse_int_value(arg, port)) return OptionResult::Error;
    } else if (arg == "--allow-exec") {
        args.parse_error =
            "--allow-exec is unavailable: inbound remote command "
            "execution is disabled until child processes have bounded "
            "shutdown support";
        return OptionResult::Error;
    } else if (arg == "--exec") {
        const char* value = cursor.take_optional_value();
        if (!value) {
            args.parse_error = "--exec requires a command";
            return OptionResult::Error;
        }
        args.exec_cmd = value;
    } else if (arg == "--control") {
        args.control_mode = true;
        if (const char* value = cursor.take_optional_value()) {
            args.control_id = value;
        }
    } else if (arg == "--id") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        args.control_id = value;
    } else if (arg == "--list-controlled") {
        args.list_controlled = true;
    } else if (arg == "--name" || arg == "--client-id") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        (arg == "--name" ? args.preferred_name : args.preferred_id) = value;
    } else {
        return OptionResult::Unhandled;
    }
    return OptionResult::Handled;
}

OptionResult parse_relay_option(ParseCursor& cursor, const std::string& arg) {
    auto& args = cursor.args();
    if (arg == "--relay-mode" || arg == "--relay-trust-mode" ||
        arg == "--relay-trust-dir") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        if (arg == "--relay-mode") {
            args.relay_mode = value;
            args.relay_mode_override = true;
        } else if (arg == "--relay-trust-mode") {
            args.relay_trust_mode = value;
            args.relay_trust_mode_override = true;
        } else {
            args.relay_trust_dir = value;
            args.relay_trust_dir_override = true;
        }
    } else if (arg == "--relay-peer-pin") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        const std::string_view pin(value);
        const auto separator = pin.find('=');
        if (separator == std::string_view::npos || separator == 0 ||
            separator + 1 >= pin.size() ||
            !valid_sha256_fingerprint(pin.substr(separator + 1))) {
            args.parse_error =
                "--relay-peer-pin expects endpoint=64-hex-fingerprint";
            return OptionResult::Error;
        }
        args.relay_peer_pins.emplace_back(pin);
    } else if (arg == "--allow-inbound-admin" ||
               arg == "--deny-inbound-admin") {
        args.allow_inbound_admin = arg == "--allow-inbound-admin";
        args.allow_inbound_admin_override = true;
    } else if (arg == "--allow-outbound-admin" ||
               arg == "--deny-outbound-admin") {
        args.allow_outbound_admin = arg == "--allow-outbound-admin";
        args.allow_outbound_admin_override = true;
    } else if (arg == "--root") {
        args.keep_root = true;
    } else if (arg == "--allow-chat" || arg == "--deny-chat") {
        args.allow_chat = arg == "--allow-chat";
        args.allow_chat_override = true;
    } else if (arg == "--allow-file" || arg == "--deny-file") {
        args.allow_file = arg == "--allow-file";
        args.allow_file_override = true;
    } else if (arg == "--allow-bytes" || arg == "--deny-bytes") {
        args.allow_bytes = arg == "--allow-bytes";
        args.allow_bytes_override = true;
    } else if (arg == "--history-dir" || arg == "--relay-receive-dir" ||
               arg == "--relay-key-file" || arg == "--instance") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        if (arg == "--history-dir") {
            args.history_dir = value;
            args.history_override = true;
        } else if (arg == "--relay-receive-dir") {
            args.relay_receive_dir = value;
        } else if (arg == "--relay-key-file") {
            args.relay_key_file = value;
        } else {
            args.instance_name = value;
        }
    } else if (arg == "--no-history") {
        args.history_enabled = false;
        args.history_override = true;
    } else if (arg == "--attach-local") {
        args.attach_local = true;
    } else if (arg == "--codec" || arg == "--codec-listen") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        if (arg == "--codec") {
            args.app_codec = value;
            args.app_codec_override = true;
        } else {
            args.app_codec_listen = value;
            args.app_codec_listen_override = true;
        }
    } else if (arg == "--monero-rpc") {
        args.app_codec = "monero-rpc";
        args.app_codec_override = true;
    } else if (arg == "--monero-rpc-listen") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        args.app_codec = "monero-rpc";
        args.app_codec_override = true;
        args.app_codec_listen = value;
        args.app_codec_listen_override = true;
    } else if (arg == "--chat") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        args.chat_target = value;
    } else if (arg == "--send-file" || arg == "--send-bytes") {
        const char* peer = cursor.take_value(arg);
        if (!peer) return OptionResult::Error;
        const char* path = cursor.take_value(arg);
        if (!path) return OptionResult::Error;
        if (arg == "--send-file") {
            args.file_target = peer;
            args.file_path = path;
        } else {
            args.bytes_target = peer;
            args.bytes_path = path;
        }
    } else if (arg == "--directory") {
        args.directory_mode = true;
    } else if (arg == "--admin-attach") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        args.admin_target = value;
    } else {
        return OptionResult::Unhandled;
    }
    return OptionResult::Handled;
}

OptionResult parse_transport_option(ParseCursor& cursor, const std::string& arg) {
    auto& args = cursor.args();
    if (arg == "--tls-ca" || arg == "--tls-name" || arg == "--tls-pin" ||
        arg == "--transport-profile" || arg == "--tls-backend" ||
        arg == "--tls-helper" || arg == "--proxy") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        if (arg == "--tls-ca") args.tls_ca_cert = value;
        else if (arg == "--tls-name") args.tls_server_name = value;
        else if (arg == "--tls-pin") args.tls_pin_sha256 = value;
        else if (arg == "--transport-profile") args.transport_profile = value;
        else if (arg == "--tls-backend") args.tls_backend = value;
        else if (arg == "--tls-helper") args.tls_helper_path = value;
        else {
            args.outbound_proxy_url = value;
            args.outbound_proxy_override = true;
        }
    } else if (arg == "--no-proxy" || arg == "--tor") {
        if (arg == "--tor") {
            args.outbound_proxy_url = "socks5://127.0.0.1:9050";
        } else {
            args.outbound_proxy_url.clear();
        }
        args.outbound_proxy_override = true;
    } else if (arg == "--profile") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        if (!http_profile::transport_client_supported(value)) {
            args.parse_error =
                "this YUME build has no complete transport fixture for that profile";
            return OptionResult::Error;
        }
        args.tls_stealth_profile = value;
        args.tls_stealth_profile_override = true;
    } else if (arg == "--tls-fingerprint-log") {
        args.tls_fingerprint_log = true;
        args.tls_fingerprint_log_override = true;
    } else if (arg == "--tls-fingerprint-log-path") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        args.tls_fingerprint_log_path = value;
        args.tls_fingerprint_log_path_override = true;
    } else if (arg == "--tls-fingerprint-verify") {
        args.tls_fingerprint_verify = true;
        args.tls_fingerprint_verify_override = true;
    } else if (arg == "--tls-fingerprint-test-endpoint") {
        const char* value = cursor.take_value(arg);
        if (!value) return OptionResult::Error;
        args.tls_fingerprint_test_endpoint = value;
        args.tls_fingerprint_test_endpoint_override = true;
    } else if (arg == "--self-dpi" || arg == "--no-self-dpi") {
        args.self_dpi = arg == "--self-dpi";
        args.self_dpi_override = true;
    } else if (arg == "--accept-monitoring") {
        args.accept_monitoring = true;
    } else if (arg == "--service-streams-only") {
        args.service_streams_only = true;
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
        return OptionResult::Unhandled;
    }
    return OptionResult::Handled;
}

}  // namespace

ParsedArgs parse_args(int argc, char** argv) {
    ParseCursor cursor(argc, argv);
    while (!cursor.at_end()) {
        const std::string arg = cursor.current();
        OptionResult result = parse_general_option(cursor, arg);
        if (result == OptionResult::Unhandled) {
            result = parse_benchmark_option(cursor, arg);
        }
        if (result == OptionResult::Unhandled) {
            result = parse_forwarding_option(cursor, arg);
        }
        if (result == OptionResult::Unhandled) {
            result = parse_relay_option(cursor, arg);
        }
        if (result == OptionResult::Unhandled) {
            result = parse_transport_option(cursor, arg);
        }
        if (result == OptionResult::Error) {
            return cursor.take_args();
        }
        if (result == OptionResult::Unhandled) {
            cursor.args().parse_error =
                (arg.rfind('-', 0) == 0 ? "unknown option: " :
                                          "unknown argument: ") +
                arg + " (try --help)";
            return cursor.take_args();
        }
        cursor.advance();
    }
    return cursor.take_args();
}

}  // namespace yume::client
