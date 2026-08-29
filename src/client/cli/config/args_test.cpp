/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/config/args.hpp"

#include <cassert>
#include <string>
#include <vector>

namespace {

yume::client::ParsedArgs parse(std::vector<std::string> values) {
    std::vector<char*> argv;
    argv.reserve(values.size());
    for (auto& value : values) argv.push_back(value.data());
    return yume::client::parse_args(static_cast<int>(argv.size()), argv.data());
}

void CheckDomainDispatch() {
    auto args = parse({
        "yume", "--config", "client.json", "--server", "cover.example",
        "--port", "8443", "--bench-direction", "UP", "--threads", "3",
        "--rhost", "127.0.0.1", "--rport", "9000", "--udp",
        "--relay-mode", "trusted", "--allow-chat", "--history-dir", "hist",
        "--tls-name", "origin.example", "--tor", "--live-status"});
    assert(args.parse_error.empty());
    assert(args.config_specified && args.config_path == "client.json");
    assert(args.server == "cover.example" && args.port == 8443);
    assert(args.bench && args.bench_direction == "up");
    assert(args.io_threads_override && args.io_threads == 3);
    assert(args.rhost == "127.0.0.1" && args.rport == 9000);
    assert(args.use_udp && args.udp_override);
    assert(args.relay_mode == "trusted" && args.relay_mode_override);
    assert(args.allow_chat && args.allow_chat_override);
    assert(args.history_dir == "hist" && args.history_override);
    assert(args.tls_server_name == "origin.example");
    assert(args.outbound_proxy_override &&
           args.outbound_proxy_url == "socks5://127.0.0.1:9050");
    assert(args.live_status);
}

void CheckOptionalValuesAndAliases() {
    auto args = parse({"yume", "completion", "bash", "-i", "id.pem",
                       "--accept-server-control", "--help", "--control",
                       "peer", "--"});
    assert(args.parse_error.empty());
    assert(args.completion && args.completion_shell == "bash");
    assert(args.identity == "id.pem");
    assert(args.server_in_charge && !args.server_in_charge_port_override);
    assert(args.help);
    assert(args.control_mode && args.control_id == "peer");
    assert(args.non_interactive);

    auto proxy = parse({"yume", "--tor", "--no-proxy"});
    assert(proxy.parse_error.empty());
    assert(proxy.outbound_proxy_override);
    assert(proxy.outbound_proxy_url.empty());
}

void CheckFirstErrorAndDiagnostics() {
    auto first = parse(
        {"yume", "--server", "example", "--unknown", "--port", "bad"});
    assert(first.parse_error == "unknown option: --unknown (try --help)");

    auto missing = parse({"yume", "--send-file", "peer"});
    assert(missing.parse_error == "missing value for --send-file");

    auto integer = parse({"yume", "--threads", "many"});
    assert(integer.parse_error == "invalid integer for --threads: many");

    auto argument = parse({"yume", "unexpected"});
    assert(argument.parse_error ==
           "unknown argument: unexpected (try --help)");
}

}  // namespace

int main() {
    CheckDomainDispatch();
    CheckOptionalValuesAndAliases();
    CheckFirstErrorAndDiagnostics();
    return 0;
}
