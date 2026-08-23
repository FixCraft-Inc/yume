/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/config/args.hpp"
#include "client/cli/config/config.hpp"
#include "client/cli/entry.hpp"

#include <cassert>
#include <filesystem>

int main() {
    using namespace yume::client;

    char program[] = "yume";
    char option[] = "--relay-receive-dir";
    char value[] = "incoming";
    char* argv[] = {program, option, value};
    auto parsed = parse_args(3, argv);
    assert(parsed.parse_error.empty());
    assert(parsed.relay_receive_dir == "incoming");

    ClientConfig configured;
    configured.relay_mode = "trusted";
    apply_cli_config_overrides(parsed, "/tmp/yume-cli-config-test", &configured);
    assert(configured.relay_receive_dir ==
           "/tmp/yume-cli-config-test/incoming");
    // An absent --relay-mode must not erase the persisted value.
    assert(configured.relay_mode == "trusted");

    char trust_mode_option[] = "--relay-trust-mode";
    char trust_mode_value[] = "pinned";
    char trust_dir_option[] = "--relay-trust-dir";
    char trust_dir_value[] = "trust";
    char peer_pin_option[] = "--relay-peer-pin";
    char peer_pin_value[] =
        "peer:client=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    char* trust_argv[] = {
        program,
        trust_mode_option,
        trust_mode_value,
        trust_dir_option,
        trust_dir_value,
        peer_pin_option,
        peer_pin_value,
    };
    const auto trust_args = parse_args(7, trust_argv);
    assert(trust_args.parse_error.empty());
    ClientConfig trust_config;
    apply_cli_config_overrides(
        trust_args, "/tmp/yume-cli-config-test", &trust_config);
    assert(trust_config.relay_trust_mode == "pinned");
    assert(trust_config.relay_trust_dir ==
           "/tmp/yume-cli-config-test/trust");
    assert(trust_config.relay_peer_pins.at("peer:client") ==
           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    char bad_peer_pin_value[] = "peer=short";
    char* bad_pin_argv[] = {program, peer_pin_option, bad_peer_pin_value};
    assert(!parse_args(3, bad_pin_argv).parse_error.empty());

    char tunnels_option[] = "--tunnels";
    char tunnels_value[] = "3";
    char secondary_option_1[] = "--secondary-auth";
    char secondary_value_1[] = "secondary-2.key";
    char secondary_option_2[] = "--secondary-auth";
    char secondary_value_2[] = "secondary-3.key";
    char* tunnel_argv[] = {
        program,
        tunnels_option,
        tunnels_value,
        secondary_option_1,
        secondary_value_1,
        secondary_option_2,
        secondary_value_2,
    };
    const auto tunnel_args = parse_args(7, tunnel_argv);
    assert(tunnel_args.parse_error.empty());
    assert(tunnel_args.tunnel_count == 3);
    assert(tunnel_args.secondary_identities.size() == 2);
    assert(tunnel_args.secondary_identities[0] == "secondary-2.key");
    assert(tunnel_args.secondary_identities[1] == "secondary-3.key");

    char exec_option[] = "--exec";
    char exec_value[] = "uname -a";
    char* exec_argv[] = {program, exec_option, exec_value};
    const auto exec_args = parse_args(3, exec_argv);
    assert(exec_args.parse_error.empty());
    assert(exec_args.exec_cmd == "uname -a");
    assert(!exec_args.allow_exec);
    assert(!exec_args.allow_exec_override);

    char* missing_exec_argv[] = {program, exec_option};
    assert(!parse_args(2, missing_exec_argv).parse_error.empty());

    char allow_exec_option[] = "--allow-exec";
    char* allow_exec_argv[] = {program, allow_exec_option};
    assert(!parse_args(2, allow_exec_argv).parse_error.empty());

    ClientConfig unsafe_exec_config;
    unsafe_exec_config.allow_exec = true;
    Cli unsafe_exec_cli;
    assert(unsafe_exec_cli.run_config(std::move(unsafe_exec_config)) == 1);

    ParsedArgs defaults;
    ClientConfig default_config;
    default_config.history_dir = "/tmp/yume-profile/history";
    normalize_client_config_after_overrides(&defaults, &default_config);
    assert(default_config.relay_receive_dir ==
           "/tmp/yume-profile/received");
    assert(default_config.relay_trust_dir ==
           "/tmp/yume-profile/relay-trust");
    return 0;
}
