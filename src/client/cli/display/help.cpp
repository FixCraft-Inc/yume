/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * CLI help / version / credits / bash-completion output, extracted
 * verbatim from client/cli/entry.cpp. No behavior change.
 */

#include "client/cli/display/help.hpp"

#include <iostream>
#include <string>

#include "core/release/terminal.hpp"
#include "util.hpp"

namespace yume::client {

void print_bash_completion() {
    std::cout << R"(# bash completion for yume
_yume_complete() {
  local cur prev
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  local opts="--help -h --version --credits --config --server --cluster --hide-in-the-crowd --port --auth -i --socks --packet-tun --codec --codec-listen --monero-rpc --monero-rpc-listen --quick-bench --quickbench --full-bench --fullbench --localbench --bench --bench-full --endpoint-fullbench --bench-mib --bench-chunk-kib --bench-streams --bench-direction --duration-sec --latency-iters --bulk-mib --streams --cooldown-ms --repeat --configs --one-way --json --json-stdout --dev --color --no-color --keep-workdir --list-configs --threads --tunnels --obfs --obfs-secret-file --inner-psk-file export import --lport --rhost --rport --udp --tcp --allow-local-ip --server-in-charge --server-in-charge-port --server-in-charge-min-port --server-in-charge-max-port --allow-exec --exec --control --id --list-controlled --operator-ca-cert --anonym-ca-cert --tls-ca --tls-name --tls-server-name --tls-pin --profile --tls-fingerprint-log --tls-fingerprint-log-path --tls-fingerprint-verify --tls-fingerprint-test-endpoint --self-dpi --no-self-dpi --run -c --cmd --run-ipv4 --proxycmd --dest --dport --require-operator-identity --require-anonym --anonym -L -R --boring --non-interactive --live-status --timing --accept-monitoring --service-streams-only --save-server --completion --name --client-id --relay-mode --allow-inbound-admin --deny-inbound-admin --allow-outbound-admin --deny-outbound-admin --allow-chat --deny-chat --allow-file --deny-file --allow-bytes --deny-bytes --history-dir --no-history --relay-key-file --instance --attach-local --directory --chat --send-file --send-bytes --admin-attach --server-attach --root"
  local file_opts="--config --auth -i --obfs-secret-file --inner-psk-file --operator-ca-cert --anonym-ca-cert --tls-ca --tls-fingerprint-log-path --relay-key-file"
  case "$prev" in
    --completion)
      COMPREPLY=( $(compgen -W "bash" -- "$cur") )
      return 0
      ;;
    --profile)
      COMPREPLY=( $(compgen -W "chrome" -- "$cur") )
      return 0
      ;;
    --codec)
      COMPREPLY=( $(compgen -W "monero-rpc" -- "$cur") )
      return 0
      ;;
  esac
  for opt in $file_opts; do
    if [[ "$prev" == "$opt" ]]; then
      COMPREPLY=( $(compgen -f -- "$cur") )
      return 0
    fi
  done
  if [[ "$cur" == -* ]]; then
    COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
    return 0
  fi
  COMPREPLY=()
}
complete -F _yume_complete yume
)";
}

void print_version() {
    yume::release::print_version_report("Yume");
}

void print_credits() {
    std::cout
        << "YUME credits\n"
        << "Author: F1xGOD - founder, lead developer, and designer of Yume and BaseFWX.\n"
        << "Engineering partners:\n"
        << "  Codex - primary AI engineering partner across architecture, implementation, security hardening, testing, and documentation.\n"
        << "  Claude - supporting contributions to selected reviews, refactors, and bug fixes.\n"
        << "Core open-source components:\n"
        << "  BaseFWX core/runtime - LGPL-3.0-or-later\n"
        << "  liboqs (Open Quantum Safe) - MIT\n"
        << "  OpenSSL - Apache-2.0\n"
        << "  Boost.Asio - Boost Software License 1.0\n"
        << "  nlohmann/json - MIT\n"
        << "  spdlog - MIT\n"
        << "  zstd - BSD-3-Clause\n";
}

void print_help() {
    std::cout << yume::release::render_brand_header(
                     "CLIENT", yume::util::stdout_colors_enabled())
        << "\n"
        << "Usage:\n"
        << "  yume --server <host> -i <id_ed25519> [mode] [options]\n"
        << "  yume completion bash\n"
        << "  yume --help\n"
        << "  yume --version\n"
        << "  yume --credits\n\n"
        << "Connection:\n"
        << "  --server <host>          Server address\n"
        << "  --cluster <spec>         Cluster entry-point short form:\n"
        << "                             host                    (port 443)\n"
        << "                             host:port\n"
        << "                             [ipv6]:port\n"
        << "                           Sets --server + --port together.\n"
        << "  --hide-in-the-crowd chrome\n"
        << "                           Explicit spelling for the pinned Chrome 150\n"
        << "                             HTTP profile; other profiles are rejected.\n"
        << "  --config <path>          Config file\n"
        << "  -i, --auth <path>        Identity key\n\n"
        << "Modes:\n"
        << "  --socks [addr:]port      Start a SOCKS5 proxy\n"
        << "                             Example: --socks 127.0.0.1:1080\n"
        << "  --packet-tun <ifname>    Attach an operator-created Linux TUN (no route changes)\n"
        << "  --monero-rpc             Start the built-in Monero RPC application\n"
        << "                             codec on 127.0.0.1:18089. Wallets can\n"
        << "                             use --daemon-address 127.0.0.1:18089.\n"
        << "  --codec monero-rpc       Same codec mode using the generic codec flag\n"
        << "  --codec-listen <addr:port>\n"
        << "                           Override codec listener; must be loopback\n"
        << "                             (default 127.0.0.1:18089).\n"
        << "  --quick-bench            Run the local device benchmark smoke profile;\n"
        << "                             no server, auth key, or config required.\n"
        << "  --full-bench             Run the local YUME 2.0 transport benchmark;\n"
        << "                             reports MiB/s, no server/config required.\n"
        << "  --dev                    With --quick-bench/--full-bench, show raw\n"
        << "                             component tables and phase timings.\n"
        << "  --no-color               Disable colored benchmark grades.\n"
        << "  --bench                  Run authenticated endpoint up/down benchmark\n"
        << "                             against yumed --bench, then exit.\n"
        << "  --bench-full             Longer real-server profile; defaults to\n"
        << "                             1024 MiB per direction and 64 streams.\n"
        << "  --bench-mib <N>          Benchmark payload per direction (default 256).\n"
        << "  --bench-chunk-kib <N>    DATA chunk size (default: SOCKS/relay buffer, 64 KiB).\n"
        << "  --bench-streams <N>      Concurrent benchmark streams (default 1, max 240).\n"
        << "  --bench-direction <D>    both, up, or down (default both).\n"
        << "  -L [bind:]lport:host:port\n"
        << "                           Local forward\n"
        << "  -R [bind:]rport:host:port\n"
        << "                           Reverse forward\n"
        << "  --run <cmd>              Run a command through Yume\n"
        << "  --control [id]           Control a registered client\n"
        << "  --list-controlled        List controlled clients\n"
        << "  --directory              List visible relay endpoints\n"
        << "  --chat <id|name>         Start chat\n"
        << "  --send-file <id|name> <path>\n"
        << "                           Send a file\n"
        << "  --send-bytes <id|name> <path>\n"
        << "                           Send raw bytes\n"
        << "  --admin-attach <id|name> Open trusted admin channel\n"
        << "  --attach-local           Attach to a local yume\n"
        << "  --service-streams-only   Embedder mode: keep only ABI service streams\n\n"
        << "Relay:\n"
        << "  --name <slug>            Display name\n"
        << "  --client-id <32hex>      Stable client ID\n"
        << "  --relay-mode <mode>      untrusted or trusted\n"
        << "  --allow-inbound-admin / --deny-inbound-admin\n"
        << "                           Inbound admin attach\n"
        << "  --allow-outbound-admin / --deny-outbound-admin\n"
        << "                           Outbound admin attach\n"
        << "  --allow-chat / --deny-chat\n"
        << "                           Chat relay\n"
        << "  --allow-file / --deny-file\n"
        << "                           File relay\n"
        << "  --allow-bytes / --deny-bytes\n"
        << "                           Byte relay\n\n"
        << "Runtime:\n"
        << "  --threads <n>            IO threads (0 = auto)\n"
        << "  --tunnels <n>            Parallel TLS tunnels to the server (1..16; default 4)\n"
        << "  --instance <name>        Runtime instance name\n"
        << "  --history-dir <path>     Chat history directory\n"
        << "  --relay-key-file <path>  Relay key file\n"
        << "  --no-history             Disable chat history\n"
        << "  --udp                    Enable UDP forwarding\n"
        << "  --tcp                    Force TCP only\n"
        << "  --allow-local-ip         Allow private and loopback destinations\n"
        << "  --run-ipv4               Prefer IPv4 for --run\n"
        << "  --root                   Keep root privileges\n"
        << "  --non-interactive        Disable live status redraw\n"
        << "  --live-status            Enable live status redraw\n"
        << "  --timing                 Emit lightweight timing diagnostics\n"
        << "  --boring                 Minimal output\n"
        << "  --                        Service-safe launch\n\n"
        << "Security:\n"
        << "  --obfs                   Use the mandatory HTTP/2 carrier (default)\n"
        << "  --obfs-secret-file <p>  32-byte admission secret as exactly 64\n"
        << "                             lowercase hex characters in a protected file\n"
        << "  --inner-psk-file <p>    Mandatory 32-byte inner PSK in the same format\n"
        << "  The inner suite and 256 KiB / 512-frame / 500 ms directional\n"
        << "  ratchet limits are mandatory and have no 1.x downgrade switches.\n"
        << "  --require-operator-identity\n"
        << "                           Require proof authorized by the selected operator CA\n"
        << "                             (legacy aliases: --require-anonym, --anonym)\n"
        << "  --operator-ca-cert <path>\n"
        << "                           Operator CA certificate used to verify the host\n"
        << "                             (legacy alias: --anonym-ca-cert)\n"
        << "  This proof identifies the CA-authorized operator; it cannot prove that\n"
        << "  the operator does not inspect or log traffic.\n"
        << "  --tls-ca <path>          TLS CA certificate\n"
        << "  --tls-pin <sha256>       Pin TLS certificate fingerprint\n\n"
        << "Proxy:\n"
        << "  --proxy socks5://[user[:pass]@]host:port\n"
        << "                           Route the connection to the Yume server\n"
        << "                           through a SOCKS5 proxy. The hostname is\n"
        << "                           resolved on the proxy side, so .onion\n"
        << "                           targets work through Tor.\n"
        << "  --tor                    Shorthand for --proxy socks5://127.0.0.1:9050\n"
        << "  --no-proxy               Override config; connect directly\n\n"
        << "TLS:\n"
        << "  --tls-name <host>       SNI/certificate/HTTP Host name when\n"
        << "                           --server is an IP or alternate route\n"
        << "  --profile <name>         chrome (the only 2.0 dev1 fixture)\n"
        << "  --tls-fingerprint-log    Log TLS fingerprint metrics\n"
        << "  --tls-fingerprint-log-path <path>\n"
        << "                           Fingerprint log path\n"
        << "  --tls-fingerprint-verify Verify fingerprints against a test endpoint\n"
        << "  --tls-fingerprint-test-endpoint <host>\n"
        << "                           Test endpoint host\n"
        << "  --self-dpi               Warn when local carrier metadata stops\n"
        << "                             matching the selected disguise profile\n"
        << "  --no-self-dpi            Disable self-DPI warnings\n\n"
        << "Console:\n"
        << "  help, status, directory, invites, chat, send, send-file, send-bytes,\n"
        << "  accept, reject, history, history-delete, admin attach, admin status,\n"
        << "  admin sessions, admin stop, whoami, quit\n\n"
        << "Share files (server backup / device migration):\n"
        << "  export <file>            Encrypt the current config + auth key\n"
        << "                             + CA cert + PQ pubkey into a\n"
        << "                             password-protected .yss file (\"yume\n"
        << "                             secure store\"). Prompts for a\n"
        << "                             password (12+ chars, twice for\n"
        << "                             confirmation). File written 0600.\n"
        << "  import <file>            Decrypt a .yss file and write the\n"
        << "                             extracted keys + a ready-to-use\n"
        << "                             config.json to ~/.yume/imported/\n"
        << "                             <server-host>/. Prints the exact\n"
        << "                             `yume --config <path>` to use them.\n\n"
        << "Other:\n"
        << "  completion bash\n"
        << "  -h, --help               Show help\n"
        << "  --version                Show local versions and crypto capabilities\n"
        << "                             (YUME_UPDATE_CHECK=1 enables the GitHub check)\n"
        << "  --credits                Show credits and bundled component acknowledgements\n";
}
}  // namespace yume::client
