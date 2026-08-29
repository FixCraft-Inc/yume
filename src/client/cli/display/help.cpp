/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * CLI help, version, credits, and bash-completion output.
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
  local opts="-h -i export import -c -L -R --accept-monitoring --accept-server-control --accept-server-control-max-port --accept-server-control-min-port --admin-attach --admin-auth --allow-bytes --allow-chat --allow-file --allow-inbound-admin --allow-local-ip --allow-outbound-admin --attach-local --auth --bench --bench-chunk-kib --bench-direction --bench-full --bench-mib --bench-streams --boring --bulk-mib --chat --client-id --client-threads --cluster --codec --codec-listen --color --completion --config --configs --control --cooldown-ms --credits --deny-bytes --deny-chat --deny-file --deny-inbound-admin --deny-outbound-admin --dest --dev --directory --dport --duration-sec --exec --full-bench --help --hide-in-the-crowd --history-dir --id --inner-psk-file --instance --json --json-stdout --keep-workdir --latency-iters --list-configs --list-controlled --live-status --lport --monero-rpc --monero-rpc-listen --name --no-color --no-history --no-proxy --no-self-dpi --non-interactive --obfs-secret-file --one-way --operator-ca-cert --outer-carrier-evidence --packet-tun --password-stdin --port --profile --proxy --proxycmd --quick-bench --rekey-window --relay-key-file --relay-mode --relay-peer-pin --relay-receive-dir --relay-trust-dir --relay-trust-mode --repeat --require-operator-identity --rhost --root --rport --run --run-ipv4 --save-server --secondary-auth --self-dpi --send-bytes --send-file --server --server-threads --service-streams-only --socks --streams --tcp --threads --timing --tls-backend --tls-ca --tls-fingerprint-log --tls-fingerprint-log-path --tls-fingerprint-test-endpoint --tls-fingerprint-verify --tls-helper --tls-name --tls-pin --tor --transport-profile --tunnels --udp --version"
  local file_opts="--config --auth -i --secondary-auth --admin-auth --obfs-secret-file --inner-psk-file --operator-ca-cert --tls-ca --tls-helper --tls-fingerprint-log-path --relay-key-file --relay-receive-dir --relay-trust-dir --outer-carrier-evidence"
  case "$prev" in
    --completion)
      COMPREPLY=( $(compgen -W "bash" -- "$cur") )
      return 0
      ;;
    --profile)
      COMPREPLY=( $(compgen -W "chrome" -- "$cur") )
      return 0
      ;;
    --relay-mode)
      COMPREPLY=( $(compgen -W "untrusted trusted" -- "$cur") )
      return 0
      ;;
    --relay-trust-mode)
      COMPREPLY=( $(compgen -W "tofu pinned" -- "$cur") )
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
        << "                           Explicit spelling for the pinned Chrome 151\n"
        << "                             HTTP profile; other profiles are rejected.\n"
        << "  --config <path>          Config file\n"
        << "  -i, --auth <path>        Identity key (composite Ed25519+ML-DSA-87)\n"
        << "      --secondary-auth <path>\n"
        << "                           Repeat once for every data-only SOCKS tunnel\n"
        << "                             after the primary. Requires exactly N-1 values\n"
        << "                             with --tunnels N; all must authenticate.\n"
        << "      --admin-auth <path>    Second key for an admin session. Must differ from\n"
        << "                             --auth and be enrolled in the server admin store.\n"
        << "                             Presenting it is the claim; there is no admin flag.\n\n"
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
        << "  --outer-carrier-evidence <absolute-path>\n"
        << "                           Write one mode-0600 live H2/WebSocket behavior\n"
        << "                             report outside Git. Requires the pinned Chrome\n"
        << "                             backend and exact 1-MiB one-shot benchmark.\n"
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
        << "  --relay-trust-mode <mode> tofu (default) or pinned\n"
        << "  --relay-trust-dir <path> Owner-only relay-v2 peer identity store\n"
        << "  --relay-peer-pin <id=64hex>\n"
        << "                           Explicit composite identity pin; repeatable.\n"
        << "                             Required for admin channels in both modes.\n"
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
        << "  --tunnels <n>            Parallel TLS tunnels to the server (1..16; default 1;\n"
        << "                             values above 1 require bulk-key session policy,\n"
        << "                             or N-1 distinct --secondary-auth identities)\n"
        << "  --rekey-window <n>       Concurrent directional epoch offers (1..64;\n"
        << "                             default 8). Each prepared epoch adds\n"
        << "                             one negotiated epoch budget per rekey\n"
        << "                             round trip. Capped by the server.\n"
        << "  --instance <name>        Runtime instance name\n"
        << "  --history-dir <path>     Chat history directory\n"
        << "  --relay-receive-dir <path>\n"
        << "                           Confined file/byte receive directory\n"
        << "  --relay-key-file <path>  Relay key file\n"
        << "  --no-history             Disable chat history\n"
        << "  --udp                    Enable UDP forwarding\n"
        << "  --tcp                    Force TCP only\n"
        << "  --allow-local-ip         Allow private and loopback destinations\n"
        << "  --run-ipv4               Prefer IPv4 for --run\n"
        << "  --root                   Keep root privileges\n"
        << "  --non-interactive        Disable live status redraw\n"
        << "  --live-status            Enable live status redraw\n"
        << "  --timing                 Emit precise timing diagnostics (developer build only)\n"
        << "  --boring                 Minimal output\n"
        << "  --                        Service-safe launch\n\n"
        << "Security:\n"
        << "  --obfs-secret-file <p>  32-byte admission secret as exactly 64\n"
        << "                             lowercase hex characters in a protected file\n"
        << "  --inner-psk-file <p>    Mandatory 32-byte inner PSK in the same format\n"
        << "  The inner suite and per-frame keys are mandatory. JSON security_mode\n"
        << "  selects extreme (default), normal, soft, or bounded ultimate epoch\n"
        << "  limits; see docs/SECURITY_MODES.md. There is no 1.x downgrade.\n"
        << "  --require-operator-identity\n"
        << "                           Require proof authorized by the selected operator CA\n"
        << "  --operator-ca-cert <path>\n"
        << "                           Operator CA certificate used to verify the host\n"
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
        << "  --profile <name>         chrome (the only 2.0 fixture)\n"
        << "  --transport-profile <id> chrome151-node24-v1 (exact dev6 identity)\n"
        << "  --tls-backend <name>     openssl-chrome151 (default), chrome151 helper,\n"
        << "                           or openssl-diagnostic\n"
        << "  --tls-helper <path>      Helper path; valid only with chrome151 backend\n"
        << "  --tls-fingerprint-log    Diagnostic-backend fingerprint metrics\n"
        << "  --tls-fingerprint-log-path <path>\n"
        << "                           Diagnostic-backend fingerprint log path\n"
        << "  --tls-fingerprint-verify Diagnostic-backend endpoint verification\n"
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
        << "                             confirmation). Up to 16 MiB; created\n"
        << "                             0600 without following or overwriting.\n"
        << "  import <file>            Decrypt a .yss file and write the\n"
        << "                             extracted keys + a ready-to-use\n"
        << "                             config.json to ~/.yume/imported/\n"
        << "                             <server-host>/. Prints the exact\n"
        << "                             `yume --config <path>` to use them.\n"
        << "                             Input is capped at 16 MiB before KDF.\n\n"
        << "Other:\n"
        << "  completion bash\n"
        << "  -h, --help               Show help\n"
        << "  --version                Show local versions and crypto capabilities\n"
        << "                             (YUME_UPDATE_CHECK=1 enables the GitHub check)\n"
        << "  --credits                Show credits and bundled component acknowledgements\n";
}
}  // namespace yume::client
