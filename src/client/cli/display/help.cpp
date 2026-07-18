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

#include <openssl/crypto.h>
#include <openssl/opensslv.h>

#include "core/security/inner_crypto.hpp"
#include "core/version.hpp"

namespace yume::client {

void print_bash_completion() {
    std::cout << R"(# bash completion for yume
_yume_complete() {
  local cur prev
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  local opts="--help -h --version --credits --config --server --cluster --hide-in-the-crowd --port --auth -i --socks --codec --codec-listen --monero-rpc --monero-rpc-listen --quickbench --fullbench --full-bench --localbench --bench --bench-full --endpoint-fullbench --bench-mib --bench-chunk-kib --bench-streams --bench-direction --duration-sec --latency-iters --bulk-mib --streams --cooldown-ms --repeat --configs --one-way --json --json-stdout --dev --color --no-color --keep-workdir --list-configs --threads --tunnels --obfs --no-obfs --obfs-secret --obfs-pad-multiple --obfs-jitter-ms export import --lport --rhost --rport --udp --tcp --allow-local-ip --server-in-charge --server-in-charge-port --server-in-charge-min-port --server-in-charge-max-port --allow-exec --exec --control --id --list-controlled --inner --no-inner --inner-heavy --inner-light --hop --no-hop --hop-interval --pq-pub --use-embedded-master --no-embedded-master --anonym-ca-cert --tls-ca --tls-name --tls-server-name --tls-pin --profile --no-stealth --tls-stealth-rotate --tls-stealth-rotation-interval --tls-fingerprint-log --tls-fingerprint-log-path --tls-fingerprint-verify --tls-fingerprint-test-endpoint --self-dpi --no-self-dpi --run -c --cmd --run-ipv4 --proxycmd --dest --dport --require-anonym --anonym -L -R --boring --non-interactive --live-status --timing --accept-monitoring --service-streams-only --save-server --completion --name --client-id --relay-mode --allow-inbound-admin --deny-inbound-admin --allow-outbound-admin --deny-outbound-admin --allow-chat --deny-chat --allow-file --deny-file --allow-bytes --deny-bytes --history-dir --no-history --relay-key-file --instance --attach-local --directory --chat --send-file --send-bytes --admin-attach --server-attach --root"
  local file_opts="--config --auth -i --pq-pub --anonym-ca-cert --tls-ca --tls-fingerprint-log-path --relay-key-file"
  case "$prev" in
    --completion)
      COMPREPLY=( $(compgen -W "bash" -- "$cur") )
      return 0
      ;;
    --profile)
      COMPREPLY=( $(compgen -W "chrome firefox safari" -- "$cur") )
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
    std::cout
        << "yume " << yume::kVersion << "\n"
        << "BaseFWX: " << yume::kBasefwxVersion << "\n"
        << "OpenSSL: " << OpenSSL_version(OPENSSL_VERSION) << "\n"
        << "PQ/ML-KEM: " << inner::pq_backend_version() << "\n"
        << "Argon2id: " << inner::argon2_backend_version() << "\n"
        << "PBKDF2/HKDF fallback: " << (inner::pbkdf2_supported() ? "available" : "unavailable") << "\n";
}

void print_credits() {
    std::cout
        << "YUME credits\n"
        << "Author: F1xGOD - founder, lead developer, and designer of Yume and BaseFWX.\n"
        << "Engineering partners:\n"
        << "  Claude (Anthropic) - Yume/BaseFWX engineering partner.\n"
        << "  ChatGPT / Codex - implementation and debugging support.\n"
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
    std::cout
        << "yume - YUME client\n\n"
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
        << "  --hide-in-the-crowd <p>  HTTP-layer disguise profile. Sets the\n"
        << "                             User-Agent emitted in stealth probes.\n"
        << "                             Values: chrome, firefox, safari, edge,\n"
        << "                             curl, wget, yume.\n"
        << "                             When omitted, derived from --profile so the\n"
        << "                             HTTP UA stays consistent with the TLS JA3.\n"
        << "  --config <path>          Config file\n"
        << "  -i, --auth <path>        Identity key\n\n"
        << "Modes:\n"
        << "  --socks [addr:]port      Start a SOCKS5 proxy\n"
        << "                             Example: --socks 127.0.0.1:1080\n"
        << "  --monero-rpc             Start the built-in Monero RPC application\n"
        << "                             codec on 127.0.0.1:18089. Wallets can\n"
        << "                             use --daemon-address 127.0.0.1:18089.\n"
        << "  --codec monero-rpc       Same codec mode using the generic codec flag\n"
        << "  --codec-listen <addr:port>\n"
        << "                           Override codec listener; must be loopback\n"
        << "                             (default 127.0.0.1:18089).\n"
        << "  --quickbench             Run the local device benchmark smoke profile;\n"
        << "                             no server, auth key, or config required.\n"
        << "  --fullbench              Run the local scored device benchmark;\n"
        << "                             no server or auth key required.\n"
        << "  --dev                    With --quickbench/--fullbench, show raw\n"
        << "                             component tables and phase timings.\n"
        << "  --no-color               Disable colored benchmark grades.\n"
        << "  --bench                  Run authenticated endpoint up/down benchmark\n"
        << "                             against yumed --bench, then exit.\n"
        << "  --bench-full             Longer endpoint benchmark profile; currently\n"
        << "                             defaults to 1024 MiB and 64 streams.\n"
        << "  --bench-mib <N>          Benchmark payload per direction (default 256).\n"
        << "  --bench-chunk-kib <N>    DATA chunk size (default 1024, max 1024).\n"
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
        << "  --inner                  Enable inner PQ encryption\n"
        << "  --no-inner               Disable inner PQ encryption and hopping\n"
        << "  --inner-heavy            Heavy KDF mode\n"
        << "  --inner-light            Light KDF mode\n"
        << "  --hop / --no-hop         Inner key hopping on/off\n"
        << "  --hop-interval <ms>      Hop interval\n"
        << "  --obfs / --no-obfs       HTTPS masking tunnel preface on/off\n"
        << "  --obfs-secret <string>   Shared HMAC admission secret; must match\n"
        << "                             yumed. Required for public-node endpoints.\n"
        << "  --obfs-pad-multiple <N>  Pad every outbound frame payload to a\n"
        << "                             multiple of N bytes (0-256, default 0).\n"
        << "                             Reduces stable payload-size features.\n"
        << "                             Requires the same yume version on the\n"
        << "                             server (kFlagPadded support).\n"
        << "  --obfs-jitter-ms <ms>    Defer each batched write by a uniform\n"
        << "                             pseudo-random 0..ms delay (default 0).\n"
        << "                             Adds bounded variation and latency; it\n"
        << "                             does not claim ML/DPI immunity.\n"
        << "  --pq-pub <path>          PQ public key\n"
        << "  --use-embedded-master    Allow embedded BaseFWX master fallback\n"
        << "  --no-embedded-master     Disable embedded BaseFWX master fallback\n"
        << "  --require-anonym, --anonym\n"
        << "                           Require anonym proof\n"
        << "  --anonym-ca-cert <path>  Anonym CA certificate\n"
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
        << "  --profile <name>         chrome, firefox, safari\n"
        << "  --no-stealth             Disable TLS stealth mode\n"
        << "  --tls-stealth-rotate     Rotate stealth profiles after successful TLS connections\n"
        << "  --tls-stealth-rotation-interval <n>\n"
        << "                           Successful connections per active profile\n"
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
        << "                             password (8+ chars, twice for\n"
        << "                             confirmation). File written 0600.\n"
        << "  import <file>            Decrypt a .yss file and write the\n"
        << "                             extracted keys + a ready-to-use\n"
        << "                             config.json to ~/.yume/imported/\n"
        << "                             <server-host>/. Prints the exact\n"
        << "                             `yume --config <path>` to use them.\n\n"
        << "Other:\n"
        << "  completion bash\n"
        << "  -h, --help               Show help\n"
        << "  --version                Show version and compiled crypto capabilities\n"
        << "  --credits                Show credits and bundled component acknowledgements\n";
}
}  // namespace yume::client
