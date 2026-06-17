/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 *
 * yumed help / version / credits / bash-completion output, extracted
 * verbatim from main_server.cpp. No behavior change.
 */

#include "server/cli/help.hpp"

#include <iostream>
#include <string>

#include <openssl/crypto.h>
#include <openssl/opensslv.h>

#include "core/security/inner_crypto.hpp"
#include "core/protocol/runtime_policy.hpp"
#include "core/version.hpp"

void print_bash_completion() {
    std::cout << R"(# bash completion for yumed
_yumed_complete() {
  local cur prev
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  local opts="--help -h --version --credits --config --listen --cert --tls_cert --key --tls_key --auth-keys --threads --reverse-port-min --reverse-port-max --dns-server --proxy --obfs --obfs-secret --obfs-pad-multiple --obfs-jitter-ms --tls-handshake-timeout-ms --max-sessions --accept-rate-limit --egress-mbps --robots-deny --filter-list --filter-geolite --filter-memory-mib --client-filter-mode --egress-filter-mode --packet-egress --packet-tun-name --packet-cidr --packet-mtu --bench --inner --no-inner --inner-heavy --inner-light --inner-dual --inner-required --hop --no-hop --hop-interval --pq-key --pq-auto-generate --use-embedded-master --no-embedded-master --allow-exec --allow-local-ip --control-full --real --real-index --real-secret --real-secret-file --anonym --anonym-proof-mode --anonym-api --anonym-token --anonym-ca-key --anonym-ca-cert --anonym-sub-key --anonym-sub-cert --server-name --server-id --relay-enable --relay-disable --directory-enable --directory-disable --operator-keys --federation-enable --federation-auth-key --federation-anonym-ca --peer --cluster-join --cluster-bootstrap --public-node --hide-in-the-crowd --upstream-response --upstream-response-dir --upstream-response-ttl --attach-local --keys-list --keys-add --keys-remove --keys-alias --keys-gen --keys-gen-add --ui --boring --timing --completion --root"
  local file_opts="--config --cert --tls_cert --key --tls_key --auth-keys --pq-key --real-index --real-secret-file --filter-geolite --anonym-ca-key --anonym-ca-cert --anonym-sub-key --anonym-sub-cert --federation-auth-key --federation-anonym-ca --keys-add --keys-gen"
  case "$prev" in
    --completion)
      COMPREPLY=( $(compgen -W "bash" -- "$cur") )
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
complete -F _yumed_complete yumed
)";
}

void print_version() {
    std::cout
        << "yumed " << yume::kVersion << "\n"
        << "BaseFWX: " << yume::kBasefwxVersion << "\n"
        << "OpenSSL: " << OpenSSL_version(OPENSSL_VERSION) << "\n"
        << "PQ/ML-KEM: " << yume::inner::pq_backend_version() << "\n"
        << "Argon2id: " << yume::inner::argon2_backend_version() << "\n"
        << "PBKDF2/HKDF fallback: " << (yume::inner::pbkdf2_supported() ? "available" : "unavailable") << "\n";
}

void print_credits() {
    std::cout
        << "YUME credits\n"
        << "Author: F1xGOD - founder, lead developer, and designer of Yume and BaseFWX.\n"
        << "Engineering partners:\n"
        << "  Claude (Anthropic) - Yume/BaseFWX engineering partner.\n"
        << "  ChatGPT / Codex - implementation and debugging support.\n"
        << "Core open-source components:\n"
        << "  BaseFWX - GPL-3.0\n"
        << "  liboqs (Open Quantum Safe) - MIT\n"
        << "  OpenSSL - Apache-2.0\n"
        << "  Boost.Asio - Boost Software License 1.0\n"
        << "  nlohmann/json - MIT\n"
        << "  spdlog - MIT\n"
        << "  zstd - BSD-3-Clause\n";
}

void print_help() {
    std::cout
        << "yumed - YUME server\n\n"
        << "Usage:\n"
        << "  yumed [--config <path>] [options]\n"
        << "  yumed completion bash\n"
        << "  yumed --help\n"
        << "  yumed --version\n"
        << "  yumed --credits\n\n"
        << "Core:\n"
        << "  --config <path>          Config file\n"
        << "  --listen <port>          Override listen_port (binds 0.0.0.0:<port>)\n"
        << "  --listen <addr>:<port>   Bind specifically to <addr>:<port>\n"
        << "                             (use [::1]:443 / [::]:443 for IPv6).\n"
        << "                             Under --public-node, addresses in\n"
        << "                             RFC 1918 / loopback / link-local /\n"
        << "                             CGNAT / IPv6 ULA are refused at startup.\n"
        << "  --cert <path>            TLS certificate\n"
        << "  --key <path>             TLS private key\n"
        << "  --auth-keys <path>       Override auth_keys\n"
        << "  --threads <n>            Worker thread count (0 = auto)\n"
        << "  --reverse-port-min <p>   Reverse listen minimum (default "
        << yume::policy::kReversePortMinDefault << ")\n"
        << "  --reverse-port-max <p>   Reverse listen maximum (default "
        << yume::policy::kReversePortMaxDefault << ")\n"
        << "  --dns-server <ip>        Direct DNS resolver for outbound opens\n"
        << "  --proxy <socks5://...>   Route server outbound TCP through SOCKS5\n"
        << "  --obfs                   Enable obfuscation\n"
        << "  --obfs-pad-multiple <N>  Pad every outbound frame payload to a\n"
        << "                             multiple of N bytes (0-256, default 0).\n"
        << "                             Defeats per-packet size classifiers.\n"
        << "                             Requires the same yume version on the\n"
        << "                             client (kFlagPadded support).\n"
        << "  --obfs-jitter-ms <ms>    Defer each batched write by a uniform\n"
        << "                             random 0..ms delay (default 0). Breaks\n"
        << "                             the inter-arrival ML signature at the\n"
        << "                             cost of added latency.\n"
        << "  --tls-handshake-timeout-ms <ms>\n"
        << "                           Close the socket if the TLS handshake\n"
        << "                             doesn't complete in this many ms.\n"
        << "                             Slow-loris guard. 0 = no deadline\n"
        << "                             (legacy). --public-node defaults to\n"
        << "                             10000 when unset.\n"
        << "  --max-sessions <N>       Hard cap on simultaneously-tracked\n"
        << "                             sessions. New accepts past the cap are\n"
        << "                             closed immediately (looks like a busy\n"
        << "                             nginx). 0 = unlimited. --public-node\n"
        << "                             defaults to 4096 when unset.\n"
        << "  --accept-rate-limit <N>  Cap on accepts per second over a 1 s\n"
        << "                             rolling window. Refused accepts close\n"
        << "                             immediately. 0 = unlimited.\n"
        << "                             --public-node defaults to 100 when unset.\n"
        << "  --egress-mbps <N>        Weighted fair egress cap across auth keys.\n"
        << "                             0 = disabled. One active key can use the\n"
        << "                             full cap; equal active keys split it.\n"
        << "                             auth_keys_meta priority 1..100 controls\n"
        << "                             weighted shares (default 50).\n"
        << "  --filter-list <spec>     Load an IP/country filter list. spec is\n"
        << "                             <client|egress|both>:<allow|deny>:<path>\n"
        << "                             where path is JSON, vpn_db.bin, or .tar.xz.\n"
        << "  --filter-geolite <path>  Country DB archive or compact DB path.\n"
        << "  --filter-memory-mib <N>  Approximate in-memory filter cap (0 = unlimited).\n"
        << "  --client-filter-mode <m> Client source mode: blacklist or whitelist.\n"
        << "  --egress-filter-mode <m> Egress destination mode: blacklist or whitelist.\n"
        << "  --packet-egress tun      Enable packet_bulk_v1 over an operator-\n"
        << "                             prepared Linux TUN/NAT interface.\n"
        << "  --packet-tun-name <if>   TUN device to attach (default yume-pkt0).\n"
        << "  --packet-cidr <cidr>     Client IPv4 pool (default 10.89.0.0/24).\n"
        << "                             The .1 address is reserved for the TUN side.\n"
        << "  --packet-mtu <N>         Packet-native MTU (default 1420).\n"
        << "  --bench                 Enable authenticated built-in up/down\n"
        << "                             benchmark streams for yume --bench.\n"
        << "  --allow-local-ip         Allow private/loopback destinations\n"
        << "  --control-full           Allow full server-side network control\n"
        << "  --root                   Keep root privileges after bind/listen\n"
        << "  --boring                 Minimal logs\n"
        << "  --timing                 Emit lightweight timing diagnostics\n\n"
        << "Security:\n"
        << "  --inner                  Enable inner PQ crypto\n"
        << "  --no-inner               Disable inner PQ crypto and hopping\n"
        << "  --inner-heavy            Heavy KDF mode\n"
        << "  --inner-light            Light KDF mode\n"
        << "  --inner-dual             Accept heavy and light clients\n"
        << "  --inner-required         Reject clients without inner crypto\n"
        << "  --hop / --no-hop         Inner key hopping on/off\n"
        << "  --hop-interval <ms>      Hop interval\n"
        << "  --pq-key <path>          PQ private key\n"
        << "  --pq-auto-generate       Generate a PQ keypair when needed\n"
        << "  --use-embedded-master    Allow embedded BaseFWX master fallback\n"
        << "  --no-embedded-master     Disable embedded BaseFWX master fallback\n\n"
        << "HTTP / Anonym:\n"
        << "  --real                   Serve real HTTP for non-client requests\n"
        << "  --robots-deny            Serve /robots.txt with Disallow: / through\n"
        << "                             the HTTP facade for normal probes.\n"
        << "  --real-index <path>      HTML file for /\n"
        << "  --real-secret <str>      Hidden metadata secret\n"
        << "  --real-secret-file <path> Load or create secret file\n"
        << "  --anonym                 Enable anonym mode\n"
        << "  --anonym-proof-mode <m>  auto, local, or fixcraft\n"
        << "  --anonym-api <url>       Verity API URL\n"
        << "  --anonym-token <str>     Verity API token\n"
        << "  --anonym-ca-key <path>   Anonym CA private key\n"
        << "  --anonym-ca-cert <path>  Anonym CA certificate\n"
        << "  --anonym-sub-key <path>  Anonym sub-CA private key\n"
        << "  --anonym-sub-cert <path> Anonym sub-CA certificate\n\n"
        << "Relay and Runtime:\n"
        << "  --server-name <name>     Server name\n"
        << "  --server-id <32hex>      Stable server endpoint ID\n"
        << "  --relay-enable           Enable client relay features\n"
        << "  --relay-disable          Disable client relay features\n"
        << "  --directory-enable       Enable endpoint directory\n"
        << "  --directory-disable      Disable endpoint directory\n"
        << "  --operator-keys <path>   Operator key metadata\n"
        << "  --federation-enable      Enable static federation mode\n"
        << "  --federation-auth-key <path> Ed25519 key used for peer AUTH\n"
        << "  --federation-anonym-ca <path> CA used to verify peer servers\n"
        << "  --peer <json>            Add a federation peer (raw JSON form)\n"
        << "  --cluster-join <spec>    Join cluster via short form; implies --federation-enable.\n"
        << "                             spec: [id@]host[:port][?pin=<sha256>]\n"
        << "                             e.g. alice@alice.example.com:443\n"
        << "                                  alice.example.com (id+port defaulted)\n"
        << "                             repeat for multiple peers\n"
        << "  --cluster-bootstrap      Mark this node as a cluster entry point;\n"
        << "                             federation enabled but no outbound --peer required\n"
        << "                             (other servers will dial in via --cluster-join)\n"
        << "  --public-node            Hardening preset for an internet-facing yumed.\n"
        << "                             Rejects --allow-exec / --allow-local-ip /\n"
        << "                             --control-full / --no-inner; requires --auth-keys;\n"
        << "                             logs what is and is not yet enforced.\n"
        << "                             Also implicitly sets --hide-in-the-crowd nginx\n"
        << "                             when no profile is otherwise selected.\n"
        << "  --hide-in-the-crowd <p>  HTTP-layer disguise profile for the disguise\n"
        << "                             responses this daemon emits when probed.\n"
        << "                             Values: nginx, nginx-stable, apache, caddy,\n"
        << "                             cloudflare, express, gunicorn, none, yumed\n"
        << "                             (default: yumed; nginx under --public-node).\n"
        << "  --upstream-response <p>  Replay a pre-captured real HTTP/1.x response\n"
        << "                             byte-identically when probed. Capture with\n"
        << "                             `curl -i https://real-site/notfound > resp.http`\n"
        << "                             once and point this flag at it. Wins over\n"
        << "                             --hide-in-the-crowd when both are set.\n"
        << "  --upstream-response-dir <d>\n"
        << "                           Like --upstream-response but loads every\n"
        << "                             *.http / *.response in the directory and\n"
        << "                             picks one at random per probe. Defeats\n"
        << "                             'probe twice, get identical bytes' replay\n"
        << "                             checks. Wins over --upstream-response when\n"
        << "                             both are set.\n"
        << "  --upstream-response-ttl <s>\n"
        << "                           When used with --upstream-response-dir, reloads\n"
        << "                             the directory every <s> seconds so operators\n"
        << "                             can drop new captures in without restarting.\n"
        << "                             0 = load once at startup (default).\n"
        << "  --attach-local           Attach to a local yumed\n\n"
        << "Key Management:\n"
        << "  --keys-list              List authorized keys\n"
        << "  --keys-add <pub.pem>     Add authorized key\n"
        << "  --keys-remove <id>       Remove by fingerprint or alias\n"
        << "  --keys-alias <id> <a>    Set alias\n"
        << "  --keys-gen <prefix>      Generate Ed25519 keypair (<prefix>.key/.pub)\n"
        << "  --keys-gen-add           Append generated public key to auth_keys\n"
        << "  auth_keys_meta supports federation_peer_id, priority, and permissions.{allow_local_ip,control_full,allow_exec,allow_chat,allow_file,allow_bytes,allow_inbound_admin,allow_outbound_admin}\n"
        << "  --ui                     Interactive server manager\n\n"
        << "Other:\n"
        << "  completion bash\n"
        << "  -h, --help               Show help\n"
        << "  --version                Show version and compiled crypto capabilities\n"
        << "  --credits                Show credits and bundled component acknowledgements\n";
}
