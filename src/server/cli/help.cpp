/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * yumed help, version, credits, and bash-completion output.
 */

#include "server/cli/help.hpp"

#include <iostream>
#include <string>

#include "core/protocol/runtime_policy.hpp"
#include "core/release/terminal.hpp"
#include "util.hpp"

void print_bash_completion() {
    std::cout << R"(# bash completion for yumed
_yumed_complete() {
  local cur prev
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  local opts="-h --accept-rate-limit --accept-yume-clients --admin-keys --allow-exec --allow-local-ip --allow-monero-rpc --attach-local --auth-keys --auth-keys-meta --bench --boring --bulk-key-max-sessions --cert --client-deny-action --client-filter-mode --cluster-bootstrap --cluster-join --codec-allow --completion --config --control-full --credits --directory-disable --directory-enable --dns-server --egress-filter-mode --egress-mbps --exposure-check --federation-identity --federation-enable --federation-operator-ca --filter-geolite --filter-list --filter-memory-mib --help --hide-in-the-crowd --host-mode --inner-psk-file --key --keys-add --keys-admin --keys-alias --keys-gen --keys-gen-add --keys-list --keys-remove --listen --max-sessions --monero-rpc-backend --no-yume-clients --obfs-secret-file --operator-ca-cert --operator-ca-key --operator-delegated-cert --operator-delegated-key --operator-identity --operator-keys --operator-keys-meta --operator-proof-api --operator-proof-mode --operator-proof-token-file --packet-cidr --packet-egress --packet-mtu --packet-tun-name --peer --proxy --public-node --real --real-backend --real-index --real-root --real-secret-file --rekey-window --relay-disable --relay-enable --reverse-port-max --reverse-port-min --robots-deny --root --server-id --server-name --service-allow --threads --timing --tls-handshake-timeout-ms --tls_cert --tls_key --ui --upstream-response --upstream-response-dir --upstream-response-ttl --version"
  local file_opts="--operator-proof-token-file --config --cert --tls_cert --key --tls_key --auth-keys --auth-keys-meta --admin-keys --operator-keys --operator-keys-meta --obfs-secret-file --inner-psk-file --filter-geolite --operator-ca-key --operator-ca-cert --operator-delegated-key --operator-delegated-cert --federation-identity --federation-operator-ca --keys-add --keys-gen"
  case "$prev" in
    --completion)
      COMPREPLY=( $(compgen -W "bash" -- "$cur") )
      return 0
      ;;
    --codec-allow)
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
complete -F _yumed_complete yumed
)";
}

void print_version() {
    yume::release::print_version_report("Yume Server");
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
                     "SERVER", yume::util::stdout_colors_enabled())
        << "\n"
        << "Usage:\n"
        << "  yumed [--config <path>] [options]\n"
        << "  yumed completion bash\n"
        << "  yumed --completion bash\n"
        << "  yumed --help\n"
        << "  yumed --version\n"
        << "  yumed --credits\n\n"
        << "Core:\n"
        << "  --completion <shell>    Print a completion script and exit (bash only)\n"
        << "  --config <path>          Config file\n"
        << "  --listen <port>          Override listen_port (binds 0.0.0.0:<port>)\n"
        << "  --listen <addr>:<port>   Bind specifically to <addr>:<port>\n"
        << "                             (use [::1]:443 / [::]:443 for IPv6).\n"
        << "                             Under --public-node, addresses in\n"
        << "                             RFC 1918 / loopback / link-local /\n"
        << "                             CGNAT / IPv6 ULA are refused at startup.\n"
        << "  --cert <path>            TLS certificate\n"
        << "  --key <path>             TLS private key\n"
        << "  --tls_cert <path>        Alias for --cert (matches the JSON key)\n"
        << "  --tls_key <path>         Alias for --key (matches the JSON key)\n"
        << "  --auth-keys <path>       Override auth_keys\n"
        << "  --auth-keys-meta <path>  Override per-key permissions JSON\n"
        << "  --admin-keys <path>      Separate composite admin second-factor store\n"
        << "  --operator-keys <path>   Separate composite operator identities\n"
        << "  --operator-keys-meta <p> Operator-key permissions JSON\n"
        << "  --threads <n>            Worker thread count (0 = auto)\n"
        << "  --reverse-port-min <p>   Reverse listen minimum (default "
        << yume::policy::kReversePortMinDefault << ")\n"
        << "  --reverse-port-max <p>   Reverse listen maximum (default "
        << yume::policy::kReversePortMaxDefault << ")\n"
        << "  --dns-server <ip>        IPv4 resolver for outbound opens, and the resolver\n"
        << "                             handed to packet-mode clients. Required by\n"
        << "                             --packet-egress tun; no default\n"
        << "  --proxy <socks5://...>   Route server outbound TCP through SOCKS5\n"
        << "  --obfs-secret-file <p>  32-byte admission secret as exactly 64\n"
        << "                             lowercase hex characters in a protected file\n"
        << "  --inner-psk-file <p>    Mandatory 32-byte inner PSK in the same format\n"
        << "  --real-backend <url>    Required loopback://<IP-literal>:<port> Node site\n"
        << "  --tls-handshake-timeout-ms <ms>\n"
        << "                           Close the socket if the TLS handshake\n"
        << "                             doesn't complete in this many ms.\n"
        << "                             Slow-loris guard. 0 = no deadline\n"
        << "                             --public-node defaults to\n"
        << "                             10000 when unset.\n"
        << "  --max-sessions <N>       Hard cap on simultaneously-tracked\n"
        << "                             sessions. New accepts past the cap are\n"
        << "                             closed immediately. 0 = unlimited.\n"
        << "                             Default 256; 0 explicitly disables.\n"
        << "  --bulk-key-max-sessions <N>\n"
        << "                           Default concurrent sessions for each\n"
        << "                             regular key marked key_type=bulk.\n"
        << "                             Default 64; per-key max_sessions wins.\n"
        << "  --rekey-window <N>       Concurrent directional epoch offers accepted\n"
        << "                             per session, and the ceiling on this\n"
        << "                             server's own sending window (1..64;\n"
        << "                             default 8). Each prepared epoch adds\n"
        << "                             one negotiated epoch budget per rekey\n"
        << "                             round trip on high-latency links.\n"
        << "  --accept-rate-limit <N>  Cap on accepts per second over a 1 s\n"
        << "                             shared accounting window. Refused accepts close\n"
        << "                             immediately. 0 = unlimited.\n"
        << "                             --public-node defaults to 100 when unset.\n"
        << "  --egress-mbps <N>        Weighted fair egress cap across identities.\n"
        << "                             0 = disabled. One active identity can use\n"
        << "                             the full cap; equal identities split it.\n"
        << "                             auth_keys_meta weight 0.1..100 controls\n"
        << "                             weighted shares (default 1.0).\n"
        << "  --filter-list <spec>     Load an IP/country filter list. spec is\n"
        << "                             <client|egress|both>:<allow|deny>:<path>\n"
        << "                             where path is JSON, vpn_db.bin, or .tar.xz.\n"
        << "  --filter-geolite <path>  Country DB or archive (archives: Linux/GNU tar).\n"
        << "  --filter-memory-mib <N>  Approximate in-memory filter cap (0 = unlimited).\n"
        << "  --client-filter-mode <m> Client source mode: blacklist or whitelist.\n"
        << "  --egress-filter-mode <m> Egress destination mode: blacklist or whitelist.\n"
        << "  --packet-egress tun      Enable packet_bulk_v1 over an operator-\n"
        << "                             prepared Linux TUN/NAT interface.\n"
        << "  --packet-tun-name <if>   TUN device to attach (default yume-pkt0).\n"
        << "  --packet-cidr <cidr>     Client IPv4 pool (default 10.89.0.0/24).\n"
        << "                             The .1 address is reserved for the TUN side.\n"
        << "  --packet-mtu <N>         Packet-native MTU (default 1420).\n"
        << "                           Optional host setup: review yume-packet-quick up --help.\n"
        << "  --bench                 Enable authenticated built-in up/down\n"
        << "                             benchmark streams for yume --bench.\n"
        << "  --allow-exec             Reserved relayed EXEC policy input; this does not\n"
        << "                             enable command execution. Direct EXEC and current\n"
        << "                             client-side inbound EXEC both fail closed.\n"
        << "  --allow-local-ip         Allow private/loopback destinations\n"
        << "  --control-full           Allow full server-side network control\n"
        << "  --codec-allow <name>     Enable a built-in/plugin application codec\n"
        << "                             (first built-in: monero-rpc; also requires\n"
        << "                             per-key allow_codecs).\n"
        << "  --allow-monero-rpc       Alias for --codec-allow monero-rpc\n"
        << "  --service-allow <name>   Enable a native ABI named service stream\n"
        << "                             (also requires per-key allow_services\n"
        << "                             and yume_endpoint_register_service).\n"
        << "  --monero-rpc-backend <addr:port>\n"
        << "                           Loopback monerod RPC backend for the codec\n"
        << "                             (default 127.0.0.1:18089).\n"
        << "  --root                   Keep root privileges after bind/listen\n"
        << "  --boring                 Minimal logs\n"
        << "  --timing                 Emit precise timing diagnostics (developer build only)\n\n"
        << "Security:\n"
        << "  YUME 2.0 always uses ephemeral ML-KEM-1024 + X25519, a mandatory\n"
        << "  file-distributed PSK, per-message AES-256-GCM keys, and independent\n"
        << "  directional epochs. JSON security_mode selects extreme (default),\n"
        << "  normal, soft, or bounded ultimate limits; see docs/SECURITY_MODES.md.\n\n"
        << "HTTP / Operator identity:\n"
        << "  --real-backend <url>     Proxy ordinary GET/HEAD to a separately\n"
        << "                             supervised loopback Node service\n"
        << "  --robots-deny            Serve /robots.txt with Disallow: / through\n"
        << "                             the HTTP facade for normal probes.\n"
        << "  --real-index <path>      HTML file for / (maximum 8 MiB)\n"
        << "  --real-root <dir>        Serve GET/HEAD static files under <dir>\n"
        << "                             (maximum 8 MiB per response)\n"
        << "                             (implies --real; one web identity for\n"
        << "                             HTTP/1.1 and the H2 decoy). Pair with\n"
        << "                             --hide-in-the-crowd nginx for best fit.\n"
        << "  --real-secret-file <path> Cover-backend secret file; loaded, or created on first start\n"
        << "  --operator-identity      Publish an operator identity proof and enable\n"
        << "                             privacy-minimizing server behavior\n"
        << "  --operator-proof-mode <m> auto, local, or fixcraft\n"
        << "  --operator-proof-api <url> External proof API URL (fixcraft mode)\n"
        << "  --operator-proof-token-file <path> Owner-only proof API token file (1-4096 bytes)\n"
        << "  --operator-ca-key <path> Operator CA private key\n"
        << "  --operator-ca-cert <path> Operator CA certificate\n"
        << "  --operator-delegated-key <path> Delegated server identity key\n"
        << "  --operator-delegated-cert <path> CA-signed delegated server certificate\n"
        << "  The proof establishes CA-authorized operator identity, not a guarantee\n"
        << "  that the host cannot inspect or log client traffic. Display names are\n"
        << "  informational; clients trust the certificate chain and fingerprints.\n\n"
        << "Relay and Runtime:\n"
        << "  --server-name <name>     Server name\n"
        << "  --server-id <32hex>      Stable server endpoint ID\n"
        << "  --relay-enable           Enable client relay features\n"
        << "  --relay-disable          Disable client relay features\n"
        << "  --directory-enable       Enable endpoint directory\n"
        << "  --directory-disable      Disable endpoint directory\n"
        << "  --federation-enable      Enable static federation mode\n"
        << "  --federation-identity <path> composite identity used for peer AUTH v2\n"
        << "  --federation-operator-ca <path> CA used to verify peer servers\n"
        << "  --peer <json>            Add a federation peer (raw JSON form)\n"
        << "  --cluster-join <spec>    Join cluster via short form; implies --federation-enable.\n"
        << "                             spec: [id@]host[:port]?psk_file=<path>&\n"
        << "                                   carrier_secret_file=<path>[&pin=<sha256>]\n"
        << "                             pin is 64 lowercase hex; IPv6 requires id@[host]\n"
        << "                             repeat for multiple peers\n"
        << "  --cluster-bootstrap      Mark this node as a cluster entry point;\n"
        << "                             federation enabled but no outbound --peer required\n"
        << "                             (other servers will dial in via --cluster-join)\n"
        << "  --public-node            Hardening preset for an internet-facing yumed.\n"
        << "                             Rejects --allow-exec / --allow-local-ip /\n"
        << "                             --control-full; requires --auth-keys and\n"
        << "                             both protected YUME 2.0 secret files.\n"
        << "                             Also implicitly sets --hide-in-the-crowd nginx\n"
        << "                             when no profile is otherwise selected.\n"
        << "  --host-mode <mode>       Host controller mode: off, private, relay.\n"
        << "                             private = WAN host without YUME clients by default.\n"
        << "                             relay = host routing plus YUME client tunnel.\n"
        << "  --accept-yume-clients    Accept authenticated YUME clients (default).\n"
        << "  --no-yume-clients        Reject YUME AUTH/carrier; disguise only.\n"
        << "  --client-deny-action <a> IP filter deny action: close, reset, drop.\n"
        << "  --exposure-check <host>  Probe whether hostname is direct TCP or CF HTTP.\n"
        << "  --hide-in-the-crowd <p>  HTTP-layer disguise profile for the disguise\n"
        << "                             responses this daemon emits when probed.\n"
        << "                             Values: nginx, nginx-stable, apache, caddy,\n"
        << "                             cloudflare, express, gunicorn, none, yumed\n"
        << "                             (default: yumed; nginx under --public-node).\n"
        << "  --upstream-response <p>  Replay a pre-captured real HTTP/1.x response\n"
        << "                             (maximum 8 MiB after line normalization)\n"
        << "                             with complete HTTP framing; body bytes are kept.\n"
        << "                             Header LF is accepted. Capture with\n"
        << "                             `curl --http1.1 --raw -i https://real-site/notfound > resp.http`\n"
        << "                             once and point this flag at it. Wins over\n"
        << "                             --hide-in-the-crowd when both are set.\n"
        << "  --upstream-response-dir <d>\n"
        << "                           Like --upstream-response but loads every\n"
        << "                             *.http / *.response in the directory and\n"
        << "                             scans at most 4096 entries, accepts at most\n"
        << "                             256 captures of 8 MiB each, and caches at\n"
        << "                             most 64 MiB total. It then\n"
        << "                             picks one at random per probe. Avoids the\n"
        << "                             simplest identical-capture replay check.\n"
        << "                             Wins over --upstream-response when\n"
        << "                             both are set.\n"
        << "  --upstream-response-ttl <s>\n"
        << "                           When used with --upstream-response-dir, reloads\n"
        << "                             the directory every <s> seconds so operators\n"
        << "                             can drop new captures in without restarting.\n"
        << "                             0 = load once at startup (default).\n"
        << "  --attach-local           Attach to a local yumed\n\n"
        << "Key Management:\n"
        << "  --keys-list              List authorized keys\n"
        << "  --keys-add <pub.pem>     Add authorized key (visitor store)\n"
        << "  --keys-admin             With --keys-add/--keys-gen-add: enrol into the\n"
        << "                           separate admin store (--admin-keys). Admin still\n"
        << "                           requires a distinct visitor key as first factor.\n"
        << "  --keys-remove <id>       Remove by fingerprint or alias\n"
        << "  --keys-alias <id> <a>    Set alias\n"
        << "  --keys-gen <prefix>      Generate composite Ed25519+ML-DSA-87 identity (<prefix>.key/.pub)\n"
        << "  --keys-gen-add           Append generated public key to auth_keys\n"
        << "  auth_keys_meta supports key_type (individual|bulk), weight, max_sessions, federation_peer_id plus federation_psk_file, permissions.allow_codecs, permissions.allow_services, and permissions.{allow_local_ip,allow_exec,allow_chat,allow_file,allow_bytes}. True control_full or inbound/outbound-admin grants are rejected; admin requires a distinct --admin-keys identity, and outbound admin also requires the visitor identity in --operator-keys.\n"
        << "  --ui                     Interactive server manager\n\n"
        << "Other:\n"
        << "  completion bash\n"
        << "  -h, --help               Show help\n"
        << "  --version                Show local versions and crypto capabilities\n"
        << "                             (YUME_UPDATE_CHECK=1 enables the GitHub check)\n"
        << "  --credits                Show credits and bundled component acknowledgements\n";
}
