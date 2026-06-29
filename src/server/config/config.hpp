/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/protocol/runtime_policy.hpp"

namespace yume::server {

struct ServerConfig {
    int listen_port{443};
    // --listen now accepts either "<port>" (legacy: bind 0.0.0.0:<port>)
    // or "<addr>:<port>" (bind specifically to <addr>). When the addr
    // form is used, listen_address holds the parsed address string;
    // empty means "bind any" (the legacy default). Under --public-node,
    // a listen_address that resolves to a private or loopback range is
    // a hard startup error — that's the "private-IP bind refusal" item
    // the banner had been logging.
    std::string listen_address;
    std::string tls_cert;
    std::string tls_key;
    std::string auth_keys;
    int threads{0};
    bool obfuscation{true};
    bool inner_crypto{true};
    bool inner_heavy{true};
    bool inner_dual{false};
    bool inner_required{false};
    bool inner_hop{true};
    std::uint32_t hop_interval_ms{500};
    int reverse_port_min{yume::policy::kReversePortMinDefault};
    int reverse_port_max{yume::policy::kReversePortMaxDefault};
    std::string dns_server;
    std::string pq_private_key;
    bool pq_auto_generate{false};
    bool allow_embedded_master{false};
    bool allow_exec{false};
    bool allow_local_ip{false};
    bool control_full{false};
    std::vector<std::string> allowed_codecs;
    std::vector<std::string> allowed_services;
    // Compatibility shim for older config/CLI spellings. New code should use
    // allowed_codecs plus the app-codec registry.
    bool allow_monero_rpc_codec{false};
    std::string monero_rpc_backend_host{"127.0.0.1"};
    int monero_rpc_backend_port{18089};
    bool real_http{false};
    bool robots_deny{false};
    std::string real_index_path;
    std::string real_secret;
    std::string real_secret_file;
    std::string obfs_secret;
    bool anonym{false};
    std::string anonym_proof_mode{std::string(yume::policy::kAnonymProofModeAuto)};
    std::string anonym_api;
    std::string anonym_token;
    std::string anonym_hash;
    std::string anonym_sig;
    std::string anonym_ts;
    std::string anonym_nonce;
    std::string anonym_certfp;
    std::string anonym_ca_key;
    std::string anonym_ca_cert;
    std::string anonym_ca_sig;
    std::string anonym_ca_alg;
    std::string anonym_sub_key;
    std::string anonym_sub_cert;
    std::string anonym_sub_cert_b64;
    std::string anonym_sub_sig;
    std::string anonym_sub_alg;
    std::vector<std::string> anonym_proof_sources;
    std::string pq_pub_b64;
    std::string pq_sig;
    std::string pq_alg;
    std::string auth_keys_meta;
    std::string server_name;
    std::string server_id;
    std::string outbound_proxy_url;
    bool relay_enable{true};
    bool directory_enable{true};
    bool ipc_enable{true};
    std::string ipc_path;
    bool federation_enable{false};
    // True when the operator passed --cluster-bootstrap: the daemon is
    // an entry point into a federated cluster, expects peers to dial
    // it but has no outgoing dial-out list of its own. Relaxes the
    // "federation requires at least one --peer" startup check.
    bool cluster_bootstrap{false};
    // True when the operator passed --public-node: hardening preset for
    // a yumed instance reachable from the open internet. Turns the
    // existing build-feature-silent-downgrade warnings into hard
    // startup errors, requires --auth-keys, and rejects flags that
    // would expose dangerous capabilities (--allow-exec, --allow-local-ip,
    // --control-full, --no-inner).
    bool public_node{false};
    // --hide-in-the-crowd <profile>. Name of a yume::http_profile::ServerProfile
    // — controls the Server: header, 404 body shape, and supplementary
    // headers (X-Powered-By for express, CF-Ray for cloudflare, etc).
    // Empty string means "use the default", which is "yumed" unless
    // --public-node also set, in which case startup overrides to "nginx".
    std::string http_profile;
    // --upstream-response <path>. Path to a pre-captured real HTTP/1.1
    // response (operator captures it once via tcpdump or curl -i
    // against a real nginx/apache/etc and points this flag at the
    // file). When set, Session::send_disguise_404 emits those bytes
    // verbatim instead of the synthetic profile-driven 404 — probes
    // see a byte-identical-to-the-real-upstream response, defeating
    // any DPI inspector that compares body bytes against a known
    // capture. Loaded at startup; line endings are normalised so
    // operators can capture with curl -i (which prints \n) without
    // breaking HTTP wire format. Empty = use synthetic profile.
    std::string upstream_response_file;
    std::string upstream_response_bytes;
    // --upstream-response-dir <dir>. Sibling of --upstream-response that
    // loads every *.http / *.response file in the directory and rotates
    // per-probe. Defeats the "replay yumed twice, get the same Date /
    // ETag / body" tell from --upstream-response. Files are normalised
    // (lone \n → \r\n) the same way --upstream-response handles them.
    // If both --upstream-response and --upstream-response-dir are set,
    // the directory wins and the single file is ignored.
    std::string upstream_response_dir;
    // --upstream-response-ttl <s>. When > 0 alongside
    // --upstream-response-dir, Manager reloads the directory every TTL
    // seconds so operators can drop in new captures without restarting
    // yumed. 0 = load once at startup.
    std::uint32_t upstream_response_ttl_s{0};
    // --obfs-pad-multiple <N>. When > 0, every outbound frame's payload
    // is padded with trailing zeros + a 1-byte length to round its
    // on-wire size up to a multiple of N. Defeats classifiers that
    // train on per-packet payload-size histograms. 0 = off. Receivers
    // always strip padding transparently — but both ends must run a
    // version that knows about kFlagPadded, so enabling this on a new
    // sender talking to a pre-padding peer is a hard break. Clamped to
    // [0, 256] (256 is the largest N a single length byte can carry).
    std::uint16_t obfs_pad_multiple{0};
    // --obfs-jitter-ms <ms>. When > 0, each batched frame write is
    // deferred by a uniform random delay in [0, ms]. Breaks the
    // "constant ping/keepalive cadence" ML feature at the cost of
    // added send latency. 0 = no jitter.
    std::uint32_t obfs_jitter_ms{0};
    // --tls-handshake-timeout-ms <ms>. Per-connection cap on the TLS
    // handshake. A peer that opens TCP and starts TLS but never sends
    // ClientHello (slow-loris style) holds a session slot until the
    // OS keepalive eventually fires; this deadline closes the socket
    // sooner. 0 = no deadline (legacy behaviour). --public-node sets
    // this to 10000 (10 s) when the operator hasn't overridden;
    // generous enough that any legitimate client finishes in time.
    std::uint32_t tls_handshake_timeout_ms{0};
    // --max-sessions <N>. Hard cap on simultaneously-tracked sessions
    // (entries in Manager::live_sessions_). 0 = unlimited (legacy).
    // When the cap is reached, new accepts are immediately closed —
    // the TCP connection sees a successful accept then a fast RST/FIN,
    // which is what an over-capacity nginx looks like, so this stays
    // disguise-consistent. --public-node defaults to 4096 (generous
    // for typical operator use; raise via --max-sessions <N>).
    std::uint32_t max_sessions{0};
    // --accept-rate-limit <conns-per-sec>. Token bucket on the accept
    // loop: at most this many new connections per second over a 1s
    // sliding window. 0 = unlimited (legacy). --public-node defaults
    // to 100 (legitimate clients reconnect once on disconnect, not
    // hundreds per second; pure scanner / DoS traffic does). Refused
    // connections are closed immediately on accept.
    std::uint32_t accept_rate_limit{0};
    // --egress-mbps <N>. Optional weighted fair egress shaper across
    // authenticated client keys. 0 = disabled. When enabled, one active
    // key can use the full cap; N equal-priority active keys converge to
    // 1/N of the cap. auth_keys_meta priority values act as weights.
    std::uint32_t egress_mbps{0};
    std::string client_filter_mode{"blacklist"};
    std::string egress_filter_mode{"blacklist"};
    std::vector<std::string> filter_lists;
    std::string filter_geolite;
    std::uint32_t filter_memory_mib{64};
    std::string packet_egress;
    std::string packet_tun_name{"yume-pkt0"};
    std::string packet_cidr{"10.89.0.0/24"};
    std::uint32_t packet_mtu{1420};
    bool benchmark_enable{false};
    std::vector<std::string> federation_peers;
    std::string federation_auth_key;
    std::string federation_anonym_ca;
    std::string operator_keys;
    std::string operator_keys_meta;
    bool boring{false};
};

}  // namespace yume::server
