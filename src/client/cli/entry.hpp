/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>

#include "core/security/ratchet.hpp"
#include "core/security/secret_file.hpp"
#include "core/version.hpp"
#include "client/transport/socket_protection.hpp"
#include "outbound/tunnel_fwd.hpp"

namespace yume::client {

// Forward declarations so the in-process embedder gets handles to the
// constructed network primitives without dragging tunnel.hpp /
// relay_runtime.hpp into every TU that includes cli.hpp.
class RelayRuntime;
struct ParsedArgs;

struct ClientConfig {
    std::string server;
    int port{443};
    std::string identity;
    // Second factor for an admin session; empty for an ordinary visitor.
    std::string admin_identity;
    // Empty keeps the historical wildcard bind. Set an IP literal such
    // as 127.0.0.1, 0.0.0.0, ::1, or :: to choose the local SOCKS
    // listener address explicitly.
    std::string socks_bind_host;
    int socks_port{0};
    // Operator-created Linux IFF_TUN|IFF_NO_PI device. Yume only attaches;
    // interface addresses, routes, DNS, firewall, and NAT stay external.
    std::string packet_tun_name;
    int io_threads{0};
    // Number of parallel TLS tunnels the client opens to the server.
    // The first is the "primary" — owns control / relay / activity
    // handlers. The remaining are data-only and share the data plane
    // via TunnelPool least-loaded selection. Clamped to [1, 16]; 1 disables
    // multi-tunnel and matches the pre-3.7.1 single-tunnel layout.
    // Individual identities admit one authenticated server session by
    // default. Bulk identities may opt into additional parallel tunnels.
    int tunnel_count{1};
    bool obfuscation{true};
    std::string obfs_secret_file;
    std::string inner_psk_file;
    std::shared_ptr<yume::security::Secret32> obfs_secret_material;
    std::shared_ptr<yume::security::Secret32> inner_psk_material;
    // --obfs-pad-multiple <N>. Round every outbound frame payload up to
    // a multiple of N bytes via trailing pad bytes + 1-byte length. 0 =
    // off. Clamped to [0, 256]. The peer must understand kFlagPadded
    // (same yume version), so this is opt-in.
    std::uint16_t obfs_pad_multiple{0};
    // --obfs-jitter-ms <ms>. Defer each batched TLS write by a uniform
    // random delay in [0, ms]. 0 = no delay.
    std::uint32_t obfs_jitter_ms{0};
    bool inner_crypto{true};
    // --rekey-window <N>. Concurrent directional epoch offers this client
    // accepts inbound and, capped by the server's advertised depth, uses
    // outbound. One outstanding exchange caps a saturated direction at one
    // negotiated epoch byte budget per rekey round trip; N raises that to N
    // budgets without changing the selected per-epoch policy. Clamped to the
    // ratchet's supported range.
    std::uint16_t rekey_window{yume::ratchet::kDefaultRekeyWindow};
    ratchet::SecurityProfileConfig security_profile{};
    bool allow_udp{false};
    bool allow_local_ip{false};
    bool server_in_charge{false};
    int server_in_charge_port{0};
    bool allow_exec{false};
    std::string pq_public_key;
    bool allow_embedded_master{false};
    std::string anonym_pubkey;
    std::string anonym_pubkey_material_id;
    std::string anonym_ca_cert;
    std::string anonym_ca_material_id{"embedded-anonym-ca"};
    std::string auth_key_material_id;
    std::string tls_ca_cert;
    std::string tls_ca_material_id;
    std::string tls_server_name;
    std::string tls_pin_sha256;
    // The in-process patched OpenSSL emitter is the default. The optional helper
    // and stock OpenSSL diagnostic emitter remain explicit alternatives only;
    // no backend silently falls back to either one.
    std::string transport_profile{yume::kTransportProfile};
    std::string tls_backend{"openssl-chrome151"};
    std::string tls_helper_path;
    bool require_anonym{false};
    bool accept_monitoring{false};
    bool service_streams_only{false};
    bool boring{false};
    bool non_interactive{false};
    std::string instance_name;
    std::string preferred_name;
    std::string preferred_id;
    std::string relay_mode{"untrusted"};
    // Relay-v2 authenticates each peer's composite identity end-to-end. TOFU
    // records the first successfully completed ordinary-channel handshake;
    // pinned requires a configured entry before any handshake is attempted.
    // Admin channels always require an explicit configured pin in either mode.
    std::string relay_trust_mode{"tofu"};
    std::string relay_trust_dir;
    std::map<std::string, std::string> relay_peer_pins;
    bool allow_inbound_admin{false};
    bool allow_outbound_admin{false};
    bool allow_chat{true};
    bool allow_file{true};
    bool allow_bytes{true};
    bool history_enabled{true};
    std::string history_dir;
    std::string relay_receive_dir;
    std::string relay_key_file;
    bool auto_attach_local{true};
    std::string app_codec;
    std::string app_codec_listen_host{"127.0.0.1"};
    int app_codec_listen_port{18089};
    
    // TLS Stealth Mode settings
    bool tls_stealth_enabled{true};  // ON by default
    std::string tls_stealth_profile{"chrome"};  // complete fixture registry key
    bool tls_fingerprint_log{false};
    std::string tls_fingerprint_log_path{"./logs/fingerprints"};
    bool tls_fingerprint_verify{false};
    std::string tls_fingerprint_test_endpoint{"tls.peet.ws"};
    bool self_dpi{false};

    // Outbound proxy used to reach the Yume server. When set, the client
    // doesn't do a direct DNS+TCP connect to `server:port` — it connects
    // to `outbound_proxy_host:outbound_proxy_port` and asks the proxy to
    // forward to `server:port` via SOCKS5. The hostname is sent as a
    // SOCKS5 domain address so .onion targets resolve on the proxy side
    // (Tor) without leaking DNS. Leave outbound_proxy_url empty to go
    // direct. Format: "socks5://[user[:pass]@]host:port".
    std::string outbound_proxy_url;

    // In-process-only socket hook. It is deliberately absent from config
    // serialization and command-line parsing because it carries process-local
    // state owned by an embedder such as Android's VpnService.
    SocketProtectCallback socket_protect;
};

inline const std::string& effective_tls_server_name(const ClientConfig& cfg) noexcept {
    return cfg.tls_server_name.empty() ? cfg.server : cfg.tls_server_name;
}

struct RuntimeReadyInfo {
    std::string server_tls_fingerprint_sha256;
    std::vector<std::string> server_capabilities;
};

class Cli {
public:
    // Fires exactly once, on Cli's io_context worker thread, immediately
    // after Tunnel + RelayRuntime are constructed and the tunnel is
    // authenticated against the server. The in-process embedder
    // (facade::InProcClient) uses this to capture the two shared_ptrs
    // and then post requests onto Tunnel's executor — same flow the
    // local-runtime IPC handler uses, just without the socket round-trip.
    //
    // Lifetime: these objects are bound to the connected session's
    // io_context and must be released before run_connected_session returns.
    // InProcClient enforces that boundary with RuntimeLifetimeGate leases;
    // other embedders must provide equivalent operation-scoped ownership.
    using RuntimeReadyCallback = std::function<void(
        std::shared_ptr<Tunnel>,
        std::shared_ptr<RelayRuntime>,
        RuntimeReadyInfo)>;
    void set_runtime_ready_callback(RuntimeReadyCallback cb);

    // Fires when the connected-session runtime becomes active, including
    // the disconnect hook used by the normal CLI signal handler. Embedded
    // callers use this for clean shutdown without relying on private
    // tunnel internals.
    using RuntimeActiveCallback = std::function<void(
        boost::asio::io_context*,
        std::shared_ptr<Tunnel>,
        std::shared_ptr<RelayRuntime>,
        std::function<void(const std::string&)>)>;
    void set_runtime_active_callback(RuntimeActiveCallback cb);
    void set_external_stop_flag(std::shared_ptr<std::atomic<bool>> stop_flag);

    // When true, Cli skips its colour-coded "Connected to..." banner
    // and any other unsolicited std::cout writes. spdlog output is
    // separately routed via the spdlog default logger sinks - if the
    // embedder wants those silent too it should replace those sinks
    // (yume_facade does this through LogSink). Default: false, so the
    // CLI binary keeps its existing console UX.
    void set_silent(bool silent) noexcept { silent_ = silent; }
    bool silent() const noexcept { return silent_; }

    int run(int argc, char** argv);
    // In-process/ABI entrypoint: consumes an already parsed and path-resolved
    // configuration and starts the same authenticated engine without
    // reconstructing CLI arguments or implicitly enabling SOCKS.
    int run_config(ClientConfig cfg);

private:
    int run_parsed(ParsedArgs args, std::string executable_arg);
    RuntimeReadyCallback runtime_ready_callback_;
    RuntimeActiveCallback runtime_active_callback_;
    std::shared_ptr<std::atomic<bool>> external_stop_flag_;
    std::optional<ClientConfig> config_override_;
    bool silent_{false};
};

}  // namespace yume::client
