# YUME — 夢

**yume** *(Japanese: 夢)*: a dream.

Yume Universal Multiprotocol Engine. An open-source post-quantum stealth transport. The name is a single character — 夢 — and we use it the way Japanese uses it: a dream of a network you can trust, where the wire shape blends into ordinary HTTPS and neither endpoint has to advertise YUME by name.

YUME tunnels TCP and UDP through TLS 1.3 sessions with browser-profiled ClientHellos and an HTTP/2-shaped opening exchange. Its optional inner channel derives AES-256-GCM keys from ML-KEM-768, can add an Argon2id work factor, and supports 1-4 Hz per-window key derivation. The client (`yume`), daemon (`yumed`), proxy, GUI, and libyume surface are AGPL-3.0-or-later and build from this tree. They run on x86, ARMv7/8, MIPS OpenWRT, BusyBox, macOS, and Windows; the minimal build runs on routers with as little as 128 MiB of RAM.

- Website: https://yume.fixcraft.jp
- Source: https://github.com/FixCraft-Inc/yume
- Issues: https://github.com/FixCraft-Inc/yume/issues

For the current implementation / testing boundary, including host-controller,
codec, federation, plugin, and browser status, see
[docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md).

## Why YUME

VPN protocols built for performance (WireGuard, OpenVPN) are also built to be recognisable. Their handshakes have static byte signatures that ISPs and national firewalls can match in milliseconds. Commercial VPN services then resell that same recognisable transport for $20/month, bandwidth that costs them pennies, and run it from cheap KVMs that any user could rent directly.

YUME tries to do the opposite: a transport with browser-oriented TLS presets, keyed active-probe admission, and an ordinary HTTPS decoy path, with crypto that survives the move to post-quantum and both ends open for audit and self-hosting. These layers reduce obvious signatures; they do not make YUME byte-identical to Chrome or immune to stateful DPI. FixCraft will run a fleet of free public endpoints (no signup, no payment), but the endpoints run the same `yumed` you can build right here.

## Compared to other tools

|                             | YUME            | WireGuard      | OpenVPN                  | Tor (with bridges) | Shadowsocks     |
| --------------------------- | --------------- | -------------- | ------------------------ | ------------------ | --------------- |
| Post-quantum KEM/DEM (ML-KEM-768 + AES-GCM) | yes | no | no | no | no |
| Live key hopping            | 1–4 Hz, OTA     | no             | no                       | no                 | no              |
| HTTPS-shaped carrier | browser-profiled TLS + H2 opening; known limits | UDP signature | TLS-on-OpenVPN-port signature | obfs4 bridge | random-prefix |
| Anonym / no-log mode        | built in        | n/a            | per-provider             | yes                | n/a             |
| Free public endpoints       | planned (FixCraft) | none        | none                     | yes                | none            |
| Embedded / 128 MiB hardware | yes             | yes            | yes                      | partial            | yes             |
| Self-hostable, fully open   | yes (AGPL-v3+)  | yes            | yes                      | bridge only        | yes             |
| Published YUME transport measurement | 234 Mbps download in one WAN run | — | — | — | — |
| License                     | AGPL-v3+        | GPL-v2         | GPL-v2                   | BSD-3              | Apache-2        |

YUME's measured row comes from the single live run reported in [docs/PERFORMANCE.md](docs/PERFORMANCE.md). That run did not isolate CPU cost or establish an all-hardware upper bound.

## Quick start

```bash
git clone https://github.com/FixCraft-Inc/yume.git
cd yume
# BaseFWX is a pinned sibling checkout, not a submodule.
git clone https://github.com/FixCraft-Inc/basefwx.git basefwx
git -C basefwx checkout "$(cat config/refs/basefwx.ref)"
cmake -B build
cmake --build build -j$(nproc)
```

The build produces `build/bin/yume` and `build/bin/yumed`.

Server:

```bash
sudo ./build/bin/yumed \
    --listen 443 \
    --cert certs/server.crt --key certs/server.key \
    --auth-keys /etc/yume/authorized_keys
```

Public-facing server, hardened defaults bundle:

```bash
sudo ./build/bin/yumed \
    --listen 443 \
    --cert certs/server.crt --key certs/server.key \
    --auth-keys /etc/yume/authorized_keys \
    --public-node \
    --obfs-secret 'replace-with-a-long-shared-secret' \
    --hide-in-the-crowd nginx          # implicit when --public-node is set
```

`--public-node` requires a nonempty obfs secret; every client for that endpoint must use the same `--obfs-secret` value. Distribute it out of band rather than committing a production secret.

Client:

```bash
./build/bin/yume \
    --server yume.example.com \
    --auth ~/.yume/id_ed25519 \
    --obfs-secret 'replace-with-a-long-shared-secret' \
    --socks 127.0.0.1:1080
```

Cluster entry-point short form (translates to `--server` + `--port`):

```bash
./build/bin/yume --cluster yume.example.com:443 \
    --auth ~/.yume/id_ed25519 \
    --obfs-secret 'replace-with-a-long-shared-secret' \
    --socks 1080
```

For a privileged port 443 on Linux, run `yumed` with `sudo` or grant `cap_net_bind_service`. Cloudflare HTTP-mode proxies will terminate TLS and break YUME. Use Spectrum or another TCP passthrough if you front the daemon with Cloudflare.

## Optional desktop GUI (`yume-gui`)

A Dear ImGui + GLFW desktop application is available in the same tree and is **off** by default. It uses the shared facade library and drives the same linked, in-process client runtime as the CLI; no client subprocess or local IPC round trip is required. The GUI is intended for desktop users; the CLI remains the supported automation surface.

### Build

```bash
cmake -B build-gui -DYUME_BUILD_GUI=ON
cmake --build build-gui -j$(nproc)
./build-gui/bin/yume-gui          # main window
./build-gui/bin/yume-gui --help   # CLI options
./build-gui/bin/yume-gui --headless   # facade-only smoke test
```

`YUME_BUILD_GUI=ON` pulls Dear ImGui, GLFW, and ImPlot via CMake `FetchContent` (pinned tags). On Linux the system tray (minimise-to-tray) is enabled automatically when `libayatana-appindicator3-dev` is present; without it the GUI builds normally but the tray icon is disabled.

System dev packages (Debian/Ubuntu):

```bash
sudo apt install libgl-dev libglfw3-dev libxkbcommon-dev \
                 libfreetype-dev libfontconfig-dev \
                 libayatana-appindicator3-dev
```

### What's in it

- **Client** page for the main connect/disconnect workflow and saved server profile
- **Security** page for trusted anonym CAs and imported client auth keys, with a built-in default CA
- **Overview** with larger crisp desktop typography, connection status, local server status, byte counters, and a 60-second traffic graph (ImPlot)
- **Server** page that hosts a local server with the same controls as `yumed`
- **Tools** area for key generation, authorized-key management, logs, appearance, relay directory, and chat

GUI profile, trust material, generated keys, and runtime data live under `~/.yume/`.

### Debian packaging

`yume-gui` ships as a separate binary package alongside `yume`. The build is gated by the `nogui` build profile — setting `DEB_BUILD_PROFILES=nogui` produces only the CLI .deb (matching the stock GitHub release flow). The default build produces both packages.

### Limitations of the current MVP

- `ServerSession::start()` runs a real in-process `yumed` runtime through the shared server manager. Privileged ports still require root or `cap_net_bind_service`.
- `ClientSession::start()` hosts the current CLI connection runtime in-process. Its lifecycle remains deliberately isolated from the GUI thread; CLI parsing and terminal-only commands stay in the `yume` executable.
- Chat / directory pages depend on a connected background client and use the live `RelayRuntime` IPC surface.
- The tray code path is present but only assembles when `libayatana-appindicator3-dev` is installed; the rest of the GUI works without it.

## Install, man pages, and Debian packages

Install from a build tree:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
sudo cmake --install build
sudo mandb
```

Build a Debian package:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build -j$(nproc)
(cd build && cpack -G DEB)
```

Or use the helper:

```bash
./ezbuild.sh --deb
```

The package installs `yume(1)`, `yumed(8)`, and the Markdown docs. See
[docs/PACKAGING.md](docs/PACKAGING.md) for cross-architecture package
notes, BaseFWX package dependency details, and manual man-page installation.

### Embedded build

```bash
cmake -B build -DYUME_MINIMAL=ON -DYUME_USE_BASEFWX=ON
cmake --build build -j$(nproc)
```

`ezbuild.sh` cross-compiles for Linux x86_64 / x86 / ARMv7 / ARMv8, MIPS OpenWRT, BusyBox flavours, macOS x86_64 / arm64, and Windows x86_64. Prebuilt vendor toolchains live in [`vendor/`](vendor/).

## Free public endpoints (coming soon)

FixCraft will operate a small fleet of public `yumed` endpoints. They will:

- be free to use without an account, payment, or rate-limiting beyond fairness
- run the unmodified daemon you can build from this tree
- serve a real HTML page on `/` so that a browser hitting the same hostname sees something normal
- publish their public keys and authorised-keys fingerprints in advance so clients can pin them

Specific hostnames will land here once the fleet is up.

## Stealth and obfuscation

YUME stacks four independent layers of byte-shape camouflage:

1. **TLS 1.3 with browser-oriented parameters.** `--profile chrome|firefox|safari` configures cipher suites, supported groups, signature algorithms, and ALPN toward Chrome 131 / Firefox 126 / Safari 18. OpenSSL emits the real ClientHello; YUME computes JA3 and canonical JA4 diagnostics from it. Stock OpenSSL does not reproduce every current-browser detail, so these profiles do not prove browser-cluster membership. Source: [src/core/stealth/tls_stealth.cpp](src/core/stealth/tls_stealth.cpp), [src/core/stealth/tls_fingerprint.cpp](src/core/stealth/tls_fingerprint.cpp).
2. **HTTP/2 carrier admission (`--obfs`, default on).** After TLS, the client emits an HTTP/2 preface, project-defined SETTINGS, WINDOW_UPDATE, and a valid HPACK HEADERS request for `POST /<token>/<nonce>`. The server validates HMAC token, path shape, frame order, and SNI/authority; then returns server SETTINGS, ACK of client SETTINGS, and bodyless accepted response HEADERS. The client ACKs the server settings before YUME AUTH. Missing, malformed, or wrong paths remain in masquerade and receive a complete benign H2 response using configured upstream/real/profile identity. `--public-node` requires a nonempty shared `--obfs-secret`; empty-secret structural admission exists only for non-public development. The authenticated payload stream is not a fully conformant long-lived HTTP/2 session, and the opening is not claimed to be exact Chrome/Firefox traffic. Code: [src/core/stealth/obfs_h2.cpp](src/core/stealth/obfs_h2.cpp), [src/core/stealth/obfs_signal.cpp](src/core/stealth/obfs_signal.cpp).
3. **HTTP-layer server disguise (`--hide-in-the-crowd <profile>`).** Before 1.0 a non-YUME probe (curl / scanner) saw TLS handshake + immediate TCP close. With this flag yumed instead serves a synthetic profile-driven response whose header order, charset, and body template are based on expected software shapes: `nginx`, `nginx-stable`, `apache`, `caddy`, `cloudflare`, `express`, `gunicorn`, `none`, and `yumed`. These are not native nginx/Apache/etc. implementations; use operator-captured `--upstream-response` data when higher fidelity matters. The same flag on the client explicitly selects the User-Agent; otherwise the UA follows the active TLS profile, including rotation. Codec: [src/core/stealth/http_profile.cpp](src/core/stealth/http_profile.cpp).
4. **Real HTML facade (`--real --real-index <html>`).** A browser that hits the same port with `GET / HTTP/1.1` is served the configured HTML page (or a Wikipedia redirect by default). YUME clients and browsers cohabit on port 443.

Limits: this raises the cost of simple TLS-fingerprint blocking and casual active probing. It does not make YUME indistinguishable from a browser, preserve valid HTTP/2 semantics for the full authenticated stream, or defeat stateful and ML classifiers trained on record sizes, timing, or repeated connection behaviour.

### Headless carrier diagnosis

For an opt-in end-to-end carrier check, `scripts/yume_carrier_diagnose.py`
launches a local `yume` client, starts a packet capture before the TLS
handshake, drives headless Chromium through the local SOCKS listener, captures
an optional direct Chromium baseline, and runs `dpi-human-report.py`.

Fully local ephemeral run:

```bash
scripts/yume_carrier_diagnose.py --inner-heavy --hop --out ~/yume-carrier-diagnose
```

With no `--server`, the script creates temporary TLS/auth material, starts a
local `yumed`, generates an obfs secret, runs `yume` against it, probes the
daemon directly as an HTTPS active scanner, removes the temporary key material
afterwards, and keeps only the report artifacts. The local daemon defaults to
`--hide-in-the-crowd nginx`; the client defaults to `--profile firefox` plus a
matching carrier User-Agent. Override those with `--server-profile`,
`--client-profile`, or `--client-http-profile`. Pass `--keep-workdir` if you
want to inspect the generated keys and server material.

Remote-server run:

```bash
scripts/yume_carrier_diagnose.py \
  --server origin.fixcraft.jp \
  --auth ~/main.key \
  --anonym-ca-cert ~/ca.cert.pem \
  --inner-heavy \
  --hop \
  --obfs-secret 'shared-secret-or-hex' \
  --out ~/yume-carrier-diagnose
```

The quick default visits a few lightweight HTTPS pages. Add `--media` for a
direct MP4 sample that produces larger streaming-like TLS records. The script
requires Chromium/Chrome plus `dumpcap` or `tcpdump`; capture privileges must
already be configured. It never runs `sudo` itself.

## Routing through Tor (or any SOCKS5 proxy)

The CLI can hide the outbound connection behind a SOCKS5 proxy. Hostnames are sent as ATYP_DOMAIN, so `.onion` targets resolve on the proxy side and direct DNS never leaves the client.

```text
+--------------------------------+
|  HUMAN APP                     |
|  browser / curl                |
+--------------------------------+
        |
        | local SOCKS / --run
        v
+--------------------------------+
|  YUME CLIENT                   |
|  --tor or --proxy              |
+--------------------------------+
        |
        | SOCKS5 to <onion>:443
        v
+--------------------------------+
|  LOCAL TOR                     |
|  127.0.0.1:9050                |
+--------------------------------+
        |
        | encrypted Tor cells
        v
+--------------------------------+
|  TOR CIRCUIT                   |
|  hidden-service rendezvous     |
+--------------------------------+
        |
        | rendezvous on server
        v
+--------------------------------+
|  SERVER TOR                    |
|  publishes .onion              |
+--------------------------------+
        |
        | TLS 1.3 + YUME frames
        v
+--------------------------------+
|  YUMED SERVER                  |
|  binds 127.0.0.1 only          |
+--------------------------------+
        |
        | outbound socket
        v
+--------------------------------+
|  TARGET SITE                   |
|  sees yumed egress IP          |
+--------------------------------+
```

Diagram source: [docs/diagrams/tor_pipeline.spec](docs/diagrams/tor_pipeline.spec) — regenerate with `scripts/draw_pipeline.py docs/diagrams/tor_pipeline.spec`. Widths are enforced by `scripts/check_ascii_diagrams.py`.

**Client side.** Add to `config/yume.json`:
```json
{ "outbound_proxy": "socks5://127.0.0.1:9050",
  "server": "abcdefghijklmnop.onion",
  "port": 443 }
```
Or on the command line:
```
yume --tor --server abcdefghijklmnop.onion --port 443 -i id_ed25519
yume --proxy socks5://user:pass@10.0.0.5:1080 --server gateway.example --port 443 -i id
yume --no-proxy ...                # one-shot override that ignores config
```

**Server side.** No code change. Bind `yumed` to loopback and let Tor publish a hidden service. In `/etc/tor/torrc`:
```
HiddenServiceDir /var/lib/tor/yume/
HiddenServicePort 443 127.0.0.1:443
```
After Tor starts, `cat /var/lib/tor/yume/hostname` gives you the `.onion` to point clients at. `yumed` doesn't know it's reachable through Tor — it only sees `127.0.0.1` connections.

The proxy applies to the outer transport (TCP → SOCKS5 → TLS → Yume). Inner PQ crypto, anonym proof, HTTP/2 carrier obfuscation, and TLS stealth still apply on top — Tor adds an extra circuit hop, not a replacement for any of those layers.

## Anonym mode

`--anonym` strips identifying logs (no client hostname, no IP, no authentication line). `--anonym-proof-mode {auto|local|fixcraft}` selects how the server proves no-log compliance to the client:

- `auto`: use every available proof source; only fail to start if none are usable
- `local`: CA / Sub-CA-signed proof only, no remote API
- `fixcraft`: require a remote FixCraft Verity API call; local proofs may also be attached

Local proof setup is in [scripts/gen_anonym_sub.sh](scripts/gen_anonym_sub.sh). Clients trust a server's anonym claim by holding the matching CA cert (`anonym_ca_cert`) and setting `require_anonym: true`.

## Inner crypto

Optional inner encryption sits inside the TLS tunnel and runs end-to-end:

- ML-KEM-768 KEM (post-quantum); the KEM shared secret is the input to the selected KDF
- AES-256-GCM AEAD (BaseFWX) on every YUME frame
- Argon2id heavy work factor (`--inner-heavy`, default on for full builds) or HKDF-SHA256 light derivation. The transport handshake does not include a user password / PSK.
- Live key hopping: a fresh 32-byte key derived from the base key every `--hop-interval` ms (default 500, i.e. 2 Hz). Tested up to 4 Hz; configurable down to 0 (off).

Hopping separates traffic into derived-key windows, but it is not forward secrecy: possession of the retained base key permits deriving every window key.

```jsonc
// client config
{
  "inner_crypto": true,
  "inner_heavy": true,
  "pq_public_key": "/etc/yume/master_pq.pk",
  "inner_hop": true,
  "hop_interval_ms": 500
}
```

```jsonc
// server config
{
  "inner_crypto": true,
  "inner_heavy": true,
  "pq_private_key": "/etc/yume/master_pq.sk",
  "allow_exec": false
}
```

The embedded BaseFWX master PQ keypair is **off by default** ([src/core/security/inner_crypto.hpp:17](src/core/security/inner_crypto.hpp#L17)). It is only loaded when the operator explicitly passes `--use-embedded-master`, and both client and server log a warning at startup when that flag is in effect. Provide your own `--pq-pub` / `--pq-key` for production deployments.

## Performance

Numbers below are from a live run reported in [docs/PERFORMANCE.md](docs/PERFORMANCE.md). Client in the United States, relay in Japan, fixed endpoint for fair RTT.

| Metric                                | 0 Hz hopping | 2 Hz hopping |
| ------------------------------------- | ------------ | ------------ |
| YUME-only ping overhead (filtered)    | ≈ 0 ms       | +1.4 ms      |
| Throughput retained vs relay capacity | 78 %         | 78 %         |
| Client upload retained vs direct      | 92 %         | 92 %         |

In that run the relay path and its bandwidth ceiling dominated the result. The data does not isolate YUME's CPU/framing cost, and it should not be read as a universal throughput or latency guarantee.

## Cluster federation

Multiple `yumed` instances can join a single federated cluster so any client can reach any peer's clients through any entry point. Each peer keeps its own auth keys and config; the federation link is a mutual TLS 1.3 server-to-server connection with per-peer permissions.

Bootstrap node (cluster entry point, accepts incoming peer dials):

```bash
sudo yumed --listen 443 \
    --cluster-bootstrap \
    --federation-auth-key /etc/yume/fed.key \
    --federation-anonym-ca /etc/yume/fed-ca.pem \
    --auth-keys /etc/yume/authorized_keys \
    --obfs-secret 'replace-with-a-long-shared-cluster-secret' \
    --public-node
```

Joining node (dials out to the bootstrap; implies `--federation-enable`):

```bash
sudo yumed --listen 443 \
    --cluster-join alice@bootstrap.example.com:443 \
    --cluster-join bob@second.example.com \
    --federation-auth-key /etc/yume/fed.key \
    --federation-anonym-ca /etc/yume/fed-ca.pem \
    --auth-keys /etc/yume/authorized_keys \
    --obfs-secret 'replace-with-a-long-shared-cluster-secret' \
    --public-node
```

The short-form spec is `[id@]host[:port][?pin=<sha256>]` — bracket IPv6 as `[2001:db8::1]:443`. The raw `--peer '<json>'` form still works for power users; `--cluster-join` is just a friendlier wrapper that emits the same JSON internally.

ASCII cluster map from any node:

```text
$ yume-net-map
                ┌──────────────┐
                │* alice       │
                │local:443     │
                │5 endpoints   │
                └──────┬───────┘
                       │
        ┌──────────────┼──────────────┐
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│  bob         │ │  carol       │ │  dave        │
│bob:443       │ │carol:443     │ │dave:443      │
│3 ch ready    │ │2 ch ready    │ │0 ch error    │
└──────────────┘ └──────────────┘ └──────────────┘
```

`yume-net-map --ascii` falls back to `+--+` `|` chars for terminals without box-drawing support; `yume-net-map --json` emits the topology as JSON for downstream tooling.

## Modes

SOCKS proxy (default):

```bash
yume --server yume.example.com --auth id_ed25519 --socks 1080
```

Port-forward, SSH-style:

```bash
yume --lport 2222 --rhost fw-main.fixcraft.jp --rport 22
```

Reverse forward (server listens, tunnels back to the client's local port):

```bash
yume -R 7437:127.0.0.1:22
```

Local run. Every TCP/UDP socket the command opens is routed through YUME:

```bash
yume --server yume.example.com --auth id_ed25519 --run "curl https://1.1.1.1"
```

Force IPv4 for `--run` (adds `-4 --http1.1` to curl/wget):

```bash
yume --server yume.example.com --auth id_ed25519 --run-ipv4 --run "curl https://ifconfig.me"
```

SSH (auto-wrapped to route via local SOCKS when `nc`, `ncat`, or `connect-proxy` is available):

```bash
yume --server yume.example.com --auth id_ed25519 --run "ssh user@host"
```

Server-side command execution is disabled by default for safety. Use SOCKS or port forwarding.

Application codec, Monero RPC:

```bash
# server: monerod stays loopback-only
yumed --listen 443 --codec-allow monero-rpc --monero-rpc-backend 127.0.0.1:18089

# client: wallet sees a normal local monerod-compatible endpoint
yume --server yume.example.com --auth id_ed25519 --monero-rpc
monero-wallet-cli --daemon-address 127.0.0.1:18089
```

The Monero codec is protocol-aware: it parses local Monero HTTP/RPC, carries
typed Yume codec frames in transit, and reconstructs restricted HTTP only on the
trusted server side. Server-side codec enablement uses the modular
`--codec-allow <name>` path; per-key authorization uses `allow_codecs` or the
legacy `allow_monero_rpc` permission, not LAN/private-IP bridging. See
[docs/APP_CODECS.md](docs/APP_CODECS.md). Current codec and plugin-loader
status is tracked in
[docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md).

## Permissions and key management

Authentication and authorization live in two files, the way SSH splits `authorized_keys` from per-line options:

- `authorized_keys` lists Ed25519 public keys that may **connect**.
- `auth_keys.meta` is a JSON file mapping each key's fingerprint to **what it may do** (exec control / LAN bridge / app codecs / admin / chat / file / bytes). App codecs use `permissions.allow_codecs`, for example `["monero-rpc"]`. Default for every dangerous bit is **deny**; a key without a meta entry can connect but cannot exec, cannot reach LAN, cannot use privileged codecs, and cannot administer other clients.

An explicitly configured `preauth_services` peer is not a normally authorized key. It remains in a persisted `PreauthServiceOnly` tier that admits only registered named-service OPEN/DATA/CLOSE plus PING/PONG. Admin attach separately requires trusted relay mode, caller outbound policy and opt-in, and target inbound policy and opt-in; the legacy attach form uses the same predicate.

Dangerous server features (server-side exec, LAN bridging, unrestricted address bridging) sit behind a **three-layer gate** that all must agree:

1. **Build switch**: `cmake -DYUME_FEATURE_EXEC=ON` (also `_LAN_BRIDGE`, `_FULL_CONTROL`). Stock builds ship with all three OFF; the runtime CLI flag still parses but logs a warning and stays disabled.
2. **Runtime flag**: `--allow-exec`, `--allow-local-ip`, `--control-full` on `yumed`.
3. **Per-key meta**: `"allow_exec": true` (etc.) in `auth_keys.meta` for the specific key.

Removing any one layer is enough to keep the feature off. The bridge / admin matrix (server-controls-client × client-controls-server, four quadrants) and the full meta JSON schema are documented in [docs/PERMISSIONS.md](docs/PERMISSIONS.md).

```bash
./build/bin/yumed --auth-keys /etc/yume/authorized_keys --keys-list
./build/bin/yumed --auth-keys /etc/yume/authorized_keys --keys-add /path/to/user.pub --keys-alias <fingerprint> alice
./build/bin/yumed --auth-keys /etc/yume/authorized_keys --keys-remove alice
./build/bin/yumed --auth-keys /etc/yume/authorized_keys --keys-gen ./keys/user1 --keys-gen-add
```

Authorized keys are loaded once at startup. Verification uses `EVP_DigestVerify` (constant-time at the OpenSSL level). The `auth_keys.meta` file is also read once at startup; restart `yumed` after editing.

## Real HTTP facade examples

Serve a real HTML page on `/` and 302 everything else to `/`:

```bash
sudo ./build/bin/yumed \
    --listen 443 \
    --cert certs/server.crt --key certs/server.key \
    --auth-keys /etc/yume/authorized_keys \
    --real --real-index certs/index.html \
    --real-secret "change-me"
```

Auto-generate and persist the HTML hidden-blob secret:

```bash
sudo ./build/bin/yumed \
    --listen 443 \
    --cert certs/server.crt --key certs/server.key \
    --auth-keys /etc/yume/authorized_keys \
    --real --real-index certs/index.html \
    --real-secret-file ./.secrets/html_secret
```

`--real` and `--obfs` may be set together; they share port 443 and are demuxed by the first cleartext bytes after TLS.

## Security posture

- AGPL-3.0-or-later, with client, daemon, proxy, GUI, and libyume fully buildable from this tree
- BaseFWX is pinned by commit (see `config/refs/basefwx.ref`); release CI fails if mandatory crypto support is missing
- Authorized keys verified with OpenSSL `EVP_DigestVerify` ([src/core/security/crypto.cpp:78](src/core/security/crypto.cpp#L78))
- Inner-frame AEAD is verified by BaseFWX before plaintext is delivered ([basefwx/cpp/src/crypto/crypto.cpp](basefwx/cpp/src/crypto/crypto.cpp))
- Master PQ keypair off by default; explicit `--use-embedded-master` required and warned about at startup on both ends
- Server-side exec / LAN bridging / unrestricted bridging are off at compile time by default ([CMakeLists.txt](CMakeLists.txt) `YUME_FEATURE_EXEC` / `_LAN_BRIDGE` / `_FULL_CONTROL`); enabling them requires opting in at build, runtime flag, AND per-key meta (see [docs/PERMISSIONS.md](docs/PERMISSIONS.md))
- Preauth service peers are centrally confined to the named-service frame family
- Admin attach requires caller outbound and target inbound permission/opt-in; both default to deny
- Public-node masquerade requires a nonempty obfs secret; wrong/malformed paths receive a benign H2 response instead of AUTH
- Session close has a five-second deadline, pending service queues are capped, and detached client EXEC work is capped at four concurrent workers; sanitizer/soak validation is still outstanding
- Frame size capped at 16 MiB across all read paths
- New obfs path-token verifier uses `CRYPTO_memcmp` ([src/core/stealth/obfs_signal.cpp](src/core/stealth/obfs_signal.cpp))
- No independent security audit or production-scale adversarial soak is documented yet. The implementation and threat boundary are open for review, but that is not equivalent to a completed audit.

## Scalability notes

- Server sessions are fully async on a shared `io_context` thread pool (no per-connection threads)
- Authorized keys are loaded once at startup
- Frames are capped at 16 MiB per message to limit memory pressure
- Carrier-mode handshake adds one extra HEADERS frame per session, no per-frame cost in current default

## Release guarantees

- Release workflows run preflight validation against the pinned BaseFWX commit
- Release artifacts are inspected after build for linkage / runtime expectations
- Missing mandatory BaseFWX crypto support is a release failure, not a degraded release
- Full releases require Argon2, PQ/OQS, and LZMA support in the bundled BaseFWX dependency path

## License

YUME source, apps, daemon, proxy, GUI, and libyume are licensed under AGPL-3.0-or-later. See [LICENSE](LICENSE).
