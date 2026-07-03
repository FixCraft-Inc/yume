# YUME — 夢

**yume** *(Japanese: 夢)*: a dream.

Yume Universal Multiprotocol Engine. An open-source post-quantum stealth transport. The name is a single character — 夢 — and we use it the way Japanese uses it: a dream of a network you can trust, where the wire shape can't tell yume from any other HTTPS site, and where neither the client nor the server is forced to advertise itself.

YUME tunnels TCP and UDP through TLS 1.3 sessions that look like ordinary Chrome HTTPS to a DPI box, with hybrid ML-KEM-768 + AES-GCM inner crypto, an optional Argon2id heavy KDF, and 1-4 Hz live key hopping. The client (`yume`), daemon (`yumed`), proxy, GUI, and libyume surface are AGPL-3.0-or-later and build from this tree. They run on x86, ARMv7/8, MIPS OpenWRT, BusyBox, macOS, and Windows; the minimal build runs on routers with as little as 128 MiB of RAM.

- Website: https://yume.fixcraft.jp
- Source: https://github.com/FixCraft-Inc/yume
- Issues: https://github.com/FixCraft-Inc/yume/issues

For the current implementation / testing boundary, including host-controller,
codec, federation, plugin, and browser status, see
[docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md).

## Why YUME

VPN protocols built for performance (WireGuard, OpenVPN) are also built to be recognisable. Their handshakes have static byte signatures that ISPs and national firewalls can match in milliseconds. Commercial VPN services then resell that same recognisable transport for $20/month, bandwidth that costs them pennies, and run it from cheap KVMs that any user could rent directly.

YUME tries to do the opposite: a transport that looks like ordinary Chrome HTTPS to a CDN, with crypto that survives the move to post-quantum, with both ends fully open-source so anyone can audit, build, and self-host. FixCraft will run a fleet of free public endpoints (no signup, no payment), but the endpoints run the same `yumed` you can build right here.

## Compared to other tools

|                             | YUME            | WireGuard      | OpenVPN                  | Tor (with bridges) | Shadowsocks     |
| --------------------------- | --------------- | -------------- | ------------------------ | ------------------ | --------------- |
| Hybrid post-quantum (ML-KEM-768) | yes        | no             | no                       | no                 | no              |
| Live key hopping            | 1–4 Hz, OTA     | no             | no                       | no                 | no              |
| Looks like real HTTPS to DPI | yes (Chrome JA3 + HTTP/2 carrier) | UDP signature | TLS-on-OpenVPN-port signature | obfs4 bridge | random-prefix |
| Anonym / no-log mode        | built in        | n/a            | per-provider             | yes                | n/a             |
| Free public endpoints       | planned (FixCraft) | none        | none                     | yes                | none            |
| Embedded / 128 MiB hardware | yes             | yes            | yes                      | partial            | yes             |
| Self-hostable, fully open   | yes (AGPL-v3+)  | yes            | yes                      | bridge only        | yes             |
| Steady-state CPU/byte overhead | <1 % typical, <5 % always | ~0 % | a few %                  | high               | low             |
| License                     | AGPL-v3+        | GPL-v2         | GPL-v2                   | BSD-3              | Apache-2        |

YUME's row comes from the live measurement reported in [docs/PERFORMANCE.md](docs/PERFORMANCE.md). The other rows are conservative; anything contested is left blank or hedged.

## Quick start

```bash
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
    --public-node                      # rejects dangerous flags, locks Argon2 floors
    --hide-in-the-crowd nginx          # implicit when --public-node is set
```

Client:

```bash
./build/bin/yume \
    --server fixcraft.net \
    --auth ~/.yume/id_ed25519 \
    --socks 1080
```

Cluster entry-point short form (translates to `--server` + `--port`):

```bash
./build/bin/yume --cluster fixcraft.net:443 --auth ~/.yume/id_ed25519 --socks 1080
```

For a privileged port 443 on Linux, run `yumed` with `sudo` or grant `cap_net_bind_service`. Cloudflare HTTP-mode proxies will terminate TLS and break YUME. Use Spectrum or another TCP passthrough if you front the daemon with Cloudflare.

## Optional desktop GUI (`yume-gui`)

A Dear ImGui + GLFW desktop application is available in the same tree and is **off** by default. It uses the shared facade library for local server control and starts the real `yume` client runtime in the background, attaching to it through local IPC. The GUI is intended for desktop users; the CLI remains the supported automation surface.

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
- `ClientSession::start()` currently launches the `yume` binary as a managed background process and communicates with it through the existing local runtime socket. A pure in-process client controller still requires extracting the TLS/auth handshake from `src/client/cli/entry.cpp`.
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

1. **TLS 1.3 with browser fingerprint.** `--profile chrome|firefox|safari` configures cipher suites, supported groups, signature algorithms, and ALPN to match Chrome 131 / Firefox 133 / Safari 18. The handshake is a real TLS 1.3 handshake (OpenSSL emits the ClientHello against the configured profile), so JA3/JA4 fall in the browser cluster. Source: [src/core/stealth/tls_stealth.cpp](src/core/stealth/tls_stealth.cpp), [src/core/stealth/tls_fingerprint.cpp](src/core/stealth/tls_fingerprint.cpp).
2. **HTTP/2 carrier handshake (`--obfs`, default on).** After the TLS handshake the client emits a real HTTP/2 connection preface (`PRI * HTTP/2.0…`), Chrome-shaped SETTINGS, a WINDOW_UPDATE, and a HEADERS frame for `POST /<token>/<nonce>` with realistic Chrome request headers. The server validates the token (HMAC-SHA256 over `(SNI || hour || "yume-obfs-v2")` keyed by `--obfs-secret`), replies with canned SETTINGS / SETTINGS-ACK / HEADERS `:status=200`, and the YUME tunnel resumes underneath. To a stateless DPI box the first ~150 cleartext bytes of every connection look exactly like a Chrome → CDN gRPC-web request. The codec lives in [src/core/stealth/obfs_h2.cpp](src/core/stealth/obfs_h2.cpp); the token derivation in [src/core/stealth/obfs_signal.cpp](src/core/stealth/obfs_signal.cpp). Disable with `--no-obfs`. Per-frame DATA wrapping with PADDED frames and PING keepalive is implemented in the codec and is on the post-1.1 roadmap to enable by default.
3. **HTTP-layer server disguise (`--hide-in-the-crowd <profile>`).** Before 1.0 a non-YUME probe (curl / scanner) saw TLS handshake + immediate TCP close — one of the strongest DPI fingerprints. With this flag yumed instead serves a profile-driven 404 whose header order, charset, and body shape match a real install of the chosen software, captured from upstream source: `nginx`, `nginx-stable`, `apache`, `caddy` (with `Alt-Svc: h3=":443"`), `cloudflare` (with `CF-RAY` + `alt-svc`), `express` (with `X-Powered-By` + `Content-Security-Policy` + `X-Content-Type-Options`), `gunicorn`, `none` (no Server header), and `yumed` (legacy). Same flag on the client picks the User-Agent (`chrome`, `firefox`, `safari`, `edge`, `curl`, `wget`, `yume`); when unspecified, the UA is derived from `--profile` so the JA3 and the UA stay consistent. Codec: [src/core/stealth/http_profile.cpp](src/core/stealth/http_profile.cpp); fidelity check: [scripts/yume_disguise_check.py](scripts/yume_disguise_check.py).
4. **Real HTML facade (`--real --real-index <html>`).** A browser that hits the same port with `GET / HTTP/1.1` is served the configured HTML page (or a Wikipedia redirect by default). YUME clients and browsers cohabit on port 443.

Limits: this defends against stateless DPI, classifier-based ISP filters, and active probes that complete TLS and inspect the first kilobyte. It does not defend against fully-stateful HTTP/2 middleboxes that track stream and HPACK state, or against ML traffic classifiers trained on joint inter-arrival × size distributions.

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

- ML-KEM-768 KEM (post-quantum) combined with the user's password / PSK via HKDF-SHA256
- AES-256-GCM AEAD (BaseFWX) on every YUME frame
- Argon2id heavy KDF (`--inner-heavy`, default on for full builds) or HKDF-SHA256 light KDF
- Live key hopping: a fresh 32-byte key derived from the base key every `--hop-interval` ms (default 500, i.e. 2 Hz). Tested up to 4 Hz; configurable down to 0 (off).

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

The throughput loss on long routes is dominated by the relay path's own capacity, not by YUME's CPU or framing. With hopping disabled, YUME's steady-state overhead is below the noise floor of the measurement.

## Cluster federation

Multiple `yumed` instances can join a single federated cluster so any client can reach any peer's clients through any entry point. Each peer keeps its own auth keys and config; the federation link is a mutual TLS 1.3 server-to-server connection with per-peer permissions.

Bootstrap node (cluster entry point, accepts incoming peer dials):

```bash
sudo yumed --listen 443 \
    --cluster-bootstrap \
    --federation-auth-key /etc/yume/fed.key \
    --federation-anonym-ca /etc/yume/fed-ca.pem \
    --auth-keys /etc/yume/authorized_keys \
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
yume --server fixcraft.net --auth id_ed25519 --socks 1080
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
yume --server fixcraft.net --auth id_ed25519 --run "curl https://1.1.1.1"
```

Force IPv4 for `--run` (adds `-4 --http1.1` to curl/wget):

```bash
yume --server fixcraft.net --auth id_ed25519 --run-ipv4 --run "curl https://ifconfig.me"
```

SSH (auto-wrapped to route via local SOCKS when `nc`, `ncat`, or `connect-proxy` is available):

```bash
yume --server fixcraft.net --auth id_ed25519 --run "ssh user@host"
```

Server-side command execution is disabled by default for safety. Use SOCKS or port forwarding.

Application codec, Monero RPC:

```bash
# server: monerod stays loopback-only
yumed --listen 443 --codec-allow monero-rpc --monero-rpc-backend 127.0.0.1:18089

# client: wallet sees a normal local monerod-compatible endpoint
yume --server fixcraft.net --auth id_ed25519 --monero-rpc
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
- `auth_keys.meta` is a JSON file mapping each key's fingerprint to **what it may do** (exec / LAN bridge / app codecs / admin / chat / file / bytes). App codecs use `permissions.allow_codecs`, for example `["monero-rpc"]`. Default for every dangerous bit is **deny**; a key without a meta entry can connect but cannot exec, cannot reach LAN, cannot use privileged codecs, cannot administer other clients.

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
- Inner-frame AEAD verified before plaintext is delivered (OpenSSL `EVP_DecryptFinal_ex`)
- Master PQ keypair off by default; explicit `--use-embedded-master` required and warned about at startup on both ends
- Server-side exec / LAN bridging / unrestricted bridging are off at compile time by default ([CMakeLists.txt](CMakeLists.txt) `YUME_FEATURE_EXEC` / `_LAN_BRIDGE` / `_FULL_CONTROL`); enabling them requires opting in at build, runtime flag, AND per-key meta (see [docs/PERMISSIONS.md](docs/PERMISSIONS.md))
- Per-key admin permissions (`allow_inbound_admin`, `allow_outbound_admin`) default to deny
- Frame size capped at 16 MiB across all read paths
- New obfs path-token verifier uses `CRYPTO_memcmp` ([src/core/stealth/obfs_signal.cpp](src/core/stealth/obfs_signal.cpp))
- No security-by-obscurity: every claim above points at code. Features are either implemented or absent; no placeholders that pretend to protect anything.

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
