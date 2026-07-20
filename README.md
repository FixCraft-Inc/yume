# YUME — 夢

**yume** *(Japanese: 夢)*: a dream.

Yume Universal Multiprotocol Engine. An open-source post-quantum stealth transport. The name is a single character — 夢 — and we use it the way Japanese uses it: a dream of a network you can trust, where the wire shape blends into ordinary HTTPS and neither endpoint has to advertise YUME by name.

YUME 2.0-dev1 tunnels TCP and UDP through a persistent TLS 1.3 + HTTP/2 +
WebSocket connection. The focused Linux desktop slice uses mandatory
ML-KEM-1024 + X25519 + random-PSK key establishment, per-message AES-256-GCM
keys, and independent directional epochs bounded by 256 KiB, 512 DATA frames,
or 500 ms of active traffic. The client (`yume`) and daemon (`yumed`) are
AGPL-3.0-or-later and build from this tree. Other platforms and the optional GUI
have not yet passed the 2.0 release gates.

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
| Hybrid post-quantum inner channel | ML-KEM-1024 + X25519 + AES-GCM | no | no | no | no |
| Directional epoch ratchet   | ≤256 KiB / 512 frames / 500 ms active | no | no | no | no |
| HTTPS-shaped carrier | persistent TLS + H2/WebSocket; known TLS residual | UDP signature | TLS-on-OpenVPN-port signature | obfs4 bridge | random-prefix |
| Anonym / no-log mode        | built in        | n/a            | per-provider             | yes                | n/a             |
| Free public endpoints       | planned (FixCraft) | none        | none                     | yes                | none            |
| First 2.0 target            | Linux x86-64 CLI | broad          | broad                    | broad              | broad           |
| Self-hostable, fully open   | yes (AGPL-v3+)  | yes            | yes                      | bridge only        | yes             |
| Published 2.0 transport measurement | release gate pending | — | — | — | — |
| License                     | AGPL-v3+        | GPL-v2         | GPL-v2                   | BSD-3              | Apache-2        |

The older WAN run in [docs/PERFORMANCE.md](docs/PERFORMANCE.md) used 1.x and is
not a 2.0 release measurement.

## Quick start

```bash
git clone https://github.com/FixCraft-Inc/yume.git
cd yume
# BaseFWX is a pinned sibling checkout, not a submodule.
git clone https://github.com/F1xGOD/basefwx.git basefwx
git -C basefwx checkout "$(cat config/refs/basefwx.ref)"
./ezbuild.sh
```

The build produces `build/bin/yume` and `build/bin/yumed`.

`yume --version` and `yumed --version` are offline by default. Set
`YUME_UPDATE_CHECK=1` for an explicit one-shot GitHub release check;
`YUME_NO_UPDATE_CHECK=1` remains a hard disable for managed environments.

Server:

```bash
sudo ./build/bin/yumed \
    --listen 443 \
    --cert certs/server.crt --key certs/server.key \
    --auth-keys /etc/yume/authorized_keys \
    --obfs-secret-file /etc/yume/secrets/admission.hex \
    --inner-psk-file /etc/yume/secrets/inner.hex \
    --real-backend loopback://127.0.0.1:3000
```

The Node.js 24 LTS cover site is a separate supervised process bound only to
loopback. Both secret files contain exactly 64 lowercase hex characters (32
random bytes), have no group/world permission bits, and must be distributed to
clients out of band. There is no public-key-only 2.0 mode.

Client:

```bash
./build/bin/yume \
    --server yume.example.com \
    --auth ~/.yume/id_ed25519 \
    --obfs-secret-file ~/.config/yume/admission.hex \
    --inner-psk-file ~/.config/yume/inner.hex \
    --profile chrome \
    --socks 127.0.0.1:1080
```

Cluster entry-point short form (translates to `--server` + `--port`):

```bash
./build/bin/yume --cluster yume.example.com:443 \
    --auth ~/.yume/id_ed25519 \
    --obfs-secret-file ~/.config/yume/admission.hex \
    --inner-psk-file ~/.config/yume/inner.hex \
    --profile chrome \
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

The first 2.0 profile is fixed to a captured Chrome 150 client and Node.js 24
LTS cover. After a normal priming page load, the client opens an RFC 8441
extended CONNECT stream. Encrypted YUME records remain WebSocket binary
messages inside valid HTTP/2 DATA frames for the entire connection.

`yumed` terminates public TLS/H2 and proxies ordinary GET/HEAD cover requests
to the configured loopback Node process. Admission failures follow the normal
cover path and never receive AUTH. Node never sees tunnel data, identities, or
secret material.

This raises the cost of custom-protocol matching and casual active probing; it
does not make YUME byte-identical to Chrome. OpenSSL still differs from Chrome's
BoringSSL ClientHello upstream of the H2 carrier. See [docs/STEALTH.md](docs/STEALTH.md)
for the measured scope and [docs/YUME_2_0_IMPLEMENTATION_STATUS.md](docs/YUME_2_0_IMPLEMENTATION_STATUS.md)
for unfinished release gates.

### Headless carrier diagnosis

The older diagnosis script still targets the retired 1.x carrier and is not a
2.0 validation tool. Use the committed Chrome/Node fixture and the release
evidence procedure in [docs/STEALTH.md](docs/STEALTH.md); do not interpret a
1.x diagnosis run as 2.0 fingerprint evidence.

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

Inner encryption is mandatory in the 2.0 tunnel path:

- ML-KEM-1024 and X25519 contributions are combined with a random 32-byte PSK
  using versioned salted HKDF-SHA256 labels.
- AES-256-GCM uses a derived, one-use key for every protected frame.
- Client-to-server and server-to-client chains advance independently before
  256 KiB, 512 DATA frames, or 500 ms of active epoch time.
- Rekeys perform fresh ML-KEM-1024 and X25519 exchanges. Application data waits
  behind the boundary and the retired root is erased after the first valid
  new-epoch record.

Argon2id is not used at establishment or per epoch: the required PSK is already
uniform high-entropy key material, not a human password.

```jsonc
// client config
{
  "obfs_secret_file": "/home/alice/.config/yume/admission.hex",
  "inner_psk_file": "/home/alice/.config/yume/inner.hex",
  "tls_stealth_profile": "chrome"
}
```

```jsonc
// server config
{
  "obfs_secret_file": "/etc/yume/secrets/admission.hex",
  "inner_psk_file": "/etc/yume/secrets/inner.hex",
  "real_backend": "loopback://127.0.0.1:3000",
  "allow_exec": false
}
```

## Performance

The 2.0 tools report MiB/s at three different layers:

- `yume --full-bench`: local `yume` ↔ `yumed` process path through the complete
  H2/WebSocket carrier and hybrid ratchet.
- `yume --bench` or `--bench-full`: authenticated upload/download against a
  real server started with `yumed --bench`.
- `yume-basefwx-bench`: in-memory key establishment, rekey, and ratchet ceiling;
  it intentionally excludes TLS, H2, WebSocket, sockets, and process overhead.

See [docs/SELFTEST.md](docs/SELFTEST.md) for commands and how to compare the
numbers. The older WAN results in [docs/PERFORMANCE.md](docs/PERFORMANCE.md)
describe 1.x and are not evidence for the 2.0 release gates.

## Cluster federation

Federation is unchanged at the control-protocol level, but it has not passed the
focused 2.0 desktop validation gates. The examples below show configuration
shape, not a 2.0 support claim. Each public entry point still needs its own
mandatory transport secret files and loopback cover.

Bootstrap node (cluster entry point, accepts incoming peer dials):

```bash
sudo yumed --listen 443 \
    --cluster-bootstrap \
    --federation-auth-key /etc/yume/fed.key \
    --federation-anonym-ca /etc/yume/fed-ca.pem \
    --auth-keys /etc/yume/authorized_keys \
    --obfs-secret-file /etc/yume/secrets/admission.hex \
    --inner-psk-file /etc/yume/secrets/inner.hex \
    --real-backend loopback://127.0.0.1:3000 \
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
    --obfs-secret-file /etc/yume/secrets/admission.hex \
    --inner-psk-file /etc/yume/secrets/inner.hex \
    --real-backend loopback://127.0.0.1:3000 \
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

Authentication and authorization use separate regular-user and operator trust
stores, each split into public keys and policy metadata:

- `authorized_keys` lists Ed25519 public keys that may **connect**.
- `auth_keys.meta` maps each regular-key fingerprint to its permissions,
  identity type, per-key session cap, and fair-egress weight.
- `operator_keys` is a physically separate set of controller identities.
- `operator_keys.meta` holds their explicit policy. Only this store may grant
  outbound administration, and operator keys cannot be bulk keys.

Regular keys default to `key_type: "individual"` and one authenticated session.
An administrator may explicitly mark a regular key as `bulk` for many users who
must share one credential. Each bulk connection is still counted and shaped as
a separate session; the server-wide and per-key caps remain enforced. Bulk keys
cannot receive exec, LAN/private access, full control, privileged codecs or
services, administration, or federation identity. Their chat/file/bytes
permissions also default to deny.

App codecs use `permissions.allow_codecs`, for example `["monero-rpc"]`.
Every dangerous permission defaults to **deny**; a regular key without a meta
entry can connect but cannot exec, reach LAN, use privileged codecs, or
administer other clients. See [docs/PERMISSIONS.md](docs/PERMISSIONS.md) for the
full schema and privilege matrix.

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

The four key/policy files are parsed into immutable snapshots at startup.
Authenticated runtime reload atomically replaces all four together; a parse,
validation, or duplicate-store failure leaves the previous complete snapshot
active. Restarting `yumed` is the fallback when runtime reload is unavailable.
Ed25519 authentication uses OpenSSL `EVP_DigestVerify`.

## Real HTTP facade examples

Serve a real HTML page on `/` and a profile 404 for anything else:

```bash
sudo ./build/bin/yumed \
    --listen 443 \
    --cert certs/server.crt --key certs/server.key \
    --auth-keys /etc/yume/authorized_keys \
    --real --real-index certs/index.html \
    --real-secret "change-me"
```

Serve a full static site (assets, not just an index) as the cover, with
nginx-shaped responses:

```bash
sudo ./build/bin/yumed \
    --listen 443 \
    --cert certs/server.crt --key certs/server.key \
    --auth-keys /etc/yume/authorized_keys \
    --real-root /var/www/site \
    --hide-in-the-crowd nginx
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
- Inner-frame AEAD is verified before plaintext is delivered ([basefwx/cpp/src/crypto/crypto.cpp](basefwx/cpp/src/crypto/crypto.cpp))
- Mandatory ML-KEM-1024 + X25519 + random-PSK establishment; no 1.x downgrade or public-key-only mode
- Server-side exec / LAN bridging / unrestricted bridging are off at compile time by default ([CMakeLists.txt](CMakeLists.txt) `YUME_FEATURE_EXEC` / `_LAN_BRIDGE` / `_FULL_CONTROL`); enabling them requires opting in at build, runtime flag, AND per-key meta (see [docs/PERMISSIONS.md](docs/PERMISSIONS.md))
- Preauth service peers are centrally confined to the named-service frame family
- Admin attach requires caller outbound and target inbound permission/opt-in; both default to deny
- Admission and inner secrets are separate owner-only files; wrong, malformed,
  expired, replayed, or authority-mismatched admission follows the cover path
  instead of receiving AUTH
- Session close has a five-second deadline, pending service queues are capped, and detached client EXEC work is capped at four concurrent workers; sanitizer/soak validation is still outstanding
- Protected application payloads are capped at 256 KiB so one frame cannot
  cross a directional epoch byte limit
- The admission path-token verifier uses `CRYPTO_memcmp` ([src/core/stealth/obfs_signal.cpp](src/core/stealth/obfs_signal.cpp))
- No independent security audit or production-scale adversarial soak is documented yet. The implementation and threat boundary are open for review, but that is not equivalent to a completed audit.

## Scalability notes

- Server sessions are fully async on a shared `io_context` thread pool (no per-connection threads)
- Regular/operator keys and policies are immutable shared snapshots, so AUTH
  does not reread policy JSON for every connection
- Global sessions default to a bounded 256; individual keys default to one
  session and bulk keys default to 64, with explicit administrator overrides
- `--accept-rate-limit` bounds aggregate connection admission across listeners
- Optional `--egress-mbps` weighted fairness divides an administrator-chosen
  link cap among active identities without adding shaping work when unset
- Protected DATA frames are capped at 256 KiB and carrier/proxy queues are bounded
- Every authenticated record remains inside H2/WebSocket and uses a one-use AEAD key
- Hard process CPU and memory containment belongs to the service manager; see
  [docs/OPERATIONS.md](docs/OPERATIONS.md) for systemd examples

## Release guarantees

- Release workflows run preflight validation against the pinned BaseFWX commit
- Release artifacts are inspected after build for linkage / runtime expectations
- Missing mandatory BaseFWX crypto support is a release failure, not a degraded release
- The 2.0 Linux desktop transport additionally requires nghttp2 >= 1.64 and
  ML-KEM-1024 support from the pinned BaseFWX/liboqs path

## License

YUME source, apps, daemon, proxy, GUI, and libyume are licensed under AGPL-3.0-or-later. See [LICENSE](LICENSE).
