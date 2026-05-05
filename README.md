# YUME

Yume Universal Multiprotocol Engine — an open-source post-quantum stealth transport.

YUME tunnels TCP and UDP through TLS 1.3 sessions that look like ordinary Chrome HTTPS to a deep-packet-inspection box, with hybrid ML-KEM-768 + AES-GCM inner crypto, optional Argon2id heavy KDF, and 1–4 Hz live key hopping. Both the client (`yume`) and the daemon (`yumed`) are GPL-v3 and build from this tree. They run on x86, ARMv7/8, MIPS OpenWRT, busybox, macOS, and Windows; the minimal build has been exercised on routers with as little as 128 MiB of RAM.

## Why YUME

VPN protocols built for performance (WireGuard, OpenVPN) are also built to be recognisable. Their handshakes have static byte signatures that ISPs and national firewalls can match in milliseconds. Commercial VPN services then resell that same recognisable transport for $20/month — bandwidth that costs them pennies — and run it from cheap KVMs that any user could rent directly.

YUME tries to do the opposite: a transport that looks like the most boring traffic on the internet (Chrome talking HTTPS to a CDN), with crypto that survives the move to post-quantum, with both ends fully open-source so anyone can audit, build, and self-host. FixCraft will run a fleet of free public endpoints — no signup, no payment — but the endpoints run the same `yumed` you can build right here.

## Compared to other tools

|                             | YUME            | WireGuard      | OpenVPN                  | Tor (with bridges) | Shadowsocks     |
| --------------------------- | --------------- | -------------- | ------------------------ | ------------------ | --------------- |
| Hybrid post-quantum (ML-KEM-768) | yes        | no             | no                       | no                 | no              |
| Live key hopping            | 1–4 Hz, OTA     | no             | no                       | no                 | no              |
| Looks like real HTTPS to DPI | yes (Chrome JA3 + HTTP/2 carrier) | UDP signature | TLS-on-OpenVPN-port signature | obfs4 bridge | random-prefix |
| Anonym / no-log mode        | built in        | n/a            | per-provider             | yes                | n/a             |
| Free public endpoints       | planned (FixCraft) | none        | none                     | yes                | none            |
| Embedded / 128 MiB hardware | yes             | yes            | yes                      | partial            | yes             |
| Self-hostable, fully open   | yes (GPL-v3)    | yes            | yes                      | bridge only        | yes             |
| Steady-state CPU/byte overhead | <1 % typical, <5 % always | ~0 % | a few %                  | high               | low             |
| License                     | GPL-v3          | GPL-v2         | GPL-v2                   | BSD-3              | Apache-2        |

YUME's row numbers come from the live measurement at [AI_gen/PERFORMANCE_BASELINE.md](AI_gen/PERFORMANCE_BASELINE.md) on the `DEV` branch. Other rows are kept conservative.

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

Client:

```bash
./build/bin/yume \
    --server fixcraft.net \
    --auth ~/.yume/id_ed25519 \
    --socks 1080
```

For a privileged port 443 on Linux, run `yumed` with `sudo` or grant `cap_net_bind_service`. Cloudflare HTTP-mode proxies will terminate TLS and break YUME — use Spectrum or another TCP passthrough if you front the daemon with Cloudflare.

### Embedded build

```bash
cmake -B build -DYUME_MINIMAL=ON -DYUME_USE_BASEFWX=ON
cmake --build build -j$(nproc)
```

`ezbuild.sh` cross-compiles for Linux x86_64 / x86 / ARMv7 / ARMv8, MIPS OpenWRT, BusyBox flavours, macOS x86_64 / arm64, and Windows x86_64. Prebuilt vendor toolchains live in [`vendor/`](vendor/).

## Free public endpoints — coming soon

FixCraft will operate a small fleet of public `yumed` endpoints. They will:

- be free to use without an account, payment, or rate-limiting beyond fairness
- run the unmodified daemon you can build from this tree
- serve a real HTML page on `/` so that a browser hitting the same hostname sees something normal
- publish their public keys and authorised-keys fingerprints in advance so clients can pin them

Specific hostnames will land here once the fleet is up.

## Stealth and obfuscation

YUME stacks three independent layers of byte-shape camouflage:

1. **TLS 1.3 with browser fingerprint.** `--profile chrome|firefox|safari` configures cipher suites, supported groups, signature algorithms, and ALPN to match Chrome 135 / Firefox 126 / Safari 17. The handshake is a real TLS 1.3 handshake — OpenSSL emits the ClientHello against the configured profile — so JA3/JA4 fall in the browser cluster. Source: [src/core/tls_stealth.cpp](src/core/tls_stealth.cpp), [src/core/tls_fingerprint.cpp](src/core/tls_fingerprint.cpp).
2. **HTTP/2 carrier handshake (`--obfs`, default on).** After the TLS handshake the client emits a real HTTP/2 connection preface (`PRI * HTTP/2.0…`), Chrome-shaped SETTINGS, a WINDOW_UPDATE, and a HEADERS frame for `POST /<token>/<nonce>` with realistic Chrome request headers. The server validates the token (HMAC-SHA256 over `(SNI || hour || "yume-obfs-v2")` keyed by `--obfs-secret`), replies with canned SETTINGS / SETTINGS-ACK / HEADERS `:status=200`, and the YUME tunnel resumes underneath. To a stateless DPI box the first ~150 cleartext bytes of every connection look exactly like a Chrome → CDN gRPC-web request. The codec lives in [src/core/obfs_h2.cpp](src/core/obfs_h2.cpp); the token derivation in [src/core/obfs_signal.cpp](src/core/obfs_signal.cpp). Disable with `--no-obfs`. Per-frame DATA wrapping with PADDED frames and PING keepalive is implemented in the codec and is on the post-1.0 roadmap to enable by default.
3. **Real HTML facade (`--real --real-index <html>`).** A browser that hits the same port with `GET / HTTP/1.1` is served the configured HTML page (or a Wikipedia redirect by default). YUME clients and browsers cohabit on port 443.

Honest limits: this defends against stateless DPI, classifier-based ISP filters, and active probes that complete TLS and dump the first kilobyte. It does not defend against fully-stateful HTTP/2 middleboxes that track stream and HPACK state, or against ML traffic classifiers trained on joint inter-arrival × size distributions.

## Anonym mode

`--anonym` strips identifying logs (no client hostname, no IP, no authentication line). `--anonym-proof-mode {auto|local|fixcraft}` selects how the server proves no-log compliance to the client:

- `auto` — use every available proof source; only fail to start if none are usable
- `local` — CA / Sub-CA-signed proof only, no remote API
- `fixcraft` — require a remote FixCraft Verity API call; local proofs may also be attached

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

The embedded BaseFWX master PQ keypair is **off by default** ([src/core/inner_crypto.hpp:17](src/core/inner_crypto.hpp#L17)). It is only loaded when the operator explicitly passes `--use-embedded-master`, and both client and server log a warning at startup when that flag is in effect. Provide your own `--pq-pub` / `--pq-key` for production deployments.

## Performance

Numbers below are from a live run reported at [AI_gen/PERFORMANCE_BASELINE.md](AI_gen/PERFORMANCE_BASELINE.md) on the `DEV` branch — client in the United States, relay in Japan, fixed endpoint for fair RTT.

| Metric                                | 0 Hz hopping | 2 Hz hopping |
| ------------------------------------- | ------------ | ------------ |
| YUME-only ping overhead (filtered)    | ≈ 0 ms       | +1.4 ms      |
| Throughput retained vs relay capacity | 78 %         | 78 %         |
| Client upload retained vs direct      | 92 %         | 92 %         |

The throughput loss on long routes is dominated by the relay path's own capacity, not by YUME's CPU or framing. With hopping disabled, YUME's steady-state overhead is below the noise floor of the measurement.

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

Local run — every TCP/UDP socket the command opens is routed through YUME:

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

## Permissions and key management

Authentication and authorization live in two files, the way SSH splits `authorized_keys` from per-line options:

- `authorized_keys` lists Ed25519 public keys that may **connect**.
- `auth_keys.meta` is a JSON file mapping each key's fingerprint to **what it may do** (exec / LAN bridge / admin / chat / file / bytes). Default for every dangerous bit is **deny**; a key without a meta entry can connect but cannot exec, cannot reach LAN, cannot administer other clients.

Dangerous server features (server-side exec, LAN bridging, unrestricted address bridging) sit behind a **three-layer gate** that all must agree:

1. **Build switch** — `cmake -DYUME_FEATURE_EXEC=ON` (also `_LAN_BRIDGE`, `_FULL_CONTROL`). Stock builds ship with all three OFF; the runtime CLI flag still parses but logs a warning and stays disabled.
2. **Runtime flag** — `--allow-exec`, `--allow-local-ip`, `--control-full` on `yumed`.
3. **Per-key meta** — `"allow_exec": true` (etc.) in `auth_keys.meta` for the specific key.

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

`--real` and `--obfs` may be set together — they share port 443 and are demuxed by the first cleartext bytes after TLS.

## Security posture

- GPL-v3, both client and daemon fully buildable from this tree
- BaseFWX is pinned by commit (see `.basefwx-ref`); release CI fails if mandatory crypto support is missing
- Authorized keys verified with constant-time `EVP_DigestVerify` ([src/server/auth.cpp:78–99](src/server/auth.cpp#L78-L99))
- Inner-frame AEAD verified before plaintext is delivered (OpenSSL `EVP_DecryptFinal_ex`)
- Master PQ keypair off by default; explicit `--use-embedded-master` required and warned about at startup on both ends
- Server-side exec / LAN bridging / unrestricted bridging are off at compile time by default ([CMakeLists.txt](CMakeLists.txt) `YUME_FEATURE_EXEC` / `_LAN_BRIDGE` / `_FULL_CONTROL`); enabling them requires opting in at build, runtime flag, AND per-key meta — see [docs/PERMISSIONS.md](docs/PERMISSIONS.md)
- Per-key admin permissions (`allow_inbound_admin`, `allow_outbound_admin`) default to deny
- Frame size capped at 16 MiB across all read paths
- New obfs path-token verifier uses `CRYPTO_memcmp` ([src/core/obfs_signal.cpp](src/core/obfs_signal.cpp))
- No security-by-obscurity: every fingerprint claim, every comparison row, every default is grounded in code referenced above. The codebase contains no placeholder protections — features are either implemented or absent.

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

GNU GPL v3. See [LICENSE](LICENSE).
