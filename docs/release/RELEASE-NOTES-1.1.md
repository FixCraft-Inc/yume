# YUME 1.1 — First Stable Release

YUME is a **post-quantum stealth transport** that tunnels TCP and UDP
through real TLS 1.3 sessions, shaped to look like ordinary Chrome
HTTPS to a DPI box. Both ends — the client `yume` and the daemon
`yumed` — are open-source under GPL-3.0 and build from this tree.

This is the planned stable release after the public `v1.0` test release.
The `v1.0` GitHub tag is intentionally left as published; `v1.1` is the
roll-forward stable line. The wire format, authentication keys, anonym CA /
sub-key files, and `yume-obfs-v2` HTTP/2 token format are considered stable
for the 1.x line starting with 1.1.

---

## TL;DR — what shipped

| Area | What's in 1.1 |
| ---- | ------------- |
| **Outer transport** | Real TLS 1.3 (OpenSSL 3.5) with browser-cluster JA3/JA4 fingerprints. Chrome 135 by default, Firefox 126 and Safari 17 selectable; rotation supported. |
| **Carrier camouflage** | HTTP/2 obfs handshake (`PRI * HTTP/2.0`, Chrome-shaped SETTINGS, HEADERS), hourly-rotating HMAC path token, optional `--obfs-secret` peer-pinning. |
| **Decoy site** | `--real` mode serves a real HTML page (or Wikipedia redirect by default) to non-YUME visitors of the same port. YUME and a website coexist on `:443`. |
| **Inner crypto** | BaseFWX 3.7.0 — hybrid **ML-KEM-768 + AES-256-GCM** with **HKDF-SHA256**, hardened Argon2id / PBKDF2 password KDF, fixed Argon2 lane defaults across runtimes, and the blackbox plugin ABI surface (see [BaseFWX 3.7.0 release notes](../../basefwx/RELEASE-NOTES-3.7.0.md)). |
| **Live key hopping** | 1–4 Hz over-the-air key rotation. Each window encrypts with a fresh `HKDF(master, hop_index)` derivative; a captured window decrypts only that window. |
| **Authentication** | Ed25519 client keys. `yumed --auth-keys` is the server's authorised-key file (SSH-style). |
| **Routing modes** | SOCKS5 (`--socks`), local TCP/UDP forward, `--run <cmd>`, Android VPN capture (separate APK), and server-side `--reverse-port-min/--reverse-port-max` reverse tunneling. |
| **Native embed ABI** | `libyume.so.1` exposes a stable C ABI with opaque client/server handles and authenticated named service streams for C/C++ embedders. |
| **Egress options** | Direct, Tor outbound (`yumed --proxy tor://…` with obfs4 bridge support), federation links between yumed instances (mutual TLS 1.3, server-to-server). |
| **Anonym mode** | `yumed --anonym` strips logs and metadata; designed for run-by-third-party endpoints. Decoupled CA/sub-key flow for operator key management. |
| **Targets** | Linux x86_64, ARMv7, ARMv8, BusyBox-static (x86, armv7, armv8), OpenWRT MIPS, macOS arm64, Windows amd64. |
| **Minimal footprint** | Static BusyBox build runs on routers with **128 MiB of RAM** and no glibc. |
| **Optional GUI** | Dear ImGui-based `yume-gui` desktop app for Linux, Windows, macOS. Ships as portable single-file binary on Windows. |
| **Android** | Separate [yume4a](https://github.com/FixCraft-Inc/yume4a) repo. APK (~28 MiB arm64-v8a) shares the same wire protocol and authenticates against the same `yumed`. |

---

## Why YUME

VPN protocols built for performance (WireGuard, OpenVPN) are also
built to be **recognisable**. Their handshakes have static byte
signatures any ISP DPI box can match in milliseconds. Commercial VPN
services then resell that recognisable transport for $20/month from
the same cheap KVMs any user could rent directly.

YUME tries to do the opposite:

- A transport that looks like ordinary Chrome HTTPS to a CDN.
- Crypto that survives the move to post-quantum (ML-KEM-768 + AES-256
  + Grover-safe symmetric keys).
- Both ends fully open-source so anyone can audit, build, and self-host.
- FixCraft runs a fleet of free public endpoints — but those endpoints
  run the same `yumed` you can build yourself, from this tree.

See `docs/EXPLAINED.md` for the full architecture, including diagrams
for federation, Tor egress, Tor-over-YUME, Android, and the YUME ↔ Tor
↔ YUME paths.

---

## 1. Stealth stack (three independent layers)

YUME stacks three orthogonal layers of byte-shape camouflage on top
of TLS 1.3. Each defends against a different kind of observer; all
three are on by default and can be toggled independently.

### Layer 1 — Browser-fingerprint TLS

The TLS 1.3 handshake is **real**, not forged. OpenSSL emits a
genuine `ClientHello`, but the cipher suites, supported groups,
signature algorithms, key shares, and ALPN list are pinned to match
a specific browser profile. JA3 / JA4 hashes fall in the browser
cluster.

```
--profile chrome    # default — Chrome 135
--profile firefox   # Firefox 126
--profile safari    # Safari 17
--no-stealth        # bare OpenSSL defaults (recognisable as YUME)
```

Per-N-connection profile rotation is available via
`--tls-stealth-rotate` and `--tls-stealth-rotation-interval`.

### Layer 2 — HTTP/2 carrier handshake (`--obfs`)

After the TLS handshake the client emits the bytes a real Chrome
would: HTTP/2 preface, Chrome-shaped `SETTINGS`, a `WINDOW_UPDATE`,
and a `HEADERS` frame opening stream 1 with a `POST` to
`/<token>/<nonce>`. The token is
`HMAC-SHA256(K, sni || hour_epoch || "yume-obfs-v2")` truncated to
16 bytes hex; `K` is HKDF-derived from `--obfs-secret`. The server
replies with canned `SETTINGS`, `SETTINGS-ACK`, and
`HEADERS :status=200 content-type=application/grpc-web+proto`.

To a stateless DPI box, the first ~150 cleartext bytes of every
YUME connection look exactly like a Chrome → CDN gRPC-web request.
The token rotates every hour; the server accepts ±1 hour of clock
skew. A replayed token is useless: it cannot decrypt the inner
stream regardless of its timestamp.

### Layer 3 — Real HTML facade (`--real`)

A browser hitting the same hostname + port with `GET / HTTP/1.1`
gets the configured HTML page (or a Wikipedia redirect by default).
YUME and a normal website coexist on `:443`. An active prober that
completes TLS and sends a browser request gets a browser response.

`--real` and `--obfs` are independent. They're demuxed by the first
cleartext bytes after TLS: an HTTP/2 preface goes to the obfs
validator; an HTTP/1.1 method-line goes to the HTML server.

---

## 2. Crypto stack

The outer TLS layer is for stealth. The **inner** layer is BaseFWX
3.7.0 — a separate, audited crypto library that's also published
standalone — and provides:

* **AES-256-GCM** for the data step (AEAD with 96-bit nonce, 128-bit
  tag).
* **ML-KEM-768** (NIST FIPS 203, formerly Kyber-768) hybrid wrap for
  the session keys when a master public key is configured.
* **Argon2id** or **PBKDF2-HMAC-SHA256** for password-based key
  derivation, at the hardened cost (PBKDF2 600 000 iters / 1 M
  short / 2 M heavy; Argon2 4·64 MiB / 5·128 MiB / 6·256 MiB).
* **HKDF-SHA256** for all subkey derivation.
* **Ed25519** for client authentication (`--auth`, `--auth-keys`).

The full BaseFWX 3.7.0 security model — including the explanation
of why password-only mode is already PQ-resistant (AES-256 under
Grover is 128-bit equivalent; hardened KDF makes brute force
expensive) — lives in
[`basefwx/SECURITY.md`](basefwx/SECURITY.md) and
[`../../basefwx/RELEASE-NOTES-3.7.0.md`](../../basefwx/RELEASE-NOTES-3.7.0.md).

### Live key hopping

The session master key is rotated 1–4 times per second over-the-air
(`--hop-interval`, default ~500 ms). Each hop window's data key is
`HKDF(master, hop_index || direction)`. An adversary recording the
wire and later compromising one window's key recovers that window
only; previous and subsequent windows remain confidential. Disable
with `--no-hop` for latency-critical or embedded paths.

---

## 3. Routing & egress

YUME is a transport *and* a relay. Five routing modes ship in 1.1;
they can be combined.

| Mode | What it does | Typical use |
| ---- | ------------ | ----------- |
| `--socks <port>` | YUME client exposes a SOCKS5 listener; apps speak SOCKS5 locally, get tunneled out. | Browsers, curl, anything SOCKS-aware. |
| Local forward (`--proxy host:port -> local:port`) | YUME client opens a local listener; bytes go to `host:port` reachable from the server. | Reach a service behind the server's NAT. |
| `--run <cmd …>` | YUME client spawns a command and pipes its stdin/stdout through the tunnel. | One-shot CLI tools that don't speak SOCKS. |
| Android VPN capture | Separate APK ([yume4a](https://github.com/FixCraft-Inc/yume4a)) captures all OS-level traffic. | Phone-wide stealth tunneling. |
| Reverse port (`yumed --reverse-port-min/--reverse-port-max`) | Server opens an inbound port; bytes flow to a connected client. | Expose a local service through the server. |

Server-side egress can additionally:

* Direct (default — server resolves and connects).
* **Tor** (`yumed --proxy tor://…`, optional obfs4 bridge).
* **Federation** (`--federation-enable`, mutual TLS 1.3 between
  yumed instances; the server-to-server link uses `tlsv13_client` as
  of [f13fbdb](https://github.com/FixCraft-Inc/yume/commit/f13fbdb)).

The full route diagrams (YUME-over-Tor, Tor-over-YUME, etc.) are in
`docs/EXPLAINED.md`.

---

## 4. Anonym / no-log mode

`yumed --anonym` is the run-by-third-party mode:

- Drops connection-level logs (timestamps, IPs, byte counts) before
  they ever hit disk.
- Decoupled CA / sub-key flow: an operator controls the
  long-lived `--anonym-ca-key`, an ephemeral `--anonym-sub-key` is
  rotated on schedule, so a seized box reveals only the current
  sub-key.
- Optional `--anonym-token` rate-limiting that doesn't tie tokens
  back to user identities.
- Operator key management via `--operator-keys`.

This is the mode the FixCraft public endpoints will run.

---

## 5. Platforms & artifacts

| Target | CLI | Static CLI | GUI |
| ------ | --- | ---------- | --- |
| `linux-amd64` | ✓ | ✓ | ✓ |
| `linux-armv7` | ✓ | — | — |
| `linux-armv8` | ✓ | — | — |
| `busybox-amd64` | — | ✓ (musl, fully static) | — |
| `busybox-armv7` | — | ✓ (musl) | — |
| `busybox-armv8` | — | ✓ (musl) | — |
| `openwrt-mips` | maintainer-attached | — | — |
| `macos-arm64` | ✓ | — | ✓ |
| `windows-amd64` | tar.xz bundle (.exe + DLLs) | — | portable .exe (MinGW + static vcpkg) |
| `Android` | — | — | [yume4a APK](https://github.com/FixCraft-Inc/yume4a) — 28 MiB arm64-v8a |

Static / BusyBox builds **must** be statically linked. The release
pipeline enforces this with a post-package assertion: any `*-static`
artifact that has a dynamic loader entry or any `NEEDED` ELF tag
fails the build before publish. Self-test: every published artifact
is exercised with `--version` (native amd64 directly, ARM via
`qemu-aarch64-static`/`qemu-arm-static`, MIPS via `qemu-mips-static`,
PE via wine or PE32-header check) before being attached.

OpenWRT MIPS is intentionally not built in CI: cross-builds against
the OpenWRT SDK are slow and brittle on a hosted runner. Maintainers
attach the MIPS artifacts manually.

---

## 6. Performance

Steady-state CPU overhead: **<1 % typical, <5 % always** (the
measurement methodology and per-link numbers are in
[`docs/PERFORMANCE.md`](docs/PERFORMANCE.md)).

The hot inner-crypto path benefits directly from BaseFWX 3.7.0: Java now
supports Argon2id through BouncyCastle, C++ KEM paths use RAII secret wiping,
Argon2 parallelism defaults are fixed across runtimes, and the BaseFWX
blackbox plugin ABI is available for callers that explicitly opt into
plugin-tagged blobs. Full BaseFWX release details:
[`../../basefwx/RELEASE-NOTES-3.7.0.md`](../../basefwx/RELEASE-NOTES-3.7.0.md).

---

## 7. Quick start

```bash
# 1) Build
cmake -B build
cmake --build build -j$(nproc)

# 2) Create a client key
./build/bin/yume --keys-gen client > ~/.config/yume/id_ed25519

# 3) On the server: drop the public half in --auth-keys, start yumed
sudo ./build/bin/yumed \
    --listen 443 \
    --cert certs/server.crt --key certs/server.key \
    --auth-keys /etc/yume/authorized_keys \
    --obfs --obfs-secret 'shared-string' \
    --real --real-index /var/www/index.html

# 4) On the client: connect, expose a SOCKS5
./build/bin/yume --server example.com:443 \
    --auth ~/.config/yume/id_ed25519 \
    --socks 1080 \
    --obfs --obfs-secret 'shared-string'

# 5) Use it
curl --socks5 127.0.0.1:1080 https://duckduckgo.com
```

For a longer walk-through (TLS profile selection, federation,
anonym mode, Tor egress, Android), see `docs/QUICKSTART.md`,
`docs/STEALTH.md`, and `docs/OPERATIONS.md`.

---

## 8. Security model & threat model

YUME defends **the transport**; it does not by itself provide
anonymity. The route you choose decides who can see the client, who
can see the target, and how much trust is placed in the server.

**Defended against:**

- Stateless DPI fingerprinting (post-handshake byte shape, JA3/JA4,
  HTTP/2 SETTINGS shape).
- Active TLS probes that complete TLS and look for a non-browser
  response (with `--real` enabled they get a real HTML page).
- Passive crypto attacks — both classical (PBKDF2/Argon2 + AES-256
  + Ed25519) and harvest-now-decrypt-later quantum attacks (ML-KEM
  hybrid wrap when a master public key is configured; AES-256 is
  Grover-safe at 128-bit equivalent on its own).
- Single-window key compromise: live hopping keeps each window's
  data key independent.
- Operator-side log forensics in anonym mode.

**Not defended:**

- A nation-state ISP that *correlates* client and server timing
  through end-to-end traffic analysis. Use YUME → Tor (or Tor →
  YUME → Tor) for that — see `docs/EXPLAINED.md`.
- Endpoint compromise. YUME assumes both processes run on
  trustworthy hardware.
- A YUME server operator who is part of the threat. Use anonym
  mode, run your own, or chain through Tor.

Full threat-model discussion lives in `docs/STEALTH.md` ("What this
defends against, what it doesn't") and the `docs/EXPLAINED.md`
route-anonymity diagrams.

---

## 9. Verifying a release binary

Every artifact attached to a release has:

* `<artifact>.sha256` (sha256sum -c verifiable)
* `<artifact>.md5` (md5sum -c verifiable)
* `<artifact>.sig` (optional GPG detached signature, when the
  signing key is configured)

Aggregate manifests are also attached: `SHA256SUMS.txt`,
`MD5SUMS.txt`, and `release-manifest.json`. The release workflow's
self-test step exercises every published binary with `--version`
before attaching it — a failure aborts publish.

```bash
sha256sum -c yume-amd64-linux.sha256
md5sum    -c yume-amd64-linux.md5
gpg --verify yume-amd64-linux.sig yume-amd64-linux
```

---

## 10. Known limitations

* **OpenWRT MIPS is maintainer-attached.** Cross-builds against the
  OpenWRT SDK are unreliable on hosted CI runners and we don't gate
  releases on them. The static BusyBox artifacts cover most embedded
  use; MIPS-specific binaries are uploaded by the maintainer when a
  release is cut.
* **Intel macOS not built today.** The build-macos workflow is
  matrix-ized but only the arm64 entry runs. Rosetta 2 covers Intel
  Macs that need to run the arm64 binary. To add a native Intel
  build, uncomment the prepared `macos-13` matrix entry in
  [`.github/workflows/release.yml`](.github/workflows/release.yml).
* **Windows GUI is best-effort.** The Windows GUI cross-build via
  MinGW + `x64-mingw-static` vcpkg triplet is marked
  `continue-on-error: true` for 1.1 because the GUI-specific vcpkg
  packages (Freetype, GLFW3) take significantly longer to compile
  on a fresh runner than the CLI path. If the cross-build fails the
  release still publishes the CLI; the GUI lands in a follow-up.
* **`--real` is a static-page facade.** A motivated probe that
  expects per-request dynamic behaviour (e.g. session cookies,
  AJAX) will notice. Pair `--real` with a real reverse-proxy in
  front of a real site for higher fidelity.

---

## 11. Compatibility & upgrade

Upgrade from the public `v1.0` test release by installing the 1.1 client and
daemon together. Future 1.x releases keep on-the-wire compatibility:

* Authorised-key files (`--auth-keys`) carry forward unchanged.
* Anonym CA/sub-key files carry forward unchanged.
* The HTTP/2 obfs token version is `yume-obfs-v2` and is wire-stable.
* The BaseFWX inner format is byte-compatible across 3.6.x and 3.7.x for
  non-plugin-tagged blobs; plugin-tagged blobs require a 3.7.0+ peer with the
  matching plugin loaded.

---

## 12. Building from source

```bash
git clone --recursive https://github.com/FixCraft-Inc/yume.git
cd yume
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Optional flags:

```
-DYUME_BUILD_GUI=ON           # build yume-gui (needs glfw / freetype)
-DYUME_STATIC=ON              # fully static binary (use musl toolchain)
-DBASEFWX_REQUIRE_OQS=ON      # fail build if liboqs missing
-DBASEFWX_REQUIRE_ARGON2=ON   # fail build if libargon2 missing
```

Cross-builds and reproducible release tarballs are driven by
[`fullau.sh`](fullau.sh) and [`ezbuild.sh`](ezbuild.sh); see also
[`docs/PACKAGING.md`](docs/PACKAGING.md).

---

## 13. License

GPL-3.0-only. See [`LICENSE`](LICENSE). BaseFWX (the inner crypto
library) is also GPL-3.0-only; both can be built and redistributed
freely under those terms.

---

## 14. Reporting a vulnerability

Please report privately. Do not open a public issue for security
bugs.

Preferred path: GitHub Security Advisory →
*Report a vulnerability*. Coordinated-disclosure SLA matches BaseFWX:
acknowledgement ≤ 48 h, triage ≤ 5 business days, fix delivered in a
new release (Critical/High ≤ 14 d, Medium ≤ 30 d).

See [`basefwx/SECURITY.md`](basefwx/SECURITY.md) for the full
reporting policy.

---

## 15. Credits

YUME's core team is FixCraft. Several pieces of crypto and the
inner-codec engine come from
[BaseFWX](https://github.com/F1xGOD/basefwx). Stealth fingerprinting
profiles were calibrated against a Chrome / Firefox / Safari sample
captured on real hardware. The Dear ImGui-based desktop GUI uses
[Dear ImGui](https://github.com/ocornut/imgui), [GLFW](https://www.glfw.org),
[ImPlot](https://github.com/epezent/implot), and [Freetype](https://freetype.org).
PQ KEM is [ML-KEM-768](https://csrc.nist.gov/pubs/fips/203/final) via
[liboqs](https://github.com/open-quantum-safe/liboqs) on C++ and
[BouncyCastle PQC](https://github.com/bcgit/bc-java) on Java
(yume4a).

---

*See [`docs/EXPLAINED.md`](docs/EXPLAINED.md) for protocol
internals, [`docs/QUICKSTART.md`](docs/QUICKSTART.md) for getting
running, [`docs/STEALTH.md`](docs/STEALTH.md) for the camouflage
layers, and [`docs/OPERATIONS.md`](docs/OPERATIONS.md) for
production deployment.*
