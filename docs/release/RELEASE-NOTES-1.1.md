# YUME 1.1 — First Stable Release

YUME is a **post-quantum stealth transport** that tunnels TCP and UDP
through real TLS 1.3 sessions with browser-profiled ClientHellos and an
HTTP/2-shaped opening exchange. Both ends — the client `yume` and the daemon
`yumed` — are open-source under AGPL-3.0-or-later and build from this tree.

This is the planned stable release after the public `v1.0` test release.
The `v1.0` GitHub tag is intentionally left as published; `v1.1` is the
roll-forward stable line. The wire format, authentication keys, anonym CA /
sub-key files, and `yume-obfs-v2` HTTP/2 token format are considered stable
for the 1.x line starting with 1.1.

---

## TL;DR — what shipped

| Area | What's in 1.1 |
| ---- | ------------- |
| **Outer transport** | Real TLS 1.3 (OpenSSL 3.5) with browser-oriented ClientHello profiles and canonical JA4 diagnostics. Chrome 131 by default, Firefox 126 and Safari 18 selectable; rotation supported. Stock-OpenSSL/GREASE limitations remain. |
| **Carrier masquerade** | HTTP/2 opening with valid frame/HPACK ordering in focused project tests, hourly HMAC path token, benign wrong-path response, and mandatory nonempty `--obfs-secret` under `--public-node`. It is not a full-session H2 tunnel or exact-browser claim. |
| **Authorization** | Persisted `PreauthServiceOnly` dispatcher tier; directional caller-outbound plus target-inbound admin policy, including the legacy attach path; Ed25519-only AUTH key import. |
| **Decoy site** | `--real` mode serves a real HTML page (or Wikipedia redirect by default) to non-YUME visitors of the same port. YUME and a website coexist on `:443`. |
| **Inner crypto** | BaseFWX 3.7.0 — **ML-KEM-768-derived AES-256-GCM** keys with **HKDF-SHA256**, optional Argon2id / PBKDF2 work factor over the KEM secret, and the blackbox plugin ABI surface (see [BaseFWX 3.7.0 release notes](../../basefwx/RELEASE-NOTES-3.7.0.md)). |
| **Live key hopping** | 1–4 Hz per-window key derivation. Each window encrypts with an `HKDF(master, hop_index)` derivative; compromise of one hop key does not directly reveal another, but compromise of the retained master reveals every window. |
| **Authentication** | Ed25519 client keys. `yumed --auth-keys` is the server's authorised-key file (SSH-style). |
| **Routing modes** | SOCKS5 (`--socks`), local TCP/UDP forward, `--run <cmd>`, Android VPN capture (separate APK), and server-side `--reverse-port-min/--reverse-port-max` reverse tunneling. |
| **Native embed ABI** | `libyume.so.1` exposes a stable C ABI with opaque client/server handles, authenticated named service streams, peer-auth metadata, and fixed-buffer JSON helpers for C/C++ embedders. |
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

- A transport with browser-oriented TLS presets, keyed active-probe admission,
  and an ordinary HTTPS decoy path. It is not claimed to be byte-identical to
  Chrome or immune to stateful DPI.
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
signature algorithms, key shares, and ALPN list are configured toward
a specific browser profile. The project checks emitted JA3 against pinned
build-host baselines, but stock OpenSSL does not reproduce every browser
ClientHello detail (notably all GREASE positions).

```
--profile chrome    # default — Chrome 131
--profile firefox   # Firefox 126
--profile safari    # Safari 18
--no-stealth        # bare OpenSSL defaults (recognisable as YUME)
```

Per-N-connection profile rotation is available via
`--tls-stealth-rotate` and `--tls-stealth-rotation-interval`. Rotation advances
after successful TLS connections, and the carrier User-Agent follows the
active profile unless explicitly overridden.

### Layer 2 — HTTP/2 carrier handshake (`--obfs`)

After the TLS handshake the client emits an HTTP/2 preface, a
project-defined browser-oriented `SETTINGS` block, a `WINDOW_UPDATE`, and a
valid HPACK `HEADERS` frame opening stream 1 with a `POST` to
`/<token>/<nonce>`. The request authority must match the TLS SNI, and any
authority port must be decimal, in range, and equal to the accepted listener
port. The token is `HMAC-SHA256(K, sni || hour_epoch || "yume-obfs-v2")`
truncated to 16 bytes hex; `K` is HKDF-derived from `--obfs-secret`. The server
replies in one serialized write with server `SETTINGS`, an ACK of the client
settings, and bodyless `HEADERS :status=200
content-type=application/grpc-web+proto`. The client must ACK the server
settings before the server switches to YUME AUTH.

Missing, malformed, wrong-key, frame-order-invalid, or SNI/authority/listener
mismatched requests stay in masquerade and receive a complete benign H2
response with `END_STREAM` using configured upstream/real/profile identity. A
missing server-SETTINGS ACK is closed without YUME AUTH. The client classifies
decoys before attempting YUME parsing. `--public-node` requires obfs with a
nonempty shared secret; empty-secret structural admission remains only for
non-public development.

These application bytes are covered by focused project decoder tests, not a
version-pinned external Chrome/Firefox or HTTP/2-conformance capture. A passive
path observer sees encrypted TLS records, and the authenticated payload path
does not remain a conformant HTTP/2 stream after the opening exchange. The
token rotates hourly and the server accepts ±1 hour of clock skew. A captured
valid path may be replayed within that accepted window to reach the separate
Ed25519 challenge, but it cannot authenticate or decrypt the inner stream.

### Authorization boundary

Peers admitted through configured `preauth_services` now remain in a persisted
`PreauthServiceOnly` tier. A central frame gate permits only named
`service.v1` OPEN, DATA/CLOSE for accepted service streams, and PING/PONG;
control, relay/admin, generic egress, codecs, benchmarks, and packet paths are
rejected. Pending service opens are capped at 64 per service and 256 total.

Admin attach now requires trusted relay mode plus the caller's server-capped
and runtime outbound permission and the target's server-capped and runtime
inbound permission. The legacy attach form uses the same predicate and retains
its target `--server-in-charge` requirement. Federation still trusts the
authenticated source server to enforce the caller half because the 1.x wire
does not carry a separate caller-policy proof.

### Layer 3 — Real HTML facade (`--real`)

A browser hitting the same hostname + port with `GET / HTTP/1.1`
gets the configured HTML page (or a Wikipedia redirect by default).
YUME and a normal website coexist on `:443`. An active prober that
completes TLS and sends a browser request gets a browser response.

`--real-root <dir>` upgrades this from a single page to a coherent static
site: GET/HEAD for any real file under `<dir>` is served with the correct
MIME type, `Content-Length`, `Last-Modified`, an nginx-style `ETag`, and
`Accept-Ranges: bytes`; `/` and directory paths serve `index.html`, and
misses fall through to the profile 404. This closes the "single page returns
200 but every asset 404s" tell for a prober that walks more than one URL. The
same root/index is presented on both the HTTP/1.1 probe and the H2 decoy, so an
active probe sees one web identity. Resolution rejects traversal, encoded-slash
tricks, control bytes, over-length targets, and symlink escape (canonicalized
against the root), and a per-response size cap bounds one cover reply. The
server also honors the cache/range semantics of a real static host: conditional
GET (`If-None-Match`/`If-Modified-Since`) returns `304`, and byte `Range`
requests return `206 Partial Content`/`416`. HTTP/1.1 keep-alive is honored so a
browser pulls the page and its assets over one connection (bounded by a
per-connection request cap and an idle timeout); only bodyless GET/HEAD keep the
connection open. Static 200s currently use nginx-style header framing (pair with
`--hide-in-the-crowd nginx`); per-profile static templates are not yet
implemented.

`--real` and `--obfs` are independent. They're demuxed by the first
cleartext bytes after TLS: an HTTP/2 preface goes to the obfs
validator; an HTTP/1.1 method-line goes to the HTML server.

---

## 2. Crypto stack

The outer TLS layer is for stealth. The **inner** layer is BaseFWX
3.7.0 — a separate crypto library that's also published
standalone — and provides:

* **AES-256-GCM** for the data step (AEAD with 96-bit nonce, 128-bit
  tag).
* **ML-KEM-768** (NIST FIPS 203, formerly Kyber-768) KEM for
  the session keys when a master public key is configured.
* **Argon2id** or **PBKDF2-HMAC-SHA256** as an optional work factor over
  the high-entropy KEM shared secret. The YUME transport handshake does not
  mix in a user password or PSK. Runtime-selected parameters are carried on
  the wire and may be adaptively sized up to the server's per-derivation cap.
  Concurrent Argon2 handshakes additionally share a configurable aggregate
  memory and job-admission budget that is acquired before allocation.
* **HKDF-SHA256** for all subkey derivation.
* **Ed25519** for client authentication (`--auth`, `--auth-keys`).

The full BaseFWX 3.7.0 security model for BaseFWX's own file/password modes
lives in
[`basefwx/SECURITY.md`](basefwx/SECURITY.md) and
[`../../basefwx/RELEASE-NOTES-3.7.0.md`](../../basefwx/RELEASE-NOTES-3.7.0.md).

### Live key hopping

The session derives a new data key 1–4 times per second
(`--hop-interval`, default ~500 ms). Each hop window's data key is
`HKDF(master, hop_index)`. Compromise of one derived hop key does not directly
reveal the other derived keys. This is key separation, not forward secrecy:
compromise of the retained master permits deriving previous and subsequent
windows. Disable with `--no-hop` for latency-critical or embedded paths.

---

## 3. Routing & egress

YUME is a transport *and* a relay. Five routing modes ship in 1.1;
they can be combined.

| Mode | What it does | Typical use |
| ---- | ------------ | ----------- |
| `--socks [addr:]port` | YUME client exposes a SOCKS5 listener; apps speak SOCKS5 locally, get tunneled out. | Browsers, curl, anything SOCKS-aware. |
| Local forward (`-L [bind:]lport:host:port` or `--lport` + `--rhost` + `--rport`) | YUME client opens a local listener; bytes go to `host:port` reachable from the server. | Reach a service behind the server's NAT. |
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

One April 2026 WAN run measured about 234 Mbps download and 36 Mbps upload
through YUME. It did not record CPU utilization or provide a same-path bypass,
so it does not establish a CPU-overhead percentage or an "always" bound. The
methodology and per-link numbers are in [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md).

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

- Simple DPI fingerprinting based on known VPN signatures or coarse
  ClientHello / opening-exchange shape.
- Active TLS probes that complete TLS and look for a non-browser
  response (with `--real` enabled they get a real HTML page).
- Passive crypto attacks — both classical (PBKDF2/Argon2 + AES-256
  + Ed25519) and harvest-now-decrypt-later quantum attacks (ML-KEM
  hybrid wrap when a master public key is configured; AES-256 is
  Grover-safe at 128-bit equivalent on its own).
- Single-hop-key compromise: live hopping separates derived window keys, while
  retaining the master-key limitation described above.
- Operator-side log forensics in anonym mode.

**Not defended:**

- A nation-state ISP that *correlates* client and server timing
  through end-to-end traffic analysis. Use YUME → Tor (or Tor →
  YUME → Tor) for that — see `docs/EXPLAINED.md`.
- Endpoint compromise. YUME assumes both processes run on
  trustworthy hardware.
- A YUME server operator who is part of the threat. Use anonym
  mode, run your own, or chain through Tor.
- Full-session HTTP/2 conformance, exact native browser/web-server identity,
  or ML/DPI immunity. Those require separate version-pinned captures and tests.
- Complete secret-copy erasure or cancellation of detached EXEC workers.
  Shutdown/queue/worker bounds and best-effort erasure are implemented, but
  sanitizer and long-running race/soak validation remain outstanding.

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
* **No independent security audit or production-scale adversarial soak is
  documented yet.** "Stable" describes the intended compatibility/release
  line; it is not a claim of formal verification or third-party audit.
* **The HTTP/2 carrier is an opening exchange, not a full-session HTTP/2
  tunnel.** Stateful TLS-terminating middleboxes can distinguish the
  authenticated stream after the initial HEADERS exchange.

---

## 11. Compatibility & upgrade

Upgrade from the public `v1.0` test release by installing the matching 1.1
transport core on both client and daemon. The handshake rejects a different
`kVersion` before carrying traffic; desktop GUI and Android app release
versions are independent and are not part of that check. Stable artifacts
continue to carry forward across the 1.x line:

* Authorised-key files (`--auth-keys`) carry forward unchanged.
* Anonym CA/sub-key files carry forward unchanged.
* The HTTP/2 obfs token version is `yume-obfs-v2` and is wire-stable.
* The BaseFWX inner format is byte-compatible across 3.6.x and 3.7.x for
  non-plugin-tagged blobs; plugin-tagged blobs require a 3.7.0+ peer with the
  matching plugin loaded.

---

## 12. Building from source

```bash
git clone https://github.com/FixCraft-Inc/yume.git
cd yume
git clone https://github.com/FixCraft-Inc/basefwx.git basefwx
git -C basefwx checkout "$(cat config/refs/basefwx.ref)"
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

AGPL-3.0-or-later for YUME source, apps, daemon, proxy, GUI, and
libyume. See [`LICENSE`](LICENSE). BaseFWX has its own split license:
core library/API/runtime code and plugin ABI/SPI surfaces are
LGPL-3.0-or-later, standalone CLI/tools/benchmarks/scripts are
GPL-3.0-or-later, and example plugin templates are MIT OR Apache-2.0.

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
[BaseFWX](https://github.com/F1xGOD/basefwx). Stealth fingerprinting profiles
use project-labelled browser-oriented baselines; stock OpenSSL differences
remain and no exact current-browser claim is made. The Dear ImGui-based desktop GUI uses
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
