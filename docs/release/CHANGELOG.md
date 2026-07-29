# Changelog

## [Unreleased 2.0-dev4]

Hard break from `2.0-dev2` and `2.0-dev3`: the exact transport version changed,
so dev2, dev3, and dev4 binaries do not interoperate at admission or AUTH. No
compatibility mode exists or is planned.

### Added

- **TLS-exporter channel binding for AUTH.** The Ed25519 signature input and
  the establishment root now cover a 32-byte RFC 8446 section 7.5 exporter
  (`EXPORTER-yume/2.0/auth-channel-binding/v1`) that each endpoint derives from
  its own live TLS object and never transmits. A malicious endpoint that
  terminates TLS with a client and holds compatible admission and inner PSK
  material can no longer forward that live AUTH exchange to a second server:
  the two connections have independent exporters, so the relayed signature does
  not verify at the far end. Both peers require TLS 1.3 and a finished
  handshake; a peer that cannot produce a 32-byte binding fails AUTH. There is
  no unbound mode to negotiate. The signature domain moves to
  `yume/2.0/auth-signature/v2` and the root label to `yume/2.0/root/v2`, so a
  dev3 peer fails loudly instead of downgrading.

- **Bounded multi-epoch ratchet window.** A direction may keep several
  authenticated, strictly contiguous future epochs in flight or prepared
  instead of one, negotiated per connection through the AUTH transcript and
  configured with `--rekey-window` / `rekey_window` (1..64, default 8). A
  byte-saturated direction rises from 256 KiB to `window * 256 KiB` per rekey
  round trip: roughly 35 Mbit/s to 280 Mbit/s at 60 ms RTT by the protocol
  model. Every per-epoch limit is unchanged — 256 KiB, 512 application frames,
  500 ms of activity — and the receiver still enforces the byte and frame
  limits on authenticated plaintext. Gaps, duplicates, reordered ACKs, and
  offers past the advertised depth stay fatal. Offers are paced by application
  progress so a filling window does not emit a burst of rekey records.
  `docs/YUME_2_0_WAN_BEHAVIOR.md` records what remains unmeasured.

### Changed

- **Stealth and cryptographic claims now match the implementation.** The
  documentation records the current Chrome 131/150 and Windows/Linux profile
  mismatch, rejects the stale 2.0 profile-rotation claim, treats BoringSSL and
  traffic padding as evidence-driven experiments, and describes 500 ms as a
  sender-active epoch limit rather than a twice-per-second wall-clock promise.
- **The untrusted-server boundary is explicit.** Client AUTH sends a public
  Ed25519 identity plus transcript signature, not the private key; ephemeral
  hybrid exchanges provide conditional forward secrecy against later
  persistent-file compromise. `yumed` remains the terminating single-hop proxy
  with access to decrypted YUME stream bytes. AUTH is now TLS-exporter-bound,
  so live forwarding by a malicious compatible endpoint is closed, but that
  does not make the terminating node blind to traffic it exits.
- **Client identity files are owner-only by contract.** `--keys-gen`
  serializes to memory and creates both halves through the exclusive
  owner-only writer at mode `0600`, wipes the private PEM, and refuses to
  replace an existing path instead of silently overwriting an identity.
  Loading reads the private key through an already-validated descriptor and
  rejects symlinks, foreign ownership, group/world permission bits, and
  out-of-range sizes, so a poorly protected key can no longer sign an AUTH
  transcript. Enforcement is Linux/POSIX; Windows identity loading fails
  closed.
- **AUTH v2 records carry the negotiated window.** The challenge gains critical
  field 7 and the response gains critical field 4, moving the Ed25519 signature
  to field 5. The client's advertised depth is inside the signed record, so the
  negotiation is covered by the existing transcript signature.
- **An acknowledged epoch is prepared, not entered.** A direction advances when
  the current epoch can no longer carry the next application frame, so each
  prepared epoch delivers its whole byte budget.

### Fixed

- **Rekey ACKs are sealed in wire order.** `SessionRatchet::Open` used to seal
  the REKEY_ACK on the read path. A directional chain assigns sequence numbers
  at seal time, so a data frame sealed afterwards on the write path could reach
  the wire first and the peer would close the session with "replay or
  unexpected epoch/sequence". `OpenResult::control_response` is now plaintext
  and is sealed by the caller's ordered write path like any other frame. The
  defect predates the window but was only reachable in practice with several
  exchanges outstanding.
- **Federation link stream ownership.** The dialing loop's TLS stream is now
  heap-owned and shared with the write path by a counted reference instead of a
  pointer into the loop's stack frame. The lifetime was already guarded, but a
  counted reference removes the class of defect entirely.

## [Unreleased 2.0-dev2]

Dev2 was the first hard-break 2.0 desktop transport line. It was superseded by
dev3 before release; neither development version is a stable release.

### Added

- **Bounded server capacity controls.** Administrators can set worker threads,
  aggregate tracked sessions, default bulk-key sessions, aggregate accepts per
  second, and an optional weighted-fair egress cap. Default tracked and bulk
  limits are 256 and 64 respectively; unlimited behavior must be explicit.
- **Regular individual/bulk keys and a physical operator trust store.** Shared
  bulk credentials are separately counted per connection and cannot receive
  controller, exec, LAN/full-control, privileged codec/service, or federation
  policy. Only individual keys in the separate operator store may receive
  outbound admin policy.
- **External benchmark resource telemetry.** Localhost, LAN, and WAN harnesses
  can sample server/client CPU time, fair per-core CPU, RSS/peak RSS, threads,
  and host CPU/RAM context. Multi-client runs are bounded by default and require
  explicit acknowledgement above the safe local ceiling.

### Changed

- **Directional rekeys are pipelined without widening their blast radius.**
  Each sender prepares the next authenticated ML-KEM-1024 + X25519 + PSK epoch
  while bounded current-epoch traffic remains. The existing 256 KiB, 512-frame,
  and 500 ms limits remain independently enforced; writes block only if the
  ACK has not arrived at the hard boundary. Exact version equality rejects
  dev1 peers rather than silently mixing the two scheduling contracts.

- **AUTH policy lookup uses immutable snapshots.** Regular and operator
  key/policy files are parsed and validated before atomic startup/reload
  publication. Failed reloads preserve the complete previous snapshot, and the
  same public key cannot appear in both stores.
- **Capacity logic is modular.** Thread-safe identity admission and weighted
  egress controllers are independent server runtime units with focused tests.
  The optional limiter is not constructed when egress shaping is disabled.
- **Developer timing is centralized and absent from production binaries.**
  Debug/RelWithDebInfo builds share stopwatches, batched samples, asynchronous
  intervals, and event macros across connection, AUTH, ratchet, scheduler,
  TLS, H2, and WebSocket boundaries. Runtime collection remains opt-in.
  Release/MinSizeRel preprocess the hooks and detail construction away, while
  `/proc` resource sampling remains external to the measured processes.

### Security

- Authentication remains Ed25519 over the canonical transcript, and admission
  still occurs before ML-KEM decapsulation. Rekey pipelining does not change
  AEAD AAD, HKDF labels, hybrid secret composition, or directional usage
  limits. The dev2 version bump deliberately changes when the existing rekey
  records are scheduled and accepted.

## [Unreleased 1.1 historical work]

Target: `v1.1`. Do not tag until the remaining release work and remote
validation are complete.

### Added
- **Static-site masquerade cover (`--real-root <dir>`).** yumed serves GET/HEAD
  for real files under one root with correct MIME, `Content-Length`,
  `Last-Modified`, nginx-style `ETag`, and `Accept-Ranges`, so the decoy is a
  coherent multi-asset site instead of "`/` => 200, everything else => 404".
  Path resolution rejects traversal, encoded-slash/backslash, control bytes,
  over-length targets, and symlink escape (canonicalized against the root); a
  per-response size cap bounds one cover reply. The same root/index backs both
  the HTTP/1.1 probe and the H2 decoy, with HTTP/1.1 keep-alive across a page's
  assets (bodyless GET/HEAD only, bounded by a per-connection request cap and an
  idle timeout), conditional GET (`If-None-Match`/`If-Modified-Since` -> 304),
  and byte `Range` requests (-> 206 Partial Content, or 416 when unsatisfiable).
  Implies `--real`; pair with `--hide-in-the-crowd nginx` for the closest header
  fit.

### Changed
- **License**: YUME source, apps, daemon, proxy, GUI, and libyume are
  AGPL-3.0-or-later. Build scripts and CMake entry points now carry
  matching source headers.
- **Masquerade is now the active-probe boundary.** `--public-node` requires
  obfs plus a nonempty shared secret. Missing, malformed, wrong-key, bad-order,
  or SNI/authority/listener-port-mismatched H2 admission stays outside AUTH.
  Empty-secret structural admission remains development-only.
- **The H2 opening is standards-oriented, not exact-browser branding.** HPACK
  indexes, SETTINGS/ACK ordering, END_STREAM behavior, authority validation,
  mandatory client ACK of server settings, serialized fallback writes, and
  client decoy classification were corrected. Synthetic web profiles are not
  native nginx/Apache/etc. implementations.
- **TLS profile rotation now advances after successful connections.** The
  carrier User-Agent follows the active profile unless explicitly overridden.

### Fixed
- **Preauth privilege promotion.** Self-signed peers admitted for configured
  named services now persist as `PreauthServiceOnly`; a central gate confines
  them to service.v1 OPEN/DATA/CLOSE and PING/PONG.
- **Caller-blind admin attach.** Modern and legacy paths now share the trusted
  relay + caller outbound + target inbound authorization predicate.
- **Bounded shutdown and queues.** Added a five-second session-close deadline,
  64-per-service/256-total pending service limits, four-worker client EXEC cap,
  and best-effort sensitive-buffer erasure. Sanitizer and soak validation remain
  outstanding; detached EXEC workers are bounded but not cancellable/joined.

## [v1.1] - TBD

### Added
- **`--cluster-join <spec>`** + **`--cluster-bootstrap`** on `yumed`. Friendly shorthand over the existing `--peer '<json>'` federation surface: `--cluster-join [id@]host[:port][?pin=<sha256>]` parses into the same FederationPeer JSON the daemon already consumes. `--cluster-bootstrap` marks a node as a cluster entry point so federation works without an outbound peer list. Bracketed IPv6 supported. Implies `--federation-enable`.
- **`--cluster <host[:port]>`** on `yume` (client) as a friendly alias for `--server` + `--port`.
- **`--public-node`** on `yumed`: hardening preset for internet-facing daemons. Rejects `--allow-exec` / `--allow-local-ip` / `--control-full` / `--no-inner` / `--no-obfs`, requires `--auth-keys` and a nonempty `--obfs-secret`, defaults `--hide-in-the-crowd` to `nginx`, and applies bounded session/Argon2 defaults.
- **`--hide-in-the-crowd <profile>`** on both binaries: HTTP-layer disguise. Server profiles (`nginx`, `nginx-stable`, `apache`, `caddy`, `cloudflare`, `express`, `gunicorn`, `none`, `yumed`) are synthetic templates with profile-specific header order, charset, extras, and body shapes; they are not native server implementations. Client profiles (`chrome`, `firefox`, `safari`, `edge`, `curl`, `wget`, `yume`) set the User-Agent in stealth probes; when unspecified, the UA follows the active TLS preset.
- **Profile-driven disguise on every non-YUME probe.** Pre-1.0 yumed closed the connection on HTTP probes when `--real` wasn't set — TLS-handshake-then-immediate-close is a textbook DPI signal. Now serves a profile-matching 404 even without `--real`, by routing through `Session::send_disguise_404`.
- **`yume-net-map`** new read-only CLI tool: connects to a yumed admin socket and renders the current node + its federation peers as an ASCII fan/spoke diagram (Unicode box-drawing or `--ascii` fallback). `--json` mode for downstream tooling. Auto-discovers local sockets under `$XDG_RUNTIME_DIR/yume`, `/run/yume`, `/tmp/yume`.
- **`scripts/yume_disguise_check.py`** automated profile-fidelity test: spins up yumed once per profile, probes with curl, validates Server header regex / extra headers / body length range / canonical body substrings. `--dpi` mode adds nDPI flow classification (needs `tcpdump` capability and `libndpi-bin`). CI-runnable in <60 s.
- **`scripts/yume_bench_wan.py`** virtual-WAN benchmark with DPI comparison: two `ip netns` connected by a veth + tc-netem WAN profile, runs the same workload over yume and as a curl/chromium baseline, runs `ndpiReader` on captured pcaps, emits a side-by-side report (markdown or JSON).
- **Native embed C ABI in `libyume.so.1`.** `include/yume/yume.h` now exposes opaque `yume_client`, `yume_server`, and `yume_stream` handles, JSON lifecycle/status helpers, fixed-buffer last-error reporting, and direct named service stream read/write calls for C/C++ embedders.
- **Authenticated named service streams.** Clients can open project-neutral `proto: "service.v1"` streams such as `example-service-v1`; servers must explicitly enable the application-defined service in config, authorize it per key with `allow_services`, and register it through the C ABI before accepts are queued.
- **Stream peer metadata in the native ABI.** `yume_stream_peer_json` exposes the accepted stream's service, authenticated Ed25519 SPKI SHA-256 fingerprint, peer/session ids, and remote address so embedders can bind sessions to their own device registry.
- **Embed JSON bind address support.** `yume_server_start_json` accepts `listen_address` with `listen_port`, allowing loopback-only native tests and embedded local services without a wildcard bind.

### Changed

> **Browser profiles:** The v1.0 test-release block below documents the TLS profiles shipped at 1.0. Current builds use the bumped versions listed in this section.

- **Release line moved to 1.1.** The public `v1.0` tag remains the first test release. Current source, packages, man pages, GUI bundle metadata, Android `versionName`, and release notes now target `1.1` as the first stable line.
- **BaseFWX pin currently names legacy-history 3.7.0 commit** `ddf31617aab6bb9ac87129295564d6736e48c601`, carrying Java Argon2id support, fixed Argon2 lane defaults across runtimes, secret-hygiene hardening, and the blackbox plugin ABI surface. The SHA remains fetchable but is not on the rewritten current `main`/`v3.7.0` lineage; choose and validate the intended canonical release commit before shipping 1.1.
- **Inner crypto secret hygiene.** Introduced `basefwx::crypto::SecureBytes` — move-only RAII owner that wraps `Bytes` and SecureClears on destruction. Replaces the `SecretGuard` raw-pointer pattern at every KEM-touching call site in yume (`server_derive_key`, `validate_pq_keypair`) and basefwx (`filecodec.cpp` 4 sites, `keywrap.cpp` 2 sites). Eliminates a use-after-free class fixed in 66153f6 by structural change rather than placement discipline. Existing string-secret SecretGuard sites are unchanged.
- **TLS browser-profile labels corrected** to match the captured shapes: Chrome 131, Firefox 126, Safari 18, and Edge 123.
- **JA4 diagnostics made canonical.** Fingerprints now use FoxIO's `a_b_c` format, GREASE filtering, sorted lower-case cipher/extension hex lists, SNI/ALPN exclusions, and original-order signature algorithms. Focused official-vector and match-threshold tests cover the implementation.
- **`X-Yume-Blob` HTTP response header removed.** It had zero consumers in the tree; the substring "Yume" was a passive fingerprint for any layer-7 inspector. The anonym blob still ships in the body (zero-width `<span>` + HTML comment) where the actual readers look.

### Fixed
- **Use-after-free on KEM secret wipe.** SecretGuard stores raw `Bytes*` pointers and SecureClears them from its destructor. Reverse-construction-order destruction meant a SecretGuard declared BEFORE the locals it tracked accessed already-freed vector storage on scope exit. Manifested as `malloc(): unaligned tcache chunk detected` immediately after PQ keypair validation on `--pq-auto-generate` startup. Closed first by reordering (commit 66153f6), then by structural replacement with SecureBytes (commit 58c39a7).
- **Pre-existing yume_server link break** from the `f6db161` session.cpp split: `epoch_now_ms` was anonymous-namespace-local in session.cpp but referenced from session_control.cpp. Exposed at file scope in session.hpp; duplicate copy in federation_link.cpp removed.
- **Argon2 admission was not aggregate.** `argon2_env_limits()` previously returned `{0,0,0}` by default, making the parameter guard a no-op. It now seeds per-derivation ceilings (`time=12, memory=512 MiB, parallelism=8`), and positive environment values may deliberately lower or raise them. The server additionally reserves each Argon2 derivation against manager-owned aggregate memory/job limits before allocation; move-only RAII leases release accounting on all exits. Defaults are 512 MiB aggregate and four jobs, configurable through CLI or JSON. The `has_argon2_limits` gate this enabled was dead code and is removed; the client local-cap check stays for old-server backwards compatibility.

## [v1.0] - 2026-05-16

Compare: <https://github.com/FixCraft-Inc/yume/commits/v1.0> (first public test release)

### Added
- **First public test release** of YUME (Yume Universal Multiprotocol Engine) — an open-source post-quantum stealth transport that tunnels TCP and UDP through real TLS 1.3 sessions using the project's browser-oriented presets. The client (`yume`), daemon (`yumed`), proxy, GUI, and libyume surface are AGPL-3.0-or-later and build from this tree.
- **Three-layer stealth stack** stacked on top of TLS 1.3, all on by default and toggleable independently:
  - Browser-oriented JA3 shaping plus the original project-local, pre-canonical JA4-like diagnostic via genuine OpenSSL 3.5 `ClientHello` configuration. `--profile chrome` (Chrome 131) is the default; `--profile firefox` (Firefox 126) and `--profile safari` (Safari 18) are selectable, plus per-N-connection rotation via `--tls-stealth-rotate` / `--tls-stealth-rotation-interval`.
  - HTTP/2 carrier handshake (`--obfs`) with the then-current project SETTINGS, `WINDOW_UPDATE`, and a `HEADERS` frame opening a `POST` to `/<token>/<nonce>`. The token is `HMAC-SHA256(K, sni || hour_epoch || "yume-obfs-v2")` truncated to 16 bytes hex; 1.0 allowed optional peer-pinning via `--obfs-secret` and accepted ±1 hour of clock skew.
  - Real HTML facade (`--real`) so a browser hitting the same `:443` with `GET / HTTP/1.1` is served a real HTML page (or a Wikipedia redirect by default). YUME and a normal website coexist on a single port.
- **Post-quantum KEM/DEM inner crypto** via BaseFWX 3.6.4 (separate library, pinned via `config/refs/basefwx.ref`):
  - **ML-KEM-768** (NIST FIPS 203 / Kyber-768) encapsulation for session keys when a master public key is configured.
  - **AES-256-GCM** AEAD with a 12-byte nonce and 16-byte tag.
  - **Argon2id** or **PBKDF2-HMAC-SHA256** as an optional work factor over the high-entropy ML-KEM shared secret. The YUME transport handshake does not mix in a user password / PSK.
  - **HKDF-SHA256** for all subkey derivation.
  - **Ed25519** for client authentication via `--auth` / `--auth-keys`.
- **Live key hopping** at 1–4 Hz (`--hop-interval`, default ~500 ms). Each window encrypts with an `HKDF(master, hop_index)` derivative. This separates derived hop keys but is not forward secrecy: compromise of the retained master reveals every window. Disable for latency-sensitive paths with `--no-hop`.
- **Five routing modes**, combinable:
  - `--socks [addr:]port` — SOCKS5 listener on the client side.
  - Local TCP/UDP forward (`--proxy host:port -> local:port`).
  - `--run <cmd …>` — spawn a command and pipe its stdio through the tunnel.
  - Android VPN capture (separate [yume4a](https://github.com/FixCraft-Inc/yume4a) APK that captures all OS-level traffic).
  - Server-side reverse port tunneling via `yumed --reverse-port-min` / `--reverse-port-max`.
- **Server-side egress options**: direct, Tor outbound (`yumed --proxy tor://…`, optional obfs4 bridge), and yumed-to-yumed federation links over mutual TLS 1.3 (`--federation-enable`, `--federation-auth-key`, `--federation-anonym-ca`, `--peer`).
- **Anonym / no-log mode** (`yumed --anonym`) for run-by-third-party endpoints: drops connection-level logs before disk, decoupled CA / sub-key flow (`--anonym-ca-key`, `--anonym-sub-key`), optional `--anonym-token` rate-limiting that doesn't tie tokens back to user identities, operator key management via `--operator-keys`.
- **Optional Dear ImGui-based desktop GUI** (`yume-gui`) for Linux, macOS, and Windows. Ships as a portable single-file `.exe` on Windows (static MinGW runtime + `x64-mingw-static` vcpkg triplet).
- **9-target release matrix**: linux-amd64 (dynamic + static), linux-armv7, linux-armv8, busybox-amd64-static, busybox-armv7-static, busybox-armv8-static, openwrt-mips (maintainer-attached), macos-arm64, windows-amd64 (CLI tarball + portable GUI .exe). Android via [yume4a](https://github.com/FixCraft-Inc/yume4a) (~28 MiB arm64-v8a APK).
- **Minimal footprint**: the static BusyBox build runs on routers with as little as **128 MiB of RAM** and no glibc.
- **Release pipeline** with full pre-publish self-test:
  - `light-tests` host-build + `yume --version` / `yumed --version` smoke pre-gate.
  - GUI cross-builds for the three desktop OSes (continue-on-error so a GUI dep regression doesn't block CLI release).
  - Static-link assertion on every `*-static` artifact (`file` must not say "dynamically linked"; `readelf -d` must show no `NEEDED` entries).
  - `--version` self-test on every published binary (native amd64 directly, ARM via `qemu-aarch64-static`/`qemu-arm-static`, MIPS via `qemu-mips-static`, PE via wine if available else PE32 header check, tar.xz CLI bundles extracted and tested).
  - GPG-signed `*.sig` per artifact plus aggregate `SHA256SUMS.txt`, `MD5SUMS.txt`, `release-manifest.json`.
- Project documentation: `README.md`, `docs/QUICKSTART.md`, `docs/STEALTH.md`, `docs/EXPLAINED.md` (protocol internals + routing diagrams for federation, Tor egress, Tor-over-YUME, YUME-Tor-YUME, Android), `docs/PERFORMANCE.md`, `docs/OPERATIONS.md`, `docs/PACKAGING.md`, `docs/PERMISSIONS.md`, release notes, and the project website at <https://yume.fixcraft.jp>.

### Changed
- Wire format, authentication key file format, anonym CA / sub-key file format, and the `yume-obfs-v2` HTTP/2 token format were test-published in 1.0 and are treated as the compatibility base for the 1.1 stable line.
- Server-to-server federation links are pinned to **TLS 1.3 only** (no fallback to earlier TLS versions) — see commit `f13fbdb`.
- Build pipeline rewritten end-to-end vs the BETA cycle: smoke-gate before heavy builds, GUI added for desktop OSes, dynamic "busybox" artifacts dropped (they were misleadingly named — a glibc-dynamic binary can't run on a real busybox/musl target), only verified-static `*-busybox-static` ships, macOS job is matrix-ized so Intel can be added in a follow-up by uncommenting one matrix entry.
- Website's `assetMap` aligned with the new release-artifact set: GUI download cards for Linux / macOS / Windows added; dynamic-busybox cards dropped.

### Fixed
- Federation TLS regression: an earlier commit used the wrong TLS-method constant (`tls_client` instead of `tlsv13_client`); pinned in `f13fbdb`.
- 240-commit history through the ALPHA → BETA cycle accumulated and addressed: TLS-fingerprint correctness, HTTP/2 obfs token rotation, key-hop window seam handling, federation handshake edge cases, anonym-mode metadata leaks, Android VPN capture restart bugs, Windows MinGW cross-build deps, BusyBox static-link reliability across glibc/musl toolchains, GUI font rendering on Wayland vs X11 (URW Gothic Demi double-bold fix), CodeQL high-severity findings, OpenWRT SDK feed wiring, and assorted CI/website hash-rendering bugs.

### Notes
- **Threat model recap** (full version in `docs/STEALTH.md` and `docs/EXPLAINED.md`): YUME defends the **transport**. The route you choose decides who can see the client, who can see the target, and how much trust is placed in the YUME server. YUME does **not** by itself provide anonymity — combine with Tor egress, Tor-over-YUME, or YUME-Tor-YUME for that.
- **OpenWRT MIPS** is intentionally **not** built in CI because cross-builds against the OpenWRT SDK are slow and brittle on hosted runners; maintainers attach the MIPS artifacts manually when a release is cut. The static BusyBox builds cover most embedded use.
- **Intel macOS** is not built in 1.0. The `build-macos` workflow is matrix-ized so an Intel entry is a one-line uncomment in `.github/workflows/release.yml`. Rosetta 2 covers Intel Macs running the arm64 binary.
- **Windows GUI cross-build is best-effort** in 1.0: marked `continue-on-error: true` because the GUI-specific vcpkg packages (Freetype, GLFW3) on a fresh runner can take significantly longer than the CLI path and may time out. If the cross-build fails the CLI tarball still ships and the GUI lands in a follow-up.
- **Performance**: one April 2026 WAN run measured about 234 Mbps download and 36 Mbps upload on the SOCKS path; full methodology and limitations are in `docs/PERFORMANCE.md`. CPU cost was not isolated, so the prior "<1 % typical, <5 % always" wording was not supported by that dataset. The inner-crypto hot path also inherited BaseFWX 3.6.4 performance work; see `../../basefwx/RELEASE-NOTES-3.6.4.md`.
- **Compatibility policy for the 1.x line**: authorised-key files (`--auth-keys`), anonym CA / sub-key files, and the `yume-obfs-v2` token format carry forward unchanged. The BaseFWX inner format is byte-compatible across the 3.6.x and 3.7.x lines for non-plugin-tagged blobs per BaseFWX's own compatibility policy.
- **License**: AGPL-3.0-or-later across YUME binaries, source, and libyume. Bundled BaseFWX code follows its own split policy: LGPL library/API/runtime, GPL standalone tools, MIT OR Apache-2.0 example plugin templates. See `LICENSE`.
