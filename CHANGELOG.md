# Changelog

## [Unreleased]

## [v1.0] - 2026-05-16

Compare: <https://github.com/FixCraft-Inc/yume/commits/v1.0> (initial release)

### Added
- **First stable release** of YUME (Yume Universal Multiprotocol Engine) — an open-source post-quantum stealth transport that tunnels TCP and UDP through real TLS 1.3 sessions shaped to look like ordinary Chrome HTTPS to a DPI box. Both the client (`yume`) and the daemon (`yumed`) are GPL-3.0-only and build from this tree.
- **Three-layer stealth stack** stacked on top of TLS 1.3, all on by default and toggleable independently:
  - Browser-cluster JA3 / JA4 fingerprint via genuine OpenSSL 3.5 `ClientHello` shaping. `--profile chrome` (Chrome 135) is the default; `--profile firefox` (Firefox 126) and `--profile safari` (Safari 17) are selectable, plus per-N-connection rotation via `--tls-stealth-rotate` / `--tls-stealth-rotation-interval`.
  - HTTP/2 carrier handshake (`--obfs`) with Chrome-shaped `SETTINGS`, `WINDOW_UPDATE`, and a `HEADERS` frame opening a `POST` to `/<token>/<nonce>`. The token is `HMAC-SHA256(K, sni || hour_epoch || "yume-obfs-v2")` truncated to 16 bytes hex with optional peer-pinning via `--obfs-secret`; the server accepts ±1 hour of clock skew.
  - Real HTML facade (`--real`) so a browser hitting the same `:443` with `GET / HTTP/1.1` is served a real HTML page (or a Wikipedia redirect by default). YUME and a normal website coexist on a single port.
- **Hybrid post-quantum inner crypto** via BaseFWX 3.6.4 (separate library, pinned via `.basefwx-ref`):
  - **ML-KEM-768** (NIST FIPS 203 / Kyber-768) hybrid wrap for session keys when a master public key is configured.
  - **AES-256-GCM** AEAD with a 12-byte nonce and 16-byte tag.
  - Hardened **Argon2id** (default `4 / 2¹⁶`) or **PBKDF2-HMAC-SHA256** (default 600 000 iters) for password-based key derivation.
  - **HKDF-SHA256** for all subkey derivation.
  - **Ed25519** for client authentication via `--auth` / `--auth-keys`.
- **Live key hopping** at 1–4 Hz (`--hop-interval`, default ~500 ms). Each window encrypts with a fresh `HKDF(master, hop_index || direction)` derivative; compromise of one window's key recovers only that window. Disable for latency-sensitive paths with `--no-hop`.
- **Five routing modes**, combinable:
  - `--socks <port>` — SOCKS5 listener on the client side.
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
- Project documentation: `README.md`, `docs/QUICKSTART.md`, `docs/STEALTH.md`, `docs/EXPLAINED.md` (protocol internals + routing diagrams for federation, Tor egress, Tor-over-YUME, YUME-Tor-YUME, Android), `docs/PERFORMANCE.md`, `docs/OPERATIONS.md`, `docs/PACKAGING.md`, `docs/PERMISSIONS.md`, `RELEASE-NOTES-1.0.md`, and the project website at <https://yume.fixcraft.jp>.

### Changed
- Wire format, authentication key file format, anonym CA / sub-key file format, and the `yume-obfs-v2` HTTP/2 token format are declared **stable** as of 1.0. Subsequent 1.x releases will keep on-the-wire compatibility.
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
- **Performance**: steady-state CPU overhead is <1 % typical and <5 % always on the SOCKS path; full methodology and per-link numbers in `docs/PERFORMANCE.md`. The inner-crypto hot path benefits from BaseFWX 3.6.4's perf work (overall test suite −55 % to −60 % faster at constant security strength vs 3.6.3; see `basefwx/RELEASE-NOTES-3.6.4.md`).
- **Compatibility policy for the 1.x line**: authorised-key files (`--auth-keys`), anonym CA / sub-key files, and the `yume-obfs-v2` token format carry forward unchanged. The BaseFWX inner format is byte-compatible across the 3.6.x line per BaseFWX's own compatibility policy.
- **License**: GPL-3.0-only across all yume binaries, source, and bundled BaseFWX inner crypto. See `LICENCE`.
