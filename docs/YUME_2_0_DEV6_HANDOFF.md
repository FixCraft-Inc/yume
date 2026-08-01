# YUME 2.0-dev6 Chrome 151 handoff

Status: local development checkpoint, not release-qualified and not pushed.

Verified checkout date: 2026-08-01. Always refresh the Git state and rerun the
relevant gates before relying on the hashes or measurements in this document.

## Plain verdict

YUME is materially closer to competing with Xray/VLESS/REALITY, but it is not
yet a production replacement for them.

The current vertical slice has a strong cryptographic design, competitive
same-host throughput, a coherent Chrome 151 + Node 24 cover identity, and a
five-flow structural TLS first-flight parity result. It still lacks independent
security review, field classifier evidence, the complete helper failure matrix,
a sustained dev6 soak, high-RTT/loss measurements, broad client-platform
support, and Xray's mature routing, metrics, control, and deployment ecosystem.

Do not describe dev6 as indistinguishable from Chrome, immune to DPI,
quantum-proof, audited, production-scale, or ready to replace Xray. The accurate
description is: an evidence-backed Linux desktop vertical slice with promising
local security, speed, and first-flight camouflage.

## Git checkpoint

The local branch is `yume-2-dev6-chrome151`. It intentionally has no upstream
and must remain unpushed until review.

| Commit | Signed subject |
| --- | --- |
| `9b6f53f7aff908011fcabe65ef66e7284a5035c8` | `Rebaseline YUME 2.0 on Chrome 151` |
| `c9e509e53947b54d325261cdaefe18e4f0a0cfcc` | `Add the Chrome-shaped TLS client backend` |
| `716f86ef2187edd3f1763bc399b123820f2cc964` | `Bind the dev6 transport profile` |

All three commits were signed by EdDSA key
`967278FF6FA436F504CBB0058A1588B5E2598DB1`. Their base is the signed, pushed
dev5 checkpoint `119b728a95b5a88b5508b45e17ef2e4fe49b51e1` on both `main` and
`origin/main`. Never force-push this work.

Useful inspection commands:

```sh
git status --short --branch
git log --show-signature --format='%H %G? %s' 119b728..HEAD
git diff --stat 119b728..HEAD
git diff --binary 119b728..HEAD
```

## What changed

### One evidence-backed cover identity

- The exact transport version is `2.0-dev6`.
- The only admitted transport profile is `chrome151-node24-v1`.
- Five independent normal Google Chrome `151.0.7922.71` profiles on Debian 13
  were captured against official Node `24.18.0`.
- The Chrome launcher SHA-256 is
  `aea09d69ce7f24d5901f6bfb15dd44d0c856e793e0a498f8d8393ec7d2c308ec`;
  the Chrome binary SHA-256 is
  `4cf210c4a0aeee3e69a73639260918a7448626d6b99892ec61e20750bc7c7079`.
- The official Node archive SHA-256 is
  `55aa7153f9d88f28d765fcdad5ae6945b5c0f98a36881703817e4c450fa76742`.
- The fixture covers TLS/H2, document and asset order, RFC 8441, WebSocket
  controls and fragmentation, one MiB in each direction, flow-control
  recovery, 42 seconds idle, and graceful close.
- Incomplete Firefox, Safari, rotation, and mixed-OS identity claims were
  removed. One coherent identity is safer than several invented identities.

The authoritative evidence is under `tests/fixtures/chrome151-node24/`.

### Chrome-shaped client TLS backend

- A pinned uTLS `v1.8.2` helper is built with exact Go `1.26.5`, module
  checksums, `-trimpath`, no runtime downloads, and no Go build ID.
- The reproducible helper SHA-256 is
  `1a2ae7a9fcd9bb0ee5c8094a58c4c2865787231469b9afabb10746fca10489d5`.
- The helper identity is `yume-chrome151-utls-v1.8.2-ipc-v1`.
- The C++ parent establishes direct or SOCKS/Tor-routed TCP and passes the
  connected descriptor to one helper process per connection over an anonymous
  Unix socketpair.
- The helper requires TLS 1.3 and `h2`, validates hostname/CA/leaf pin, returns
  authenticated certificate metadata and the exact 32-byte TLS exporter, then
  proxies plaintext using bounded buffers and deadlines.
- The child runs with `no_new_privs`, unrelated descriptors closed, strict IPC
  lengths, and parent-owned termination/reaping. Exporter material is wiped
  after ratchet establishment.
- Client consumers now use one internal stream interface for asynchronous I/O,
  close/cancel, ALPN, certificate metadata, and exporter access.
- `chrome151` is Linux-desktop-only and supports exactly one outer tunnel.
  Unsupported requests fail explicitly.
- There is no silent fallback. `openssl-diagnostic` remains the default while
  failure-lifecycle and sustained-soak gates are incomplete, and it prints a
  visible warning that it is not Chrome ClientHello parity.

Five complete authenticated helper flows passed the normalized Chrome
ClientHello and direct-Node ServerHello structural gate. The comparator keeps
ordered ciphers, extensions, groups, signatures, versions, ALPN, key-share
geometry, padding, and record lengths; it normalizes only documented entropy
and GREASE. JA3/JA4/JA4S are summaries, not the acceptance oracle.

### Incompatible authenticated dev6 profile

- AUTH uses canonical schema 3. Schema 2/dev5, missing profiles, stale
  profiles, and helper protocol mismatches fail closed.
- `chrome151-node24-v1` is bound into admission, AUTH challenge/response/
  confirmation, the Ed25519 signature input, establishment derivation, and
  protected-frame AAD.
- The new signature domain is `yume/2.0/auth-signature/v3`.
- The new initial-root label is `yume/2.0/root/v3`.
- The new AEAD AAD domain is `yume/2.0/aad/v2`.
- There is no dev5 compatibility or downgrade path.
- ML-KEM-1024, X25519, high-entropy PSK, TLS-exporter binding, AES-256-GCM
  one-use message keys, authenticated security-mode negotiation, and
  independent fail-closed receiver limits remain mandatory.

These labels and schema numbers are wire-contract security boundaries. Any
future semantic change must bump the applicable version/domain and update the
KATs and wire documentation; never reinterpret an old label.

### Bulk stability correction

SOCKS, local-forward, and reverse-forward TCP readers now wait for the previous
transport write to complete before reading the next 64 KiB block. This applies
backpressure to fast local producers instead of overflowing the bounded
application queue and disconnecting a valid bulk transfer. The self-test also
suppresses `SIGPIPE`, unblocks and joins its reader during failure, and reports
the underlying transport error instead of aborting through a joinable thread.

## Current measured evidence

| Area | Result | Boundary of the claim |
| --- | --- | --- |
| TLS first flights | Five helper flows: `PARITY`; five middle-extension orders and measured GREASE-ECH lengths | Structural local gate; still needs fresh same-session Chrome NetLog plus wire recapture and external classifier work |
| Helper handshakes | 10 ms median versus 1 ms OpenSSL, +9 ms | Local loopback only; passes the <=10 ms gate |
| Helper bulk | 1,793.8 Mbit/s versus 1,780.6 Mbit/s OpenSSL, +0.74% | Three matched 256 MiB up + 256 MiB down, 16-stream loopback trials; passes the 5% gate |
| Full quick SOCKS flow | 121.60 MiB/s, 1,020.05 Mbit/s | Fresh 32 MiB bidirectional local regression smoke, not a release benchmark |
| Server concurrency | 100/100 same-host authenticated clients; 10.98 Gbit/s window | Full ML-KEM/X25519/ratchet locally; not idle scale or physical WAN |
| Tuned server workers | 16 workers: 10.95 Gbit/s, 13.21 average cores, 161.35 MiB peak RSS | One 50-client workload on one hybrid-CPU host |

The detailed historical evidence and exclusions remain in
`docs/YUME_2_0_IMPLEMENTATION_STATUS.md` and
`docs/YUME_2_0_WAN_BEHAVIOR.md`.

## Session-close validation

The final documentation-only checkpoint was closed on 2026-08-01 with:

- native CTest: 55/55 passed;
- ASan/UBSan CTest with leak detection and halt-on-error: 55/55 passed;
- Chrome evidence manifest: `PARITY`, five runs, stable identity SHA-256
  `6db68ff7048300867ee28736c27ac3cc5f009dffe0edd0979fabc355bbc5f56f`;
- helper TLS profile: `PARITY`, five runs, five middle-extension orders, and
  GREASE-ECH lengths 186, 218, and 282 bytes;
- `git diff --check`: passed.

These reruns validate the current local artifacts and documentation integration.
They do not replace the missing live failure, WAN, classifier, or soak gates.

## Competitive position

### Security

The construction is deliberately conservative: hybrid ML-KEM-1024 + X25519,
an independent random PSK, live TLS-exporter channel binding, Ed25519 client
authorization, one-use AES-GCM message keys, authenticated profile/policy
negotiation, and fail-closed bounds. This is a credible design advantage.

It is not evidence that YUME is safer than Xray. YUME has no independent audit,
far less deployment exposure, and incomplete adversarial lifecycle coverage.
Xray's current VLESS documentation also includes a post-quantum
ML-KEM-768 + X25519 encryption mode. Primitive checklists do not replace review
or operational experience.

### Speed

YUME passes its local helper-overhead gate and can saturate a gigabit local
path. The remaining bottleneck is not basic crypto speed. XTLS Vision is built
around direct handling of encrypted TLS data, while Xray offers several mature
transport choices. YUME needs matched high-RTT, loss, long-flow, reconnect, and
many-client results before claiming performance parity.

### Stealth

YUME now emits an evidence-backed Chrome 151 first flight and serves a genuine,
bounded Node 24 cover to ordinary probes. Rejected admission stays on that
cover and is never forwarded to an unrelated public target. That bounded-cover
choice avoids the abuseable unauthenticated-forwarding risk called out by the
REALITY documentation.

Full-flow stealth is still unproven. Record-size/timing distributions, active
probing, malformed requests, long idle/reconnect behavior, and real-network
captures must be compared repeatedly. Do not add arbitrary padding or jitter;
add shaping only when repeated classifier evidence improves within a measured
overhead budget.

### Scale and operations

YUME has bounded session and bulk-key capacity, immutable authorization-policy
snapshots, configurable worker counts, and weighted egress. It does not yet
match Xray's routing/balancing, dynamic API, statistics/metrics, observatories,
transport breadth, platform/client ecosystem, or production history. The
Chrome helper is currently one Linux child per connection, which needs explicit
process/fd/RSS scale evidence before it can be called server- or client-scale.

Official comparison references:

- <https://xtls.github.io/en/config/inbounds/vless.html>
- <https://xtls.github.io/en/config/transports/reality.html>
- <https://xtls.github.io/en/config/transport.html>
- <https://xtls.github.io/en/config/routing.html>
- <https://xtls.github.io/en/config/api.html>
- <https://xtls.github.io/en/config/stats.html>

## Ordered work for the next agent

1. **Re-derive current state.** Verify the branch, signed commits, clean
   BaseFWX boundary, helper hash, exact Chrome/Node manifest, and absence of an
   upstream. Do not trust an old private handoff over the live checkout.
2. **Finish the helper negative matrix.** Cover wrong CA, hostname, leaf pin,
   ALPN, exporter, profile, helper identity and IPC version; child crash/hang;
   malformed/truncated/oversized IPC; partial I/O; cancellation and deadlines;
   parent/child half-close; descriptor leaks; and termination/reaping. Exercise
   these under ASan/UBSan where applicable.
3. **Measure process scalability.** Run bounded 1/10/50/100/256 connection
   ramps and repeated reconnect storms. Record helper PIDs, unreaped children,
   open fds, threads, CPU, RSS, handshake percentiles, errors, and recovery.
   Decide from evidence whether one helper per connection remains acceptable or
   requires a safe bounded helper service/pool protocol.
4. **Run the sustained gate.** Perform the 30-minute bidirectional dev6 soak
   across many epochs plus at least 1,000 sequential reconnects. Require no
   queue growth, descriptor/child leak, stale key/window retention, timeout, or
   byte mismatch.
5. **Produce same-session stealth evidence.** Capture five fresh normal-Chrome
   and five YUME flows under identical certificate/SNI/ALPN/server conditions,
   including privileged raw packets where available. Compare TLS records, H2,
   request/asset sequence, WebSocket controls, bulk, idle, close, and timing
   distributions. Add external classifier and active-probe tests. Keep verdicts
   `PARITY`, `KNOWN_GAP`, or `DRIFT`.
6. **Run the WAN matrix.** Use matched Release binaries at 60/100/210 ms RTT,
   100 Mbit/s and approximately 1 Gbit/s, then 0.1% and 1% loss. Measure upload,
   download, bidirectional flows, reconnect, rekey wait/depth, H2/TCP stalls,
   retransmits, CPU, RSS, and binary hashes. Diagnose the recorded ~25 Mbit/s
   WAN ceiling before changing crypto limits.
7. **Harden operations.** Add useful health/metrics without exporting secrets or
   a stable wire marker; test graceful shutdown/reload, systemd/cgroup limits,
   disk/log pressure, per-key fairness, backend failure, and Debian installed
   helper discovery/ownership/permissions.
8. **Expand clients honestly.** Design Android and other-platform TLS backends
   separately; the Linux helper is not portable evidence. Keep unsupported
   platforms and multi-tunnel configurations explicit failures until each has
   its own profile and gates.
9. **Switch the default only after evidence.** Make `chrome151` the default and
   retain `openssl-diagnostic` only after all certificate/exporter/lifecycle,
   install-layout, performance, and soak gates pass. Never silently fall back.
10. **Seek independent review.** Commission cryptographic/protocol review and
    adversarial deployment testing before `2.0-rc1`; treat findings as release
    blockers, not documentation exceptions.

BoringSSL is not the next automatic step. The uTLS implementation already
passes the current first-flight, exporter, handshake-overhead, and local bulk
gates. Revisit BoringSSL only if uTLS fails a remaining security, lifecycle,
packaging, or field-classification gate.

## Validation entry points

```sh
ctest --test-dir build-final-review --output-on-failure -j2
ctest --test-dir build-asan-audit --output-on-failure -j1

python3 scripts/yume_chrome_evidence.py \
  --fixture tests/fixtures/chrome151-node24

python3 scripts/yume_tls_wire.py check-profile \
  --profile tests/fixtures/chrome151-node24/chrome_tls_wire_profile.json \
  --candidate tests/fixtures/chrome151-node24/helper_tls_wire_run_1.json \
  --candidate tests/fixtures/chrome151-node24/helper_tls_wire_run_2.json \
  --candidate tests/fixtures/chrome151-node24/helper_tls_wire_run_3.json \
  --candidate tests/fixtures/chrome151-node24/helper_tls_wire_run_4.json \
  --candidate tests/fixtures/chrome151-node24/helper_tls_wire_run_5.json

git diff --check
```

Build directories and generated benchmark artifacts are local evidence, not
source-of-truth. If they are absent or stale, rebuild rather than weakening a
gate. Preserve the separate BaseFWX and Android repositories and do not clean,
commit, or synchronize their user-owned changes from this branch.
