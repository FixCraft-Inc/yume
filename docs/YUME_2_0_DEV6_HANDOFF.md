# YUME 2.0-dev6 Chrome 151 handoff

Status: integrated development checkpoint on `main`; Gate B and release
qualification remain incomplete.

The authoritative merge/RC/stable checklist and branch policy are now in
`docs/YUME_2_0_STABILIZATION.md`. In particular, merging reviewed dev6 into
`main` and calling a Linux build stable 2.0 are separate milestones.

Verified checkout date: 2026-08-14. Always refresh the Git state and rerun the
relevant gates before relying on the hashes or measurements in this document.

## Current integrated checkpoint (2026-08-14)

### Gate A closure and first Gate B campaign outcome

Gate A is closed for continued development and remains `NO RELEASE` at signed
commit `e4786e049fea7b786148e55b806e37fea401741e`, tree
`81c6012cb77303260528d24b4b63b395ba9ca415`. CI, Pages, branch sync, dynamic
CodeQL/Code Quality, and static CodeQL `31777856725` passed. Local and
`origin/main` agree, workflow-owned `DEV` has tracked-content parity, and the
remote contains only `main` and `DEV`. No PR was opened and `DEV` was not
pushed directly.

The earlier clean exact-commit Gate B preparation, formerly at the now-cleaned
`/home/f1xgod/yume-gateb-artifacts-815ea40-tRn2xi`, passed Release 61/61,
pinned Go unit/race tests, strict Argon2/OQS/LZMA and warnings-as-errors,
Debian/42-symbol ABI and installed-layout checks, private-artifact audit, two
reproducible helper builds, Linux artifact preparation, exact preflight, and
transfer round trip. The helper, build-tree `yume`, build-tree and standalone
`yumed`, prepared package, and transfer hashes are respectively
`f0e2cf15f9f0f1984cf7b105ce6837537074d8b8b3d84343b37d47a9ec84f269`,
`5a4e4366549d085c45a64f664702615aa60048137bd4e63636e10a73777a1049`,
`a712fe606343f68f61d43cac57409d30e250cbfab7d9ecd7ac6914fe096b6254`,
`7d1fb5c888632ad38ee80c17217c88608d918acc33cbdebd1eec4ed070fc9112`,
and `f53406d780329d94610d678391ccf97b4e0bcbb37d868c29702fda5273e483e3`.
This qualifies exact capture inputs only.

The first five-normal/five-YUME same-session campaign exited `1` during normal
run 3. Normal runs 1 and 2 completed and sealed; run 3 is partial, and neither
the YUME arm nor the matched validator ran. The evidence identifies a capture-
driver race: `Page.navigate` was followed immediately by an awaited evaluation
that could remain bound to the old `about:blank` execution context. A separate
read-only review also found that the runner started the TLS relay without first
confirming the Node listener. This is a harness failure, not `DRIFT` and not a
YUME runtime, wire, crypto, or prepared-artifact failure. The failed root was
kept until that diagnosis and its sanitized facts were recorded, then removed
under the operator's explicit artifact-cleanup instruction. It cannot be
resumed or counted.

The corrective checkpoint containing this section enables lifecycle events
before exactly one navigation, requires the matching frame/loader `load`, then
polls only synchronous state until the exact fixture URL and readiness marker
are present. CDP commands, DevTools HTTP requests, and socket open/close are
bounded. The normal runner passively waits for the exact loopback Node listener
before starting its relay. The behavioral Node tests are part of both
`npm test` and CTest. Focused navigation/package tests, both registered Node
CTests, browser-sandbox 38/38, the remaining capture/classifier tests,
generator/dependency/Chrome evidence, exact release preflight, syntax, and diff
hygiene pass locally. Those mocked tests did not exercise a real CDP session or
its new fixed command deadline, a gap exposed by the latest campaign below.
None of the partial predecessor runs may be reused.

Gate B therefore remains open. External classifier/active-probe work, matched
WAN/loss matrices, and deployed-network soak remain blocked on an accepted
fresh same-session matched-input report.

Signed correction `4a9c24d8204d7acf97a1bdbaf344ef1aa412572f` passed a
fresh exact-commit preparation: Release CTests 63/63, pinned Go unit/race,
tracked private-artifact audit, reproducible helpers, exact package preflight,
and transfer round trip. Its CI build and sanitizer jobs compiled successfully
and passed 65/66 tests, including both new Node regressions, but their shared
browser-sandbox test failed before its intended Chrome-exit assertion because
that isolated fixture supplied a fake `ss` and omitted the `rg` used by the new
passive-listener wait. CodeQL passed. The checkpoint containing this paragraph
adds only the missing test-local `rg` shim; it does not change a production
runner, Chrome behavior, YUME binary, helper, wire, crypto, or default. The
focused browser suite passes 38/38 locally. Signed checkpoint `e4786e0`, its
automatic read-back, and a fresh exact-commit preparation then passed. The
retained exact root
`/home/f1xgod/yume-gateb-artifacts-e4786e0-mg9N7f` passed Release 63/63,
pinned Go 1.26.5 unit/race, tracked-private audit over 625 paths, two identical
helpers, exact package preflight, and transfer round trip; every retained
evidence checksum verifies.

The new five-plus-five campaign nevertheless failed closed during normal
Chrome run 1, before any completed normal arm, YUME arm, or matched-input
report. Preflight, private-kit creation, and Xvfb passed; exact Chrome DevTools,
Node, and the passive relay announced ready, but `Page.navigate` did not answer
within its new 15-second command deadline. The result is `FAIL`, not `DRIFT`,
with `MATCHED_INPUT_VERDICT/EXIT=not-run`. A bounded fresh-profile canary using
the same exact Chrome and Node reproduced the timeout with Chrome connected
directly to Node and no TLS-wire relay, excluding the relay and all YUME
client/server/helper paths. No resource limit fired and no child, listener, or
display residue remained. Raw NetLogs and private kits from both failed
campaigns were deleted during the approved cleanup after their sanitized facts
were recorded; they are not recoverable evidence.

Before another full campaign, the real CDP boundary needs a reviewed,
deterministic stalled/late-response test, bounded payload-free navigation-event
diagnostics, and one isolated exact-Chrome canary. A source correction then
requires new exact artifacts and a completely fresh five-plus-five root.

The architecture chronology below remains retained evidence.

The live outer-carrier architecture is integrated as signed commit
`1593fc62de89d613e107f1e173adf3edb7ed7568`, tree
`eeead05b222cbd46137828b8ce5c3b089889dc04`, subject `Add live outer carrier
evidence capture`. Its verified EdDSA fingerprint is
`967278FF6FA436F504CBB0058A1588B5E2598DB1`. The checkpoint adds an opt-in,
payload-free observer on the production nghttp2/WebSocket
carrier plus an exclusive mode-0600 evidence writer. The exact capture mode is
restricted to one direct `chrome151-node24-v1` tunnel, the pinned `chrome151`
backend, disabled optional padding/jitter, and a one-shot exact 64-by-16-KiB
application echo transaction followed by a completed 42-second quiet interval
and bounded graceful close. Actual SETTINGS, WINDOW_UPDATE,
HEADERS/CONTINUATION metadata, WebSocket geometry/control frames, actual
peer-window stalls/recovery, opaque-correlated H2 PING/ACK, and terminal state
are reconstructed into `behavior.json`; payloads,
carrier paths, credentials, peer addresses, TLS secrets, and PING opaque bytes
are never written to evidence. The classifier rejects incomplete, placeholder,
malformed, or aggregate-inconsistent live event streams and compares ordered
request/WebSocket lifecycle, including Chrome's stream-9 favicon request and
the server-PING/first-fragment relationship. The unchanged production carrier
can therefore return `DRIFT` for its absent favicon stream, early server PING,
authenticated framing, or ratchet overhead; capture mode does not alter those
wire behaviors to force a match.

The architecture checkpoint has an explicit read-only code/security
`GO / MERGE` after three high findings were repaired: ordinary production PING
and CLOSE wire behavior was restored, passive lifecycle was added to the
classifier projection, and executable hash gates now precede version probes.
The complete local native suite passed 66/66, and the freshly reconfigured
serial ASan+UBSan suite passed 66/66 with leak detection and halt/abort-on-error.
The combined provenance/manifest/finalizer/classifier/sandbox suite passed
95/95; pinned offline Go 1.26.5 unit and race tests, five-flow fixture/TLS
evidence checks, generator/dependency verification, source release preflight,
Debian source creation, installed/42-symbol ABI checks, six workflow YAML
files, shell/Python syntax, diff hygiene, and the tracked private-artifact audit
also passed. Those local CMake caches use warnings-as-errors and strict Argon2,
but strict OQS/LZMA requirements are off.

Two independent exact Go 1.26.5 helper rebuilds and the configured helper are
identical at
`f0e2cf15f9f0f1984cf7b105ce6837537074d8b8b3d84343b37d47a9ec84f269`.
The fresh `raptorlake` checkout of that exact commit and pinned BaseFWX
`4692d4ce4edec2aa9835d04ad9ff6c3ad3ab9374` then passed strict native 66/66,
serial ASan+UBSan 66/66, Release/LTO 61/61, pinned Go unit/race, the same 95
focused evidence tests, Debian/42-symbol ABI, tracked private-artifact audit,
two clean helper builds, Linux artifact preparation, exact release preflight,
and artifact-transfer round trip. Every retained evidence log passed its
SHA-256 check. The prepared bundle, standalone server, and transfer hashes are
respectively `c3049ab89f1e254f6b94aa096d9ab18e58fdc9e82ccf20e087d80ef2945b2bb8`,
`7af87fc556a86339e84dde435d35f629fa801f57087a697b0c67c25bd0de3d6c`,
and `abb637b23ef03b10cd58c628ea5641a16a586dfc5ca525d5cf0ae64f7203816f`.

The first GitHub CI run for `1593fc62` built both native and sanitizer lanes but
failed their shared browser-sandbox test before its intended hash assertion
because the minimal runner lacked `ss` or `rg`. The current test supplies inert
temporary shims for those later-stage prerequisites. It changes no production
runner, and an independent read-only review returned `MERGE`; complete local
native and serial sanitizer registrations pass with the correction. CodeQL,
Code Quality, branch sync, and Pages passed for the architecture commit. The
corrective checkpoint's CI and branch-sync read-back remains a final automation
check, not evidence of a wire, crypto, release-artifact, or runtime failure.

This integrated development checkpoint implements the missing YUME
behavior-input capability; it does not claim
that a real five-run matched normal/YUME campaign, external classification,
active probing, WAN/loss qualification, or deployed soak has run.

### Matched-input baseline

The matched-input baseline integrated into `main` is signed commit
`656d6851cedb5e3f21ac9a04537214a2960df135`, tree
`cd82add238d4cf7ef46704ee182d3543eb111cbc`, subject
`Seal matched capture evidence inputs`. Its parent is the signed classifier
input-contract commit `21a262f456c784726fd2970311508715a71c7960`.
Both signatures verify with EdDSA fingerprint
`967278FF6FA436F504CBB0058A1588B5E2598DB1`. No PR or temporary branch was
created; only `main` was pushed and workflow sync continues to own `DEV`.

The latest checkpoint gives the direct normal-Chrome capture target and
classifier-input validator one frozen workload, exact runtime/source/session
bindings, portable relative checksums, and a completion marker written only
after all declared runs verify. Failed, partial, relabeled, symlinked, FIFO,
oversized, or tampered evidence fails closed. The installed production HTTP/1
cover backend remains a separate bounded GET/HEAD site; this checkpoint does
not expose ordinary public WebSocket CONNECT or claim live outer-carrier
parity.

The scoped read-only code/security diff reviewer returned `MERGE`; that review
is not the still-missing independent cryptographic, protocol, deployment, and
adversarial release audit. The full configured native suite passed 63/63
locally, affected serial ASan+UBSan CTests passed 7/7, and focused
manifest/finalizer/classifier/sandbox/setup/metadata/Node tests passed. A later
full local sanitizer rebuild was interrupted and is not claimed as a pass for
this exact commit. A fresh exact-commit remote checkout independently
reverified the pinned Chrome/Node hashes and focused suites. Its bounded
native/sanitizer build lane must be read from the private operational handoff
before using that result. The automatic CI/CodeQL and `DEV` sync from the
latest push must also be read back before claiming branch parity.

Gate B remains open. No real matched normal/YUME five-run capture, accepted
external classifier or active-probe campaign,
matched WAN/loss matrix, uninterrupted deployed-network soak, default switch,
version bump, tag, publication, RC, release, or stable-2.0 claim is established
by this checkpoint.

## Plain verdict

YUME is materially closer to competing with Xray/VLESS/REALITY, but it is not
yet a production replacement for them.

The current vertical slice has a strong cryptographic design, competitive
same-host throughput, a coherent Chrome 151 + Node 24 cover identity, and a
five-flow structural TLS first-flight parity result. Its bounded helper failure
matrix, process ramps, reconnect storm, and segmented full-speed soak now pass.
It still lacks independent security review, field classifier evidence, matched
high-RTT/loss measurements, broad client-platform support, and Xray's mature
routing, metrics, control, and deployment ecosystem.

Do not describe dev6 as indistinguishable from Chrome, immune to DPI,
quantum-proof, audited, production-scale, or ready to replace Xray. The accurate
description is: an evidence-backed Linux desktop vertical slice with promising
local security, speed, and first-flight camouflage.

## Historical pre-integration Git checkpoint (2026-08-11)

At that earlier checkpoint the local branch was `yume-2-dev6-chrome151`, had no
upstream, and correctly remained unpushed until review. The current integrated
state above supersedes this retained chronology.

| Commit | Signed subject |
| --- | --- |
| `9b6f53f7aff908011fcabe65ef66e7284a5035c8` | `Rebaseline YUME 2.0 on Chrome 151` |
| `c9e509e53947b54d325261cdaefe18e4f0a0cfcc` | `Add the Chrome-shaped TLS client backend` |
| `716f86ef2187edd3f1763bc399b123820f2cc964` | `Bind the dev6 transport profile` |

All three commits were signed by EdDSA key
`967278FF6FA436F504CBB0058A1588B5E2598DB1`. Their base is the signed, pushed
dev5 checkpoint `119b728a95b5a88b5508b45e17ef2e4fe49b51e1` on both `main` and
`origin/main`. Never force-push this work.

Later signed local closure commits document this handoff, harden the benchmark
workflow, and close the helper lifecycle. The lifecycle checkpoint is exact
commit `30cad6e23b651a6c68ba8036299e863c59b9ab54`, subject `Harden Chrome helper
failure lifecycle`. The second documentation checkpoint has subject `Record
dev6 qualification evidence`. Use the signed `git log` command below for all
exact hashes; this document deliberately does not embed the hash of the commit
containing itself.

Useful inspection commands:

```sh
git status --short --branch
git log --show-signature --format='%H %G? %s' 119b728..HEAD
git diff --stat 119b728..HEAD
git diff --binary 119b728..HEAD
```

### Historical post-checkpoint architecture candidate (2026-08-11)

The working tree after signed checkpoint `a673d3e058656ee86ebd68be742f1192cd0cbe95`
was intentionally dirty with a reviewed modularization slice. This retained
section is chronology only: later signed `main` commits integrated and
superseded it. Do not use its old remote overlay as current provenance. The
candidate added
`config/transport_profiles.json` plus validated generated immutable C++ and Go
registries, routes production TLS/HTTP/H2 consumers through
`cover_profile::active()`, and makes the helper choose an audited ClientHello
provider by the explicitly requested helper build identity. Each profile entry
names its own manifest, HTTP/2 profile, TLS acceptance profile, and candidate
artifacts; shared generator, CMake, test, install, and release logic no longer
assume Chrome-specific fixture filenames.

BaseFWX repository, exact revision, and minimum version are likewise
centralized in `config/dependencies.json`. CMake, build scripts, CI, CodeQL, and
release preflight consume that one fail-closed manifest; BaseFWX remains pinned
and is not allowed to float to a branch. See `docs/TRANSPORT_PROFILES.md` for
the extension and evidence contract.

The same manifest records the official OpenSSL source revision used by the
checksum-pinned CI fallback. Full builds require OpenSSL >= 3.5 because
composite AUTH uses ML-DSA-87 and the qualified native profile uses
X25519MLKEM768; older libraries are rejected during CMake configuration rather
than producing a binary that fails only at first use. CI, CodeQL, and release
builds force the supported OpenSSL 3.5.7 source pin, while native Linux
development may use a system OpenSSL >= 3.5 with the required provider.
The prepared Linux release lane separately pins and checksum-verifies liboqs
0.16.0 and links its archive statically so artifacts have no `liboqs.so`
runtime dependency or build-cache search path.

The candidate changes no authenticated profile ID, wire byte, IPC protocol,
AEAD/AAD label, KDF, algorithm, or default backend. Adding a registry entry is
not permission to accept it on the wire: a new authenticated ID still requires
a deliberate protocol revision, new evidence, KATs, documentation, and all
release gates.

Validation passed on the 32-core `raptorlake` host in the isolated non-secret
checkout `/home/f1xgod/yume-profile-build-t4CutW/repo`: 54/54 native tests and
54/54 serial ASan+UBSan tests, both with the Chrome helper enabled. Cache
inspection later established that `YUME_WARNINGS_AS_ERRORS`,
`BASEFWX_REQUIRE_OQS`, and `BASEFWX_REQUIRE_LZMA` were all `OFF`; the overlay is
therefore not strict release acceptance. Local seven-case negative metadata tests, release preflight, Debian
source/ABI consistency, Python compilation, pinned Go helper and race tests,
shell syntax, and `git diff --check` also pass. This is regression evidence for the candidate,
not new installed-Chrome, matched-WAN, stealth, or release qualification. The
temporary remote checkout remains available for review and contains no copied
`.private` evidence. It does contain an ignored `.secrets/` directory whose
contents were deliberately not inspected; the reviewed candidate must prove
that Debian source creation and validation exclude such roots.

The later Gate A integration converted that overlay into signed clean commits.
The present live-observer candidate is a separate change and must be validated
from its own fresh exact-commit checkout. The old overlay remains regression
evidence only.

### Gate A review fixes in the live dirty candidate (2026-08-12)

The read-only code/security review initially returned `NO-MERGE`. The primary
integrator resolved its concrete findings without changing the authenticated
profile, helper IPC version, wire format, crypto/AAD domains, or default
backend:

- the generated active profile must equal authenticated `kTransportProfile`;
- helper build IDs are unique, cross-checked against evidence, generated into
  Go, and ambiguous lookup fails closed;
- the generator rejects carrier metadata outside dev6's exact 1/3/5/7 stream
  and two-asset geometry;
- CLI/facade helper routing reads the active profile's backend metadata;
- pinned BaseFWX overrides require an exact lowercase 40-hex commit;
- the source-only registry is no longer installed with unusable fixture paths;
- the standalone server is hash/size/mode/version-bound into the release
  manifest, and CI transports prepared artifacts inside a tar so executable
  mode survives artifact upload/download;
- orig-tar creation, archive validation, and `dpkg-source` all exclude ignored
  `.private` and `.secrets` roots, with regression coverage.

Post-fix local regression evidence is 59/59 native CTests, 59/59 serial
ASan+UBSan CTests with leak detection and halt-on-error, 14 metadata/archive
tests, pinned Go 1.26.5 unit and race tests offline, all workflow YAML parsing,
release preflight, Debian source/42-symbol ABI consistency, and a clean
private-artifact diff audit. Both local CMake caches had warnings-as-errors ON
but strict OQS/LZMA requirements OFF, so this remains pre-commit regression
evidence—not Gate A release acceptance. Explicit commit authority, one signed
commit, and the strict fresh exact-commit remote build/artifact lane remain
mandatory.

### Historical exact Chrome staging (2026-08-12)

The exact normal Google Chrome package was downloaded without root and
extracted without installation on `raptorlake` under
`/home/f1xgod/yume-profile-build-t4CutW/chrome-151.0.7922.71/`.

- Package: `google-chrome-stable_151.0.7922.71-1_amd64.deb`
- Official package URL:
  `https://dl.google.com/linux/chrome/deb/pool/main/g/google-chrome-stable/google-chrome-stable_151.0.7922.71-1_amd64.deb`
- Package size: `139922812` bytes
- Package SHA-256:
  `c86cafc697ecdb88259312cef47e464d1278643610500a7c9104e6bb1af3ba5c`
- Extracted launcher SHA-256:
  `aea09d69ce7f24d5901f6bfb15dd44d0c856e793e0a498f8d8393ec7d2c308ec`
- Extracted Chrome binary SHA-256:
  `4cf210c4a0aeee3e69a73639260918a7448626d6b99892ec61e20750bc7c7079`
- Extracted binary output: `Google Chrome 151.0.7922.71`

Both extracted hashes exactly match the committed fixture manifest. The daily
installed browser was not changed. Reverify every hash before use, launch with
a fresh isolated user-data directory, and keep NetLogs/PCAPs private. Because
unprivileged extraction leaves `chrome-sandbox` owned by the extracting user,
use a container/VM with correct sandbox ownership or a separately validated
user-namespace sandbox. Never use `--no-sandbox` merely to make capture start. The
artifact makes same-session capture possible; it does not itself constitute a
new capture or parity result.

That historical local staging root is absent as of the 2026-08-13 live
checkout audit. Do not assume the path exists. A remote or re-staged copy may
be used only after rechecking the package, launcher, binary, version, and valid
sandbox against the values above; never substitute the installed browser or
add `--no-sandbox`.

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
- Historical August 10 strict builds produced helper SHA-256
  `6dbcda7e626f4c3bedce687a232fa7c2c02fe8649ecb7f0322497670093f9d36`.
  The current modularized source rebuilds reproducibly as
  `f0e2cf15f9f0f1984cf7b105ce6837537074d8b8b3d84343b37d47a9ec84f269`;
  the capture runner pins this current checkpoint. The immutable August 1 wire
  fixture retains its own historical artifact hash and is not rewritten.
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
  matched WAN, same-session stealth, independent-review, and remaining RC gates
  are incomplete, and it prints a visible warning that it is not Chrome
  ClientHello parity.

Five complete authenticated helper flows passed the normalized Chrome
ClientHello and direct-Node ServerHello structural gate. The comparator keeps
ordered ciphers, extensions, groups, signatures, versions, ALPN, key-share
geometry, padding, and record lengths; it normalizes only documented entropy
and GREASE. JA3/JA4/JA4S are summaries, not the acceptance oracle.

### Incompatible authenticated dev6 profile

- AUTH uses canonical schema 3. Schema 2/dev5, missing profiles, stale
  profiles, and helper protocol mismatches fail closed.
- `chrome151-node24-v1` is bound into admission, AUTH challenge/response/
  confirmation, the composite signature input, establishment derivation, and
  protected-frame AAD.
- The current signature domain is `yume/2.0/auth-signature/v4`.
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
| Helper process ramp | 256/256 clients and 256 helpers; 65,536 MiB exact; zero unexpected failures | Same-host process/fd/RSS gate; not physical-network concurrency |
| Sequential reconnect | 1,000/1,000; 2,000 MiB exact; p95 120.931 ms; no post-cleanup growth | Same-host reconnect lifecycle evidence, not WAN recovery |
| Full-speed soak | 225,280 MiB exact over 2,314.193 endpoint seconds; 816.607 Mbit/s aggregate | Seven back-to-back bounded segments; not one >16 GiB connection or WAN evidence |

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

These reruns validate the August 1 local artifacts and documentation
integration. The August 10/11 sections below supersede their helper-lifecycle,
process-scale, reconnect, and soak status; WAN, classifier, and independent
review gates remain open.

## Competitive position

### Security

The construction is deliberately conservative: hybrid ML-KEM-1024 + X25519,
an independent random PSK, live TLS-exporter channel binding, composite
Ed25519 + ML-DSA-87 client authorization, one-use AES-GCM message keys,
authenticated profile/policy negotiation, and fail-closed bounds. This is a
credible design advantage.

It is not evidence that YUME is safer than Xray. YUME has no independent audit,
far less deployment exposure, and incomplete adversarial deployment coverage.
Xray's current VLESS documentation also includes a post-quantum
ML-KEM-768 + X25519 encryption mode. Primitive checklists do not replace review
or operational experience.

### Speed

YUME passes its local helper-overhead gate and can saturate a gigabit local
path. The remaining bottleneck is not basic crypto speed. XTLS Vision is built
around direct handling of encrypted TLS data, while Xray offers several mature
transport choices. YUME now has same-host long-flow, reconnect, and many-client
results, but still needs matched high-RTT and loss measurements before claiming
performance parity.

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

## Recommended agent execution model

Use two roles under one strong root/integrator when two agent slots are
available. The root is the only source-editing owner; the lighter agent is a
benchmark operator and evidence recorder. Two autonomous coding agents sharing
one checkout are worse than one because they can invalidate baselines, race on
build outputs, and leave ambiguous ownership of wire/security decisions.

The safe order is:

1. Root verifies the live branch, selects one acceptance gate, and freezes the
   benchmark contract.
2. Benchmark agent runs the baseline from a clean pinned worktree/build tree,
   records source and binary hashes, preserves raw artifacts, and makes no
   source edits.
3. Root reviews evidence and implements the smallest justified change in a
   separate worktree/build tree.
4. Benchmark agent repeats the exact matched matrix against the candidate.
5. Root reviews the complete diff and artifacts, runs bounded native/sanitizer
   gates, updates documentation, and creates a signed local commit. Any future
   candidate stays unpushed until explicit review approval; development is
   never pushed directly to workflow-owned `DEV`.

Parallelize only independent work in isolated worktrees. If only one checkout
or benchmark host is available, run baseline, edit, and candidate benchmark
sequentially. Never benchmark a tree while another agent is rebuilding or
editing it.

A long benchmark must not consume an agent session merely waiting. The
benchmark agent should start a bounded supervised job, return the unit/PID,
exact command, source hash, artifact directory, and inspection commands, then
end its turn. Prefer a uniquely named `systemd-run --user` unit for
unprivileged jobs. Root-required netem runs belong in an explicit benchmark
terminal. On resumption, inspect `report.json` and logs before polling or
rerunning anything.

The local `.codex/skills/run-yume/` skill is the authoritative agent runbook.
It uses a two-job build default to avoid OOM, supports dev6 helper builds,
native/sanitizer tests, evidence checks, Chrome-through-SOCKS smoke, sampled
local benchmarks, and read-only host/driver inventory. The `.claude` driver is
a thin delegate to the same implementation so the runbooks cannot silently
diverge.

The matching benchmark refresh added an explicit recorded `--tls-backend` to
the virtual-WAN harness and replaced stale Chrome 150 checks in both LAN and
WAN with one manifest-derived exact Chrome `151.0.7922.71` matcher. Focused
validation passed eight Python tests, 55/55 native CTests, skill validation,
shell/Python syntax, both fixture evidence gates, a bounded local process
smoke, and an unprivileged Chrome-helper carrier smoke. The last smoke was a
`FUNCTIONAL PASS` with H2 selected; raw capture was disabled, so it adds no new
stealth claim.

Do not update a kernel, NIC driver/firmware, offload setting, congestion
control, or CPU governor in the middle of a comparison. Record it first.
Change it only for a reproducible fault or an explicitly isolated experiment,
then reboot when required and restart the complete baseline/candidate series.

## Remaining ordered work for the next agent

The bounded helper negative matrix, 1/10/50/100/256 ramps, 1,000 sequential
reconnects, and segmented 30-minute full-speed soak are complete as documented
below. Do not silently rerun or broaden them without freezing a new workload
and artifact location.

1. **Re-derive current state.** Verify the branch, signed commits, clean
   BaseFWX boundary, helper hash, exact Chrome/Node manifest, and absence of an
   upstream. Do not trust an old private handoff over the live checkout.
2. **Produce same-session stealth evidence.** Restore exact Chrome
   `151.0.7922.71`, then capture five fresh normal-Chrome
   and five YUME flows under identical certificate/SNI/ALPN/server conditions,
   including privileged raw packets where available. Compare TLS records, H2,
   request/asset sequence, WebSocket controls, bulk, idle, close, and timing
   distributions. Add external classifier and active-probe tests. Keep verdicts
   `PARITY`, `KNOWN_GAP`, or `DRIFT`.
3. **Run the WAN matrix.** Use matched Release binaries at 60/100/210 ms RTT,
   100 Mbit/s and approximately 1 Gbit/s, then 0.1% and 1% loss. Measure upload,
   download, bidirectional flows, reconnect, rekey wait/depth, H2/TCP stalls,
   retransmits, CPU, RSS, and binary hashes. Diagnose the recorded ~25 Mbit/s
   WAN ceiling before changing crypto limits.
4. **Harden operations.** Add useful health/metrics without exporting secrets or
   a stable wire marker; test graceful shutdown/reload, systemd/cgroup limits,
   disk/log pressure, per-key fairness, backend failure, and Debian installed
   helper discovery/ownership/permissions.
5. **Expand clients honestly.** Design Android and other-platform TLS backends
   separately; the Linux helper is not portable evidence. Keep unsupported
   platforms and multi-tunnel configurations explicit failures until each has
   its own profile and gates.
6. **Switch the default only after evidence.** Make `chrome151` the default and
   retain `openssl-diagnostic` only after all certificate/exporter/lifecycle,
   install-layout, performance, and soak gates pass. Never silently fall back.
7. **Seek independent review.** Commission cryptographic/protocol review and
    adversarial deployment testing before `2.0-rc1`; treat findings as release
    blockers, not documentation exceptions.

## 2026-08-10 helper lifecycle and Linux release closure

Ordered handoff item 2 is complete at the bounded unit/integration level. The
parent/helper tests cover every truncated IPC prefix, oversized payload
declaration before allocation, invalid magic/version/type, bounded fields and
error strings, partial control and plaintext I/O, wrong helper identity, ALPN,
connection ID and IPC version, explicit rejection, child crash/hang/timeout,
post-ready parent and child half-close, asynchronous cancellation, unsafe file
modes, symlinks, synchronous termination/reaping, 64 repeated child launches,
and parent fd balance. The Go tests are a first-class CTest gate.

The production Go wrapper still enforces Linux and `no_new_privs`, adopts only
connected TCP fd 3 and private IPC fd 4, and then calls an injectable
connection core. In-process real TLS tests cover success plus wrong CA,
hostname, leaf pin, ALPN, and an injected exporter failure. Only fixed bounded
errors cross IPC; verification details remain local. The exporter must be
exactly 32 bytes before a ready response is encoded.

This testing exposed a production lifecycle defect: after `posix_spawn`, the
parent retained duplicates of the child-side IPC and connected TCP descriptors.
A helper that crashed or returned a truncated response therefore could not
produce EOF/HUP at the parent and was reported only after the handshake timeout.
The parent now closes both duplicates immediately after a successful spawn;
spawn-failure cleanup remains RAII-managed. The launcher also obtains its IPC
connection ID through the approved BaseFWX RNG helper (with the existing YUME
crypto helper retained only for builds that explicitly disable BaseFWX), rather
than calling OpenSSL RNG directly.

Validation on 2026-08-10:

- RelWithDebInfo `yume` and the pinned Go helper built with two jobs;
- complete normal CTest: 57/57 passed;
- complete ASan+UBSan CTest, serial with leak detection and halt-on-error:
  57/57 passed;
- offline pinned Go tests and `go test -race`: passed;
- helper SHA-256 from two clean strict Release CMake directories:
  `6dbcda7e626f4c3bedce687a232fa7c2c02fe8649ecb7f0322497670093f9d36`
  for both outputs;
- helper identity remained `yume-chrome151-utls-v1.8.2-ipc-v1`, protocol 1,
  built by Go 1.26.5;
- the explicit `YUME_USE_BASEFWX=0` launcher fallback compiled with warnings as
  errors;
- Chrome fixture and five helper first flights: `PARITY`;
- mandatory CLI process smoke: passed at 83.37 MiB/s (local regression only);
- functional Chrome-helper-through-SOCKS smoke: passed with H2 selected and no
  packet capture; installed Chrome was not used as parity evidence;
- `linux-desktop-2.0` release preflight, exact bundle-content/hash/mode checks,
  ABI/export checks, and Debian source consistency: passed.

The first 2.0 release lane is now glibc Linux x86-64 CLI/server only. It builds
with exact Go 1.26.5, helper ON, GUI/static/cross-platform surfaces OFF, and
strict PQ/Argon2/LZMA requirements. `yume-amd64-linux.tar.xz` contains adjacent
`yume` and `yume-chrome-tls-helper`, licensing, quick-start, and a machine
manifest; `yumed-amd64-linux` is separate. The workflow defaults to preparation
only and cannot publish without explicit independent-review and RC-gate
acknowledgements. No Debian archive publication is claimed.

No IPC version, helper identity, exporter label, transport profile,
cryptographic derivation, public API, or wire format changed.

The local host was not a valid continuation of the August 1 matched
Chrome/performance baseline: its installed Chrome was `151.0.7922.108` rather
than pinned `151.0.7922.71`. The process-scale, reconnect, and soak gates were
therefore moved to an isolated clean checkout on the separate Linux host
documented below. Installed Chrome `.108` remains functional-only evidence;
it was not used to rewrite fixtures or make fresh Chrome-parity claims.

## 2026-08-11 remote process and soak qualification

The second dev6 qualification ran from clean commit
`30cad6e23b651a6c68ba8036299e863c59b9ab54` with clean BaseFWX
`4692d4ce4edec2aa9835d04ad9ff6c3ad3ab9374` on `raptorlake`: Debian Linux
`6.12.94+deb13-amd64`, x86-64, Intel Core i9-14900K, 32 logical CPUs, 62.49 GiB
RAM, and approximately 1.4 TiB free. The server used pinned Node `24.18.0`.
Installed Chrome was not part of these endpoint benchmarks.

The exact binaries were:

- `yume` SHA-256
  `c0e8b69fc002aceac07dfcd689dbd80ae1b657d9e3f5fdb375edfbc6d25a7e38`;
- `yumed` SHA-256
  `7a005998d3c5194a431d197f21beddeed9f49acb0eae37d4242584fc4cc09bcb`;
- `yume-chrome-tls-helper` SHA-256
  `6dbcda7e626f4c3bedce687a232fa7c2c02fe8649ecb7f0322497670093f9d36`.

Qualification results:

- the 1/10/50/100-client ramps completed every requested authenticated client
  with exact bytes and no unexpected failure;
- the 256-client ramp held 256 `yume` plus 256 helper processes concurrently,
  transferred exactly 65,536 MiB in 47.781 seconds, reported zero unexpected
  failures, and returned the server to its eight-fd/34-thread baseline with no
  helper or zombie left behind; the conservative sum of client-group peak RSS
  was 12,814.049 MiB;
- 1,000/1,000 sequential reconnects transferred exactly 2,000 MiB in 122.402
  seconds with zero unexpected failure; median latency was 95.234 ms and p95
  was 120.931 ms. Server fds remained 8 -> 8, threads 34 -> 34, helpers and
  zombies remained zero, and final RSS was below its baseline;
- the full-speed bidirectional soak transferred 112,640 MiB per direction,
  225,280 MiB total, over 2,333 seconds of script wall time and 2,314.193
  seconds of endpoint activity. Aggregate throughput was 97.347 MiB/s
  (816.607 Mbit/s), comprising 73.809 MiB/s upload and 142.972 MiB/s download;
- all seven soak segments exited zero with exact bytes, no timeout or
  interruption, client peak RSS at 90.168 MiB, and a two-process client/helper
  peak. Server fds remained 8 -> 8, threads 34 -> 34, RSS fell from 571,092 to
  472,740 KiB, and the final helper, zombie, and unexpected server-error counts
  were zero.

The signed checkpoint's endpoint benchmark intentionally caps one invocation
at 16,384 MiB per direction. To test the exact signed binary without weakening
that bound, the soak used six 16,384 MiB segments plus one 14,336 MiB segment,
back-to-back. This passes the bounded 30-minute full-load batch and many-epoch
gate, but is not evidence for one uninterrupted connection beyond 16 GiB per
direction. It is loopback scale/performance evidence, not matched WAN or
same-session stealth evidence.

The long-lived server sampler retained its final 10,000 of 66,393 samples and
dropped earlier samples after its bounded retention window; its post-idle
summary is therefore not used as the ramp/soak peak oracle. Acceptance instead
uses each run's sampler plus explicit before/after procfs and systemd cgroup
observations. The private SHA-256-verified evidence is outside Git under
`.private/ai/qualification/30cad6e-raptorlake-20260811/`; its 484-file checksum
inventory hashes to
`91784a4546126eb6448e6b300c611ebe41ec998bcab8607436e1f2e76e5c1b41`.
The isolated remote server, checkout, artifacts, and tmux dump were stopped and
removed only after that local copy verified.

These results close the documented bounded lifecycle, process-ramp, reconnect,
and segmented-soak gates. They do not close matched WAN, exact Chrome
`151.0.7922.71` same-session capture, external classification/active probing,
or independent security review. `chrome151` remains opt-in;
`openssl-diagnostic` remains the explicit default; and no `2.0-rc1` bump, tag,
push, publication, or default switch is authorized.

BoringSSL is not the next automatic step. The uTLS implementation already
passes the current first-flight, exporter, handshake-overhead, and local bulk
gates. Revisit BoringSSL only if uTLS fails a remaining security, lifecycle,
packaging, or field-classification gate.

## Validation entry points

```sh
ctest --test-dir build-final-review --output-on-failure -j2
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  ctest --test-dir build-asan-audit --output-on-failure -j1

(cd helper/chrome_tls && \
  GOTOOLCHAIN=local GOPROXY=off ../../.cache/toolchains/go1.26.5/bin/go test \
    -mod=readonly -count=1 -race ./...)

python3 scripts/yume_chrome_evidence.py \
  --fixture tests/fixtures/chrome151-node24

python3 scripts/yume_tls_wire.py check-profile \
  --profile tests/fixtures/chrome151-node24/chrome_tls_wire_profile.json \
  --candidate tests/fixtures/chrome151-node24/helper_tls_wire_run_1.json \
  --candidate tests/fixtures/chrome151-node24/helper_tls_wire_run_2.json \
  --candidate tests/fixtures/chrome151-node24/helper_tls_wire_run_3.json \
  --candidate tests/fixtures/chrome151-node24/helper_tls_wire_run_4.json \
  --candidate tests/fixtures/chrome151-node24/helper_tls_wire_run_5.json

python3 scripts/release_preflight.py
scripts/check_debian_source.sh

git diff --check
```

Build directories and generated benchmark artifacts are local evidence, not
source-of-truth. If they are absent or stale, rebuild rather than weakening a
gate. Preserve the separate BaseFWX and Android repositories and do not clean,
commit, or synchronize their user-owned changes from this branch.
