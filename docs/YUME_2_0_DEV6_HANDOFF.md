# YUME 0.2.0-dev6 Chrome 151 handoff

Status: core/ABI/CLI stabilization checkpoint completed for Linux x86-64;
consumer and release qualification remain incomplete.

## 2026-08-23 core/ABI/CLI stabilization checkpoint

This section supersedes the older implementation totals and ordered-work lists
below. Those sections are retained as engineering history. The checkpoint
closes the shared work selected before later GUI and Android synchronization;
it is not a claim that either frontend, another platform, or a release is
qualified.

The closed shared boundaries are:

- H2 receive credit follows downstream ownership, unauthenticated cover work
  and pending TLS output have connection/process caps, service admission and
  endpoint queues are bounded, and UDP/packet producers preserve or reject
  work under explicit backpressure instead of growing without limit.
- OPEN and CONTROL decoding is schema-strict and authorization is applied
  before dispatch. Inbound EXEC is disabled in both directions. Stream IDs are
  reserved through publication, collisions fail closed, and failed opens roll
  back without publishing orphan state.
- Config replacement and key metadata updates use locked, owner-only durable
  transactions on the qualified POSIX path. The server publishes a validated
  five-file authorization snapshot atomically. The stable C ABI reports typed
  parse/type/missing/permission/I/O outcomes and has a strict-C integration
  fixture covering a real TLS/H2/AUTH named-stream lifecycle.
- Relay setup is exact protocol v2: canonical composite peer signatures,
  pinned or post-verification TOFU identity, ephemeral ML-KEM-1024 + X25519,
  per-channel ratcheting, bounded records/queues, and deterministic lifecycle
  cleanup. POSIX receive publication is descriptor-confined and atomic; relay
  outbound hashing and streaming use the same pinned regular-file descriptor.
- Reverse listeners, federation links, facade sessions, transport callbacks,
  cancellation, and shutdown now use owned/weak lifetimes and bounded cleanup.
  Principal exceptional paths wipe KEM, root, PSK, transcript, ratchet, and
  pending-channel material on success, failure, throw, and teardown.

Exact-source qualification on the 32-core Linux x86-64 host includes two full
warnings-as-errors Release suites: system OpenSSL 3.5.6 and the declared
OpenSSL 3.5.7 build each passed 102/102 CTest cases. Eight high-risk
control/stream/federation/listener/relay/auth tests each passed 20 consecutive
executions, and the helper C++ and Go integration tests each passed ten
consecutive executions. The exact Go 1.26.5 helper module also passed
`go test -race -mod=readonly -count=1 ./...` with network module resolution
disabled. The separate client-only warnings-as-errors build passed 101/101
tests; eight concurrency/lifecycle tests passed ten executions each under
TSan; and the optional GUI completed its 231-step warnings-as-errors build,
`ldd -r`, and help-path smoke. The full serial
ASan+UBSan+LeakSanitizer lane passed 102/102 with leak detection and
halt-on-error enabled. A separately built checksum-pinned liboqs 0.16.0 archive
was selected by exact CMake cache/link path, reported by the CLI, and passed the
full 102/102 Release suite.

BaseFWX is independently signed and published at
`e6ffbb79daa02bf62c31c3ae6513d5c603ec8dcd`; YUME pins that exact commit. The
experimental Go/uTLS Chrome helper remains opt-in and disabled by default. It
is intentionally retained because the OpenSSL C++ backend matches the current
Chrome 151 JA4 and normalized non-GREASE sets but does not yet match the raw
first-flight GREASE, extension placement/rotation, or brotli-only certificate
compression gate. Removing the helper now would narrow the supported stealth
experiment and invalidate its wire/lifecycle evidence.

Still outside this checkpoint are GUI/Android functionality; Windows,
ARM/NDK, and hardware qualification; release/tag/artifact signing and a second
reproducible clean build; same-session Chrome resumption/raw-wire and active
classifier campaigns; deployed slow-reader and WAN loss/jitter/bidirectional/
soak work; a matched Xray/VLESS reference run; relay destination ancestor-
symlink policy under a malicious local account; ABI handle destruction without
caller synchronization; and removal of remaining server-to-client layering.
These are explicit next gates, not hidden claims of this checkpoint.

## GUI facade synchronization preparation

The core-side handoff now has a truthful facade boundary for the visual
redesign. `ClientStatus` reports the configured security mode, effective
composite-auth/hybrid-ratchet posture, TLS backend, rekey window, server
fingerprint, and capabilities; it no longer presents the legacy
light/heavy/off selector as runtime security state. Embedded client logs flow
through the typed `LogSink` only, whose subscribers are invoked outside the
ring lock with exceptions contained. The unused duplicate log and chat
callback promises were removed.

Chat open returns the admitted channel and canonical peer identities. Send and
close reject a different channel, and facade history preserves direction and
timestamp. The GUI DNS worker is owned and joined through `App` destruction,
and the macOS bundle version follows the project version. These are core and
lifecycle preparations, not a rendered-GUI acceptance claim. The visual pass
still owns removal of optional/light/heavy/dual server controls and the major
layout/theme redesign; the headless command still needs a real positive and
negative connect/stop/reconnect contract before it can be an acceptance gate.

The material below begins with a historical 2026-08-21 checkpoint. Its
ordered-next-work list predates
the TCP-autotuning, bounded H2-credit, exact Release/sanitizer, and matched WAN
work recorded in `docs/YUME_2_0_WAN_BEHAVIOR.md` and
`.private/ai/CURRENT_STATE.md`; use those live records before acting on an old
performance item below.

The authoritative merge/RC/stable checklist and branch policy are now in
`docs/YUME_2_0_STABILIZATION.md`. In particular, merging reviewed dev6 into
`main` and calling a Linux build stable 2.0 are separate milestones.

Verified checkout date: 2026-08-21. Always refresh the Git state and rerun the
relevant gates before relying on the hashes or measurements in this document.

## Current continuation checkpoint (2026-08-21)

### Independent audit findings, verified

An independent read-only audit was checked against the source. Most of it holds;
three items were corrected, and one gap it flagged turned out to be larger than
reported.

Confirmed and fixed in the working tree:

- Superseded inner keys were freed without clearing. `server/session/auth.cpp`
  promoted the alternate key by copy, leaving two live copies until the
  alternate slot was reset; it now wipes the outgoing key and moves. The client
  `TransportCore::set_inner_key` now wipes before assigning. Both types are
  `std::optional<crypto::Bytes>`, so nothing was clearing them.
- The raw ECDH shared secret in `crypto.cpp generate_session_key` outlived its
  use. It is now wiped on scope exit, which also covers the throwing paths.
- `anonym.cpp` used `util::random_hex(16)` for a proof nonce without checking
  the result. It now fails instead of shipping an empty replay binding.

Confirmed, still open (recorded, not fixed here):

- The legacy inner AEAD has no replay binding: `build_aad` is
  `'YUME' | frame_type | stream_id`, with no epoch or sequence, so a captured
  ciphertext would replay under the retained static key. Since the federation port
  to AUTH v2 (`yume/federation-v2`) no establishment path can arm that layer,
  so the weakness is unreachable rather than live. Hop plumbing has been
  removed; the primitive remains only for direct fail-closed tests and awaits
  the broader legacy-static-inner retirement. Resolution is removal, not a
  partial AAD patch without per-direction state and a wire version.
- `crypto.cpp` remains a parallel raw-EVP stack. Its relay key-schedule HKDF
  info strings are now versioned as one schedule (`yume-relay-*-v1`,
  `client/relay/runtime.hpp`, closed 2026-08-22); what remains open for that
  file is consolidation onto the basefwx primitive layer and an AAD-capable
  ChaCha API.

Corrected:

- **The KDF guard was dead code, not an active enforcement gap, and the gap was
  wider than reported.** The audit found `server_derive_key` unused; the
  `KdfAdmissionController` also had no live consumer after federation moved to
  AUTH v2. This was
  not exploitable, because the v2 session path pins `inner_kdf_` to `"hkdf"` and
  never accepts a peer-supplied KDF request, so no attacker-controlled Argon2
  parameter reaches a derivation. What was real is the comment above the caps,
  which asserted that `server/session/auth.cpp` calls
  `argon2_params_exceed_limits` -- it does not. That comment has been corrected,
  because a false claim that a control exists is more dangerous than the dead
  code. The server derivation family, controller, injection surface, standalone
  test, and obsolete budget configuration were subsequently removed.
- **The inherited master-PQ-private-cache finding is not reproducible in the
  current tree.** The only static cache in `inner_crypto.cpp` holds a public
  key; `LoadMasterPrivateKey` has no production caller, and private-key loads
  use scoped wiping. There is no process-lifetime cached private master key to
  list as a residual.
- **The non-constant-time KEM comparison is not a vulnerability.** It sits in
  `validate_pq_keypair`, a local self-check where both operands are derived from
  local files. There is no attacker input and no timing oracle.
- **`random_hex` does not swallow RNG failure.** It returns empty on
  `RAND_bytes` failure, and `key.cpp` checks it. One caller did not; see above.

Release and ASan+UBSan suites pass 72/72 with these changes.

### Per-key permissions now reach AUTH v2 sessions (fixed)

The routed loopback benchmark had never produced a number: it always reported
`FAILED SOCKS CONNECT rejected` because its key never received
`allow_local_ip`. The cause was that one key had two fingerprints.

An authorized identity is a composite -- two consecutive PEM blocks, classical
Ed25519 then ML-DSA-87 -- and the server both authorizes on
`composite_canonical_encoding` and looks up per-key permissions by
`crypto::composite_fingerprint`. Key *generation* already recorded that same
composite value. But `facade::keys::list_authorized` split the file into single
PEM blocks and fingerprinted each one classically, so it reported one identity
as two `ed25519` entries under values the server never looks anything up by, and
`append_authorized` wrote meta under the same wrong value. This was therefore
not a policy question about which fingerprint should be canonical: generation
and the server already agreed, and listing and appending were the outliers.

Fixed by making every reader composite-aware. In the facade,
`list_authorized` pairs consecutive blocks into one identity and reports the
composite fingerprint, `append_authorized` records meta under it, and
`fingerprint_pubkey_file` returns it. The classical `fingerprint_pem_der` helper
is retained and documented as what it is -- a SubjectPublicKeyInfo digest for
non-composite material such as TLS leaf pinning -- and is explicitly not an
AUTH v2 identity.

`yumed --keys-list` had its own copy of the defect: it read the store as a flat
list of public keys and called the classical `fingerprint_pubkey` on each, so it
printed one identity as two entries. It now lists through
`server::load_authorized_keys`, which applies the same pairing the server does.
Verified: a freshly generated key is two PEM blocks and `--keys-list` reports
exactly one fingerprint, where it previously reported two.

To keep one identity from being computed two ways again, the digest itself now
has a single implementation: `crypto::composite_fingerprint_from_canonical`
hashes the canonical encoding, and `composite_fingerprint` delegates to it. The
store already holds identities in canonical form, so the CLI needs no second
parse.

`src/tools/selftest.cpp` had the same defect twice over: it derived the
fingerprint by shelling out to `openssl pkey -pubin`, which reads only the
first PEM block, and it never passed `--auth-keys-meta` to yumed, so the file it
wrote was never read. Both are fixed; the fingerprint is now computed with
`crypto::composite_fingerprint`, which also removes an openssl dependency from
that path.

Result: the YUME 2.0 local transport benchmark runs for the first time.
Unconstrained on `192.168.1.165` it reports 0.743 ms median, 0.876 ms p95 and
1154.87 Mbit/s over loopback. That number is a useful bound for the separate
delayed-path investigation: loopback throughput is not the constraint at
roughly 25 Mbit/s over a 60 ms path.

### First constrained-host tier results

With the benchmark working, `scripts/yume_constrained_host.py` produced the
first real tier measurements. Both pass with the full hybrid post-quantum,
ratcheting stack on, verified from the daemon and client logs the run leaves
behind rather than from stdout:

| Tier | Verdict | Peak RSS | Of tier | Tasks | CPU used | Throttled |
| --- | --- | --- | --- | --- | --- | --- |
| 1 vCPU / 1 GiB | PASS | 19 MiB | 1.81% | 66 | 0.86 s | yes, 7x |
| 2 vCPU / 2 GiB | PASS | 18 MiB | 0.88% | 66 | 0.33 s | no |

The shape is informative: memory headroom is enormous and the 1-vCPU tier is
CPU-bound, throttling while still completing.

### Handshake percentiles and leak behaviour

`--repeat N` runs the workload N times in one scope, so percentiles have a
sample and a leak has somewhere to show up. Twenty iterations per tier, hybrid
post-quantum handshake, verified from the run's own logs:

| Metric | 1 vCPU / 1 GiB | 2 vCPU / 2 GiB |
| --- | --- | --- |
| Handshake p50 | 1.42 ms | 1.42 ms |
| Handshake p95 | 2.01 ms | 1.70 ms |
| Handshake p99 | 2.29 ms | 1.93 ms |
| Round-trip p95 (median of runs) | 0.51 ms | 0.66 ms |
| Throughput p50 | 120.1 MiB/s | 151.2 MiB/s |
| Peak RSS | 23 MiB (2.20%) | 18 MiB (0.88%) |
| Peak open fds | 36 | 36 |
| Peak tasks | 66 | 66 |
| CPU throttle events | 43 | 3 |

Handshake p50 is identical across tiers: the ML-KEM-1024 + X25519 exchange is
not CPU-starved at one vCPU, and only the tail moves (p99 2.29 ms against
1.93 ms). Throughput is where the missing core shows, about 20 percent lower
with 43 throttle events against three. Memory is not the constraint at either
tier.

Leak check, same workload at 5 and at 40 iterations on the 1 vCPU tier -- eight
times the work:

| | repeat 5 | repeat 40 |
| --- | --- | --- |
| Peak open fds | 36 | 36 |
| fd steady drift | 0 | 0 |
| Peak tasks | 66 | 66 |
| Peak RSS | 16 MiB | 19 MiB |
| Handshake p50 | 1.14 ms | 1.34 ms |

Descriptors, tasks and RSS do not scale with iteration count, so nothing is
being retained between sessions. Note that the drift figure compares the second
half of the samples against the first half rather than last against first: every
run ramps from zero to its working set, and a first-to-last delta reports that
startup as if it were a leak.

Note what none of this establishes. It bounds resources; it does not emulate
slower cores, storage or NICs, the transfer is loopback, and the
admission-flood, backend-slowdown, session-cap-rejection, recovery and sustained
soak parts of the `docs/OPERATIONS.md` matrix have not been run. A tier may not
be published on this alone.

### Legacy hop plumbing removed

After the federation AUTH v2 port made the time-derived inner hop unreachable,
the remaining implementation and configuration surface was removed rather than
retained as decoration: key derivation, skew-window trial decryption, cached
keys/ids, TransportCore and Session branches, CLI/facade/GUI fields, share
bundle fields, and status output. `docs/SECURITY_MODES.md` records why hop was
not a lighter ratchet: every hop derived from one retained base key, while the
directional ratchet performs a fresh authenticated hybrid exchange per epoch.

`inner_crypto_limits_test.cpp` now pins fail-closed negatives on the remaining
unreachable legacy AEAD primitive: wrong key, frame type, stream id, and
ciphertext tampering are all rejected. Ratchet ordering, window, timeout, and
key-retirement negatives remain in the ratchet suites.

### Argon2 admission: superseded by the federation port

`KdfAdmissionController` was constructed, injected into every session, and never
called; `server_derive_key` and its Argon2 ceilings had no callers either. The
second group was genuinely orphaned rather than missing: the server session
speaks only AUTH v2, which pins its KDF to HKDF and never accepts a
peer-supplied KDF request. With the federation dial now on AUTH v2 as well,
`server_derive_key`/`server_derive_key_resolved` have been deleted outright;
`resolve_server_kdf_params` and the `*_exceed_limits` guards survive only as
policy pinned by tests, with their non-live status stated in the header.

The admission controller's original consumer -- the legacy federation dialer
running `inner::client_prepare` (Argon2, 256 MiB per dial) inside the server
process -- is gone with that dial. The controller is currently constructed but
inert; it was deleted with the hop-retire cleanup, including its standalone
unit target and the server/session/federation injection surface. The obsolete
Argon2 admission-budget configuration fields were removed at the same time.

### Classifier gate: scoring engine frozen before any data exists

`config/classifier_gate_v1.json` plus `scripts/yume_classifier_gate.py` freeze
the classifier-resistance decision rules ahead of the first capture, which is
the only order in which "frozen thresholds" means anything. See
`docs/YUME_2_0_STABILIZATION.md`. The immediate planning consequence is that the
five-run campaign is about an order of magnitude too small to produce a verdict;
the gate returns `INSUFFICIENT` rather than a pass, by design.

### Gate B blocker cleared: Chrome startup traffic, not YUME

The `Page.navigate` timeout that blocked every capture campaign is diagnosed and
fixed. It was never a YUME, Node, or CDP-driver defect.

A direct Chrome 151.0.7922.71 to Node 24.18.0 canary on `192.168.1.165`, with no
TLS relay and no YUME path, reproduced it exactly. Instrumenting both ends showed
Chrome completing TCP and TLS 1.3 to the fixture immediately, negotiating ALPN
`h2` and opening the session, then sending no HEADERS for about 11 seconds.
Chrome's netlog named the cause: the browser's network pipeline goes completely
silent for roughly 10 seconds at a time, twice, while Chrome performs its startup
service calls (`optimizationguide-pa.googleapis.com/v1:GetModels`,
`accounts.google.com/ListAccounts`, `clients2.google.com/time`). Every queued
request waits in `NETWORK_DELEGATE_BEFORE_START_TRANSACTION` until those finish,
about 24 seconds in. The fixture navigation is behind them, so the driver's
bounded 15 second CDP deadline expires first. A marginal 15 second deadline
against a roughly 24 second stall also explains why earlier campaigns failed at
different run indices instead of consistently.

The host was not at fault: DNS resolved in about 20 ms, Google was reachable in
43 ms, and an HTTPS fetch returned 200 in 120 ms.

Measured remedies, identical hardware, toolchain and navigation ladder:

| Variant | plain HTTP | HTTPS by IP | HTTPS by SNI |
| --- | --- | --- | --- |
| Current runner flags | timeout at 12 s | 11423 ms | 6 ms |
| `--host-resolver-rules=MAP * 127.0.0.1` | timeout at 12 s | 11430 ms | 5 ms |
| Dead `--proxy-server` with fixture bypassed | timeout at 12 s | 11420 ms | 6 ms |
| Service feature flags disabled | timeout at 12 s | 11452 ms | 6 ms |
| **Loopback-only network namespace** | **3 ms** | **11 ms** | **4 ms** |

Only real namespace isolation works. Making the Google requests fail fast does
not help; Chrome skips the work only when no network exists at all.

This matters beyond the timeout. In an unisolated run the netlog records a
*completed* TLS handshake against a Google Trust Services certificate inside the
capture window, so every capture taken so far carried non-fixture traffic that
the YUME arm neither has nor should reproduce.

`scripts/yume_capture_netns.sh` implements the fix. `setup` creates the
`yume-capture` namespace and brings `lo` up; `exec` re-enters it and drops back
to the invoking user via `SUDO_UID`/`SUDO_GID`, restoring `HOME`, `USER` and
`LOGNAME` because `setpriv` changes credentials but not the environment. Only
namespace creation needs privilege. Because the capture itself runs as the
normal user, Chrome keeps its user-namespace sandbox and artifacts stay owned by
that user, so `chrome_sandbox: user-namespace` remains accurate and neither
`scripts/yume_capture_manifest.py` nor `scripts/yume_classifier_evidence.py`
needed changing.

Both capture runners now refuse to start outside that namespace, after their
binary-hash and clean-source gates so the more fundamental errors still surface
first. `scripts/test_yume_browser_sandbox.py` covers both sides through one
parameterised fixture: an isolated `ip` stub reaches the intended Chrome-exit
diagnostic, a connected one is refused without executing the browser.

Verified end to end on `192.168.1.165`: a real two-run campaign with the pinned
Chrome and Node completed (`run-01: complete`, `run-02: complete`) and produced
`sanitized.json` plus `SHA256SUMS` per run. In that capture only two TLS sessions
completed, both `next_proto: h2` to the fixture; every Google attempt failed
first with `NAME_NOT_RESOLVED`, `INTERNET_DISCONNECTED` or `ADDRESS_UNREACHABLE`.
Chrome still *tries* those requests, and the netlog still records the attempts
and the hardcoded URLs; what changed is that none of them reach the network.

This is unsigned working-tree evidence from a scratch clone, not exact-signed-
tree qualification, and it does not by itself close Gate B: the matched five-run
normal and YUME campaign, the validator comparison and the classifier work all
remain. It does remove the blocker that prevented any campaign from running.

Usage:

```
sudo scripts/yume_capture_netns.sh setup
sudo scripts/yume_capture_netns.sh exec -- \
    tools/cover-node/capture_chrome151_runs.sh <out> <node> [runs] [idle-ms]
sudo scripts/yume_capture_netns.sh teardown
```

### Cover server HTTP/1.1 hang (fixed in the working tree)

Separately, `tools/cover-node/server.mjs` set `allowHTTP1: true` -- so Node
accepts an HTTP/1.1 connection -- but registered only a `stream` handler. An
HTTP/1.1 client was parsed and never answered, hanging until its own deadline.
Measured before the fix: h2 returned 200 in 5 ms, HTTP/1.1 never returned. This
did not cause the campaign failure above, but it produces exactly the same
symptom and would have been indistinguishable from it.

The first attempted fix, adding a `request` listener, was wrong and the capture
campaign caught it: registering `request` also switches on Node's HTTP/2
compatibility layer, which attaches to every stream and consumes the
extended-CONNECT stream the reference WebSocket runs on. The capture then failed
with `WebSocket fixture timeout` while still answering the CONNECT with 200, so
a status-only assertion would have passed. The server is now `allowHTTP1: false`:
an HTTP/1.1-only client is refused at ALPN instead of hanging, and this is
invisible to an HTTP/2 client because the ServerHello carries only the selected
protocol, never the server's list.

`tools/cover-node/test_cover_server_protocols.mjs` drives the real server with
bounded deadlines and covers both regressions: restoring `allowHTTP1: true`
fails with `HTTP/1.1 request did not answer within 5000 ms`, and adding the
`request` listener fails with `extended CONNECT did not answer within 5000 ms`.
The WebSocket case asserts a masked-ping/pong round trip rather than the CONNECT
status, because only the data path breaks.

### Latest working-tree change: authenticated-ACK rekey deadline

The candidate now also carries the first half of the RTT-adaptation item. The
fixed five-second rekey ACK deadline in `src/core/security/session_ratchet.cpp`
is replaced by an RFC 6298-shaped estimator over authenticated ACK round trips,
granting each offer `clamp(SRTT + 4 * RTTVAR, 5 s, 30 s)`, frozen at offer time.
The design, its invariants and its one honest cost are in
`docs/YUME_2_0_WAN_BEHAVIOR.md` under "Authenticated-ACK deadline adaptation".

What did **not** change is the point of the change: the negotiated per-epoch
byte, frame and sender-active-time limits are untouched, and a test asserts that
a session which has measured a 20 s path and one which has measured a 1 ms path
advance through exactly the same epochs on the same workload. Latency now buys
patience, never a larger blast radius.

Preparation depth and lead time were deliberately left static. The deadline is
invisible on the wire; depth and lead decide when `REKEY_INIT` records appear,
so adapting them writes measured network conditions into the traffic shape.
They stay behind the capture/classifier gate.

Evidence for this change alone, on `192.168.1.165` in `build-ci`: full Release
suite 70/70 with warnings-as-errors, including three new ratchet cases
(`TestAckDeadlineClampedInBothDirections`,
`TestGrantedAckDeadlineIsFrozenAtOfferTime`,
`TestRttAdaptationNeverWidensEpochLimits`). This is unsigned working-tree
evidence and does not alter the NO MERGE CLAIM / NO RELEASE verdict below.

### Working tree the next agent receives

The handoff is intentionally an **uncommitted candidate**, based on signed
commit `a0745fec638b0391af58e8c4cb3f13ebb3f30d31` (tree
`ab55d3d9af2be56671bc4bf4164092ef38d57099`). Do not reset, clean, or replace
it with `origin/main`. Begin with `git status --short`, `git diff --check`, and
`git diff`; every current change is part of the candidate and there are no
known unrelated edits. BaseFWX is a separate clean checkout at pinned commit
`4692d4ce4edec2aa9835d04ad9ff6c3ad3ab9374` and must remain separate.

The candidate changes the shared-ABI/LTO build policy, the hermetic browser
sandbox fixture, the transactional signed-vendor `ensure` path and its tests,
plus the public handoff/status/gate text. Its isolated copy on
`192.168.1.165` is
`/home/f1xgod/yume-current-test-da1EUE/repo`. The existing network path to that
host was sufficient for build and correctness tests; it is **not** accepted as
a direct-gigabit benchmark path. Connect and inventory the dedicated NIC before
using that host for LAN throughput evidence.

The unsigned candidate passed strict shared-ABI Release 70/70, serial
ASan+UBSan 70/70, CLI help smokes, pinned Go 1.26.5 unit/race tests, an ordinary
non-shared-ABI focused LTO check, and repeat signed-vendor `ensure` checks on
that isolated host. These results make the tree ready for review and continued
editing, not for release: no commit or push was made, registered CI has not run
on it, and exact signed-tree dependency/reproducibility/Debian/package/artifact
qualification remains mandatory.

At the 2026-08-21 read-back, the latest signed product-code checkpoint on
local `main` and `origin/main` was
`97ed846dcae92c4d8b5a67173c8d9a5c1e7c4341`, tree
`3b6b967c62c1779a750a244feb2721443c04e6cf`. The signature verifies with
EdDSA fingerprint `967278FF6FA436F504CBB0058A1588B5E2598DB1`. Workflow-owned
`origin/DEV` is commit `81f59a68e0a56519fe4997fcd4c17a35e5bd9b00`
with the same tree. CodeQL run `32443839284`, Code Quality run `32443838665`,
and branch-sync run `32443839323` passed. No PR was opened and `DEV` was not
pushed directly.

The exact Chrome `151.0.7922.71` staging directory remains present on
`192.168.1.165` at
`/home/f1xgod/yume-profile-build-t4CutW/chrome-151.0.7922.71`; reverify the
documented package, launcher, and binary hashes before use. The failed
`yume-final-0a7468a.service` unit remains visible as status evidence, but its
temporary validation root was removed and cannot be resumed.

The dependency hardening after `f2ffce6` made the product's real cryptographic
minimum explicit: full builds require OpenSSL >= 3.5, CI/CodeQL/release use the
checksum-pinned OpenSSL 3.5.7 source fallback, and prepared releases use the
exact liboqs 0.16.0 source pin with static linkage plus RPATH/RUNPATH and
dynamic-liboqs rejection. Local optimized and serial ASan+UBSan suites passed
67/67 before those dependency/release changes. A later fresh remote run reached
66/67; its only failure was the isolated normal-Chrome sandbox fixture, and it
therefore did not reach the final reproducibility/package portion. Do not
reuse the earlier 67/67 result as exact-tree qualification.

Signed commit `b677938d361c37a47da822a3eeb756a3d83399ee` corrected a GitHub
Actions environment bug: invoking the OpenSSL and nghttp2 helpers in separate
child shells caused the later `GITHUB_ENV` assignment to discard OpenSSL's
pkg-config prefix. All affected CI, CodeQL, and release lanes now source and
invoke both helpers in one shell, and release preflight enforces the exact
2/1/1 occurrence counts. The next CI run proved the combined environment,
configured and built both native and sanitizer targets, and then exposed a
test-only executable/library mismatch: the browser-sandbox fixture replaced
`PATH` with `/usr/bin:/bin` while retaining the pinned 3.5.7
`LD_LIBRARY_PATH`, so Ubuntu's 3.0 OpenSSL executable crashed against 3.5.7
libraries.

Signed commit `97ed846dcae92c4d8b5a67173c8d9a5c1e7c4341` retained the inherited
dependency path behind the fixture's fake-command directory. Locally the full
browser-sandbox suite passed 38/38 and its intended Chrome-exit case passed
20/20. Exact CI run `32443839339` confirmed pinned OpenSSL 3.5.7 and nghttp2
environment propagation plus successful native and sanitizer configure/build,
but both test lanes still passed only 69/70. The same isolated case exited
nonzero with empty stderr before its expected `Chrome exited unsuccessfully`
diagnostic. Because certificate generation suppresses OpenSSL output, the next
agent must first make this unit fixture hermetic—prefer a test-local fake
`openssl` that creates the dummy key/certificate outputs, restore the bounded
fixture `PATH`, and prove the intended Chrome failure is reached—rather than
weakening the production capture runner or merely changing the assertion.

The current working-tree correction on signed documentation base `a0745fe`
does exactly that: its test-local `openssl` accepts only `req`, requires both
fixture output paths, creates the dummy key and certificate, and lets the
fixture return to `fake-bin:/usr/bin:/bin`. The direct browser-sandbox suite
passed 38/38, including the intended `Chrome exited unsuccessfully` path with
the sanitizer marker absent.

A fresh isolated run of that working tree on `192.168.1.165` then found two
build-harness defects. GCC 14.2 could not link LTO-enabled test objects against
the deliberately non-LTO, hidden static archives used to construct `libyume`;
the same Release build without LTO passed 70/70. Shared-ABI input archives now
propagate their required `-fno-lto` policy to consumers, while ordinary builds
without `YUME_BUILD_SHARED_ABI` retain LTO. The signed vendor-archive `ensure`
path is also transactional and repeatable: an existing tree is accepted only
when its normalized content/metadata digest matches a fresh verified
extraction, and drift still fails without overwrite. With those corrections,
the strict shared-ABI Release lane passed 70/70, serial ASan+UBSan passed 70/70,
both CLI help smokes passed, and pinned Go 1.26.5 unit/race tests passed. This
is unsigned working-tree evidence, not exact-signed-tree qualification or CI.

Verdict for the `97ed846` product-code checkpoint: **NO MERGE CLAIM / NO
RELEASE** until the fixture correction is signed, native and sanitizer CI pass
all 70 tests, and an exact signed-tree qualification completes every applicable
dependency, reproducibility, package/preflight, and artifact check. Gate B
remains independently open on the real Chrome DevTools navigation boundary and
all later classifier/WAN/soak work. The older evidence below remains historical
and must not be generalized to `97ed846`. A documentation-only successor does
not change this product-code verdict; refresh Git before acting.

## Earlier integrated checkpoint (2026-08-14)

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

- The exact transport version is `0.2.0-dev6`.
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

## Historical ordered work (superseded 2026-08-23)

The bounded helper negative matrix, 1/10/50/100/256 ramps, 1,000 sequential
reconnects, and segmented 30-minute full-speed soak are complete as documented
below. This list predates the completed core/ABI/CLI continuation and is kept
for chronology, not as the current queue. The current consumer-sync boundary is
in `docs/YUME_2_0_IMPLEMENTATION_STATUS.md`; do not silently rerun or broaden
old campaigns without freezing a new workload and artifact location.

1. **Preserve and qualify this candidate.** Review the complete dirty diff,
   freeze it only after approval, then require native and sanitizer CI 70/70
   plus an exact signed-commit remote run through dependency, reproducibility,
   Debian/ABI, package/preflight, and artifact checks. Do not convert the
   unsigned results above into a release claim.
2. **Repair the deterministic Chrome/CDP boundary.** Reproduce the direct
   exact-Chrome-to-Node `Page.navigate` timeout with no YUME process in the
   path, add bounded late/stalled-response coverage, and pass a fresh exact
   Chrome canary. Only then run a new five-normal/five-YUME same-session
   campaign; no partial predecessor capture may be reused.
3. **Measure learnability, not just structural parity.** Split sessions rather
   than packets and hold out capture day, host, network and provider. Freeze
   acceptance thresholds before the run; report multiple classifiers,
   confidence intervals, ROC/PR results and detection rate at operationally low
   false-positive rates. Include active TLS/H1/H2/WebSocket probes and record
   endpoint, certificate, timing and volume features that remain visible.
4. **Finish WAN qualification without reopening the diagnosed defect.** The
   former approximately 25-Mbit/s result was traced to pinned TCP buffers and
   then H2/ratchet credit geometry, not crypto CPU or offer pacing. The matched
   60/100/210-ms zero-loss measurements are complete for their named arms;
   100-Mbit/s, controlled loss, bidirectional and soak arms remain. If future
   adaptation is added, authenticated ACK observations may select preparation
   depth and a bounded deadline; RTT must never relax or select the
   cryptographic byte/frame/time limit. See
   `docs/YUME_2_0_WAN_BEHAVIOR.md`.
5. **Qualify weak-host operation.** Freeze constrained-host tiers, exercise the
   complete crypto and cover stack under cgroup CPU/RSS/fd limits, and measure
   handshake/rekey latency, queue growth, overload rejection and recovery. Do
   not save resources by disabling PQ establishment, authenticated ratchets,
   TLS verification, or fail-closed admission.
6. **Synchronize consumers, then publish a tested platform matrix.** The
   selected core/ABI/CLI gate is complete enough for Android and GUI source work
   to begin; ABI v2 is not a prerequisite. Packet backpressure and facade
   lifecycle races must be fixed first, then each consumer needs its own exact
   build, cancellation/restart, transport, and platform tests. Current supported
   scope remains glibc Linux x86_64 CLI/server/helper, not “any server.”
7. **Finish operations and independent review.** Validate reload/shutdown,
   backend and disk/log failure, installed helper discovery and permissions,
   per-key fairness, resource telemetry without a new wire marker, and obtain
   independent cryptographic/protocol plus adversarial deployment review before
   `0.2.0-rc1`.

The long-term stealth target is low measured classifier advantage against a
specific cover distribution, not a promise that DPI or a neural classifier can
never track or learn YUME. Endpoint/IP reputation, certificate, connection
volume, timing and operator mistakes remain observable unless the deployment
and cover workload match them too. Arbitrary random padding or a “randomish
millisecond” cadence can itself become the most stable YUME signature.

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
- `linux-desktop-0.2.0` release preflight, exact bundle-content/hash/mode checks,
  ABI/export checks, and Debian source consistency: passed.

The first 0.2.0 release lane is now glibc Linux x86-64 CLI/server only. It builds
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
`openssl-diagnostic` remains the explicit default; and no `0.2.0-rc1` bump, tag,
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
