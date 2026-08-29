# YUME 0.2.0 stabilization and integration gates

Status: working checklist for the Linux x86-64 `0.2.0-dev6` vertical slice.
Passing the merge lane below permits landing reviewed development work on
`main`; it does not by itself make YUME 0.2.0 release-qualified.

## Supported 0.2.0 scope

The first credible 0.2.0 release is the glibc Linux x86-64 CLI client with the
in-process patched-OpenSSL emitter, plus `yumed`, as described by the
`linux-desktop-0.2.0` release profile. The Go helper is temporarily retained as
an optional comparison backend, not a runtime requirement.
Android, the GUI, static/cross-platform packages, multiple simultaneously
admitted browser identities, H3, federation, and a mature control-plane
ecosystem are follow-up scopes. They must not be advertised as supported, but
they do not block this deliberately narrow Linux release.

## Repository branch contract

Development work must not be pushed to `DEV`. A push to `main` runs
`.github/workflows/branch-sync.yml`, which replaces non-excluded `DEV` content
with the `main` snapshot and creates a bot-owned sync commit. The end state is
expected to have only `main` and `DEV` on the remote.

For a large feature, a temporary review branch is acceptable and safer because
it lets pull-request CI run before `main` changes. Delete that temporary remote
branch after integration and parity verification. The ordered path is:

1. freeze a clean, signed feature commit;
2. push a temporary review branch and require CI/CodeQL/review success;
3. fetch `origin/main` again and create a signed local `--no-ff` merge;
4. run the final preflight against that exact merge commit;
5. push `main`, never `DEV`;
6. wait for branch sync, then run `scripts/check_branch_parity.sh main DEV`;
7. delete the temporary remote branch only after `main`, `DEV`, CI, and sync
   are all confirmed healthy.

Do not combine the integration with a version bump, backend-default switch,
tag, or publication. Those are separate reviewable decisions.

## Gate A: land dev6 on `main` while it remains development software

All items in this section block merging whichever candidate is current. Dated
exceptions and old feature hashes are historical evidence, never standing
authorization for a later integration.

- Refresh and verify the signed base, preserve unrelated dirty work, inventory
  every modified/untracked/deleted path, and review the complete diff against
  the actual requested scope.
- Treat product `0.2.0-dev6`, transport/AUTH/relay v2, ABI v1, and helper IPC v1
  as independent version axes. Any change to an authenticated profile, wire
  field, KDF/AEAD/AAD domain, algorithm, backend default, or public JSON field
  requires an explicit compatibility decision plus synchronized consumers,
  tests, comments, and documentation.
- Freeze an exact source manifest and validate from that source with the
  build variants proportionate to the change: warnings-as-errors Release,
  focused and integration CTest, client-only ABI when the C surface changes,
  and sanitizers for lifetime/concurrency/security-sensitive changes. Run the
  pinned Go/race lane only while the optional helper is affected or shipped.
- If generated fixtures, dependencies, packaging, or release workflows change,
  exercise the corresponding negative checks and end-to-end artifact path;
  parser-only evidence is insufficient.
- Pass Debian source consistency, the current 43-symbol ABI header/map/symbol
  checks, installed-layout tests, workflow validation, `git diff --check`, and
  a private/secrets/artifact staging audit.
- Create and verify a signed commit only after the exact candidate passes. Then
  refresh `origin/main`; if it moved, repeat every affected review and test
  rather than attaching stale evidence to a rebased result.

Signed architecture commit
`1593fc62de89d613e107f1e173adf3edb7ed7568` passed this lane from the fresh
`raptorlake` checkout recorded in `docs/YUME_2_0_DEV6_HANDOFF.md`. Native and
serial ASan+UBSan suites passed 66/66, Release/LTO passed 61/61, strict
Argon2/OQS/LZMA and warnings-as-errors were enabled, pinned Go unit/race and
95 focused evidence tests passed, Debian and all 42 ABI symbols agreed, and
two clean helpers were reproducible. Exact Linux artifacts passed source,
prepared-directory, and transfer-round-trip preflight. This closes the old
dirty-overlay qualification gap for that architecture checkpoint; it does not
close any Gate B or Gate C item.

## Gate B: authorize `0.2.0-rc1` as a stable-ish Linux preview

These gates may follow the merge. Until they pass, keep the source version at a
development label, keep the native backend's claim limited to its structural
six-row gate, and avoid release-parity claims.

- Use the staged exact Chrome `151.0.7922.71` artifact documented in the dev6
  handoff, reverify its package/launcher/binary hashes before capture, and run
  it only from an isolated profile/environment with a valid setuid or user-
  namespace sandbox. Do not use `--no-sandbox` or downgrade the operator's
  normal auto-updated browser.
- In one frozen session and environment, capture normal Chrome and YUME flows
  against the same Node `24.18.0` cover, certificate, SNI, ALPN, and workload.
  Preserve private NetLog/PCAP provenance and compare TLS, HTTP headers/client
  hints, H2 settings/priorities, WebSocket behavior, assets, and server identity.
  The YUME CLI now has an exact-policy `--outer-carrier-evidence` producer for
  the live `behavior.json`; its presence closes the instrumentation gap only.
  Gate B still requires five accepted same-session runs and sealed bundle
  provenance outside Git. Use `capture_yume151_runs.sh` so the YUME executable,
  native backend, clean source identity, exact Chrome/Node
  identities, PEM certificate hash, DER leaf pin, TLS-wire relay, per-run
  behavior, and runtime snapshot are bound into that arm. The runner never
  copies the external client config or its secret files.
- Complete external H2/WebSocket conformance and passive-classifier/active-probe
  tests, including malformed extended CONNECT, replay, ordinary cover paths,
  backend outage, certificate/site consistency, and hosting/IP metadata. Record
  every remaining classifier-visible difference; do not claim DPI immunity.
- Complete matched one-tunnel WAN upload, download, and bidirectional matrices
  at 60, 100, and 210 ms, at 100 Mbit/s and approximately 1 Gbit/s, with
  controlled loss. The current exact candidate already has three interleaved
  default-path repeats at 60 ms and two diagnostic repeats at 100/210 ms under
  a 1-Gbit/s, zero-loss cap, with machine-readable artifacts and no manual-
  credit regression or stall. The former ~25-Mbit/s ceiling was diagnosed as
  pinned TCP buffers followed by H2/ratchet credit; do not reopen offer pacing
  or cryptographic CPU as its cause. The 100-Mbit/s, controlled-loss,
  bidirectional, three-repeat high-RTT, and soak arms remain open.
- Run one uninterrupted authenticated tunnel for at least 30 minutes in the
  intended deployed-network environment. The prior seven-segment loopback soak
  is not a substitute.
- Extend adversarial coverage for mid-record WebSocket splits, multi-fragment
  messages with interleaved controls, counter wrap, malformed/tampered records,
  sustained flow-control stalls, bounded backpressure, disk/log pressure,
  reload/shutdown, and backend timeout/failure under deployed load.
- Make and document the time-limit threat-model decision: retain the present
  honest-sender active-time rule with receiver-enforced byte/frame limits, or
  introduce a versioned receiver-local lifetime design with its availability
  trade-off. Do not imply that a signed sender timestamp makes its clock honest.
- Obtain independent cryptographic/protocol and deployment review, including
  key erasure, the OpenSSL patch/default-off boundary, profile registry,
  downgrade resistance, and
  failure paths. A same-agent self-review is useful but is not independent.

The development default is already `openssl-chrome151`; that does not waive
Gate B. Only after these items pass should a separate change qualify that
default, retire the helper, and consider bumping to `0.2.0-rc1`.

## Gate C: call the narrow target exact `0.2.0`

- Resolve every blocking RC review finding and repeat any evidence affected by
  source, dependency, fixture, browser, toolchain, kernel, NIC, or workload
  changes.
- Reconcile CLI help, wire contract, threat model, stealth, operations,
  packaging, quick-start, implementation status, and changelog with the exact
  release behavior and supported scope.
- Rebuild all versioned ABI/package targets after the version bump; pass native,
  sanitizer, Go race, Debian source/binary metadata, installed-consumer,
  reproducibility, license, private-artifact, and release-manifest checks from a
  clean tag candidate. Add a second clean C++ binary comparison (today only the
  Go helper is byte-compared), pin release Actions by reviewed commit, and bind
  the dynamic `DT_NEEDED` set, glibc/libstdc++ floors, nghttp2/toolchain inputs,
  SBOM, and provenance attestation into the release evidence. Exercise the
  separate publish job in a declared compatible runtime. The candidate fix
  statically embeds pinned patched OpenSSL and rejects `libssl`/`libcrypto`
  dependencies; close this item only after exact artifact inspection and
  execution in the fresh publish environment.
- Review the final `origin/main` delta, create a signed release commit and signed
  tag, and run the preparation-only release workflow with its explicit
  independent-review and RC-gate acknowledgements. Inspect artifacts before any
  publication action. Before publication is enabled, make automation enforce
  this policy: current preflight checks only that the named tag resolves to
  `HEAD`, not `git verify-commit`/`git verify-tag`, and artifact signatures are
  optional when `GPG_PRIVATE_KEY` is absent. A publish job must fail when the
  trusted commit/tag signatures or required artifact signatures are missing.
- Publish only claims directly supported by retained evidence. In particular,
  hybrid post-quantum establishment is not “quantum-proof,” structural parity
  is not indistinguishability, and Linux qualification is not Android or
  cross-platform support.

## Product goals that require evidence, not promises

The longer-term goal is to make YUME difficult to distinguish from its chosen
cover workload while remaining safe and usable on constrained and high-latency
hosts. “DPI/neural cannot learn YUME,” “works on any server,” and “high ping can
never interrupt a session” are not acceptable release claims. Use these
bounded gates instead:

- **Classifier resistance (scoring engine frozen, dev6):** the decision rules
  now live in `config/classifier_gate_v1.json` and are executed by
  `scripts/yume_classifier_gate.py`. They were written before any candidate
  capture existed, which is the whole point: thresholds chosen after seeing
  results are not a gate. The protocol is hashed into every result, the split is
  leave-one-group-out over capture day / host / network / provider, the
  bootstrap resamples whole groups rather than sessions, and the verdict follows
  the *strongest* classifier because an adversary picks the best one. Feature
  extraction is deliberately a separate later stage so it cannot influence the
  frozen thresholds. Calibration is pinned by
  `scripts/test_yume_classifier_gate.py`: identical arms pass, a half-sigma
  difference fails, and a per-group bias applied to both arms yields no
  advantage. `config/classifier_gate_v1.json` is still
  `status: draft-pending-signoff` -- the numeric ceilings need an explicit
  decision *before* the first real evaluation, after which they must not move.

  **Consequence for capture planning:** the preconditions require at least 40
  sessions per arm spread across at least four groups, and refuse to return a
  verdict otherwise (exit status 2, `INSUFFICIENT`, never a pass). The planned
  five-run campaign supplies five sessions per arm from one host on one day. It
  is roughly an order of magnitude short of what any held-out claim needs, and
  no threshold choice fixes that. Capture volume and diversity have to grow
  before the gate can return anything but `INSUFFICIENT`.

- **Classifier resistance (remaining):** evaluate complete sessions with train/test groups
  separated by capture day, host, network and provider; compare more than one
  classifier; report confidence intervals, ROC-AUC, PR-AUC and true-positive
  rate at pre-declared low false-positive rates. Include active probes and the
  metadata an observer really sees. Freeze thresholds before examining the
  candidate results. A passed fixture or matching JA3/JA4 is not this gate.
- **Latency tolerance:** retain the negotiated byte, frame and sender-active
  time limit as hard security caps. The authenticated-ACK RTT estimator landed
  in dev6 and drives the rekey ACK deadline only, as
  `clamp(SRTT + 4 * RTTVAR, 5 s, 30 s)` frozen per offer; the 60 s keepalive
  stall bound remains the separate watchdog and the cap sits below it. See
  `docs/YUME_2_0_WAN_BEHAVIOR.md`. Preparation depth and lead time are still
  static, on purpose: they are wire-visible and the deadline is not, so they
  stay behind the classifier-evidence gate. Peer-supplied timestamps and
  unauthenticated observations do not steer the estimator. Unit coverage exists
  for clamping, freezing, queue ordering and the epoch-limit invariant; still
  required before any latency-tolerance claim are the real first-exchange,
  steady-state, loss, reordering, outage and recovery matrices.
- **Constrained operation:** publish minimum/candidate host tiers only after the
  full TLS, hybrid-PQ, ratchet and Node cover stack passes under explicit cgroup
  CPU, RSS, task and fd limits. Record handshake/rekey p95/p99, throughput,
  queue growth, overload rejection and recovery. Resource pressure must not
  silently downgrade cryptography or change cover identity.
- **Portability:** replace “any server” with an exact OS, architecture, libc,
  toolchain and package matrix. Each supported cell needs a reproducible build,
  dependency/SBOM evidence, startup/service check and real or named-emulation
  smoke. The current narrow target remains glibc Linux x86_64 CLI/server; the
  helper is a separately labelled optional comparison arm until retirement.

Timing or padding shaping may be considered only after real-cover captures
define the target distribution and a held-out comparison demonstrates benefit
within a frozen overhead budget. Uniform or per-install “randomish” timing is
not automatically camouflage and may create a durable classifier feature.

The reason is worth keeping explicit, because “add random jitter” keeps
resurfacing as a proposal. Under Kerckhoffs the adversary knows the algorithm,
so they know the distribution being sampled from and can test against it. Three
consequences follow. First, randomising a rotation interval cannot improve a
security bound: the bound is the tail of the distribution, so either it is
capped -- in which case the cap is the real parameter and the randomness only
adds cost -- or it is uncapped, in which case there is no bound at all. Second,
a per-install or per-host random parameter is a fingerprint: an observer who
sees `n` intervals estimates the parameter with error shrinking as
`1/sqrt(n)`, so after enough rotations the draw itself links sessions to a
host. Randomness that is not identically distributed across the whole
population identifies the population member. Third, uniform or Gaussian jitter
is not what real traffic looks like -- inter-arrival times in browser workloads
are heavy-tailed -- so injecting it is a positive signal, and a two-sample test
separates it from the cover with power growing in `sqrt(n)`. The target is
never randomness; it is the cover's measured distribution, which is why the
capture gate exists.

## Current continuation boundary (2026-08-21)

1. At the 2026-08-21 read-back, the latest product-code checkpoint on local
   `main` and `origin/main` was signed commit
   `97ed846dcae92c4d8b5a67173c8d9a5c1e7c4341`; workflow-owned `origin/DEV`
   had exact tracked-tree parity. CodeQL, Code Quality, and branch sync passed
   for that commit. Refresh Git before relying on branch tips.
2. CI run `32443839339` proved the pinned OpenSSL 3.5.7/nghttp2 environment and
   completed both native and sanitizer builds. Both CTest lanes passed 69/70;
   only `yume_browser_sandbox_test` failed.
3. The failing unit fixture invoked real certificate generation before the
   behavior it meant to test. Its previous fixed `PATH` paired Ubuntu's OpenSSL
   3.0 executable with pinned 3.5.7 libraries; retaining the inherited path
   removed that crash but exact CI still exited silently before the intended
   fake-Chrome diagnostic. The current working-tree correction supplies a
   strict test-local `openssl` that creates only the dummy fixture outputs and
   restores `fake-bin:/usr/bin:/bin`; production sandboxing, hash gates, and
   capture failure handling are unchanged.
4. The direct browser-sandbox suite passes 38/38 with the correction, including
   the intended unsuccessful-Chrome diagnostic and absent sanitizer marker. A
   subsequent isolated GCC 14.2 run found a mixed-LTO/shared-ABI link defect and
   a non-repeatable vendor `ensure` path. The working-tree corrections propagate
   the required non-LTO policy from protected ABI input archives, retain LTO for
   ordinary builds without the shared ABI, and accept an existing vendor tree
   only when it matches a fresh verified extraction. Strict shared-ABI Release
   and serial ASan+UBSan then passed 70/70 each; CLI smokes and pinned Go unit/
   race tests passed. Require the same 70/70 result in CI, then complete the
   fresh exact-signed-tree dependency, sanitizer, reproducibility, Debian/ABI,
   package, preflight, and artifact checks not reached by the prior remote run.
5. The `97ed846` source checkpoint is **NO MERGE CLAIM / NO RELEASE**.
   A documentation-only successor does not change that verdict. Historical
   Gate A closure remains valid only for its named checkpoints.
6. Gate B's blocker is cleared but Gate B is not closed. The real-CDP
   `Page.navigate` timeout was Chrome's own startup service traffic stalling the
   browser's network pipeline for about 24 seconds, not a YUME, Node, or driver
   defect; captures now run inside a loopback-only network namespace via
   `scripts/yume_capture_netns.sh`, and a real two-run campaign completed with
   the pinned Chrome and Node. See `docs/YUME_2_0_DEV6_HANDOFF.md`. Still
   required: the matched five-run normal and YUME campaign, the validator
   comparison, and every classifier and probe gate above. Note also that all
   pre-existing captures were taken with egress and therefore contain
   Chrome-to-Google traffic the YUME arm never produced; they cannot be reused
   as matched inputs.

## Earlier continuation boundary (2026-08-14)

1. Gate A is `MERGE` for continued development and `NO RELEASE` at signed
   commit `e4786e049fea7b786148e55b806e37fea401741e`. CI, Pages, branch sync,
   dynamic CodeQL/Code Quality, and static CodeQL `31777856725` passed.
   Workflow-owned `DEV` has tracked-content parity. No PR was opened and `DEV`
   was not pushed directly.
2. The exact `e4786e0` Gate B artifact preparation passed fresh Release 63/63,
   pinned Go unit/race, Debian/ABI/installed-layout, reproducibility,
   private-artifact, Linux preparation, preflight, checksum, and transfer
   round-trip gates. It qualifies capture inputs only.
3. The first same-session campaign failed closed during normal-Chrome run 3
   because the driver could evaluate the old `about:blank` context immediately
   after `Page.navigate`. Runs 1-2 are complete but the third is partial; the
   YUME arm and matched validator never ran. The result is neither `PARITY` nor
   `DRIFT`, and no predecessor run may be reused.
4. Signed corrective checkpoint `4a9c24d` waits for the exact
   navigated frame and loader, bounds CDP/HTTP/socket operations, passively
   confirms Node is listening before the relay, and registers deterministic
   Node regressions in package and CTest automation. Signed commit `4a9c24d`
   passed clean exact-commit artifact preparation and CodeQL. Both CI lanes
   built and passed 65/66 tests; only a shared isolated fixture failed because
   it omitted the `rg` executable used by the passive listener wait. The
   signed `e4786e0` checkpoint supplies that test-local shim and passes
   browser-sandbox 38/38. Its read-only review, automatic read-back, and clean
   exact-commit artifact preparation passed.
5. The fresh `e4786e0` campaign failed closed in normal run 1 because real
   Chrome DevTools did not answer `Page.navigate` within the bounded 15-second
   command deadline. No normal arm, YUME arm, or matched report completed, so
   the result is neither `PARITY` nor `DRIFT`. A direct exact-Chrome/Node canary
   reproduced the timeout without the TLS relay or any YUME path. Mocked tests
   did not cover this real-CDP deadline. Both failed private capture roots were
   deleted after sanitized diagnosis under the operator's cleanup instruction.
6. Add reviewed deterministic stalled/late-CDP coverage and bounded
   payload-free navigation diagnostics, pass one fresh exact-Chrome canary,
   rebuild exact artifacts after any source change, then rerun the entire
   five-normal/five-YUME campaign in a fresh root with exact
   Node `24.18.0`, staged Chrome `151.0.7922.71`, a fresh profile, and a valid
   sandbox. Only an accepted matched-input report may unblock external
   classifier/active-probe work, WAN/netem matrices, and uninterrupted deployed
   soak. Gate B remains open.

No agent should silently turn “finish the checks” into permission to change the
wire contract, weaken fail-closed behavior, push `DEV`, publish artifacts, or
claim stable 2.0 before the applicable gates pass.
