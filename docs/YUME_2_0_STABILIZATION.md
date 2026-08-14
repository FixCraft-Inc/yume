# YUME 2.0 stabilization and integration gates

Status: working checklist for the Linux x86-64 `2.0-dev6` vertical slice.
Passing the merge lane below permits landing reviewed development work on
`main`; it does not by itself make YUME 2.0 release-qualified.

## Supported 2.0 scope

The first credible 2.0 release is the glibc Linux x86-64 CLI client, Chrome TLS
helper, and `yumed` server described by the `linux-desktop-2.0` release profile.
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

For the current 2026-08-13 live-observer integration the operator explicitly
forbids a PR or temporary review branch. The authorized path is one reviewed,
signed commit directly on refreshed `main`, a push only to `main`, and one
workflow snapshot; do not poll long-running workflows. This narrow operator
instruction supersedes steps 2-3 above for this change only.

## Gate A: land dev6 on `main` while it remains development software

All items in this section block merging the current feature branch.

- Review the complete dirty diff on top of signed checkpoint
  `a673d3e058656ee86ebd68be742f1192cd0cbe95`. Confirm that it contains only
  the transport-profile/dependency modularization and synchronized status
  corrections described in `docs/YUME_2_0_DEV6_HANDOFF.md`.
- Review the generated/profile boundary for path containment, bounded input,
  duplicate identities, stale generated output, fail-closed helper selection,
  and absence of runtime downloads or installed-browser auto-selection.
- Confirm no authenticated profile ID, IPC version, AUTH field, KDF/AEAD/AAD
  label, algorithm, wire byte, or backend default changed.
- Create a signed commit and verify its signature. The validation source must
  then be a clean checkout at that exact commit; the prior remote overlay tests
  are strong regression evidence but are not exact-commit provenance.
- From a fresh remote clone with exact BaseFWX revision, pass the native and
  serial ASan+UBSan suites, pinned Go tests and `-race`, generator/metadata
  negative tests, fixture/TLS evidence checks, and `git diff --check`.
- Exercise the changed release path, not only its parser: produce the bounded
  Linux preparation artifacts, validate their manifest, perform two clean
  strict helper rebuilds, compare helper hashes, and run release preflight with
  the exact candidate artifacts and source commit.
- Pass Debian source consistency, the 42-symbol ABI checks, installed-layout
  tests, workflow YAML validation, and a clean private-artifact audit.
- Refresh `origin/main` immediately before integration. If it moved, redo the
  merge review and every affected validation rather than silently rebasing
  evidence onto new code.

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

## Gate B: authorize `2.0-rc1` as a stable-ish Linux preview

These gates may follow the merge. Until they pass, keep the source version at a
development label, keep `chrome151` opt-in, and avoid release-parity claims.

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
  adjacent reproducible helper, clean source identity, exact Chrome/Node
  identities, PEM certificate hash, DER leaf pin, TLS-wire relay, per-run
  behavior, and runtime snapshot are bound into that arm. The runner never
  copies the external client config or its secret files.
- Complete external H2/WebSocket conformance and passive-classifier/active-probe
  tests, including malformed extended CONNECT, replay, ordinary cover paths,
  backend outage, certificate/site consistency, and hosting/IP metadata. Record
  every remaining classifier-visible difference; do not claim DPI immunity.
- Run matched one-tunnel WAN upload, download, and bidirectional matrices at
  60, 100, and 210 ms, at 100 Mbit/s and approximately 1 Gbit/s, with controlled
  loss. Freeze binaries, TLS backend, payload, stream geometry, NIC state, and
  exact commands; retain machine-readable reports for at least three matched
  samples where medians are compared.
- Diagnose the observed roughly 25 Mbit/s delayed-path ceiling before accepting
  high-RTT performance or tuning the ratchet again.
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
  key erasure, helper isolation, profile registry, downgrade resistance, and
  failure paths. A same-agent self-review is useful but is not independent.

Only after these items pass should a separate change consider switching the
Linux release default from `openssl-diagnostic` to the qualified helper and
bumping to `2.0-rc1`.

## Gate C: call the narrow target exact `2.0`

- Resolve every blocking RC review finding and repeat any evidence affected by
  source, dependency, fixture, browser, toolchain, kernel, NIC, or workload
  changes.
- Reconcile CLI help, wire contract, threat model, stealth, operations,
  packaging, quick-start, implementation status, and changelog with the exact
  release behavior and supported scope.
- Rebuild all versioned ABI/package targets after the version bump; pass native,
  sanitizer, Go race, Debian source/binary metadata, installed-consumer,
  reproducibility, license, private-artifact, and release-manifest checks from a
  clean tag candidate.
- Review the final `origin/main` delta, create a signed release commit and signed
  tag, and run the preparation-only release workflow with its explicit
  independent-review and RC-gate acknowledgements. Inspect artifacts before any
  publication action.
- Publish only claims directly supported by retained evidence. In particular,
  hybrid post-quantum establishment is not “quantum-proof,” structural parity
  is not indistinguishability, and Linux qualification is not Android or
  cross-platform support.

## Current continuation boundary (2026-08-13)

1. Gate A is `MERGE` for continued development and `NO RELEASE` at signed
   commit `815ea405568edeb661389bae128a6678cb4cdf1b`. All five automatic
   workflows passed and workflow-owned `DEV` had content parity. No PR was
   opened and `DEV` was not pushed directly.
2. The exact `815ea40` Gate B artifact preparation passed its fresh strict
   Release, Go unit/race, Debian/ABI/installed-layout, reproducibility,
   private-artifact, Linux preparation, preflight, and transfer-round-trip
   gates. It qualifies capture inputs only.
3. The first same-session campaign failed closed during normal-Chrome run 3
   because the driver could evaluate the old `about:blank` context immediately
   after `Page.navigate`. Runs 1-2 are complete but the third is partial; the
   YUME arm and matched validator never ran. The result is neither `PARITY` nor
   `DRIFT`, and no predecessor run may be reused.
4. The corrective checkpoint containing this checklist waits for the exact
   navigated frame and loader, bounds CDP/HTTP/socket operations, passively
   confirms Node is listening before the relay, and registers deterministic
   Node regressions in package and CTest automation. Focused local validation
   passes; its independent read-only review, signed checkpoint, automatic
   workflow read-back, and clean exact-commit artifact preparation control the
   next launch.
5. Rerun the entire five-normal/five-YUME campaign in a fresh root with exact
   Node `24.18.0`, staged Chrome `151.0.7922.71`, a fresh profile, and a valid
   sandbox. Only an accepted matched-input report may unblock external
   classifier/active-probe work, WAN/netem matrices, and uninterrupted deployed
   soak. Gate B remains open.

No agent should silently turn “finish the checks” into permission to change the
wire contract, weaken fail-closed behavior, push `DEV`, publish artifacts, or
claim stable 2.0 before the applicable gates pass.
