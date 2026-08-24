# YUME 2.0 desktop implementation status

Status: core/ABI/CLI stabilization checkpoint implemented; frontend/platform
and release gates remain incomplete.

The older signed-commit inventory and performance chronology are in
`docs/YUME_2_0_DEV6_HANDOFF.md`; its dated ordered-work sections are historical.
This page carries the current implementation and consumer-readiness boundary.
The explicit development-merge, `0.2.0-rc1`, exact-`0.2.0`, and branch-sync gates
are in `docs/YUME_2_0_STABILIZATION.md`.

This is a truthful inventory of the focused Linux x86-64 client/server work. It
does not claim Android, GUI, nginx, alternate browser profiles, H3, multi-hop
anonymity, Windows runtime, or release qualification. Composite AUTH,
dual-identity admin, and single-hop federation are implemented in the CLI/server
scope. Development-merge evidence must
include a fresh full optimized and sanitizer qualification of the exact signed
tree; results from an earlier checkpoint do not transfer across corrections.

## 2026-08-23 stabilization checkpoint (authoritative)

The shared Linux x86-64 core, stable C ABI, and CLI gate selected before later
GUI/Android synchronization is closed in this checkpoint. This supersedes the
older 80/86-test development totals below. It does not qualify a release,
mobile/desktop consumer, Windows, or ARM.

Implemented and regression-covered:

- bounded carrier receive credit, cover-request/pending-wire admission,
  service and endpoint writes, packet batches, and TCP/UDP proxy queues;
- strict typed OPEN/CONTROL/auth schemas and containment, disabled inbound
  EXEC, collision-safe stream-ID reservation, and rollback-safe publication;
- durable atomic POSIX config/key transactions, immutable five-file server
  authorization snapshots, typed ABI errors, and real strict-C stream
  integration;
- relay-v2 composite peer identity, pinned/TOFU trust, ephemeral hybrid KEX,
  per-channel ratchet, ordered bounded records, pinned outbound file sources,
  atomic receive publication, and deterministic teardown;
- facade, transport, reverse-listener, federation, cancellation, and callback
  lifecycle ownership, plus scope-bound wiping of exceptional-path secrets.

The exact-source Release matrix passed 102/102 tests with both system OpenSSL
3.5.6 and pinned OpenSSL 3.5.7 under first-party warnings-as-errors. Eight
high-risk tests passed 20 repeats apiece, the C++ and Go Chrome-helper tests
passed ten repeats apiece, and the exact Go 1.26.5 module passed its offline
read-only race suite. Shared-library and CLI dependency scans found no missing
or unresolved symbols; the normal developer Release lanes statically link the
prepared liboqs and Argon2 archives.

The client-only warnings-as-errors ABI build completed 379 build steps and
passed 101/101 tests plus `ldd -r`. The full serial
ASan+UBSan+LeakSanitizer suite passed 102/102 with leak detection and
halt-on-error enabled. Eight concurrency/lifecycle tests each passed ten
executions under TSan. The optional GUI completed 231 warnings-as-errors build
steps, `ldd -r`, and its help-path smoke; that is only a compile/link gate. A
checksum-pinned liboqs 0.16.0 archive was built from the declared source,
selected by exact cache and link path, reported as 0.16.0 by the CLI, and
passed 102/102 Release tests.

The Go/uTLS helper is not scheduled for removal in this checkpoint. It remains
an experimental, opt-in, default-off backend because it is the only current
backend that passes the normalized Chrome 151 raw-first-flight gate. OpenSSL
C++ reaches exact JA4 and exact non-GREASE cipher/signature/extension sets, but
still lacks equivalent GREASE geometry, extension placement/rotation, and the
required certificate-compression offer. Any later removal must first put the
C++ backend through the same wire, same-session, classifier, lifecycle, and
reproducibility gates.

Remaining work is deliberately outside the shared checkpoint: GUI/Android
consumer behavior; Windows/ARM/NDK/hardware; release/tag/artifact signing and
reproducible publishing; same-session Chrome/resumption/active-classifier
evidence; deployed slow-reader and WAN loss/jitter/bidirectional/soak; a
matched Xray/VLESS comparison; relay ancestor-symlink policy against another
local account; caller-synchronized ABI destruction; and server-to-client
layering cleanup.

### Historical pre-checkpoint core/ABI/CLI continuation

The current development tree also carries the completed core/ABI/CLI slice:

- The stable C header has prefix-safe build-info negotiation, documented exact
  millisecond timeout and zero-time poll behavior, clean EOF versus aborted
  stream semantics, strict config error mapping, and a real strict-C11
  server/client integration that exercises TLS/H2/AUTH, named streams,
  peer metadata, bidirectional payloads, half-close/EOF, and abort propagation.
- In-process server startup now crosses the same mandatory obfs/inner-secret and
  loopback-backend preparation boundary as CLI startup. Packet writes use a
  condition-variable-backed bounded batch queue with nonblocking, timeout, and
  shutdown wakeup behavior instead of polling.
- Relay setup is strict protocol version 2. Canonical composite signatures bind
  the channel context and both peer identities; ephemeral ML-KEM-1024 + X25519
  plus the fixed ordinary-channel PSK policy feed a per-channel
  `SessionRatchet`. The exact `YRR2` record schema, one ordered DATA/INIT/ACK
  path, bounded pending-application queue, rekey deadline, target policy, and
  kind/role/state authorization are covered by focused negative and lifecycle
  tests. TOFU commits only after a verified transcript; pinned mode and admin
  use explicit out-of-band composite fingerprints. The bounded POSIX file sink
  remains in use and Windows file/bytes/trust persistence fails closed where
  equivalent descriptor-relative protection is unavailable. The unused v1
  record/KDF implementation and tests have been removed.
- Linux qualification of this unsigned working tree passed the full optimized
  suite (80/80), full shared ABI (86/86), client-only shared ABI (85/85), and
  full shared-ABI Debug ASan+UBSan+LeakSanitizer suite (86/86). These are
  development results, not exact signed-commit or release qualification.

### Consumer synchronization gate (2026-08-23)

The stable C ABI is sufficient to begin Android and other consumer-side source
synchronization. An ABI v2 redesign is **not** a prerequisite: ABI v1 has exact
millisecond timeout/poll behavior, readiness through status polling, packet and
named-stream surfaces, and a real strict-C integration gate. Beginning a port is
not a support claim, however. The following consumer-specific defects must be
closed before either frontend is called synchronized or qualified:

- **Packet/VPN congestion (shared core closed):** `PacketChannel` retains an
  accepted, encoded outbound batch while waiting in bounded,
  cancellation-aware slices for transport admission. Temporary saturation no
  longer loses the dequeued batch or closes the channel; saturation/recovery,
  shutdown wakeup, and exact queue caps have focused tests. Android still needs
  its own JNI/device/VPN saturation gate.
- **Android migration:** the separate Android checkout still pins
  `0.2.0-dev1`, accepts a bare Ed25519 PEM even though dev6 requires the exact
  Ed25519 + ML-DSA-87 composite private identity, and its BaseFWX Java sync list
  omits direct dependencies `PasswordPolicy.java` and
  `PayloadKeySeparation.java` (plus the separately required `X25519.java`
  parity file). The socket-protector callback covers connected carrier sockets,
  not the resolver that runs first; use a numeric underlying-network endpoint
  plus `tls_server_name` until a protected resolver handoff exists. Shared
  pre-ready DNS/connect/proxy/TLS/H2/AUTH/helper cancellation is now prompt and
  regression-tested, but Android must still prove its VpnService revoke and
  airplane-mode handoff. Packet v1 is IPv4-only, so the VPN must block IPv6
  deliberately rather than route it to native or let it bypass. NDK/ARM, JNI
  lifecycle, device
  leak/revoke/reconnect, and forward/reverse throughput gates remain unrun.
- **GUI lifecycle (shared facade closed):** client/server facade start, stop,
  restart, join, callback reentrancy/exception, and destruction use serialized
  generations and separately owned workers. Pre-ready stop reaches every
  connection phase and cannot be followed by a late successful start. This
  removes the shared blocker; a real GUI window-level lifecycle smoke is still
  required before functional GUI qualification.
- **GUI facade/core preparation:** the DNS worker is owned and joined instead
  of detaching with an `App*`; the facade reports the actual security mode,
  effective composite/hybrid ratchet posture, TLS backend, rekey window,
  fingerprint, and server capabilities instead of deriving obsolete
  light/heavy/off status. The dead in-process log callback promise is removed;
  the typed `LogSink` remains the single log stream and now invokes reentrant,
  exception-throwing subscribers outside its lock. Chat open returns a real
  channel id, send/close enforce it, and history carries direction and time;
  the unused live-chat callback promise is removed. macOS bundle versions now
  follow the project version. The visual redesign must still remove the
  obsolete optional/light/heavy/dual server controls. `--headless` still exits
  successfully when valid session startup fails or configurations are absent,
  so it is not a real connect/stop/reconnect gate.

An isolated `YUME_BUILD_GUI=ON` RelWithDebInfo build of this exact source on
`192.168.1.165` completed all 209 build steps and `ldd -r` found no missing or
unresolved symbols. That closes only the compile/link check; no real GUI
connection, cancellation, restart, window, tray, or platform behavior was
qualified.

## Implemented

- A browser-neutral build-time transport-profile registry now owns profile
  aliases, fixture paths, artifact names, backend routing, and captured
  HTTP/2/HTTP/WebSocket identity. It generates checked-in immutable C++ data
  consumed through `cover_profile::active()` and the Go helper registry;
  active/authenticated-profile drift, stale generation, duplicate profile,
  alias, or helper identities, escaping artifact paths, unsupported dev6
  stream geometry, and incomplete metadata fail closed. The Go TLS helper
  resolves audited ClientHello providers by explicit build identity instead of
  branching in the connection lifecycle. Dev6 still
  admits exactly one authenticated profile; this is an extensibility boundary,
  not runtime profile negotiation or evidence for another browser.
- BaseFWX repository, exact commit, and minimum version are defined once in
  `config/dependencies.json` and consumed by CMake, build scripts, CI, CodeQL,
  and release tooling; a floating branch is rejected. The repeated Argon2
  discovery cache-reset correction and subsequent crypto/format hardening are
  separately signed, pushed, and pinned at
  `5c42eafbb95e5c7ea3b6cd57299d577be814f5f2`, so the YUME candidate no longer
  depends on an unpublished BaseFWX worktree.
- Full builds now fail configuration below OpenSSL 3.5 instead of discovering
  the missing ML-DSA-87 provider during AUTH. The official OpenSSL source
  revision is recorded beside BaseFWX metadata; CI, CodeQL, and release builds
  force a SHA-256-verified 3.5.7 source fallback, while native Linux development
  may use a capable system OpenSSL >= 3.5. Debian package metadata carries the
  same build and runtime floor explicitly.
- Prepared Linux release artifacts pin and checksum-verify liboqs 0.16.0,
  link it statically, and are rejected if they contain a dynamic `liboqs.so`
  dependency or an embedded runtime library search path.

- Version-pinned Chrome `151.0.7922.71` / Node `24.18.0` reference fixture,
  manifest, and sanitized HTTP/2 profile. One immutable Chrome 151/Debian 13 +
  Node 24 profile supplies the TLS selection, User-Agent/client hints, H2
  settings/priorities/header order, assets, and cover-server identity.
- A Linux-only experimental Chrome TLS backend is implemented as one pinned
  uTLS helper process per outer connection. The C++ parent performs direct or
  SOCKS/Tor routing and passes only the connected descriptor plus an anonymous
  IPC socketpair. The helper enforces TLS 1.3, hostname/CA/leaf-pin validation,
  `h2`, exact build/protocol identity, and returns the live 32-byte TLS
  exporter before proxying plaintext through bounded buffers. It runs with
  `no_new_privs`, strict IPC lengths/deadlines, and parent-owned child reaping.
  The build pins uTLS `v1.8.2`, module checksums, and Go `1.26.5`. Its bounded
  certificate/exporter, IPC, partial-I/O, cancellation, half-close, teardown,
  fd/zombie, process-scale, reconnect, and segmented-soak gates pass. It remains
  opt-in pending matched WAN, same-session stealth, classifier/active-probe,
  independent-review, and remaining RC gates.
- A capture-derived TLS wire parser and normalized profile gate now preserve
  cipher/extension/group/signature/version/ALPN order, key-share geometry,
  padding, and record lengths while normalizing only documented entropy and
  GREASE. Five complete authenticated helper flows now pass that structural
  gate; a fresh same-session normal-Chrome NetLog plus wire recapture remains
  required for release evidence quality.
- The Gate B capture inputs now have one immutable
  `cover-page-websocket-v1` workload shared by the direct HTTP/2 capture target
  and classifier-input validator. The production HTTP/1 cover backend remains
  a separate bounded GET/HEAD site because ordinary public RFC 8441 CONNECT is
  not an admitted carrier. The normal-Chrome runner can reuse a campaign
  certificate/SNI, binds clean source and user-namespace sandbox state, rejects
  output inside the checkout, and executes a private checksummed source
  snapshot. Portable relative checksums plus a final mode-0600 completion
  marker make failed, partial, moved, or tampered arms fail closed. This closes
  normal-arm provenance and workload-definition gaps.
- An opt-in production-carrier observer can now write the corresponding YUME
  `behavior.json` from actual nghttp2 and WebSocket events. It retains bounded,
  sanitized metadata only, correlates H2 PING/ACK internally without exporting
  opaque bytes, records real peer-window stalls rather than application data
  starvation, parses inbound raw frames across TLS-read boundaries (including
  CONTINUATION), and marks incomplete collection fail-closed without failing
  the carrier. The CLI accepts it only for the exact direct, single-tunnel,
  pinned-backend workload: 64 ordered 16-KiB messages are echoed byte-for-byte
  for exactly 1 MiB each way, then the authenticated application stream remains
  open through a 42-second quiet interval and a bounded graceful carrier close.
  Ordinary endpoint benchmarks retain their sequential upload/download
  behavior and normal logical-stream closes. The classifier reconstructs the
  stable summaries from the event stream, enforces exact successful H2
  lifecycle/cardinality and frame bounds, compares the ordered request sequence
  (including normal Chrome's stream-9 favicon request) and WebSocket control/data
  order, and rejects placeholders or inconsistencies. This is a capture
  capability and reports YUME
  framing/ratchet overhead rather than synthesizing Chrome-sized outer
  messages. The current production carrier's missing favicon stream and earlier
  server PING remain truthful classifier-visible drift rather than capture-only
  wire changes. It is not evidence that the required five matched runs,
  classifier/active-probe work, WAN matrix, or soak have passed.
- `tools/cover-node/capture_yume151_runs.sh` is the unprivileged YUME-arm
  producer. It requires a clean exact source, fresh owner-only output outside
  every Git worktree, a prepared bundle whose manifest binds the supplied YUME
  client and adjacent helper to that source commit, pinned Chrome/Node/helper
  identities, the adjacent helper selected explicitly, a certificate-valid
  SNI and separate DER leaf pin, and one
  per-run TLS-wire plus live-behavior report. It copies no config or secret,
  restores its relay on exit/signal, and seals the arm only after all five runs
  and their runtime-source/checksum manifests verify.
- Persistent nghttp2 carrier with priming page and asset requests, RFC 8441
  extended CONNECT, WebSocket masking/fragmentation/control frames, flow
  control, serialized writes, backpressure, and graceful H2 shutdown.
- Loopback-IP-literal-only Node backend proxy with startup health check, bounded
  headers/body/timeouts, hop-by-hop header removal, and no tunnel-data routing
  to Node.
- Strict file-only admission and inner PSK configuration. Both files are
  mandatory 32-byte random secrets encoded as exactly 64 lowercase hex
  characters and protected from group/world access.
- Version/profile/SNI/hour/nonce HMAC admission, authority matching, bounded
  replay cache, and ordinary cover behavior before AUTH on rejection.
- Canonical schema-3 AUTH transcript with strict parsing, exact
  `chrome151-node24-v1` challenge/response/confirmation fields, and composite
  Ed25519 + ML-DSA-87 authorization before ML-KEM work.
- Admin AUTH requires a second, different composite identity from the separate
  `admin_keys` store. The visitor identity must already be enrolled in the
  regular or operator store, so a preauth-only visitor cannot use an admin
  factor as an alternate admission route. The signed checkpoint passed the
  original live 5/5 admin matrix; the current correction passed the paired
  unenrolled-admin refusal and matched visitor-only preauth control.
- ML-KEM-1024 + X25519 + high-entropy PSK salted-HKDF root derivation. Argon2 is
  absent at connection establishment and per epoch.
- AES-256-GCM one-use message keys with profile/direction/epoch/sequence/type/
  stream/flags AAD binding. The same exact profile is included in the
  establishment root under a new dev6 label.
- Independent directional hybrid rekeys under an authenticated bounded policy.
  Extreme remains the default at 256 KiB, 512 encrypted data frames, or 500 ms
  of active epoch time; Normal, Soft, and exact bounded Ultimate profiles widen
  all three budgets without changing the mandatory algorithms or one-use
  message keys. The next epoch is prepared while
  bounded current-epoch traffic remains, hiding the exchange latency without
  increasing any hard usage limit. Idle silence, bounded boundary waits,
  timeout close, simultaneous rekeys, old receiving-chain retirement, and
  independent receiver enforcement remain fail closed. Server
  rekey/control frames are scheduled ahead of saturated DATA queues so normal
  throughput cannot turn congestion into a rekey timeout.
- Encrypted `.yss` migration uses the BaseFWX 12-character minimum and carries
  separate TLS/operator CA material, TLS/SNI name, admission secret, inner PSK,
  tunnel count, and operator-proof policy. Legacy v1 files that carried only
  the shared private CA remain importable.
- Exact `0.2.0-dev6` version and `chrome151-node24-v1` profile equality at
  admission, AUTH, establishment, and protected-frame boundaries. Schema-2
  AUTH/dev5, stale-profile, and missing-profile records have no downgrade path.
  Legacy
  inner/light/heavy/dual/hop/no-inner/raw-carrier and literal-secret CLI choices
  are rejected. The unreachable client-side 1.x AUTH response, Argon2 challenge
  metadata, and long-lived PQ auto-trust/reconnect implementation have been
  removed. The federation dial now speaks AUTH v2 as well (`yume/federation-v2`):
  carrier admission, composite identity, channel binding, per-peer PSK and
  ratchet establishment, so no live path retains the separate legacy AUTH and
  inner-key flow. Legacy hop derivation, skew-window decryption, cached state,
  configuration/share/status fields, and the inert Argon2 admission controller
  have now been removed. Focused legacy-AEAD negatives reject wrong key, wrong
  AAD fields, and ciphertext modification.

## Development evidence completed

- At the 2026-08-21 read-back, the latest signed product-code checkpoint was
  `97ed846dcae92c4d8b5a67173c8d9a5c1e7c4341`. Local `main` and
  `origin/main` agreed, workflow-owned `origin/DEV` had exact tree parity, and
  CodeQL, Code Quality, and branch sync passed. CI run `32443839339` confirmed
  the pinned OpenSSL 3.5.7 plus nghttp2 environment and built both native and
  sanitizer configurations, but each lane passed 69/70 because the same
  isolated browser-sandbox fixture exited before its intended fake-Chrome
  failure assertion. This is not an observed YUME runtime, AUTH, wire, or
  sanitizer defect, but that product-code checkpoint's development
  qualification is incomplete. Refresh Git before relying on branch tips.
- The current working-tree correction makes that unit fixture's certificate
  prerequisite hermetic with a strict test-local `openssl`, restores the
  bounded fake-command-first `PATH`, and leaves production fail-closed behavior
  unchanged. The direct browser-sandbox suite passes 38/38, including the
  intended unsuccessful-Chrome diagnostic and absent sanitizer marker. A
  subsequent isolated GCC 14.2 run exposed and corrected the shared-ABI
  mixed-LTO link policy and made signed vendor extraction safely repeatable.
  The resulting strict shared-ABI Release and serial ASan+UBSan lanes passed
  70/70 each; CLI help smokes and pinned Go 1.26.5 unit/race tests also passed.
  Ordinary non-shared-ABI builds retain LTO. Require 70/70 native and sanitizer
  CI plus the complete fresh exact-tree dependency/reproducibility/package/
  preflight lane before claiming current-head Gate A acceptance. Earlier
  exact-tree results remain evidence for their named commits only.
- Gate A first closed for continued development, with `NO RELEASE`, at signed
  commit `815ea405568edeb661389bae128a6678cb4cdf1b`: all five automatic
  workflows passed and workflow-owned `DEV` reached content parity. That
  checkpoint's clean exact-commit Gate B artifact preparation passed Release
  61/61, pinned Go unit/race, strict dependency, Debian/ABI/installed-layout,
  reproducibility,
  Linux preparation, exact preflight, and transfer-round-trip gates.
- The first same-session five-normal/five-YUME campaign failed closed during
  normal run 3 because the CDP driver could await fixture state in the old
  `about:blank` context. Two normal runs completed, but the third is partial;
  no YUME run or matched report exists. The corrective checkpoint waits for the
  exact frame/loader lifecycle, bounds CDP/HTTP/socket operations, passively
  confirms Node listener readiness, and registers deterministic Node tests.
  Focused local tests pass. This is a harness correction, not parity evidence;
  fresh exact-commit artifacts and an entirely new campaign remain required.
- Signed harness correction `4a9c24d8204d7acf97a1bdbaf344ef1aa412572f`
  passed fresh exact-commit Release 63/63, pinned Go unit/race, reproducibility,
  packaging, and round-trip gates. CodeQL passed. Native and sanitizer CI both
  built and passed 65/66 tests; their only failure was a shared isolated
  browser fixture that supplied fake `ss` but omitted the `rg` now used by the
  passive listener wait. The current checkpoint adds that test-local shim and
  passes browser-sandbox 38/38; production capture behavior is unchanged.
- Signed checkpoint `e4786e049fea7b786148e55b806e37fea401741e`
  passed CI, Pages, branch sync, dynamic CodeQL/Code Quality, static CodeQL
  `31777856725`, tracked-content parity with workflow-owned `DEV`, and fresh
  exact-commit Release 63/63, pinned Go unit/race, private-artifact,
  reproducibility, package-preflight, checksum, and transfer-round-trip gates.
- Its new same-session campaign failed closed during normal Chrome run 1:
  preflight, private-kit, Xvfb, Chrome DevTools, Node, and relay readiness
  passed, but real CDP `Page.navigate` did not answer within 15 seconds. No
  complete normal arm, YUME arm, or matched report exists. A fresh-profile
  direct Chrome-to-Node canary reproduced the timeout without the TLS relay or
  any YUME path, so this is a campaign-control failure, not `DRIFT`. The mocked
  navigation tests did not exercise the real CDP session/deadline. Both failed
  raw capture roots were deleted after sanitized diagnosis under explicit
  operator cleanup authority; they cannot be reused or independently
  revalidated.
- Signed live-observer architecture commit
  `1593fc62de89d613e107f1e173adf3edb7ed7568` passed independent read-only
  review, complete local native and serial ASan+UBSan suites, and a fresh clean
  strict `raptorlake` lane: native 66/66, serial ASan+UBSan 66/66,
  Release/LTO 61/61, exact Go 1.26.5 unit/race, 95 focused evidence tests,
  strict Argon2/OQS/LZMA, warnings-as-errors, Debian/42-symbol ABI, two
  reproducible helpers, exact Linux preparation, release preflight, and
  transfer round trip. This is Gate A development-integration evidence, not
  the same-session Chrome, WAN, deployed-soak, or independent release audit
  required for `0.2.0-rc1`.
- The architecture push's first GitHub CI run exposed one test-only portability
  defect: the Chrome/Node hash negative test assumed `ss` and `rg` were
  installed. Signed correction `815ea405568edeb661389bae128a6678cb4cdf1b`
  supplied inert test-local prerequisites without changing production behavior;
  its automatic workflows and branch-parity read-back passed.

- Exact Chrome loaded `/`, CSS, and JavaScript through `yumed` backed by exact
  Node `24.18.0`; the page completed its expected DOM readiness marker.
- Ordinary HTTP/1.1 and HTTP/2 GET/HEAD requests returned the same loopback
  Node site through `yumed`. After the backend was stopped, both paths returned
  bounded Node-shaped 502 responses without exposing a YUME marker.
- A persistent H2 benchmark transferred 1 MiB in each direction while crossing
  multiple 256 KiB rekey boundaries. Repeated short loopback runs reported
  about 217-240 Mbit/s combined throughput after capture-sized WebSocket
  shaping. These are smoke results, not sustained WAN or release throughput
  evidence.
- Wrong admission did not emit AUTH. Wrong PSK reached no usable plaintext
  session and failed inner AEAD authentication.
- A local real-SOCKS regression transferred 33 MiB continuously for 16 seconds
  across many rekey epochs, then completed a follow-up request on the same
  connection. This covers the prior server-side rekey-starvation disconnect;
  it is not an Android background-lifecycle or WAN throughput result.
- Focused unit/KAT coverage exercises AUTH parsing/transcripts, initial roots,
  directional keys/AAD/ciphertext, threshold transitions, idle behavior,
  simultaneous rekeys, rekey timeout, secret files, WebSocket framing, HTTP/2
  header/stream shape, and admission handling.
- The local benchmark harness now starts only `base-direct` and the mandatory
  `yume-v2` stack. Its 1.x raw/light/heavy/hop and Argon2/PQ-file rows were
  removed. Short development-laptop smokes measured about 79-96 MiB/s for
  `yume-v2`, depending on payload and concurrency; these are functional
  datapoints, not the pending full or sustained release benchmark.
- The crypto microbenchmark now uses the production SessionRatchet. A 2 MiB
  per-direction smoke with 64 KiB DATA frames measured about 415-440 MiB/s and
  performed seven authenticated hybrid rekeys per direction.
- The full profile passed on an approved 32-core Debian 13 host using liboqs
  0.16.0 and the pinned nghttp2 1.69.0 fallback. Across three 8 GiB, 64-stream,
  four-tunnel trials, `yume-v2` measured 226.19 MiB/s (1,897.44 Mbit/s) median
  with 0.709 ms median loopback RTT. Hybrid establishment measured 0.175 ms
  median and directional rekey 0.219 ms median. This proves ample local
  throughput, not WAN performance, Chrome TLS parity, or the pending bulk-wire
  overhead gate.
- A sustained direct-Ethernet authenticated stream-core matrix completed 1 GiB
  upload plus 1 GiB download at 1, 4, 16, and 64 logical streams without a
  queue overrun, replay failure, crash, timeout, or byte mismatch. With a
  production 256 KiB relay buffer, upload measured 311.9-362.8 Mbit/s and
  download 149.0-158.3 Mbit/s. This validates the DATA/ratchet/H2/WebSocket/TLS
  boundary on that single-tunnel LAN path; it excludes local SOCKS and target
  sockets, the packet ABI/TUN path, WAN behavior, and Android. The persistent
  download asymmetry in that historical build became the next profiling target.
- Receive-path profiling found that one maximum-size 256 KiB server DATA record
  consumed an entire byte epoch and delayed client delivery until the whole
  H2/WebSocket/AEAD record had arrived. Server target and benchmark-source reads
  are now capped at 32 KiB records; the 256 KiB / 512-frame / 500 ms ratchet
  limits and wire format are unchanged. In a controlled three-run loopback
  comparison with both processes configured with `YUME_RELAY_READ_BUF=256`,
  128 MiB per direction, and 16 streams, uncapped download measured 284.9
  Mbit/s median and capped download measured 1,077.7 Mbit/s median, a 278%
  increase. The capped upload median was 1,267.9 Mbit/s. This local functional
  run used Node 20.19.2 rather than the pinned Node 24 fixture; the direct
  Ethernet result was still limited by the dev1 stop-and-wait epoch exchange.
- Matched `0.2.0-dev2` client/server binaries pipelined that exchange without
  changing the 256 KiB, 512-frame, or 500 ms limits. On the direct
  10.77.77.2-to-10.77.77.1 one-gigabit link (940-941 Mbit/s raw iperf3), three
  256 MiB-per-direction one-stream trials measured 930.6 Mbit/s upload and
  930.6 Mbit/s download median. A final exact 1 GiB-per-direction one-stream
  run sustained 931.2/930.0 Mbit/s, while the requested 16-stream run sustained
  931.1/926.9 Mbit/s. Same-host one-stream endpoint traffic measured
  1,894.5/1,910.2 Mbit/s. These runs cover the authenticated
  DATA/ratchet/H2/WebSocket/TLS benchmark path, not SOCKS target sockets,
  packet ABI/TUN, WAN, Android, or a release soak. The generated benchmark
  bundle was retired during the 2026-07-28 machine cleanup; this document
  preserves the reviewed result, not a claim that raw artifacts remain in the
  checkout.
- Dev2 had only one pending future epoch, so exhausting 256 KiB before its ACK
  returned reintroduced a hard-boundary wait on a saturated high-BDP path: a
  model of about 35/21/10 Mbit/s at 60/100/210 ms RTT.
- Dev3 replaces that with a negotiated bounded window of authenticated,
  strictly contiguous future epochs (`--rekey-window`, default 8, range 1..64),
  raising the same model to `window * 256 KiB` per rekey round trip — about
  419/280 Mbit/s at 40/60 ms at the default depth. Every per-epoch limit is
  unchanged and the depth bounds both the ML-KEM work a peer can request and
  the number of prepared future epochs an endpoint compromise exposes. Unit
  coverage is in `src/core/security/session_ratchet_test.cpp` (window budget,
  progress pacing, inbound overflow, non-contiguous offer) and
  `src/core/security/auth_v2_test.cpp` (record vectors, range rejection).
  These are unit and model results, not measured WAN results: the 100 ms time
  lead and 64-frame lead can still run out on continuous or small-frame
  traffic, and H2/TCP bandwidth-delay-product work is still required before any
  WAN line-rate claim. See `docs/YUME_2_0_WAN_BEHAVIOR.md`.
- Timing instrumentation now uses one shared diagnostics layer. It is compiled
  only into Debug/RelWithDebInfo builds and remains runtime opt-in; Release and
  MinSizeRel contain no timing clocks, counters, handlers, event strings, or
  environment activation path.
- The external `/proc` benchmark sampler and bounded multi-client LAN harness
  passed a 1/2/4/8/16-process loopback ramp on a 24-core/32-thread x86-64 desktop
  host with 64 MiB per direction and 16 streams per client. At 16 clients the
  full-wall application rate was 9,023.5 Mbit/s; clients used 14.65 core-seconds
  (7.695 average cores, 24.046% of the machine) with a conservative 494.83 MiB
  summed peak-RSS bound. Over the matching sampled window, `yumed` averaged
  12.001 cores (37.502% of the machine), 70.34 MiB RSS, and 101.18 MiB peak
  RSS. All stages completed normally. This is same-host scaling evidence, not
  physical-LAN or WAN throughput evidence.
- Authorization keys and per-key policies are now loaded together into an
  immutable server snapshot at startup/reload instead of reparsing the metadata
  file in every session. A 50-client burst previously lost one authentication
  when a concurrent `last_seen` update overlapped a policy-file read; the same
  run passed 50/50 after the snapshot fix. A single bounded 100-client run then
  passed 100/100 with full ML-KEM-1024/X25519 authentication and ratcheted
  traffic. With 24 server workers, the 10.98-Gbit/s load window used 14.48
  average `yumed` cores (45.25% of the 32-thread host), 155.1 MiB average RSS,
  and 233.1 MiB peak RSS. This validates 100 same-host active clients; it is not
  an idle-connection soak or a physical-network result.
- On the same 50-client workload, 24 server workers slightly improved full-wall
  throughput over the 32-worker default (11.30 versus 11.21 Gbit/s) while
  reducing sampled `yumed` CPU from 15.51 to 14.65 average cores. Sixteen
  workers used 13.21 cores and 161.35 MiB peak RSS at 10.95 Gbit/s. This supports
  deployment-specific worker tuning; it does not justify a universal thread cap
  from one hybrid-CPU host.
- Server capacity policy now has an operator-facing bounded model: 256 live
  sessions by default, configurable bulk-key concurrency (64 by default),
  weighted fair egress through decimal per-key `weight`, and separate physical
  `operator_keys` authentication. Individual and operator keys admit one
  authenticated session; explicitly marked bulk-key sessions are counted and
  shaped separately. Bulk policies fail closed if they request exec, LAN,
  full-control, codecs/services, admin, or federation privileges. Process-wide hard CPU/RSS
  ceilings remain the job of systemd/cgroups; `threads`, accept/session limits,
  and filter memory bounds constrain YUME-owned work.
- A focused live policy smoke passed two simultaneous clients using one bulk
  key. Under a 64-Mbit/s egress cap their download shares were 30.8 and 32.6
  Mbit/s (63.4 Mbit/s combined). A separate smoke with an empty regular store
  authenticated through `operator_keys` and logged the explicit outbound-admin
  policy. These prove standard authenticated benchmark traffic and the physical
  operator store; they do not constitute a full GUI admin-attach workflow test.
- The current 2.0 carrier diagnostic provisions protected admission/inner
  secret files and the real loopback Node cover. An unprivileged local audit
  passed Chromium-through-SOCKS, H2 ALPN, and ordinary cover probing. Raw packet
  capture was unavailable on that host, so this adds functional evidence but no
  new ClientHello or Chrome-parity claim. The diagnostic emits JA3, JA4, and
  JA4_r evidence when `dumpcap` or `tcpdump` access is available.
- Five complete authenticated flows through the pinned uTLS helper passed the
  normalized Chrome 151 ClientHello and direct-Node ServerHello gate. They
  produced five distinct allowed extension orders and GREASE-ECH lengths of
  186, 218, and 282 bytes. The live test also caught and fixed helper build
  permissions, uTLS renegotiation disabling the mandatory exporter, relay
  authority binding, late half-close capture handling, and `yumed` choosing
  TLS cipher `0x1301` instead of Node 24's `0x1302`.
- Five matched loopback handshakes measured 10 ms median through the helper and
  1 ms through OpenSSL (+9 ms, within the 10 ms gate). Three matched 256 MiB
  upload plus 256 MiB download trials at 16 streams measured 1,793.8 Mbit/s
  helper median versus 1,780.6 Mbit/s OpenSSL median. This passes the local 5%
  bulk-overhead gate; this comparison itself is not WAN or loss evidence.
- TCP SOCKS, local-forward, and reverse-forward upload reads now wait for the
  prior transport write completion before reading another 64 KiB block. This
  preserves the bounded transport queue under a fast local producer instead of
  turning legitimate bulk traffic into an `application write queue full`
  disconnect. The self-test send path now suppresses SIGPIPE, unblocks and
  joins its reader on failure, and reports the underlying transport error
  instead of terminating during thread destruction. A fresh 32 MiB
  bidirectional quick smoke completed at 121.60 MiB/s (1,020.05 Mbit/s) on the
  development laptop; this is a regression signal, not a release benchmark.
- At exact clean signed lifecycle commit `30cad6e`, isolated Linux
  qualification completed 1/10/50/100/256 Chrome-helper process ramps, 1,000
  sequential reconnects, and a 2,333-second bidirectional full-speed batch.
  The 256-client run held 256 clients plus 256 helpers and moved 65,536 MiB
  exactly with zero unexpected failure. Reconnects completed 1,000/1,000 with
  server fds/threads 8 -> 8 and 34 -> 34, and no post-cleanup helper or zombie.
  The soak moved 225,280 MiB exactly at 816.607 Mbit/s aggregate with zero
  timeout, interruption, mismatch, or unexpected server error. It used seven
  back-to-back segments to preserve the signed endpoint's 16,384 MiB
  per-invocation bound, so it is not one uninterrupted >16 GiB connection or
  matched WAN evidence.

## Required before `0.2.0-rc1`

- Run an actual desktop tunnel bidirectionally across multiple epochs and
  reconnect cleanly in the intended deployed network; current long-flow and
  reconnect qualification is same-host loopback evidence.
- Complete external HTTP/2/WebSocket conformance checks, not only project tests
  and Chrome interoperability.
- Exercise sustained carrier flow-control stalls, malformed carrier paths,
  backend timeout/failure, and bounded backpressure under deployed-network
  load. Helper partial control/plaintext I/O and teardown are already covered.
- Decide the time-limit threat model explicitly. Today the receiver
  independently enforces inbound byte/frame usage while the configured active-time boundary is
  sender-local. A signed timestamp does not make a malicious sender's clock
  truthful. Alternatives are to retain and document the honest-sender rule, or
  enforce a receiver-local lifetime from first authenticated arrival and accept
  its delay/availability tradeoff. Any wire timestamp needs explicit semantics,
  a version/AAD change, and a leakage analysis.
- Fuzz WebSocket reassembly across mid-record splits, multi-fragment binary
  messages, and interleaved PING/PONG control frames. Strict inner-record
  sequencing makes this carrier boundary security-critical.
- Capture and compare the live YUME connection against the committed fixture;
  record every remaining classifier-visible TLS/H2 difference.
- Run the external-classifier gate on complete-session groups with held-out
  day, host, network and provider rather than a packet-random split. Freeze the
  feature set and threshold first; report multiple classifier families,
  confidence intervals, ROC/PR results and detection at low false-positive
  rates. Include active probes and metadata-only baselines. This can bound a
  measured advantage; it cannot prove that future DPI or a neural model is
  unable to learn YUME.
- Preserve fixture-backed coherence between the TLS selection, HTTP headers,
  H2 shape, assets, and cover server while closing the remaining OpenSSL
  ClientHello differences.
- Obtain independent cryptographic/protocol review and adversarial deployment
  testing before authorizing `0.2.0-rc1`.

## Required before exact version `2.0`

- A valid uninterrupted tunnel lasting at least 30 minutes in the intended
  deployment environment. The current >30-minute loopback qualification is a
  seven-segment bounded batch, not one continuous >16 GiB connection.
- Broader fuzz, disk/log-pressure, graceful reload/shutdown, and adversarial
  operational soak beyond the completed native sanitizer and loopback gates.
- Complete the implemented bounded-future-epoch qualification with matched
  one-tunnel upload/download/both matrices at 60, 100, and 210 ms, 100 Mbit/s
  and approximately 1 Gbit/s, plus controlled loss and a 30-minute soak. The
  exact candidate already has three interleaved default-path repeats at 60 ms
  and two diagnostic repeats at 100/210 ms under a 1-Gbit/s, zero-loss cap;
  those runs found no manual-credit regression or stall. The former ~25-Mbit/s
  result was diagnosed as pinned TCP buffers followed by H2/ratchet credit, not
  cryptographic CPU or offer pacing. The missing rate/loss/bidirectional/soak
  arms remain release work; see `docs/YUME_2_0_WAN_BEHAVIOR.md`.
- Security-negative coverage for counter wrap and all malformed/tampered cases
  in the acceptance list, plus independent review of key erasure and failure
  paths.
- Directly affected CLI, wire, stealth, threat-model, and deployment docs
  reconciled with the final capture and commands.
- If the release claims constrained-host support, qualify the named CPU/RAM
  tier with the full Chrome-helper/Node/hybrid-PQ stack under cgroup limits and
  retain latency, RSS/fd/queue, overload-rejection and recovery evidence. If it
  does not pass, omit the claim rather than weakening cryptography.
- If the release claims any target beyond glibc Linux x86_64 CLI/server/helper,
  add an exact OS/architecture/libc/toolchain/package matrix with native or
  explicitly named emulation smoke evidence. “Any server” is not a supported
  scope.

The negotiated rekey window and preparation lead remain static, but the ACK
deadline is implemented as `clamp(SRTT + 4*RTTVAR, 5 s, 30 s)` from locally
measured, authenticated, offer-ordered ACKs and is frozen per offer. This is a
liveness adaptation only: it never expands negotiated byte/frame/sender-active-
time security caps. Extreme-RTT claims still require real first-exchange,
steady-state, loss, reordering, outage, and recovery evidence. Any future
preparation-depth/lead adaptation is wire-visible and remains classifier-gated;
arbitrary “randomish millisecond” rotation is not an accepted substitute.

## Known residual

The former Chrome 131/150 and Windows/Linux identity mismatch is fixed behind
one immutable Chrome 151/Debian 13 + Node 24 profile. The normal build still
defaults to the explicitly named `openssl-diagnostic` backend. The new pinned
uTLS helper builds reproducibly with official Go 1.26.5 and its five live
first flights pass the normalized ClientHello/ServerHello structural gate.
Selecting `chrome151` never silently falls back: a build without the helper
fails closed. The bounded certificate/exporter and process lifecycle matrix,
process ramps, reconnect storm, segmented full-speed soak, and partial matched
WAN qualification pass. The remaining WAN loss/rate/soak arms, one
uninterrupted deployed-network soak, exact Chrome `151.0.7922.71` same-session
capture, classifier/active-probe evidence, and independent review remain
required before that backend becomes the default or YUME claims release-
qualified Chrome parity. Matching ALPN or a coarse JA3/JA4 summary is
insufficient. Traffic padding is likewise an evidence-driven option, not an
automatic improvement.

Client AUTH sends a composite Ed25519 + ML-DSA-87 public identity and both
signatures over the complete
canonical challenge/response transcript; it never sends the private key. As of
`0.2.0-dev4` the signature input also covers a 32-byte RFC 8446 exporter that
each endpoint derives from its own live TLS object and never transmits, and the
same value is folded into the establishment root. A malicious terminating
endpoint with compatible admission/PSK access can no longer relay a live AUTH
exchange to a second server: the forwarded signature is over a different
connection's exporter. Both endpoints require TLS 1.3 and a finished handshake;
there is no unbound mode and no way to negotiate the binding away.

Identity-file safety is now a creation and loading invariant rather than
operator hygiene. Composite generation serializes the Ed25519 and ML-DSA-87
halves into one private and one public file, creates both through the exclusive
owner-only writer, wipes the private PEM buffer, and refuses to replace an
existing path. `crypto::load_composite_keypair()` reads the private file through
an already-validated descriptor and requires exactly two private-key PEM blocks
in the fixed order. Windows has no equivalent ownership/mode enforcement and
fails closed, which remains open work alongside protected secret loading there.

The hybrid ephemeral establishment/rekeys provide a forward-secrecy design
against later long-term-file compromise, not secrecy from `yumed` itself.
`yumed` terminates the ratchet and handles decrypted stream bytes. Historical
secrecy still depends on honest non-retention, ephemeral erasure, primitive/RNG
security, and the absence of live endpoint compromise.
