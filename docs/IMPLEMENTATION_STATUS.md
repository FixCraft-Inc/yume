# YUME implementation status

This page is the current engineering status snapshot for features that are easy
to overstate. It should stay conservative: implemented means code exists in this
tree; tested means it has a specific validation path; planned means no supported
runtime contract should rely on it yet.

The native core/CLI/C-ABI stabilization candidate is not a synchronized
consumer release. Before publication remediation and commit splitting, its
aggregate passed
108/108 full RelWithDebInfo/warnings-as-errors tests, 103/103 client-only ABI
tests, and 104/104 Debug ASan+UBSan+LeakSanitizer tests. Those results are
behavioral evidence for the closely related implementation, not exact-source
qualification of the signed checkpoint after documentation and licensing
remediation. The GUI source contains only the facade adaptations required to
compile against the candidate, and the separate Android checkout must be
re-synchronized and re-qualified later.

YUME raises the cost of blocking and can reduce metadata exposure depending on
the route. It should not be described as impossible to block, impossible to
trace, or a replacement for a full anonymity network by itself.

The public code-health findings and their resolved/open state are maintained in
`docs/CODE_HEALTH.md`. In particular, packaging startability, strict operator
signing-key loading, history authentication-failure wiping, anonym refresh
thread ownership, C ABI stream-open rollback ownership, and the optional
static-Linux curl proof boundary are fixed in the current source. The common
operator-proof HTTPS boundary now rejects ambiguous endpoints, binds CA
verification to the configured DNS name or IP literal, and applies a bounded
request deadline and response limits. The live
tunnel rollback coverage gap and exact-candidate release qualification remain
open. The current source has behavior-preserving seams for parser domains,
local attach, AUTH state commit, TCP/UDP result classification, write
settlement, bounded control requests, and server worker/operator-proof
ownership; remaining large functions are not open defects solely because of
their line count.

## Local configuration and secure-material persistence

Status: the supported POSIX facade/CLI paths are bounded, no-follow,
owner-protected, transaction-locked, and atomically published with focused
failure/concurrency tests. Platforms that cannot provide equivalent guarantees
fail closed for the affected operation.

- Secure-material imports cap PEM input at 64 KiB, metadata at 16 MiB, records
  at 1,024, and labels at 256 bytes. Metadata JSON types, IDs, fingerprints,
  material types, and regular-file status are validated before use. New IDs
  are 128-bit random lowercase hex; legacy timestamp IDs remain readable, but
  persisted paths are ignored and the next mutation writes schema-v1 path-free
  metadata.
- Profile IDs accept only 1--64 ASCII lowercase alphanumeric/hyphen bytes.
  Profile JSON is capped at 1 MiB, display names at 159 bytes, and invalid or
  unsafe active pointers, including pointers to missing or unsafe profile
  entries, are not returned. Save, collision selection, active pointer updates,
  and removal share the profile transaction lock.
- Encrypted `.yss` share files are capped at 16 MiB before parsing or password
  KDF work. CLI and GUI use the same bounded read and exclusive mode-0600
  publication path; exports refuse overwrite, symlinks, and non-regular
  destinations. Bundle copies, moves, assignment, destruction, cancellation,
  and GUI dismissal wipe the private key, obfuscation secret, inner PSK,
  password, plaintext, and preview buffers they own.

## Masquerade and authorization hardening

Status: transport AUTH/permission gates and the relay-v2 authorization,
peer-identity, hybrid-establishment, ratcheted-record, and confined-file
boundaries are implemented with focused unit/build validation. External audit,
cross-platform qualification, and long-running adversarial concurrency/soak
validation remain.

- `PreauthServiceOnly` is persisted on the session and enforced by one
  post-auth dispatcher gate. Its allowlist is service.v1 OPEN, DATA/CLOSE on
  accepted service streams, and PING/PONG.
- Modern and legacy admin attach use the same trusted-relay, caller-outbound,
  target-inbound predicate at server admission. Ordinary relay routing enforces
  the target's chat/file/bytes policy, accepted OPEN must match the invite kind,
  and endpoint dispatch applies an exact kind/role/state transition table before
  handling decrypted JSON. Relay setup accepts exact protocol version 2 only:
  both endpoints composite-sign a canonical context containing the channel
  kind, visible endpoint IDs, fixed password policy, nonce, metadata digest,
  ephemeral ML-KEM-1024 and X25519 contributions, and the peer identities.
  Verified peers enter a per-channel `SessionRatchet`; DATA and rekey records
  share one ordered, bounded queue and an exact `YRR2` schema. TOFU commits only
  after transcript verification, pinned mode requires an explicit or persisted
  match, and admin always requires an explicit out-of-band pin. POSIX file
  receive is descriptor-confined, exclusive/no-follow, owner-only, and bounded
  by declared/chunk/cumulative/time limits; partials are removed. Windows
  file/bytes receive and secure mutable peer-trust storage remain unadvertised
  or fail closed. Federation still trusts the authenticated source server to
  enforce the caller half; adding a caller-policy proof would require an
  explicit wire-compatibility decision.
- AUTH requires a composite Ed25519 + ML-DSA-87 identity and verifies both
  signatures. Admin additionally requires a distinct composite identity from
  the separate admin store.
- Public-node startup requires obfs and a nonempty secret. Raw frame-looking,
  partial-timeout, malformed, wrong-key, bad-order, missing server-SETTINGS ACK,
  and authority/SNI/listener-port mismatch paths remain outside AUTH.
- The H2 opening uses corrected HPACK indexes, SETTINGS/ACK ordering,
  END_STREAM handling, serialized writes, and client-side decoy classification.
  Wrong-path responses use configured upstream/real/profile identity.
- `--real-root <dir>` serves GET/HEAD static assets under one root (safe path
  resolution, MIME, `Content-Length`/`Last-Modified`/nginx `ETag`, size cap),
  shared across the HTTP/1.1 probe and the H2 decoy, with HTTP/1.1 keep-alive
  across a page's assets (bodyless GET/HEAD only; per-connection request cap +
  idle timeout), conditional GET (`If-None-Match`/`If-Modified-Since` -> 304),
  and byte `Range` requests (-> 206 / 416). Static 200s use nginx-style framing;
  per-profile static templates are not yet implemented.
- The 2.0 CLI pins the only configured Chrome transport path. There is no flag
  to rotate or disable the fixture; the client registry holds exactly one
  profile entry.
- Whole-session close has a five-second deadline, pending service opens are
  capped at 64 per service and 256 total, service writes have bounded
  completion-owned admission, and packet senders are joined at shutdown.
  Inbound client EXEC is unavailable and the former detached process worker is
  removed. Principal shutdown paths use best-effort buffer erasure.

Focused validation in the current development tree covers the obfs codec and
decoy classifier, authorization predicate/tier, relay channel policy,
relay-v2 handshake/trust/record/runtime lifecycle and rekey queues, confined
file receive, public-node policy, TLS profile selection helpers, transport
core, and service-queue policy. A registered integration fixture launches two
real `yumed` nodes and two real clients, waits for reciprocal AUTH-v2
federation/directory exchange, then checks exact relayed bytes and channel
close. Final sanitizer and repeated integration results are recorded for the
pre-remediation aggregate above; the signed checkpoint still needs its own
exact-tip reconciliation rather than inferring qualification from the presence
of the fixtures.

## Capacity, admission, and key tiers

Status: implemented with unit and bounded multi-client runtime validation;
long-running adversarial resource-pressure testing remains.

- Regular and operator keys/policies are loaded as immutable shared snapshots.
  Runtime reload validates a complete replacement before atomically publishing
  it; failed reloads preserve the previous snapshot, and a public key appearing
  in both physical trust stores is rejected.
- Regular keys are either `individual` (one session by default) or explicitly
  shared `bulk` identities. Bulk keys have a server default cap (64), support a
  lower per-key cap, and cannot receive controller, exec, LAN/full-control,
  privileged codec/service, or federation policy. Their chat/file/bytes policy
  defaults to deny.
- The server has one aggregate tracked-session cap (256 by default) and one
  accept-rate controller shared by all listeners. Authenticated per-key
  admission is maintained by a dedicated thread-safe controller and released
  idempotently when sessions close.
- Optional `--egress-mbps` shaping uses a dedicated weighted-fair controller.
  Decimal per-key weights are bounded, and each bulk connection participates
  as a separately counted identity. With the cap unset, the limiter is not
  constructed and the existing data path only performs the null check.
- CPU and memory telemetry lives in the external benchmark harness, not the
  client/server binaries. Linux `/proc` sampling reports process CPU time,
  fair per-core utilization, RSS/peak RSS, thread counts, and host CPU/RAM
  context at a bounded interval.

Focused coverage includes concurrent auth snapshot reads/reloads, policy value
validation, identity admission/release races, weighted limiter behavior, and
resource-sampler aggregation. The approved 2026-07-20 `remote-builder` run admitted
100/100 full-auth clients and exercised two simultaneous bulk clients below the
64-session cap; see `docs/YUME_2_0_IMPLEMENTATION_STATUS.md` for the exact
throughput and host-resource evidence.

Not done / not fully tested:

- Version-pinned Chrome/Firefox captures or an external HTTP/2 conformance
  client against both accepted and decoy paths.
- Repository-wide TSan, long-running close/reconnect, and resource-pressure
  soak testing. Focused signal, service-admission, packet-close, and lifecycle
  concurrency tests pass TSan, and ASan + UBSan are configured for the unit
  suite, but those gates are not soak evidence.
- Portable bounded child-process cancellation is not implemented, so inbound
  EXEC remains explicitly disabled instead of starting detached work.
- Best-effort erasure is not a locked allocator and cannot erase prior copies.
- External HTTP/2 conformance, exact native browser/web-server identity, and
  ML/DPI immunity are not implemented claims. Full-session HTTP/2 is present in
  `0.2.0-dev6`, but external conformance and sustained-session release gates are
  still open. Direct one-stream LAN traffic reached line rate, and dev3 removes
  the modeled one-pending-epoch ceiling. The former high-RTT ceiling was traced
  first to explicit TCP buffer pins and then to H2/ratchet credit geometry, not
  cryptographic CPU or an offer-pacing defect. Matched 60/100/210-ms zero-loss
  evidence and the still-open loss/rate/bidirectional/soak arms are recorded in
  `docs/YUME_2_0_WAN_BEHAVIOR.md`.

## Host controller

Status: implemented, lightly validated.

- `host_mode`, `accept_yume_clients`, `client_deny_action`, HTTPS routes,
  extra listeners, runtime info, runtime filter reload, runtime session kill,
  and exposure checks are present in code and configuration.
- Current implemented host-controller backend scheme is
  `loopback://<ip-literal>:<port>` only.
- `tls_terminate`, `tcp_passthrough`, and `starttls_mail` listener modes exist.
- Validation so far is lightweight: shell syntax checks, diff whitespace checks,
  focused C++ syntax checks, and `host_types_test`.

Not done / not fully tested:

- Full WAN cutover test with only `yumed` bound to `:443`.
- Browser-level HTTPS ingress smoke against a real certificate, SNI route, and
  loopback backend.
- Cloudflare Spectrum / non-Cloudflare TCP passthrough exposure checks from an
  external network.
- Long-lived reverse-proxy soak, backend failure behavior, and real mail
  STARTTLS interop.
- Kernel/firewall-level packet blackhole behavior. `client_deny_action=drop` is
  a userspace close after accept, not a true pre-accept network drop.

## Public host mode

Status: config/API present; production cutover needs real deployment testing.

- `host_mode=private` is intended for a WAN-facing host that serves configured
  backends and rejects YUME clients.
- `host_mode=relay` is intended for host routing plus authenticated YUME
  clients on the same daemon.
- Private host mode avoids HTTP/2 ALPN when YUME clients are disabled because
  the current host reverse proxy is HTTP/1.x.

Not done / not fully tested:

- Real browser compatibility matrix for common Linux/Windows/macOS browsers.
- Direct public IP vs TCP proxy vs HTTP proxy deployment matrix.
- Certificate renewal, hot reload, and operational runbook coverage.
- Performance and memory measurements under public probe/load traffic.

## Application codecs

Status: registry-driven built-ins exist; external plugin codecs do not.

- `monero-rpc-v1` is the first built-in application codec. It lives entirely in
  `src/core/app_codec/builtin/monero_rpc.cpp` and reaches generic lookup through
  the explicit registry entry assembled in `src/core/app_codec/codec.cpp`.
- Codec identity, permission, request policy, body caps, and backend policy are
  carried on `CodecDescriptor`. Request dispatch reads those descriptor fields;
  the current config adapter still maps the Monero-specific backend option to
  its endpoint.
- Codec enablement flows through `--codec-allow <name>` / `allow_codecs` plus
  per-key `permissions.allow_codecs`.
- Codec streams use typed app-codec envelopes over normal YUME frames instead of
  raw TCP forwarding.

Codec plugin format decision: built-in C++ units now, sandboxed out-of-process
runner later. Dynamic `.so` / DLL loading is deliberately not planned as the
third-party path, because a dlopen'd codec would execute in `yumed` alongside
identity and session key material, and would freeze a C ABI for a surface that
is still moving. See `docs/APP_CODECS.md`.

Not done / not fully tested:

- Live `monero-wallet-cli` / `monerod` smoke against a real daemon.
- Regression tests for allowed/denied RPC paths and backend failures.
- A second built-in codec. The registry is generic and covered by
  `yume_app_codec_test`, but the multi-codec path has not been exercised in
  production.
- Sandboxed out-of-process plugin runner and its SPI for third-party codecs.

## Host-controller backend schemes

Status: loopback TCP only.

- Implemented: `loopback://127.0.0.1:PORT`, `loopback://127.x.x.x:PORT`, and
  `loopback://[::1]:PORT`.
- Not implemented: `service://`, `codec://`, and `unix://`.

Those schemes must stay rejected until runtime drivers exist and have their own
validation, timeout, permission, and test coverage.

## Federation and multi-hop privacy

Status: AUTH v2 single-hop federation with real two-node coverage and a
three-node line regression; this is federation, not multi-hop anonymity.

- Federation dials now speak AUTH v2 end to end (`yume/federation-v2`): the
  link performs H2-carrier admission, AUTH v2 with a composite identity
  (`--federation-identity`) and TLS-exporter channel binding, a per-peer PSK,
  and ratchet establishment, then rides the same protected-frame path as a
  client. The accepting peer uses the enrolled composite key's unique
  `federation_peer_id` and required `federation_psk_file` metadata to select
  that identity's pairwise PSK; it does not reuse the daemon-wide ordinary
  client PSK.
- `yume_federation_v2_integration_test` launches two real `yumed` nodes and two
  real clients, proves both links ready, exchanges both directory endpoints,
  and verifies exact relayed bytes plus channel CLOSE. Legacy hop plumbing and
  its inert Argon2 admission controller are removed. Release/soak and
  classifier evidence remain separate gates. It is not a Tor-like onion-
  routing layer.
- `federation.status` and `federation.topology` provide one redacted source of
  truth for configured and authenticated inbound-only peers, distinct overall,
  outbound, and inbound link state, advertised endpoints, edges, and active relay
  channels. `yume-net-map` and the attached daemon console use the same
  topology document and renderer. The document explicitly reports
  `transit.supported=false` and `transit.max_hops=1`.
- `yume_federation_cluster_integration_test` launches three nodes in a line,
  gives the A-B and B-C adjacencies different pairwise PSKs, proves all direct
  links, and holds the far endpoint absent and unroutable across multiple
  directory refresh cycles.

Designed but not implemented:

- Relay-channel-only transit through a hub, guarded by explicit operator opt-in,
  a bounded visible route vector, per-hop budgets, and pinned end identities.
- Exit/proxy traffic transit is explicitly out of scope; `yumed` remains a
  terminating proxy for SOCKS, forwards, and packet/TUN traffic.
- The complete staged design and required negative/evidence gates are in
  [`protocol/YUME_2_0_FEDERATION_TRANSIT.md`](protocol/YUME_2_0_FEDERATION_TRANSIT.md).

## Browser

Status: separate repo scaffolded; no production browser exists in this
tree.

- The separate Linux-first browser repository is not part of this tree.
- It currently contains a Qt Quick / Qt WebEngine scaffold, renderer adapter
  interfaces, a `libyume` wrapper boundary, and a placeholder `yume://` scheme
  handler.
- The intended first renderer is Qt WebEngine behind a renderer adapter so
  WebKitGTK or Servo can be added later.
- The intended transport integration is `libyume`, not launching the `yume`
  CLI as a sidecar.
- The intended first visible feature is loading a `yume://name.xxx:port`
  hidden-service page from a signed YUME directory.

Not done:

- Hidden-service descriptor format and signature verification.
- Browser-grade `libyume` ABI for descriptor resolution, circuit creation,
  `yume://` streams, trust roots, and safe circuit telemetry.
- 3-hop onion routing.
- Browser profile isolation tests.
- End-to-end `yume://` page rendering without normal DNS.

## Tor positioning

YUME can be useful as an additional stealth transport or bridge path for Tor in
restricted networks, and Tor-over-YUME is a valid route choice. Tor already has
its own pluggable transports and bridge ecosystem, so YUME documentation should
avoid claiming that Tor has no stealth. The accurate claim is that YUME provides
a different HTTPS-shaped transport and can be combined with Tor depending on
which party must not learn which fact.
