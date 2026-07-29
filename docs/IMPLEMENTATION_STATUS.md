# YUME implementation status

This page is the current engineering status snapshot for features that are easy
to overstate. It should stay conservative: implemented means code exists in this
tree; tested means it has a specific validation path; planned means no supported
runtime contract should rely on it yet.

YUME raises the cost of blocking and can reduce metadata exposure depending on
the route. It should not be described as impossible to block, impossible to
trace, or a replacement for a full anonymity network by itself.

## Masquerade and authorization hardening

Status: implemented with focused unit/build validation; external protocol and
long-running concurrency validation remain.

- `PreauthServiceOnly` is persisted on the session and enforced by one
  post-auth dispatcher gate. Its allowlist is service.v1 OPEN, DATA/CLOSE on
  accepted service streams, and PING/PONG.
- Modern and legacy admin attach use the same trusted-relay, caller-outbound,
  target-inbound predicate. Federation still trusts the authenticated source
  server to enforce the caller half; adding a caller-policy proof would require
  an explicit wire-compatibility decision.
- AUTH rejects imported keys that are not Ed25519.
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
- Client profile rotation advances after successful TLS connections; the HTTP
  User-Agent follows the active preset unless explicitly overridden.
- Whole-session close has a five-second deadline, pending service opens are
  capped at 64 per service and 256 total, and client EXEC dispatch is capped at
  four concurrent workers. Principal shutdown paths use best-effort buffer
  erasure.

Focused validation in the current development tree covers the obfs codec and
decoy classifier, authorization predicate/tier, public-node policy, TLS profile
rotation, transport core, and service-queue policy. `yume`, `yumed`, and
`yume_facade` also link in the focused build tree.

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
- Thread-race (TSan), long-running close/reconnect, and resource-pressure soak
  testing. ASan + UBSan are configured to run the focused unit suite in CI
  (`YUME_SANITIZE`), but that gate is not soak or concurrency evidence.
- Detached EXEC workers are bounded but are not cancellable/joined at shutdown.
- Best-effort erasure is not a locked allocator and cannot erase prior copies.
- External HTTP/2 conformance, exact native browser/web-server identity, and
  ML/DPI immunity are not implemented claims. Full-session HTTP/2 is present in
  `2.0-dev3`, but external conformance and sustained-session release gates are
  still open. Direct one-stream LAN traffic reached line rate, and dev3 removes
  the modeled one-pending-epoch ceiling. A separate measured high-RTT ceiling
  remains unidentified; see `docs/YUME_2_0_WAN_BEHAVIOR.md`.

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

Status: cluster federation exists; onion-style routing does not.

- Current federation connects `yumed` peers and can route endpoint invites /
  channels through cluster links.
- It is not a Tor-like onion-routing anonymity layer.

Planned but not implemented:

- Client-selected guard/middle/service or exit paths.
- Per-hop layered encryption where each server knows only adjacent hops.
- Signed node and service descriptors for path selection.
- Browser-safe circuit telemetry.
- Tests proving no single non-client node sees the whole route and plaintext.

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
