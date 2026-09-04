# YUME implementation status

This page is the public support boundary for the live source tree. It uses
three terms deliberately:

- **Implemented** means code exists in this repository.
- **Tested** means a named executable or integration path exercises it.
- **Qualified** means the exact candidate passed the complete gate for the
  named platform and environment.

YUME is development software. The transition tree contains two explicit
tracks: the default build keeps the runnable `0.2.0-dev6` client/daemon and
transport-v2/AUTH-v2 path, while the `0.3.0-dev1` YTP/1 replacement foundation
is built alongside it. Neither track is a stable or production-qualified
release.

## Current 0.3 foundation

Implemented and covered by focused tests:

- a dependency-pure C++20 engine foundation with move-only bounded buffers,
  cancellation, executor affinity, byte-channel, secure-channel, carrier,
  stream-handler, route-provider, exact provider descriptors, and an
  instance-local freezing builder;
- a role-neutral, one-session bootstrap coordinator that composes the frozen
  client provider chain or a server front door's typed ready-carrier promotion,
  validates TLS 1.3 suite provenance and exact carrier/affinity continuity,
  waits for cancellation settlement, cleans every rejected layer, and reports
  success only after the YTP session becomes active in focused in-memory tests;
- an opt-in bounded `h2-duplex` carrier provider over `SecureChannel`, with
  genuine client priming plus extended-CONNECT acceptance, a typed live-state
  server-promotion seam, carrier-private record framing, move-owned outer
  credit, and flow-controlled send completion. Focused fake-channel tests and
  the retained transport-v2 H2 regression pass; no production FrontDoor or
  admission provider is implied;
- 31-bit YTP stream identifiers with stream zero reserved for control, odd
  client ownership, even server ownership, and exhaustion checks;
- a dependency-pure YTP/1 protocol kernel with bounded canonical frame, OPEN,
  destination, capability, credit, AUTH-TLV, mandatory-security-parameter, and
  key-schedule-input codecs;
- entirely new `yume/ytp/1/...` domains plus checked-in canonical encoding
  vectors;
- an opt-in, build-tree-only OpenSSL 3.5 session-security provider candidate
  with exact Ed25519 plus ML-DSA-87 authentication, X25519 plus ML-KEM-1024
  establishment, per-identity access PSKs, exporter/transcript/capability binding,
  one-use AES-256-GCM record keys, and crossed directional rekey tests. It is
  not wired to a live endpoint or qualified for production use;
- an opt-in, build-tree-only Boost.Asio client TCP ByteChannel provider with
  bounded DNS/connect work, socket-protection-before-connect, bounded ordered
  operation queues, per-operation and provider cancellation, real TCP
  half-close, and explicit executor affinity. Server listening remains a
  FrontDoor responsibility, and this provider is not runtime-wired;
- an independent opt-in OpenSSL 3.5 TLS 1.3 secure-channel foundation which
  wraps arbitrary engine byte channels through memory BIOs, enforces exact
  TLS 1.3 plus ALPN `h2`, verifies client-side hostname/trust, exposes bounded
  outer certificate evidence and exporter binding, and keeps its provider
  provenance immutable. It is not an HTTP/2 carrier, front door, browser
  profile, live endpoint integration, or production-qualified TLS claim;
- strict immutable numeric config schema 1 with closed objects, duplicate-key
  rejection, exact provider values, file-only credential references, bounded
  services/adapters/resources, and RFC 6901 error locations;
- the experimental role-neutral C ABI v1 candidate header, symbol allowlist,
  typed metadata and diagnostics, and exception-contained handle scaffolding;
- an explicitly enabled unversioned `libyume.so` build-tree library with
  build-tree C and C++ consumers that verify metadata, both configuration
  dialects, handle lifecycle, registration ordering, and a real transport start
  reaching the runtime rather than a stub, plus an integration probe that
  provisions a real server and client and moves bytes both directions over an
  authenticated named service stream. Client socket protection is connected
  to every outbound transport-v2 dial and fails closed. The candidate has no
  install rules, no generated CMake package or pkg-config metadata, and is not
  emitted as an ABI package. `cmake/yumeConfig.cmake.in`,
  `cmake/yume.pc.in`, `cmake/check_yume_abi_install.cmake`, and
  `tests/abi/install_consumer/` are retained for that future installed
  contract and are currently unreferenced by the build;
- one compatibility manifest reporting product, YTP, config, ABI, logical
  suite components, concrete providers, cryptographic backend, and
  evidence-profile versions without treating an unwired component as active;
- deterministic validation of declared source dependencies and regeneration of
  a source-dependency SPDX SBOM. This inventory is not proof of source
  ancestry.

The lasting automated evidence includes warning-as-error builds, strict C and
C++ ABI consumers, exact built/header/map/candidate-symbol agreement, schema
examples and negative parser cases, real-key hybrid handshake/record/rekey
tests, malformed canonical-codec cases, fake-channel TLS/H2 provider tests,
real loopback TCP and connected-UDP route tests, the transport-v2 H2 regression,
and the end-to-end ABI named-stream probe. Exact candidate run results belong
to CI or private qualification artifacts rather than this current-behavior
document. Passing focused tests does not qualify the replacement end to end.

## Not yet implemented end to end

The following required 0.3 paths are still open in this development tree and
must not be advertised as working:

- the genuine HTTP/2 web front-door provider (the opt-in duplex carrier
  foundation does not implement public ingress or cover routing);
- replay-protected admission and promotion whose failure is indistinguishable
  from ordinary cover handling at the public HTTP boundary;
- wiring the opt-in hybrid authentication/KEM/AEAD provider candidate to the
  native TLS/HTTP/2 endpoint, runtime, and ABI, followed by production
  qualification;
- a complete authenticated session lifecycle over the native provider graph,
  including real-carrier rekey races, close ordering, and all
  credit/backpressure paths;
- wiring the implemented opt-in direct TCP/connected-UDP route provider and
  route handler into the endpoint graph, plus working SOCKS5, named-service,
  and packet adapters on the new engine;
- a public-ABI packet data path, and the same stream path on the YTP/1 backend;
- authenticated clean-prefix C and C++ consumers using an installed CMake
  package and pkg-config, which the build does not generate yet;
- the final narrow `yume` and `yumed` runtimes and setup-to-first-SOCKS smoke;
- external active-probe, classifier, performance, soak, fuzz, sanitizer, and
  security-review gates.

The replacement ABI attaches a runtime through one backend seam. A default
build compiles the transport-v2 backend, so `yume_endpoint_start` really starts
the runnable client or daemon, `yume_endpoint_register_service`,
`yume_endpoint_open_stream`, and `yume_endpoint_accept_stream` carry
authenticated named byte streams, and `yume_stream_read`/`write`/
`shutdown_write`/`close` move real bytes with typed transport failures. A
schema-1 endpoint still fails with a typed unsupported status because the YTP/1
provider graph has no live front door, and nothing silently reroutes one
dialect into the other runtime. Packet channels remain unsupported on both
backends. The working `yume` and `yumed` binaries remain a separate, explicit
product path during the transition.

## Retained runnable 0.2 product

The default transition build continues to produce the runnable 0.2 `yume` and
`yumed` tunnel, including its transport-v2/AUTH-v2 implementation and the
dependencies needed by that working path. It is not called a fallback or
deprecated implementation: it remains the current runnable product until the
replacement passes its tunnel, cover, routing, embedding, packaging, and
qualification parity gates.

The current quick start, operations guide, control API, and transport-v2
protocol documents remain authoritative for the runnable product. Historical
contracts remain available in signed Git history. Transport v2 and its
configuration are incompatible with YTP/1 and schema 1;
coexistence does not add an automatic converter, downgrade, suite fallback, or
migration promise. Optional and
product-specific 0.2 surfaces are reviewed individually rather than deleted
solely because the replacement architecture does not yet model them.

## Security boundary

The YTP/1 design requires all of the following:

- Ed25519 **and** ML-DSA-87 authentication;
- X25519 **and** ML-KEM-1024 establishment;
- a distinct per-identity random access PSK;
- the live TLS 1.3 exporter and exact roles, identities, transcript,
  capabilities, suite, and fixed security parameters in the key schedule;
- independent directional ratcheting, one-use AES-256-GCM keys for protected
  records, and a candidate-new-root authenticated rekey acknowledgement;
- bounded work and allocation before attacker-controlled parsing, KEM,
  stream creation, queueing, or rekey preparation;
- hard failure on a missing component, provider mismatch, role confusion,
  replay, malformed canonical encoding, or authentication failure.

The opt-in provider candidate implements the cryptographic portions in focused
in-memory tests; dependency-pure engine tests cover the matching record and
resource contracts. They remain design and acceptance requirements, not a
product guarantee, until the live TLS exporter, native carrier/runtime wiring,
and full qualification gates land. They are not an independent proof, audit,
or certification. The ratchet is described only as
post-compromise-oriented.

## Ingress evidence boundary

The retained transport-profile capture pipeline and immutable Chrome/Node
fixture are evidence inputs, not a claim of universal indistinguishability.
Any release claim must name the exact profile, capture, candidate binary,
environment, TLS/H2 semantic results, active-probe cover results, and held-out
classifier result. ALPN, JA3/JA4, or a short successful navigation is
insufficient.

## Performance boundary

No 0.3 performance claim exists. A matched pre-reset performance baseline has
not yet been captured; the signed pre-reset commit remains identifiable in Git
history for that isolated comparison. A claim such as “faster” requires at
least five matched
runs with throughput, p50/p99 latency, CPU/byte, allocations, peak memory, and
1/32/256-stream fairness plus reported uncertainty.

## Freeze gates

Before `0.3.0-rc1`, the exact candidate must pass:

- clean supported-platform builds and target/include layering checks;
- YTP/1 vectors, mutation/component-stripping/replay/role/provider tests, and
  parser fuzzing;
- ASan, UBSan, TSan, failure injection, flood/resource-pressure, and sustained
  soak qualification;
- clean-prefix SDK installation and C/C++ stream and packet consumers through
  both CMake and pkg-config;
- clean-machine setup, permissions, doctor, cover-browser, and first-stream
  smoke tests;
- immutable ingress/profile evidence and reproducible performance evidence;
- synchronized source, tests, help, manual pages, package metadata, website,
  declared-dependency/SBOM, and documentation drift checks;
- an external protocol and cryptography review.

Until those gates close, report only the focused evidence above and do not
claim production readiness, browser identity, DPI resistance, anonymity,
post-quantum security certification, or setup-to-tunnel completion.
