# YUME implementation status

This is the public support boundary for the current source tree. It uses three
terms consistently:

- **Implemented** means the code exists in this repository.
- **Tested** means a named unit, integration, or build path exercises it.
- **Qualified** means the exact release candidate passed the full gate for the
  stated platform and use.

Implemented or tested code is not automatically qualified. The exact product
version is recorded in `src/core/version.hpp`; no stable release has been
published.

## Supported development target

The first target is the Linux x86-64 command-line client and daemon built with
the BaseFWX and patched OpenSSL revisions pinned by the build inputs.
The source tree also contains an optional desktop GUI and a stable C ABI v1.

Windows, macOS, the GUI as a human-facing application, the separate Android
client, and external browser work are not qualified release targets. Some of
their build or focused lifecycle paths exist, but those results do not transfer
Linux qualification to another consumer or platform.

## Core transport

Implemented:

- TLS 1.3, HTTP/2, and WebSocket carrier on one persistent connection
- keyed admission before AUTH v2
- composite Ed25519 and ML-DSA-87 client authentication
- ML-KEM-1024, X25519, random-PSK, and TLS-exporter-bound session setup
- independent directional ratchets and one-use AES-256-GCM message keys
- multiplexed TCP, UDP, forwarding, service, codec, and packet streams
- bounded queues, session limits, key-specific admission, and optional weighted
  egress shaping

Focused tests cover carrier parsing and ordering, authentication vectors and
channel binding, ratchet transitions, permission checks, bounded admission,
service queues, packet lifecycle, and shutdown paths.

Still open:

- exact-candidate reconnect, loss, resource-pressure, and long-running soak
- repository-wide thread-sanitizer coverage
- external HTTP/2 conformance and active-probe review
- proof that full sessions match the selected browser and cover identity closely
  enough for the stated deployment

## Browser-shaped carrier

The only configured client profile is the browser and cover identity named by
the active registry entry. The native backend passes the six pinned
ClientHello structure checks and centralizes the TLS, HTTP/2, header, and cover
identity.

That evidence is structural. Resumed and hello-retry handshakes, full exporter
and certificate paths, same-session browser comparison, traffic timing and
volume, held-out classifier tests, reproducible release artifacts, and deployed
soak remain open. Matching ALPN, JA3, JA4, or a short functional path is not
proof that YUME is identical to Chrome or immune to DPI.

The cover backend is a separate supervised process bound to a loopback IP
literal. Ordinary GET and HEAD requests are proxied to it. Tunnel payloads,
identities, and secrets do not go to the cover process.

## Permissions and storage

Individual, bounded bulk, and separate administrator identities are
implemented. Bulk identities cannot receive administrator, controller,
unrestricted network, federation, or privileged codec permissions. Session
admission is counted and released through one controller.

On POSIX, secure-material and profile operations use bounded input, no-follow
file checks, owner-only permissions, transaction locks, and atomic publication.
Imports validate JSON shapes and identifiers before use. Share bundles are
encrypted and refuse unsafe overwrite targets.

Windows operations that need equivalent secure mutable storage fail closed or
remain unadvertised until that policy is implemented and tested. Best-effort
memory wiping does not protect allocator copies, swap, core dumps, or a live
process compromise.

## Routing and host features

Implemented entry and exit surfaces include SOCKS, TCP and UDP forwarding,
packet routing, built-in services, the `monero-rpc-v1` application codec, and
the host-controller HTTPS and extra-listener configuration.

The host controller currently accepts only loopback TCP backends:

- `loopback://127.0.0.1:PORT`
- `loopback://127.x.x.x:PORT`
- `loopback://[::1]:PORT`

`service://`, `codec://`, and `unix://` backends are rejected because their
runtime drivers do not exist. Public-host cutover, real certificate renewal,
browser ingress, mail STARTTLS interoperability, proxy deployment, and
long-running backend-failure behavior still need deployment testing.

Inbound child-process execution is disabled. Portable bounded cancellation is
not implemented, so the daemon does not start detached work and claim that it
can control its lifetime.

## Federation and relay

AUTH v2 direct federation is implemented. A two-node integration test starts
two real daemons and clients, exchanges the directory, relays exact data in
both directions, and closes the channel. A three-node line test proves direct
links while keeping the far endpoint absent and unroutable.

The runtime reports `transit.supported=false` and `transit.max_hops=1`.
Multi-hop relay-channel transit is design-only. SOCKS, forward, packet, and
other exit traffic cannot transit another YUME server. The daemon remains a
terminating proxy, not an onion relay.

Relay v2 uses composite-signed setup, explicit peer trust, a hybrid ratchet,
bounded records and rekey queues, and confined POSIX file receive. Windows
secure trust/history/file storage, GUI and Android wiring, external review, and
long-running loss and soak tests remain open.

## Public APIs and consumers

C ABI v1 is the stable native interface and has a versioned SONAME
`libyume.so.1`. Its header, symbol map, Debian symbols, full and client-only
implementations, and ABI tests must change together. Exceptions do not cross
the ABI.

Generic request operations return a JSON operation envelope. Transport and
lifecycle failures use typed ABI statuses. Callers must not recover a status by
parsing an error string. See [C ABI](ABI.md) and [control API](CONTROL_API.md).

The Dear ImGui application builds around the same facade and in-process
runtime. Headless Linux lifecycle checks cover connect, stop, reconnect, and
stop. Interactive window behavior, tray integration, accessibility, and
cross-platform behavior are not qualified.

## Performance and network qualification

The carrier uses kernel TCP autotuning, an 8 MiB authenticated HTTP/2 receive
window, bounded sink-coupled receive credit, and bounded TCP and UDP queues.
Focused tests cover pause, drain, resume, and queue limits. These mechanisms do
not amount to a universal end-to-end flow-control claim.

Development lab runs have been useful for finding queue, socket-buffer, and
high-latency limits. They are not published release benchmarks. There is no
stable-release throughput, latency, classifier, or overhead figure.

Before publishing one, the exact candidate needs repeated matched tests across
the stated rates, delay, controlled loss, both directions, competing streams,
and a deployed-network soak. The result must include binary provenance and host
context and must keep correctness failures separate from performance numbers.

## Release gates

A stable release still requires, at minimum:

- an exact-source portable build and test matrix with warnings as errors
- exact-source sanitizer reconciliation and sustained lifecycle coverage
- package installation, service startup, upgrade, and artifact verification
- browser and HTTP/2 comparison for the selected profile and cover identity
- WAN, loss, resource, and long-running soak qualification
- platform and consumer qualification for every advertised target
- independent cryptographic, protocol, and deployment review
- synchronized source, tests, CLI help, man pages, website claims, and release
  notes

Until those gates close, describe YUME as experimental development software.
Report narrower evidence with its exact platform and test path. Do not claim
that YUME is impossible to block or trace, identical to a browser, a complete
anonymity network, or production-qualified.
