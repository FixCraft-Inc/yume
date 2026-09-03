# YUME architecture

This describes the **YTP/1 replacement** contracts. It is not a map of the code
that runs today: the shipping transport-v2 product is roughly 117k of the tree's
168k lines and is not covered here. For that, and for which of the two stacks a
given file belongs to, read the [source map](SOURCE_MAP.md) first.

The modular YTP/1 replacement has downward-only client and server
compositions:

```text
client: ByteChannel -> SecureChannel -> Carrier ---------+
                                                         +-> SessionEngine
server: FrontDoor -> AcceptedCarrier --------------------+      -> StreamDispatcher
                                                                   -> StreamHandler
                                                                   -> RouteProvider
```

An application may supply or consume the endpoints at these boundaries. The
session engine does not know about sockets, TLS libraries, HTTP/2 libraries,
JSON, configuration files, command-line parsing, or GUI state.

This is not yet the runnable tunnel graph. The default-built transport-v2
architecture remains documented in the
[signed 0.2 snapshot](https://github.com/FixCraft-Inc/yume/tree/f0cc9e7/docs/ARCHITECTURE.md) until replacement parity.

## Core contracts

### ByteChannel

`ByteChannel` owns a reliable, ordered asynchronous byte path. Buffers are
move-only, reads and writes are bounded before admission, accepted operations
complete exactly once on a declared executor affinity, and cancellation is
distinct from terminal close. Its idempotent write shutdown is ordered after
accepted writes and preserves the read direction; providers that cannot
implement a genuine half-close fail instead of substituting a full close.

### SecureChannel

`SecureChannel` adds exporter-quality channel binding and bounded outer-channel
peer evidence to a byte channel. That evidence may be unauthenticated: in the
normal server-authenticated TLS shape, the server has no TLS client credential.
`SecureChannelPeerEvidence` records what the outer channel actually established
and is never application identity or dispatcher authorization. The default
provider is TLS 1.3.

### FrontDoor

`FrontDoor` owns listening, ordinary HTTP behavior, replay-protected cheap
admission, and promotion to a ready `AcceptedCarrier`. Missing, invalid,
replayed, or resource-exhausted admission follows the genuine configured cover
path. The front door does not emit a YUME-specific public rejection.

The ready-carrier boundary is necessary for genuine HTTP/2. Admission occurs
inside an established H2 connection and stream; reducing it back to a raw
`SecureChannel` would lose SETTINGS, stream, parser, and flow-credit state.
`AcceptedCarrier` transfers the carrier with immutable provider provenance and
keeps provider-specific shared connection state behind typed interfaces. It is
not an opaque context handle.

### Carrier

`Carrier` maps secure plaintext onto YTP record units and owns outer flow
credit. On the client, the exact frozen carrier provider constructs it from a
`SecureChannel`. On the server, the front door returns the already-promoted
carrier so its admitted application-protocol state remains intact. The first
provider uses a duplex HTTP/2 exchange. HTTP/2 is not a session-engine
dependency, and transport-profile geometry is not a YTP field.

The experimental `h2-duplex` provider reuses the retained libnghttp2/RFC 8441
state machine without changing the runnable transport-v2 path. It performs the
client's genuine priming and extended-CONNECT acceptance sequence, while the
server construction seam accepts only an already-admitted live H2 carrier so
SETTINGS, HPACK, stream, and flow-credit state are not reconstructed. Its
private fixed 12-byte length envelope preserves YTP record boundaries across
arbitrary WebSocket and secure-channel fragmentation. Send completion means
the complete record has drained through H2 flow control and the secure-channel
write queue, not merely that it entered an internal queue.

### SessionBootstrap

`SessionBootstrap` is a dependency-pure, one-session orchestration seam. A
client consumes the frozen byte-channel, secure-channel, and carrier providers;
a server borrows a shared persistent front door until one accept settles. It
validates the YTP/1 role, the suite's explicit TLS 1.3 requirement, exact
accepted-carrier provider ID/API/capabilities, and equal front-door, carrier,
and secure-channel executor affinity before constructing `SessionEngine`.

Every layer transfers single ownership into the next accepted asynchronous
operation. Cancellation requests the active operation's token and waits for its
one completion, closes a late returned object, and only then reports one
terminal completion. Success is reported only after `SessionEngine` reaches
`Active`; the reusable server front door is neither cancelled nor closed by a
session bootstrap.

### SessionEngine and StreamDispatcher

`SessionEngine` owns YTP/1 authentication, the key schedule, directional
ratchets, record protection, stream IDs, multiplexing, capabilities,
backpressure, and teardown. Stream zero is session control; clients own odd
application stream IDs and servers own even IDs.

Only a successful complete YTP authentication creates `PeerEvidence`. That
post-YTP evidence represents the authenticated application peer and is the
identity passed to the dispatcher, stream handlers, and route policy. Outer
`SecureChannelPeerEvidence` and post-YTP `PeerEvidence` are distinct types so a
TLS observation cannot be promoted accidentally into application authority.

The dispatcher checks the authenticated capability and calls the selected
handler's authorization policy for every OPEN. It reserves stream, pending,
queue, packet, credit, control, and rekey resources before allocation or
expensive work. A capability advertisement never bypasses per-open policy.
Service dispatch is keyed by `(canonical name, service kind)`, so the same name
may intentionally expose one byte-stream handler and one packet handler without
colliding or weakening either policy. Names use a bounded lowercase ASCII
namespace grammar shared by the wire, config, engine, and ABI; authorization
never depends on Unicode normalization or case folding.

### StreamHandler and RouteProvider

`StreamHandler` receives an authenticated byte-stream or packet-channel open.
It owns service-specific authorization and resource policy. `RouteProvider`
implements egress such as direct TCP or UDP, but its request type can be
constructed only after the dispatcher has authenticated and authorized the
peer, service, and destination.

The provider-level `DirectRouteHandler` is the reusable adapter between those
contracts. It opens egress only from `on_route`, forwards at most one bounded
operation in each direction, retains inbound carrier credit through the exact
route write completion, preserves packet boundaries, and maps byte-stream EOF
to directional write shutdown. Provider errors, partial completions, and
cancellation close both sides once.

The opt-in `AsioDirectRouteProvider` is the first concrete egress
implementation. It resolves a bounded number of DNS results, applies the
instance-local socket protector after open and before connect, enforces
pending-open, active-connection, read, write, packet, resolution-time, and
connect-time bounds, and exposes TCP as `ByteChannel` and connected UDP as
`PacketChannel`. It is build-tree-only and is not yet wired into a runtime or
the C ABI endpoint graph.

## Provider composition

`TransportSuiteDescriptor` is immutable composition metadata: exact provider
IDs, provider API versions, required capabilities, service kinds, and resource
requirements. `EngineBuilder` registers provider instances locally, validates
the entire graph, and freezes after its first successful build.

There is no process-global mutable registry, reflection-based provider
selection, dynamic loading in key-holding processes, fallback, or partial
build. A configured provider that is absent, incompatible, or missing a
required capability causes a typed hard failure.

Trusted custom providers may use the experimental source-level C++20 provider
interfaces. Cross-language applications target the C ABI candidate after its
functional and freeze gates pass. An out-of-process plugin protocol is
intentionally deferred.

## First suite

YTP/1 ships one mandatory suite:

| Layer | Required implementation |
| --- | --- |
| secure channel | native TLS 1.3 |
| front door | genuine HTTP/2 website or loopback reverse proxy |
| carrier | bounded duplex HTTP/2 |
| session | YTP/1 hybrid security and multiplexing |
| authentication | Ed25519 **and** ML-DSA-87 |
| establishment | X25519, ML-KEM-1024, per-identity access PSK, TLS exporter |
| records | directional ratchet, one-use AES-256-GCM keys |
| routes | explicit direct TCP and UDP through dispatcher policy |

YTP/1 contains no suite negotiation. A second suite cannot be added as a
fallback; useful reviewed alternatives require a later wire version with an
explicit negotiation design.

## Source and target boundaries

The implemented replacement foundation is organized by dependency:

| Path | Ownership |
| --- | --- |
| `src/engine/` | dependency-pure channels, providers, builder, bootstrap, dispatcher, and session state |
| `src/ytp/` | dependency-pure YTP/1 codecs, domains, and canonical vectors |
| `src/config/v1/` | strict immutable schema-1 parsing; no secret loading |
| `src/providers/` | opt-in session-security, memory-BIO TLS 1.3 secure-channel, and direct-route foundations; not a production H2/front-door/endpoint graph |
| `src/abi/` | experimental exception-contained C ABI handles and blocking timeout scaffold |
| `tools/` | provisioning and evidence tooling |

Dedicated replacement adapter and CLI targets do not exist yet. The runnable
transport-v2 executables and optional GUI remain in their existing source graph
until those replacement layers reach parity.

The foundational CMake targets enforce the following dependency rule:

```text
yume_engine + yume_ytp1 +     no OpenSSL, nghttp2, socket, JSON, CLI,
yume_session_bootstrap        filesystem, or GUI dependency
yume_config_v1                nlohmann JSON only
native providers              engine/YTP plus their explicit system libraries
replacement ABI               frozen instance graph; no private-header API
future adapters/executables   candidate ABI or explicit application layer
```

BaseFWX owns reusable cryptographic primitives and secret-wiping containers.
YUME owns YTP authentication, domains, transcript construction, key schedules,
ratchet semantics, admission, and authorization. `basefwx/` is a separate
ignored checkout pinned by `config/dependencies.json`.

## Public ABI boundary

The explicitly enabled `libyume.so.1` candidate exposes opaque runtime, config,
endpoint, stream, and packet handles. It is not a frozen installed product ABI.
The surface is role-neutral and has no JSON operation bus. A runtime owns
bounded executors and callback delivery; an immutable config owns validated
values; an endpoint owns a frozen provider graph; stream and packet handles own
application I/O lifetimes.

The ABI contract defines thread safety, one-reader/one-writer rules, callback
re-entry, cancellation, timeouts, shutdown, destruction, peer identity, and
handle-scoped diagnostics. No exception or private C++ type crosses it.

## Ingress and evidence boundary

Captured browser geometry lives in `config/transport_profiles.json` and
immutable fixtures. It may change independently of YTP/1. Profile qualification
requires exact TLS/H2 semantic gates, active-probe cover behavior, immutable
captures, and held-out classifier evidence for the named environment. A
fingerprint string or successful request is not whole-session equivalence.

## Trust boundary

The default topology is single hop:

```text
application -> local adapter -> YTP session -> yumed -> authorized target
```

The server terminates YTP cryptography and is the explicit exit. It is not an
onion relay. Federation, transit, directory, reverse administration, command
execution, chat/file relay, and host-controller modes are outside the first
YTP/1 path; their transport-v2 implementations remain separate during the
transition.

See [YTP/1](protocol/YTP_1.md), [C ABI](ABI.md), and the
[threat model](THREAT_MODEL.md) for the normative boundaries.
