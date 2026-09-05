# YUME explained

YUME is an independently implemented, embeddable stealth universal transport.
Its own wire protocols carry application traffic over authenticated carriers.
The runnable transport-v2 tunnel and the experimental YTP/1 replacement are
separate implementations. The replacement's core abstraction is an
authenticated peer opening a named byte stream or packet channel.

## The runnable transport-v2 path

The current `yume` and `yumed` commands use transport v2. A direct connection
follows this path:

1. An application reaches the client through SOCKS5, a forward, packet routing,
   or the experimental ABI's supported named-stream interface.
2. The client establishes TLS 1.3 to `yumed`, with certificate/hostname checks
   and configured trust policy. `yumed` terminates public TLS and HTTP/2. The
   reference cover site runs in a separate loopback Node process; it receives
   ordinary web requests, not tunnel records or credentials.
3. The client primes the page and assets over HTTP/2, then requests an RFC 8441
   WebSocket carrier. The server checks keyed, replay-protected admission
   before sending an AUTH challenge. HTTP/2 remains active for the whole
   connection.
4. AUTH v2 verifies the composite Ed25519 and ML-DSA-87 client identity and
   binds it to the live TLS exporter. ML-KEM-1024, X25519, and the random file
   PSK contribute to session establishment. An admin session requires a
   separate second identity. The protected `AUTH_OK` arrives only after the
   inner channel is active.
5. YUME frames multiplex application traffic through WebSocket binary messages
   inside HTTP/2 DATA. Independent directional ratchets use one-use
   AES-256-GCM message keys. Stream credit, bounded queues, and backpressure
   control how much work each connection can retain.
6. `yumed` applies destination and authorization policy before opening egress.
   The destination sees the server's egress address. The server knows the
   authenticated client and destination; independent application TLS can still
   protect the application content end to end.

The client authenticates the server through TLS trust, optional leaf pinning,
and optional operator proof. The server's client-identity stores do not supply
a server identity to the client. The admission secret and inner PSK are
separate deployment gates.

Missing or invalid admission never reaches AUTH. The exact cover response
depends on the request path: the current rejected extended CONNECT receives a
bounded synthetic 404, which differs from the reference Node response. YUME
emits no synthetic idle traffic, and encrypted timing, size, and volume remain
observable.

The [transport-v2 wire contract](protocol/YUME_2_0_WIRE.md) owns the exact
framing, admission, key schedule, and remaining profile differences. The
[source map](SOURCE_MAP.md) identifies the running components. The sections
below describe the intended YTP/1 replacement; its providers do not yet form a
live endpoint. The current ABI carries transport-v2 named streams, while its
packet operations remain unsupported.

## The replacement dependency path

```text
ByteChannel
  -> SecureChannel
  -> Carrier
  -> SessionEngine
  -> StreamDispatcher
  -> StreamHandler or RouteProvider
```

- `ByteChannel` owns reliable ordered asynchronous bytes, cancellation,
  executor affinity, bounded writes, and move-only buffers.
- `SecureChannel` adds an exporter-quality binding plus bounded outer-channel
  evidence, which may represent an unauthenticated TLS client. Only successful
  YTP authentication creates application `PeerEvidence` for policy. TLS 1.3 is
  the required first provider.
- `FrontDoor` owns listening, real website/reverse-proxy traffic, cheap
  replay-protected admission, and promotion to a typed ready carrier that
  retains the admitted HTTP/2 connection, stream, and flow-credit state.
- `Carrier` maps secure plaintext to records and owns outer flow credit. The
  first carrier is duplex HTTP/2.
- `SessionEngine` owns YTP/1 authentication, records, ratchets,
  multiplexing, capabilities, backpressure, and lifecycle without depending on
  sockets, TLS, HTTP/2, JSON, filesystem, CLI, or GUI.
- `StreamHandler` independently authorizes each authenticated named OPEN.
- `RouteProvider` performs explicit egress only after dispatcher policy passes.

`EngineBuilder` selects exact, instance-local providers and freezes the graph.
There is no global mutable registry, reflection configuration, runtime
`dlopen()`, provider fallback, or YTP/1 suite negotiation.

## The replacement connection path

The intended direct tunnel route is:

```text
application -> SOCKS/ABI adapter -> YUME endpoint -> TLS 1.3 + HTTP/2
            -> authenticated YTP/1 session -> authorized direct route
            -> destination
```

A local adapter asks the endpoint to open the named `tcp`, `udp`, or another
application service. Service identity is the pair `(name, kind)`, allowing one
name to expose distinct stream and packet semantics. YTP/1 assigns a 31-bit odd/even stream ID, preserves
application payload opacity, and applies connection and stream credit. Direct
TCP/UDP destinations use strict built-in binary encodings rather than JSON.

The server terminates the YUME session and therefore learns the authenticated
client identity, service, and direct destination. HTTPS or another independent
application protocol can still protect content end to end. YUME does not
provide anonymity from its terminating server.

## Public front door

The public listener is a genuine application-protocol endpoint. Normal browser
traffic and invalid or missing admission remain in the real cover website or
reverse proxy. Only a bounded, replay-protected admission path can promote a
connection to YTP/1; unauthenticated failures must not receive a YUME-shaped
response.

Browser-shaped geometry is an independently versioned evidence profile. A new
capture does not revise authenticated YTP semantics. Claims must name the exact
qualified profile and environment; YUME does not claim universal
indistinguishability or DPI resistance.

## Session security contract

YTP/1 fixes one mandatory composition and binds it into a canonical schedule:

- Ed25519 **and** ML-DSA-87 authentication;
- X25519 and ML-KEM-1024 establishment;
- a unique access PSK for each authorized key;
- the live TLS exporter;
- suite, roles, transcript, both identities, both capability manifests, and
  exact security parameters;
- independent directional rekeying and one-use AES-256-GCM keys for protected
  records. The sole bare post-AUTH record is the candidate-new-root
  authenticated rekey acknowledgement defined by YTP/1.

All required components must succeed. A mismatch is terminal; there is no
downgrade or retry with a weaker provider. Ratcheting is described as
post-compromise-oriented until recovery assumptions have formal and
experimental support.

## Capabilities and policy

AUTH binds a bounded canonical service-capability manifest. Every OPEN is still
checked independently against identity, service kind, destination policy, and
resource limits. Capability advertisement cannot bypass authorization.

Routes are fenced by construction: only the session dispatcher can create an
`AuthorizedRouteRequest`, and it does so after the policy gate. Slow consumers,
stream floods, malformed input, packet batches, control messages, and rekey work
all meet explicit bounds before allocation.

## Embedding

The [C ABI candidate](ABI.md) exposes runtime, immutable configuration,
endpoint, stream, and packet handles through `<yume/yume.h>`. It provides
blocking calls with timeouts over the asynchronous engine. The current
build-tree library supports transport-v2 named streams.

Trusted in-process providers use the experimental C++20 SDK. Out-of-process
plugins remain a separate design decision.

## Product boundary

The first complete YTP/1 path targets direct routing, SOCKS5, named-service,
and packet adapters; those adapters are not wired yet. GUI, direct single-hop
federation, directory, relay applications, reverse administration, and
product-specific codecs remain separate transport-v2 surfaces. Transit is
design-only, and command execution is reserved and disabled. None is a
prerequisite for the first replacement tunnel. Dynamic plugins and
cryptographic suite negotiation are outside YTP/1.

See [implementation status](IMPLEMENTATION_STATUS.md) for the integration gates.
