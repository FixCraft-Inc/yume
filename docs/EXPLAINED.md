# YUME explained

YUME is a stealth universal transport. Its modular replacement keeps that
role: the core abstraction is an authenticated peer opening a named byte
stream or packet channel over one carrier. The runnable transport-v2 tunnel
remains available while the replacement is completed.

## The dependency path

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

## The connection path

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

These are normative requirements. The current `0.3.0-dev1` tree has an
opt-in, build-tree-only OpenSSL security-provider candidate with focused
real-key handshake, record, and rekey tests. It is still unwired from the
native TLS/HTTP/2 runtime and public ABI, is not production-qualified, and has
not completed external protocol/cryptography review.

## Capabilities and policy

AUTH binds a bounded canonical service-capability manifest. Every OPEN is still
checked independently against identity, service kind, destination policy, and
resource limits. Capability advertisement cannot bypass authorization.

Routes are fenced by construction: only the session dispatcher can create an
`AuthorizedRouteRequest`, and it does so after the policy gate. Slow consumers,
stream floods, malformed input, packet batches, control messages, and rekey work
all meet explicit bounds before allocation.

## Embedding

Future stable consumers will include only `<yume/yume.h>` and link the
installed replacement library. The current role-neutral ABI candidate exposes runtime, immutable config,
endpoint, stream, and packet handles with blocking timeout calls over the
asynchronous implementation. Applications never need a CLI, private header,
Boost.Asio, OpenSSL, nghttp2, or JSON operation bus.

The experimental C++20 provider SDK is source-level and intended only for
trusted in-process providers. Out-of-process plugins are deferred until a real
consumer justifies a protocol and threat model.

## Product boundary

The first complete YTP/1 path targets direct routing, SOCKS5, named-service,
and packet adapters; those adapters are not wired yet. GUI, federation,
transit, directory, relay applications, reverse administration, command
execution, and product-specific codecs remain separate transport-v2 surfaces
rather than prerequisites for the first replacement tunnel. Dynamic plugins
and cryptographic suite negotiation are outside YTP/1.

The current implementation boundary is tracked in
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md); this description does not
turn an unwired component into supported runtime behavior.
