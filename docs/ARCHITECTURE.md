<!-- Generated from docs/src/en_US/pages/architecture.doc by scripts/yume_docs.py. Edit that file, not this one. -->
# YUME architecture

This page describes how native YUME is put together: which component owns
what, which way dependencies point, and where the runtime boundaries are. The
[source map](SOURCE_MAP.md) says where each piece lives in the tree.

## Why YTP/1

YUME has to work as a standalone client and server and inside other
applications. YTP/1 (YUME Transport Protocol 1) meets that with a session
engine that owns its state explicitly and does not depend on sockets, TLS
libraries, configuration parsing or application policy. Providers plug those
in from outside.

The native graph reuses transport-v2 components where their contracts fit,
such as the HTTP/2 and WebSocket carrier code and the browser profile. Relay,
federation, the control API and the GUI still exist only in the transport-v2
reference build. Move each one with its tests before removing the old path.
A new protocol name proves neither better speed nor stronger security.
[Implementation status](IMPLEMENTATION_STATUS.md) lists the open gates.

## Composition

Client and server compositions depend only downward:

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

## Core contracts

### ByteChannel

`ByteChannel` owns a reliable, ordered asynchronous byte path. Buffers are
move-only, reads and writes are bounded before admission, accepted operations
complete exactly once on a declared executor affinity, and cancellation is
distinct from terminal close. Its idempotent write shutdown is ordered after
accepted writes and preserves the read direction; providers that cannot
implement a genuine half-close fail instead of substituting a full close.

The native TCP provider uses a shared `AsioExecutionContext`. Its source-level
factories take that owner; socket adoption uses its concrete executor type.
The caller runs exactly one execution thread at a time and initiates create,
read, write and write-shutdown there. Wrong-context initiation accepts no work;
the throwing methods reject synchronously, while write-shutdown returns a typed
failure. Completions may occur inline on the declared context. Thread-safe
cancel/close use embedded, coalesced control tasks and a reserved scheduler
operation, without an allocating strand or caller-thread completion fallback.
The execution owner contains no thread: after closing providers and channels,
the runtime calls `finish()` and keeps running until all completions drain.
`stop()` interrupts execution and does not establish successful cleanup.
Like Asio, `run()` and `poll()` can propagate delivery exceptions; the runtime
must contain them at its runner boundary and resume to drain reserved failure
tasks. This concrete lifecycle is separate from the platform-independent
engine contract.

Name lookup does not run in the process that holds session keys.
`SystemResolver` sends each lookup over a private socketpair to a helper
process. The helper calls the system resolver with its unchanged NSS and DNS
configuration, one thread per lookup, so a slow name does not delay others.
`getaddrinfo` cannot be interrupted. Cancellation therefore settles a lookup
at once, and closing the resolver kills and reaps the helper, so final drain
never waits for a stalled system call. A cancelled lookup keeps its slot until
the helper answers. When every slot is taken and some belong to abandoned
lookups, the helper is replaced and its live lookups fail. The helper holds
only its standard streams and the socketpair. It drops every capability and
sets no-new-privileges before serving, which keeps system DNS and NSS parsing
away from key material. `yume` and `yumed` re-execute their own image as the
helper. Embedding hosts name the installed `yume-resolver` program. A numeric
host never starts the helper. A name without a configured helper fails closed,
and there is no in-process fallback.

### SecureChannel

`SecureChannel` adds exporter-quality channel binding and bounded outer-channel
peer evidence to a byte channel. That evidence may be unauthenticated: in the
normal server-authenticated TLS shape, the server has no TLS client credential.
`SecureChannelPeerEvidence` records what the outer channel actually established
and is never application identity or dispatcher authorization. The default
provider is TLS 1.3. Its client uses the same browser-profile configuration as
transport v2. The browser's offer can include TLS 1.2 and HTTP/1.1, but YTP
accepts only negotiated TLS 1.3 and H2; profile application never relaxes that
boundary. Both native emitters require the pinned patched OpenSSL.

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
not an opaque context handle. Promotion also requires all front-door I/O,
cover fetches and H2 output to settle before transfer. At most one promotion
is allowed per TLS connection. The [admission contract](protocol/YTP_1.md#h2-admission-v1)
defines the exporter-bound proof and replay rules.

The native `H2WebFrontDoor` implements this boundary with a native TCP listener
and `AsioTcpAcceptedChannelOwner`. Its configured immutable static site loads
through `runtime::FileRoot`, requires an index and explicit not-found file,
and serves ordinary and rejected-admission requests from the same content.
The public TLS connection supports TLS 1.2/1.3 and HTTP/1.1/H2; its separate
promotion operation publishes strict TLS 1.3/H2 provenance only after admission.
SNI and exporter bytes come from the accepted SSL connection.

Promotion transfers the same TLS/BIO and H2 parser state after cover output
and the connection timer have drained. The carrier retains the accepted TCP
owner, bounded cover state and provider/executor provenance. A previously
answered cover stream need not wait for the peer to close its request side;
that stream transfers with the existing parser and cover ledger. Ordinary H2
requests still receive cover after promotion, and listener destruction does
not close a published carrier. This is a source-level ingress provider. The
experimental schema-1 ABI backend and the development standalone runtimes
compose it through `NativeEndpoint`.

The caller supplies the single-runner `AsioExecutionContext`. The front door
binds promoted carriers to that context's ordinary and reserved control
dispatch. The runtime contains runner exceptions and resumes execution, closes owners, calls `finish()` and
drains completions. This ingress performs no DNS resolution.

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

The source-level `H2Dispatch` separates ordinary operation submission from
reserved control delivery. Ordinary submission may reject before accepting an
operation. Close, cancellation and move-owned credit return use an embedded,
coalesced task whose submission must not allocate or invoke inline. Both paths
run serially on the declared affinity; the caller drains the executor through
final owner release. Asio and deterministic provider tests share the same
intrusive control mailbox. Allocation failure retains typed errors and
exactly-once completion even when diagnostic text cannot be retained.

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

### Native endpoint composition

`runtime::NativeEndpoint` composes schema-1 configuration, protected credential
files, per-identity service policy, client TCP/TLS/H2 or server FrontDoor, and
`SessionBootstrap` on one caller-owned `AsioExecutionContext`. Its two roles
share the same session engine; no transport-v2 dependency supplies the runtime.
Credential parsing uses a private OpenSSL context and passes canonical DER to
the independent security factory. Admission, traffic access and administrator
authority remain separate. `yume_private_files` owns the protected-file reader
shared with the older runtime, without importing BaseFWX.

Creation validates the mapped session limits and requires capacity for the
complete 64 KiB AUTH envelope before opening listeners. Static cover loads a
bounded directory snapshot with index/404 pages and the active browser profile's
priming assets; links, hidden entries and special files fail startup. IPv6
listeners use IPv6-only sockets so configured IPv4 and IPv6 wildcards coexist.
Every configured service needs a handler for its exact name and kind. The
immutable credential policy and the handler independently authorize each OPEN.
An optional `NativeEndpointOptions::route_provider` enables explicitly bound
DirectTcp/DirectUdp handlers. It must use the endpoint context; the engine
passes this selected instance to each routed OPEN and the endpoint owns its
cancellation. Handlers no longer select or retain a second provider. Exact
provider ID, API and capabilities remain checked. An explicitly bound handler
carries its caller's destination policy, and its provider needs a
resolved-address policy for DNS egress. Schema-1 `direct_tcp` and `direct_udp`
declarations create handlers for their service names and kinds when the provider
is supplied. Each declaration requires `destinations`: public unicast addresses,
explicit networks, or both. `runtime::NativeEgressPolicy` checks them after
credential authorization and before DNS or socket creation, and a provider
built with the same policy checks every address a name resolves to.
Unspecified, multicast and reserved addresses are never permitted, and
IPv4-mapped IPv6 is evaluated as IPv4. An optional `route_authorization`
callback runs only after the configured destinations permit an OPEN and can
only refuse more. No destination authority exists without configuration or an
explicit handler. Explicit service bindings cannot also own a declared direct
adapter, and an unused route callback is refused. Other services still require
explicit bindings. SOCKS5 declarations require a caller that explicitly owns
those adapters; `NativeClientRuntime` supplies that ownership. Packet declarations
require the caller to supply the matching packet binding and retain its adapter.
The native runtimes own Linux TUN addresses, routes and optional per-link DNS.
Reverse-proxy cover remains unsupported. The C ABI composes named channels and
routed client OPENs; standalone SOCKS5/TUN adapter declarations remain outside
its application-owned interface.

The endpoint bounds active sessions and pending starts and retains their engines.
When a session ends, the engine settles its pending callbacks and queues, then
notifies the endpoint through a reserved control task. The endpoint releases the
slot before calling `session_ended` on its context, so the callback can start a
replacement. Startup failures use the start completion alone. Endpoint close
also delivers session-ended callbacks; owners keep the endpoint alive through
close and drain. This notification does not mean OS cancellation has drained.
Retaining a closed engine also retains its carrier's admission reservation;
release old engine handles so they do not consume front-door capacity.
A server may hand accepting to the endpoint. It keeps a set number of starts
pending on every listener within that bound, re-arms after each settlement and
waits a retry delay after a refused or immediately failed start. Manual and
automatic server starts are exclusive. If a listener stops accepting, or a retry
cannot be scheduled while its listener has nothing pending, the endpoint closes
and reports that failure once. The schema-1 ABI backend uses this loop.
Client startup has one absolute dial/TLS/carrier/AUTH deadline. A server starts
its session-creation/AUTH deadline after validated carrier promotion; idle accept
waiting does not consume that budget. FrontDoor independently bounds connections
and work before promotion. Expired startup cannot succeed because timer delivery
was delayed. Cancellation waits for owned bootstrap operations to settle before
releasing their slots. Close uses reserved
control dispatch; repeated close and destruction after final drain are inert.
The caller contains runner exceptions, closes the endpoint, calls `finish()`
and drains. An explicit dial address can differ from the authenticated DNS
name. A dial name uses the endpoint's `SystemResolver`, which endpoint close
also closes.

### SessionEngine and StreamDispatcher

`SessionEngine` owns YTP/1 authentication, the key schedule, directional
ratchets, record protection, stream IDs, multiplexing, capabilities,
backpressure, and teardown. Stream zero is session control; clients own odd
application stream IDs and servers own even IDs.

`notify_when_closed` accepts one observer for the engine's lifetime. It runs
outside engine locks after teardown, or inline if registered afterward, and
contains callback exceptions. Callers dispatch onto their own executor when
needed. The native client uses the endpoint notification to reconnect when its
session ends. Failed attempts, and sessions shorter than the longest backoff,
wait for exponential backoff.

A server `NativeEndpoint` can reload its credentials on its context. The
engine graph is immutable, so reload builds a new one with the new session
security factory and the same handlers and route provider, and later sessions
use it. Service wrappers read the authorization policy through a shared holder
instead of capturing it, which lets established sessions see new grants. A
session that finishes AUTH against the previous graph after its identity was
removed is refused at admission.

`traffic()` returns cumulative payload and carrier-record byte counts from
relaxed atomics, readable from any thread after termination too. They carry no
content or key material. The native client runtime folds them into its
thread-safe `status()` snapshot for status displays.

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

Stream reads report authenticated FIN as `EndOfStream` after delivering prior
records. The responder retains that result across normal stream retirement.
Its thread-safe `terminated()` observation overrides retained EOF after an
abort, local close or session loss, including for adapters holding delivered
records. Reading part of a delivered record retains that record's carrier
credit until the remainder is consumed or discarded.

### StreamHandler and RouteProvider

`StreamHandler` receives an authenticated byte-stream or packet-channel open.
It owns service-specific authorization and resource policy. `RouteProvider`
implements egress such as direct TCP or UDP, but its request type can be
constructed only after the dispatcher has authenticated and authorized the
peer, service, and destination.

The provider-level `DirectRouteHandler` is the reusable adapter between those
contracts. It opens egress only from `async_route`, forwards at most one bounded
operation in each direction, retains inbound carrier credit through the exact
route write completion, preserves packet boundaries, and maps byte-stream EOF
to directional write shutdown. Provider errors, partial completions, and
cancellation close both sides once.
The dispatcher supplies the graph's validated route provider to `async_route`;
the bridge retains that instance through asynchronous settlement. Creating a
handler requires destination authorization but does not select a provider.
If asynchronous acceptance returns `PermissionDenied`, the engine sends an
unauthorized CLOSE. This preserves policy refusals that can be decided only
after DNS resolution. Other acceptance failures send a handler-failure CLOSE.

The native `AsioDirectRouteProvider` is the first concrete egress
implementation. Its factory requires an explicit resolved-address policy in
addition to the handler's service/name authorization. Before opening any socket,
it passes every selected numeric destination and the original authenticated
request to that policy. A refusal rejects the whole OPEN, including mixed DNS
answers. IPv4-mapped IPv6 is checked as IPv4; scoped IPv6 is refused because
the route contract has no scope field. Exceptions and reentrant cancellation
fail closed. This supplies the enforcement boundary; the embedding application
still owns its destination rules. It retains a bounded number of DNS results, applies the
instance-local socket protector after open and before connect, enforces
pending-open, active-connection, read, write, packet, resolution-time, and
connect-time bounds, and exposes TCP as `ByteChannel` and connected UDP as
`PacketChannel`. It shares the concrete single-runner `AsioExecutionContext`
with ingress. Initiation stays on that context; cross-thread cancellation and
close use reserved control tasks. Channel adoption can report allocation
failure, and final closed-handle release schedules no new cleanup. Destination
names use the shared `SystemResolver`. A canceled lookup returns the open's
reservation at once, while its resolver slot stays taken until the helper
answers or is replaced, so abandoned DNS work stays bounded. This
build-tree-only provider can be explicitly composed into `NativeEndpoint`.
The development `yumed` composes it with `NativeEgressPolicy`, and the
schema-1 ABI backend composes no route provider.

## Provider composition

`TransportSuiteDescriptor` is immutable composition metadata: exact provider
IDs, provider API versions, required capabilities, service kinds, and resource
requirements. `EngineBuilder` registers provider instances locally, validates
the required role-specific graph, and freezes after its first successful build.
The suite declares provenance for all layers. Clients require byte/TLS/carrier
factories; servers validate the actual accepted carrier at bootstrap instead.
A front-door factory is optional because bootstrap borrows the actual listener.
Named-only handlers need no route instance; a DirectTcp/DirectUdp handler
requires a concrete route provider with that capability. Every supplied
optional instance still undergoes exact ID, API and capability checks.

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

Native source is organized by dependency:

| Path | Ownership |
| --- | --- |
| `src/engine/` | dependency-pure channels, providers, builder, bootstrap, dispatcher, and session state |
| `src/ytp/` | dependency-pure YTP/1 codecs, domains, and canonical vectors |
| `src/config/v1/` | strict immutable schema-1 parsing; no secret loading |
| `src/providers/` | native session security, browser-shaped TLS, client/accepted TCP channels, native FrontDoor/static cover, H2 admission/carrier and direct routes |
| `src/runtime/` | protected schema-1 credentials, immutable per-identity authorization, native endpoint/session lifetimes, configured egress policy, and the `yume`/`yumed` runtimes with their SOCKS5 and TUN adapters |
| `src/admission/` | protocol-neutral H2 path/authority parsing, HMAC and replay reservations; each protocol owns its encoding |
| `src/abi/` | experimental exception-contained C ABI handles, validation, diagnostics, and backend leasing. Each dialect reaches its runtime through its own embed backend |
| `src/abi/native_backend.cpp` | experimental schema-1 embedding backend that runs `NativeEndpoint` on its own thread behind the blocking ABI |
| `tools/` | provisioning and evidence tooling |

The installed `yumed` and `yume` build from `src/runtime/` with every native
provider. The GUI and the features not yet moved stay in the opt-in,
uninstalled transport-v2 graph, which gets no separate stabilization work. The
[source map](SOURCE_MAP.md#replacement-integration-gaps) lists the missing
connections and the components already shared with YTP/1.

The foundational CMake targets enforce the following dependency rule:

```text
yume_engine + yume_ytp1 +     no OpenSSL, nghttp2, socket, JSON, CLI,
yume_session_bootstrap        filesystem, or GUI dependency
yume_config_v1                nlohmann JSON only
native providers              engine/YTP plus their explicit system libraries
native runtime                config, bootstrap, providers, protected files
yume_embed               native runtime, OpenSSL security provider and
                              threads, no transport v2 or BaseFWX
C ABI                         config_v1 plus embed backends, no private-header API
future adapters/executables   C ABI or explicit application layer
```

YUME owns YTP authentication, domains, transcript construction, key schedules,
ratchet semantics, admission and authorization. The concrete YTP/1 security
provider calls OpenSSL 3.5 directly. BaseFWX supplies primitives and secret
containers to the transport-v2 graph; it is a separate ignored checkout pinned
by `config/dependencies.json`. The [source map](SOURCE_MAP.md#authentication-and-cryptographic-ownership)
connects each mechanism to its implementation and explains the data path.

The intended primary transport does not require BaseFWX. Any retained BaseFWX
integration belongs to optional file encryption or file-format support outside
the live-traffic core. Dependency removal must preserve required authentication,
ratchet/rekey, post-quantum, secret-lifetime and relay/hop security properties
through tested reuse or ports. Keeping those properties does not require the
same primitive library: native YTP obtains its post-quantum algorithms from
OpenSSL 3.5. Its direct-session implementation does not establish completion of
the relay/hop migration.

## Public ABI boundary

The explicitly enabled candidate builds as unversioned
`libyume.so`. It exposes opaque runtime, config, endpoint, stream, and packet
types but is not a frozen installed product ABI. The surface is role-neutral
and has no JSON operation bus. A runtime owns callback delivery and coordinates
child endpoints; execution resources belong to the selected backend. An
immutable config owns validated values, an endpoint owns one backend selection,
and stream/packet handles own their application I/O lifetimes. Native packet
handles preserve record boundaries and credit. Transport-v2 packets remain
unsupported. Development SDK installation is a separate opt-in, not an ABI freeze.

The ABI selects a backend by configuration dialect. Transport-v2 documents run
the existing client and daemon runtimes. Schema-1 documents run the native
endpoint through `yume_embed` when the provider graph is built, and fail
closed otherwise. Neither dialect is an implicit provider for the other. The
schema-1 backend owns one execution thread per started endpoint and performs
every engine and provider call on it. Application threads hand requests over
through allocation-free control tasks. Received records keep their receive
credit until the application has copied every byte.

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
