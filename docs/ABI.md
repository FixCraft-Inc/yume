<!-- Generated from docs/src/en_US/pages/abi.doc by scripts/yume_docs.py. Edit that file, not this one. -->
# YUME C ABI v1

`include/yume/yume.h` is the experimental candidate for YUME's future stable
cross-language interface. It defines role-neutral endpoints and handles for
authenticated named byte streams and packet channels; it does not expose CLI
commands, a JSON operation bus, private C++ classes, or provider selection. The
current implementation boundary is stated below.

The ABI line, product version, YTP version, and config schema are independent.
During `0.3.0-dev*`, this replacement surface is still allowed to break without
an ABI-version bump. The opt-in candidate is an unversioned `libyume.so`; it is not
`libyume.so.1`. `YUME_INSTALL_EXPERIMENTAL_SDK=ON` enables development
installation of that library, the public C header, `yume.pc`, and the
`yume::yume` CMake target. It requires `YUME_BUILD_SHARED_ABI=ON` and remains
off by default. This does not freeze compatibility or create a release package. ABI v1 and SONAME `libyume.so.1` freeze
at `0.3.0-rc1` only after the functional and installed-consumer gates in this
document pass.

## Current development candidate

When explicitly enabled for a development build, the `0.3.0-dev1` library
implements build and compatibility metadata, strict schema-1 config parsing,
runtime and endpoint construction, bounded diagnostics, callback containment,
cancellation, and teardown. It starts a client or server through
`NativeEndpoint` and carries authenticated named byte streams through open,
accept, read, write, half-close, close, and destroy. Clients can also open TCP
destinations through a native daemon's configured direct TCP service. Packet
handles support named packet services and UDP destinations, with whole-packet
batch I/O and endpoint cancellation. A client can also carry the traffic of
a TUN device the application owns as streams and datagrams on its services.
An endpoint reports a status snapshot and the lines it has said about its
lifecycle, and the library opens a sealed kit with its code. The backend is not qualified end to end, and the library
remains experimental and unfrozen.

The remaining sections state the candidate contract and the gates that still
must pass before installation or ABI freeze.

## Development SDK installation

Build and stage the candidate into a private prefix:

```sh
cmake -S . -B build-sdk -DYUME_BUILD_SHARED_ABI=ON \
  -DYUME_INSTALL_EXPERIMENTAL_SDK=ON -DYUME_BUILD_TESTING=ON
cmake --build build-sdk
ctest --test-dir build-sdk --output-on-failure
cmake --install build-sdk --prefix /path/to/development-prefix
```

Use the pinned OpenSSL installation described in [Contributing](../CONTRIBUTING.md)
when configuring directly. A CMake consumer uses `find_package(yume CONFIG REQUIRED)`
and links `yume::yume`; a C or C++ compiler can use `pkg-config --cflags --libs yume`.
The package advertises `yume_EXPERIMENTAL=TRUE` and makes no version-compatibility
promise. `yume_abi_installed_consumers` installs into a fresh build-owned prefix
and compiles and runs separate C and C++ consumers through both discovery paths.
With the native daemon built, it also carries named streams/packets and routed
TCP/UDP through that installed library and staged daemon. A loader check verifies
the library comes from the staged prefix.

## Configuration and the backend seam

The internal embedding seam has one backend, `yume_embed`, which composes
the native endpoint and links no BaseFWX. The seam and the public ABI candidate
change together with their callers and tests. Exported names are not frozen.

A configuration document is configuration schema 1. It must name its role and
carry `"schema": 1`, and those two members are checked first. A document
written for another schema or runtime is therefore refused by them, not by the
first key schema 1 does not know. The strict parser rejects unknown keys, so a
misspelled security key is an error, never "not configured".

Streams are opened by a client endpoint and accepted by a server endpoint. The
backend refuses the direction it does not own with
`YUME_STATUS_INVALID_ARGUMENT`, so neither role can silently behave like the
other. YTP/1 itself lets either peer open a service, so this is an ABI
boundary rather than a protocol rule. A server has many sessions, and a
server-initiated open would need an authenticated way to choose one. Until that
is designed, a client refuses OPENs from its server.

`yume_endpoint_register_service` names a service that a server endpoint
accepts. A client endpoint has no accept path, so registration on it fails
with `YUME_STATUS_INVALID_ARGUMENT`. A server registers while stopped. Each
registration must match the immutable service table in the configuration and
remains attached across stop and restart. A configured service that was never registered is refused when a peer
opens it, so the configuration alone never exposes a service.

A named service stream carries no destination. Declare the shorter prefix size
to say so:

```c
yume_open_options options;
memset(&options, 0, sizeof(options));
options.struct_size = YUME_OPEN_OPTIONS_MIN_SIZE;   /* no destination field */
options.abi_version = YUME_ABI_VERSION;
options.service = (yume_string_view){name, name_length};
options.kind = YUME_SERVICE_BYTE_STREAM;
```

Passing `sizeof(options)` declares that the nested `yume_destination` is
present, and a zeroed descriptor is then a truncated destination rather than an
absent one.

Because the ABI receives configuration as bytes rather than as a file, there
is no document location to resolve relative credential paths against. Set
`yume_runtime_options.config_base_dir`, or use absolute paths. A NULL value
selects the process working directory, which is rarely what an embedded host
wants.

A client whose `endpoint.host` is a name, and that has no numeric
`connect_address`, looks it up in a separate helper process. Set
`yume_runtime_options.resolver_program` to the absolute path of the
`yume-resolver` program installed with the SDK. The pkg-config variable
`resolver_program` and the CMake package variable `yume_RESOLVER_PROGRAM` name
it. The file must be owned by root or the effective user and must not be
writable by group or others. With a NULL value such a client fails to start.
There is no in-process fallback. Stopping the endpoint kills the helper, so a
stalled system lookup never delays stop or destroy. A host that resolves names
itself, for example on a specific Android network, can pass the numeric
address as `connect_address` instead.

## Minimal embedding

The call sequence, client side. Every struct is sized, so set `struct_size` and
`abi_version` on each one and check every status.

```c
#include <yume/yume.h>

yume_runtime_options options;
memset(&options, 0, sizeof(options));
options.struct_size = sizeof(options);
options.abi_version = YUME_ABI_VERSION;
options.config_base_dir = "/etc/yume";   /* relative credential paths */
/* Name lookup helper, from pkg-config --variable=resolver_program yume. */
options.resolver_program = "/usr/local/libexec/yume/yume-resolver";

yume_runtime* runtime = NULL;
yume_runtime_create(&options, &runtime);

/* A schema-1 document. See "Configuration and the backend seam" above. */
yume_config* config = NULL;
yume_config_parse_json(runtime, json_bytes, json_size, &config);

yume_endpoint* endpoint = NULL;
yume_endpoint_create(runtime, config, &endpoint);
yume_config_destroy(config);            /* the endpoint copied what it needs */

yume_endpoint_start(endpoint, 30000);   /* now YUME_ENDPOINT_RUNNING */

yume_open_options open_options;
memset(&open_options, 0, sizeof(open_options));
open_options.struct_size = YUME_OPEN_OPTIONS_MIN_SIZE;  /* no destination */
open_options.abi_version = YUME_ABI_VERSION;
open_options.service = (yume_string_view){"my-service-v1", 13};
open_options.kind = YUME_SERVICE_BYTE_STREAM;

yume_stream* stream = NULL;
yume_endpoint_open_stream(endpoint, &open_options, 20000, &stream);

size_t written = 0;
yume_stream_write(stream, "ping", 4, &written, 20000);

char buffer[4096];
size_t received = 0;
yume_stream_read(stream, buffer, sizeof(buffer), &received, 20000);

yume_stream_shutdown_write(stream, 20000);   /* drains accepted writes first */
yume_stream_close(stream, 0);      /* immediate; nonzero is rejected */
yume_stream_destroy(stream);

yume_endpoint_stop(endpoint, 0);   /* synchronous; nonzero is unsupported */
yume_endpoint_destroy(endpoint);
yume_runtime_destroy(runtime);
```

A server calls `yume_endpoint_register_service` **before**
`yume_endpoint_start` and then uses `yume_endpoint_accept_stream` instead of
`yume_endpoint_open_stream`. A client names its server host as a DNS name,
because that name is also the TLS server name and the admission binding, and
lists every byte-stream service it opens.

The complete working version of both sides, including peer-identity checks and
teardown on every failure path, is
[`src/abi/stream_probe.c`](../src/abi/stream_probe.c). It runs as
`yume_abi_stream_integration`. It provisions a kit with `yume-setup` and also checks refusals, deadlines,
restart, and stream handles that outlive their endpoint.

## Intended installed interface

After the install gates close, consumers will include one header and link the
installed target or pkg-config module:

```c
#include <yume/yume.h>
```

```cmake
find_package(yume 0.3 CONFIG REQUIRED)
target_link_libraries(my_service PRIVATE yume::yume)
```

```bash
cc service.c $(pkg-config --cflags --libs yume)
```

No private YUME header or transitive private library will be part of the
contract. The installed CMake target and pkg-config file must carry every
required public link flag.

## Handles and ownership

The six opaque handle types are:

- `yume_runtime`: callback delivery and child-endpoint coordination;
- `yume_config`: one immutable, validated schema-1 configuration;
- `yume_endpoint`: a role-neutral client or server endpoint;
- `yume_stream`: one authenticated named byte stream;
- `yume_packet`: one authenticated named packet channel; and
- `yume_kit`: the files of one opened sealed kit.

Every successful `*_create`, `*_parse`, `*_open`, or `*_accept` transfers one
handle to the caller. The matching destroy function accepts null. A config is
immutable after parsing and may be used to create more than one endpoint in
the runtime that parsed it. Cross-runtime use fails with
`YUME_STATUS_INVALID_ARGUMENT`. An endpoint copies the validated configuration
state it needs, so destroying the config after endpoint creation is safe.

Destroy is a cancellation boundary. Runtime and endpoint destruction request
stop, wake blocked calls, join owned work, and then release storage. Stream and
packet destruction close the logical channel if needed. Because destroy cannot
report a cleanup error, applications that need the result call `stop` or
`close` first.

The caller must not race destruction of a handle with another operation on
that same handle, use a handle after destruction, or alias an output-handle
pointer with an input object. Runtime destruction stops child endpoint state
but does not free caller-owned child handles. Child handles keep the shared
implementation state they need alive; applications still close/destroy streams
and packets before their endpoint and destroy endpoints before the runtime.

## Thread safety

Version and manifest functions are thread-safe and have no mutable state.
Config handles are immutable and may be inspected concurrently. Endpoint
lifecycle, service registration, open, and accept calls are serialized inside
the endpoint and may be called from different application threads. A stop
does not wait behind a client start: it cancels it, as
[Endpoint lifecycle](#endpoint-lifecycle) describes. `yume_endpoint_get_status`
and `yume_endpoint_read_message` may be called from any thread at any time,
during a start included, and never wait for a lifecycle call. A kit handle is
immutable and may be read concurrently.

A stream supports one active reader and one active writer concurrently.
Write-side shutdown belongs to the write direction. Callers must not overlap
two operations in the same direction; the handle's direction mutexes are a
defensive serialization boundary, not an extension of a caller deadline. A
packet handle uses the same one-reader/one-writer rule. The caller must otherwise synchronize operations on one handle.

YUME does not hold state or diagnostic mutexes while invoking application
callbacks. It may retain endpoint lifecycle sequencing across a callback so
state-event order cannot interleave. Callback arguments and strings are
borrowed for that invocation only. To avoid self-deadlock, callbacks may
re-enter only the side-effect-free version/status queries and
`yume_handle_get_diagnostic`. Lifecycle, I/O, and registration calls return
`YUME_STATUS_INVALID_STATE`; the `void` destroy functions are ignored and
ownership remains with the caller. Exceptions thrown by C++ callbacks are
contained before returning through the C boundary.

## Runtime callbacks and bounds

`yume_runtime_options` configures the maximum simultaneous callback count and
an optional endpoint-event callback. Zero selects the bounded default. The ABI layer
does not expose an executor-count knob: execution resources belong to the
selected backend. Endpoint-state events are currently delivered synchronously
on the initiating lifecycle thread. This ABI has no logging callback. An
application reads what an endpoint has said with `yume_endpoint_read_message`.

Event callbacks are observational and must not be used as the source of
an authentication, authorization, close, or resource-limit decision. Callback
delivery is bounded; excess simultaneous observations may be dropped. The
current event surface reports endpoint-state changes only. Secrets, raw
credentials, PSKs, plaintext, and packet contents are never callback fields.

The socket-protection callback, which `yume_endpoint_set_socket_protector`
installs, is endpoint-scoped. It runs synchronously after
an outbound socket is created and before connect. Its `uintptr_t` argument
holds the platform-native socket value. Returning zero fails closed, and a
client start then reports `YUME_STATUS_IO_ERROR` with a
diagnostic. The callback and its user data must stay valid until cleared or
endpoint destruction finishes. No ABI re-entry is allowed from this callback.

## Strict configuration

`yume_config_role` reports a parsed document's role, `YUME_ROLE_CLIENT` or
`YUME_ROLE_SERVER`. `yume_config_parse_json` accepts a pointer plus explicit
byte count; the input
does not need a trailing NUL and is copied before return. Input is limited to
1 MiB and 16 nesting levels before any object model is built. Every document
requires a `client` or `server` role and a numeric `"schema": 1`. The strict
parser validates closed endpoint, suite, credential, cover, service/adapter,
and resource-limit objects.

Unknown keys, wrong types, inline private material, unsupported providers, and
unsafe combinations are errors, and no partial config handle is published.
Schema 1 has no key aliases.

A refused document reports its first failure as `YUME_STATUS_PARSE_ERROR` with
an RFC 6901 JSON pointer when it is attributable to one member, and an empty
pointer when it is not, such as malformed JSON or a document-wide validation
failure. Input over the 1 MiB limit reports `YUME_STATUS_RESOURCE_EXHAUSTED`. A
pointer or message longer than its fixed ABI field is marked by
`YUME_DIAGNOSTIC_JSON_POINTER_TRUNCATED` or
`YUME_DIAGNOSTIC_MESSAGE_TRUNCATED`. Config paths remain references;
permission and trust-material
checks that require the filesystem occur at endpoint start and in
`yume-doctor`.

YTP/1 has exactly one provider composition, reported by
`yume_get_compatibility`. It is not selected by the application and has no
fallback.

## Endpoint lifecycle

An endpoint moves through these visible states, which
`yume_endpoint_state` reports as `YUME_ENDPOINT_CREATED` to
`YUME_ENDPOINT_FAILED`:

```text
CREATED -> STARTING -> RUNNING -> STOPPING -> STOPPED
   |               \-> FAILED -> STOPPING -> STOPPED
   \-----------------------> STOPPING -> STOPPED
```

`yume_endpoint_start` is blocking. A client uses a positive millisecond
deadline, and zero selects the backend's 30-second default. A client deadline
may not exceed five minutes. A server accepts only zero because
server startup has no caller-bounded deadline. Success means the client
completed authenticated establishment or the server is accepting work. Failure
never publishes a partially started backend.

Once `STARTING` is visible, allocation or startup exceptions still settle the
state and deliver its terminal event. Allocation failure reports
`YUME_STATUS_RESOURCE_EXHAUSTED` and enters `FAILED`, unless runtime shutdown
has cancelled startup.

Idle server accepts retain bounded queue slots without consuming
an authentication deadline. Validated carrier promotion begins a separate
30-second session-creation/AUTH budget. FrontDoor independently limits
pre-promotion connections and work; idle waiting grants no peer authority.
When the configuration sets `limits.max_egress_mbps`, the server paces the
payload of every stream it serves as `yumed` does, sharing the rate between
identities by their authorized-keys `weight`.

A server keeps up to four starts pending per listener, at most 32 in
total, and retries a refused or immediately failed start after 100 ms. If a
listener runs out of descriptors or memory, its FrontDoor pauses OS accepts
for one second and retries. If a listener stops accepting, or an endpoint
start retry cannot be scheduled while that listener has nothing pending, the
backend closes the endpoint's sessions.
Accepts then report `YUME_STATUS_INVALID_STATE` until the application stops and
restarts the endpoint. The state stays `RUNNING`, as for a client whose session
ended.

A start failure carries the runtime's typed outcome rather than one generic
code, so an embedder does not have to read the diagnostic prose to tell the
cases apart. A backend that is already running reports
`YUME_STATUS_INVALID_STATE`, an exhausted resource is
`YUME_STATUS_RESOURCE_EXHAUSTED`, and a failure with no more specific
classification stays `YUME_STATUS_IO_ERROR`. Listener socket setup reports OS permission refusal as `YUME_STATUS_PERMISSION_DENIED`, an occupied
address as `YUME_STATUS_INVALID_STATE`, an unavailable or invalid local address
as `YUME_STATUS_INVALID_ARGUMENT`, and exhausted socket resources as
`YUME_STATUS_RESOURCE_EXHAUSTED`. Other socket failures remain
`YUME_STATUS_IO_ERROR`. A failed listener publishes no running endpoint and
can retry after the cause is resolved and `yume_endpoint_stop(endpoint, 0)`
settles `FAILED` through `STOPPING` to `STOPPED`. Start accepts only `CREATED`
or `STOPPED`; a direct retry from `FAILED` returns `YUME_STATUS_INVALID_STATE`
without starting work or emitting lifecycle events. A client start
that outlives its deadline reports `YUME_STATUS_TIMEOUT`. Declared adapters,
a `control` socket, a `cluster` section and reverse-proxy cover report
`YUME_STATUS_UNSUPPORTED` instead of starting without them. Never infer a status from the message.

`stop` is synchronous, idempotent after a start attempt, and accepts only zero.
It closes the endpoint's sessions, wakes blocked calls, and joins the backend's
execution threads before `STOPPED` is published. Registrations remain. A
client whose session ends later stays `RUNNING`, and its OPENs report
`YUME_STATUS_INVALID_STATE` until the application stops and starts it again.

A stop, an endpoint destroy or a runtime destroy on another thread cancels a
client start that is still in progress. The start ends its connection
attempt, returns `YUME_STATUS_CANCELLED` and leaves the endpoint `STOPPED`,
with one `STOPPED` event that carries `YUME_STATUS_CANCELLED`. The stop then
returns `YUME_STATUS_OK`. An application can therefore give up a start that
waits on a dead network without waiting out its deadline. A cancelled start
is not recorded as the endpoint's latest failure.
Explicit stop, runtime destruction, or endpoint destruction may take an
endpoint directly from `CREATED` through `STOPPING` to `STOPPED` without
starting a backend.

Services are registered by a canonical name and kind. Resource controls remain
in immutable configuration and the selected runtime; the ABI descriptor does
not duplicate them. Names contain 1 through 128 bytes of lowercase ASCII
namespace segments separated by `.`; `-` and `_` are allowed only inside a
segment. Service names are unique by `(name, kind)` within an endpoint. A
registration must match the immutable service table and occurs before start.
Registration is endpoint-local: there is no process-global provider or service
registry. A server OPEN is dispatched
only after the authenticated identity, advertised capability, service policy,
and resource reservation all succeed. Route providers are reached through the
same dispatcher and cannot bypass those checks.

## Open and accept

`yume_open_options` contains a service name, stream/packet kind, and an
optional typed destination. Custom named services omit the suffix or use
destination kind `NONE`. Hostname, IPv4, and IPv6 descriptors are validated
strictly, including a nonzero port. Clients send the destination with
the named service to the native server. Its direct TCP adapter authorizes the
request, resolves hostnames, checks every resolved address against configured
destinations, and only then connects. Application-accepted named services
refuse destination-routed OPENs. The embedding server still does not compose
adapters, so use the native daemon for direct egress. There is no generic JSON
metadata channel.

Open and accept publish an output handle only on success. A timeout before an
OPEN is admitted sends nothing, including when the request waits for execution
thread dispatch past its deadline. The backend uses YTP/1's 31-bit odd/even
stream identifiers. A timed-out OPEN is cancelled on the endpoint's execution
thread. An OPEN still held behind a rekey is dropped, a sent one is aborted,
and a crossed acceptance is closed instead of published.

A client opens only byte-stream services its configuration declares.
An undeclared name returns `YUME_STATUS_NOT_FOUND` without sending OPEN. When
the server's credential grant or registration refuses the service, the OPEN
returns `YUME_STATUS_PERMISSION_DENIED` and the session stays usable. A server
holds each authorized OPEN until `yume_endpoint_accept_stream` takes it,
so a client OPEN succeeds only after the server application accepted the
stream. At most 256 OPENs wait per endpoint, and they hold no receive credit.
An OPEN that its client abandons is skipped. Taking an OPEN that is already
waiting finishes on the execution thread, even with a zero timeout.

Each stream exposes a sized `yume_peer_identity`, which
`yume_stream_get_peer_identity` copies: authenticated state, peer
role, an optional composite fingerprint, an opaque transport `peer_label`, and
service. The label carries no application meaning: it is not a device, account,
or enrollment record. A stream in either role reports the composite fingerprint that YTP/1 authentication established for its
peer, and `peer_label` holds the same value in lowercase hex.

## Stream I/O

Timeouts are milliseconds:

- `0` polls current state without waiting;
- every positive value is one finite relative deadline for the backend
  operation; and
- there is no infinite-timeout sentinel.

These rules apply to open, accept, read, write, and write-side shutdown. A
zero-timeout client OPEN returns `WOULD_BLOCK` without sending OPEN. Lifecycle
and immediate-close timeouts are operation-specific as described above.

Reads may be partial. `YUME_STATUS_OK` with a positive byte count returns data.
`YUME_STATUS_EOF` means the peer shut down its write side and all buffered data
has been returned. A local cancellation or reset is a typed non-EOF status. A
lost session, peer abort, or endpoint stop is never reported as EOF, so EOF is
the peer's authenticated end of data. Termination takes precedence even after
an earlier read returned EOF. An abort or session loss discards
data that was not yet read.

Writes copy the complete input into a bounded queue before returning OK and
report the complete size in `bytes_written`. Admission is all-or-none. One
write carries at most 256 KiB, and a larger write returns
`YUME_STATUS_INVALID_ARGUMENT`. A write is admitted once the previous accepted
write was sent. A zero-timeout call while that is in progress returns
`WOULD_BLOCK`, an expiring positive deadline returns `TIMEOUT`, and a transport
that had capacity but could not take ownership of the write returns
`YUME_STATUS_IO_ERROR`. None of the three consumes the input,
reserves capacity, or sends a partial record. A zero-length write is a
successful no-op on an open stream.

`shutdown_write` sends an authenticated half-close after prior writes. A
positive deadline bounds the wait for those writes and the execution-thread
result. For schema 1, once shutdown is queued, `WOULD_BLOCK` or `TIMEOUT` can
leave it pending. Later writes are refused; retrying shutdown observes the
same operation and never sends another FIN. A timeout while prior writes are
still draining does not begin shutdown.

Accept transfers an already authenticated waiting stream to the
application and queues its peer acceptance without waiting for runner dispatch.
The peer's OPEN completes only after that acceptance executes. A crossed abort
can leave the returned handle closed. Failed public handle publication aborts
it; if that close precedes runner dispatch, pending peer acceptance is refused.

`close` cancels
both directions and releases retained inbound credit. Data received after
terminal close is a protocol failure and is never delivered. A stream handle
may outlive its endpoint's stop. Its operations then report
`YUME_STATUS_CLOSED`, and closing or destroying it remains safe.

## Packet I/O

A client opens a packet channel with `yume_endpoint_open_packet` for a service
of kind packet, and a server takes one with `yume_endpoint_accept_packet`.
`yume_packet_write_batch` takes an array of borrowed views. The implementation
validates the count, every pointer and length, total bytes, and queue
capacity before it copies or admits any packet. Batches contain 1–256
nonempty packets of at most 65535 bytes each and at most 16 MiB in total;
negotiated limits may be smaller. Writes exceeding `limits.max_packet_batch`
return `RESOURCE_EXHAUSTED` without admission, and reads deliver no more than
that configured count. A successful batch preserves every packet boundary; a
failed batch admits none.

`yume_packet_read_batch` copies complete packets into caller storage and
reports their offsets/sizes in caller-owned slots. If the first queued packet
does not fit, `BUFFER_TOO_SMALL` reports the required storage and leaves it
queued. Later packets are not skipped to manufacture a partial success.
`yume_packet_close` and `yume_packet_destroy` end a channel as the stream
functions do, and `yume_packet_get_peer_identity` reports its peer.

## Device bridge

A client endpoint can carry everything that enters a TUN device the
application owns, such as the device of an Android `VpnService`, over the
same services `yume` uses for SOCKS5: one stream OPEN for each TCP
connection and one packet OPEN for each UDP destination, each with its
destination. A kit made for `yume` therefore works without a packet service
on the server, and the server's egress policy and per-identity weights apply
as they do to any other client.

`yume_endpoint_set_device` takes a sized `yume_device_options`:

| Field | Value |
| --- | --- |
| `descriptor` | An open TUN descriptor that reads and writes whole IP packets without a packet-information header |
| `mtu` | The device's MTU, 576 to 65535, and at least 1280 with an IPv6 address |
| `stream_service` | The byte-stream service TCP connections open, which the configuration must declare |
| `packet_service` | The packet service UDP destinations open. Empty drops UDP |
| `ipv4_address`, `ipv4_peer` | The device's own IPv4 address and a second address that routes to the device and nothing else uses, as IP literals |
| `ipv6_address`, `ipv6_peer` | The same pair for IPv6. Empty drops IPv6. At least one family is required |

The library duplicates the descriptor and sets it non-blocking, which also
applies to the caller's copy because both name one open device. The caller
keeps and closes its own. The call is accepted while the endpoint is
`CREATED` or `STOPPED`, the device stays attached across stop and start, and
a null `options` detaches it. A server endpoint returns
`YUME_STATUS_UNSUPPORTED`, and a service the configuration does not declare
with the right kind `YUME_STATUS_NOT_FOUND`.

The bridge runs while the endpoint is `RUNNING`. Nothing reads the device
otherwise, so its traffic waits and then drops inside the device and never
leaves another way. A start fails with `YUME_STATUS_INVALID_ARGUMENT` when
the device's address is not usable for the bridge's listener.

An endpoint with a device keeps its session up. Its start still returns when
the first session has authenticated, or fails with that attempt. After that
the endpoint stays `RUNNING` and replaces a lost session itself, as `yume`
does: at once after a session that lasted 30 seconds, otherwise after a wait
that doubles from 1 to 30 seconds. While it has no session the bridge still
answers, so an application's new connection is reset at once instead of
waiting. `yume_endpoint_retry_now` starts a waiting endpoint's next attempt
without the rest of its wait, for an application that learns the network is
back, and takes effect at most once a second. The server's address stays the
one the configuration names, so an application that must dial another one
stops the endpoint and starts it with a new configuration.

How traffic crosses:

- **TCP.** The bridge rewrites each packet's addresses so the host's own
  kernel accepts the application's connection on a listener the library owns
  at the device's address, then opens `stream_service` with the connection's
  destination and joins the two. No TCP is implemented in the library. The
  listener accepts only peers the bridge translated, so no other local
  process can use it. An application's connection is accepted locally at
  once and is reset when no session is active. With a session it waits for
  its OPEN, and closes if that is refused or fails, or if the connection has
  no stream 30 seconds after its accept. The bridge keeps at most three
  quarters of `limits.max_pending_opens` in flight, so a burst of
  connections queues inside the bridge and none is refused by the session's
  own bound, and a connection that finds every stream of the session in use
  waits for one within the same 30 seconds. At most 1024 connections are
  open at once, and further ones wait in the kernel's accept queue. A
  segment of a connection the bridge does not know, such as one from before
  a restart, is answered with a reset.
- **UDP.** A datagram from a local port to a destination opens
  `packet_service` with that destination, as a SOCKS5 UDP association does,
  and replies return to that port from that destination. A local port
  reaches at most 32 destinations at once and the device 512 in total.
  Datagrams waiting for their stream hold at most 64 datagrams and 1 MiB
  for the whole device, and a full queue drops the newest. A reply the
  device cannot take at once is dropped. A destination without traffic for
  60 seconds closes, and after a refused or failed OPEN its datagrams are
  dropped for one second. Fragments and replies larger than the MTU are
  dropped.
- **Name lookups.** Datagrams to port 53 of one address share one packet
  OPEN, whatever local port they come from. A resolver would otherwise get
  an OPEN for every query, because each uses a new port, and every lookup
  would wait for it. The bridge gives each query a random DNS identifier of
  its own and returns the reply to the port that asked with the identifier
  it used. At most 1024 queries of one resolver wait for a reply, each for
  10 seconds.
- **Everything else** is dropped: ICMP and other protocols, IPv6 packets
  with extension headers, and packets whose source is not the device's
  address.

Destinations are addresses, never names: a name lookup is a datagram to
whatever resolver the application configured for the device. Streams end
when the session ends or the endpoint stops, so applications reconnect
after a restart.

The application routes traffic to the device and both peer addresses with
it, keeps the transport's own connection outside it with
`yume_endpoint_set_socket_protector`, and lets its own process's replies to
the peer address reach the device.

## Endpoint status

`yume_endpoint_get_status` copies a point-in-time snapshot into a sized
`yume_endpoint_status`. It is what [control protocol 1](protocol/CONTROL_1.md)
reports for `yume`. An endpoint without a device makes one attempt per
start, so the fields of a retry loop stay zero for it. The call changes
nothing, waits for no lifecycle call and holds no key, credential or
payload.

| Field | Value |
| --- | --- |
| `role`, `state` | `YUME_ROLE_*` and the `YUME_ENDPOINT_*` state |
| `session` | `YUME_SESSION_NONE`, or `YUME_SESSION_ACTIVE` while a client's session is authenticated. Without a device, `YUME_SESSION_ENDED` once it has ended while the endpoint stays `RUNNING`. With one, `YUME_SESSION_CONNECTING` during an attempt and `YUME_SESSION_WAITING` before the next |
| `connected_ms` | While the session is active: how long it has been up |
| `retry_ms` | While waiting: the delay before the next attempt |
| `sessions`, `failed_attempts` | Sessions authenticated since the endpoint last started, and failed attempts since the latest of them |
| `peer_fingerprint_sha256` | While the session is active: the server's verified composite fingerprint, otherwise zero bytes |
| `epoch_bytes` | While the session is active: its key epoch, the smaller of the two sides' `max_epoch_bytes`, otherwise 0 |
| `payload_bytes_sent`, `payload_bytes_received`, `record_bytes_sent`, `record_bytes_received` | Totals over every session of this endpoint handle |
| `last_failure`, `last_failure_message` | The latest failed start, failed attempt or ended session of this handle as a typed status and its text, or `YUME_STATUS_OK` and an empty text when there has been none |
| `max_queued_bytes`, `max_epoch_bytes`, `credit_returns_per_window`, `idle_epoch_rotation` | The configuration's limits that a tuning preset sets, the last as 0 or 1 |
| `device_tcp_connections`, `device_udp_destinations` | With a device bridge: the TCP connections and UDP destinations it carries now |

A later success does not clear `last_failure`, so a display can still say
why the previous session ended. Stopping the endpoint is not a
failure and records nothing. The fixed composition that a posture display
states with these limits comes from `yume_get_compatibility`.

A server endpoint reports its role, state, limits and latest failed start.
Its session, identity and traffic fields are zero, because the ABI does not
report a server's sessions yet. From a callback the call returns
`YUME_STATUS_INVALID_STATE`.

## Endpoint messages

An endpoint keeps the lines it has said about its lifecycle, as `yume` keeps
the lines it prints: its latest 256, each cut to 512 bytes and numbered from
1 in order. A client says when its session authenticated, why a start failed
and why a session ended, and a server says when it accepts sessions and why
it stopped accepting. The lines hold no key, credential or payload.

`yume_endpoint_read_message` copies the oldest kept line numbered above
`after` into a sized `yume_message`: its `seq`, its `time_unix_ms` in UTC
and its `text`. `missed` counts the lines numbered above `after` and below
`seq` that the endpoint no longer keeps. `instance` is 16 hexadecimal digits
that stay the same while the numbering continues and change when it starts
again at 1, which happens when the endpoint's services or socket protector
change while it is stopped. When no kept line is numbered above `after`, the
call returns `YUME_STATUS_WOULD_BLOCK` with `seq` 0 and the `instance`. An
application follows the feed by asking again after the last `seq` it read:

```c
yume_message message;
uint64_t after = 0;
for (;;) {
    memset(&message, 0, sizeof(message));
    message.struct_size = sizeof(message);
    message.abi_version = YUME_ABI_VERSION;
    if (yume_endpoint_read_message(endpoint, after, &message,
                                   sizeof(message)) != YUME_STATUS_OK) break;
    after = message.seq;
    /* message.text is NUL-terminated. */
}
```

The call never waits. From a callback it returns `YUME_STATUS_INVALID_STATE`.

## Sealed kits

A [sealed kit](protocol/SEALED_KIT_1.md) is a client's `yume.json` and
credential files in one file, opened with a 25-character code. `yume
--import-kit` writes one to a directory. `yume_kit_open` opens one in memory
with the same implementation, so an embedder stores the files as its
platform requires, for example under a hardware-backed key.

```c
yume_kit* kit = NULL;
yume_status status = yume_kit_open(runtime, sealed, sealed_size,
                                   code, code_size, &kit);
for (size_t index = 0; index < yume_kit_file_count(kit); ++index) {
    yume_kit_file file;
    memset(&file, 0, sizeof(file));
    file.struct_size = sizeof(file);
    file.abi_version = YUME_ABI_VERSION;
    yume_kit_get_file(kit, index, &file, sizeof(file));
    /* file.path, file.data, file.size and file.executable */
}
yume_kit_destroy(kit);   /* wipes the files */
```

`code` is what the user typed: separators and spaces are dropped, letters
are upper-cased, and `O` reads as `0` and `I` or `L` as `1`. It is not kept
after the call. Opening derives a key with Argon2id over 64 MiB, so the call
takes a noticeable time and belongs off an interface thread.

| Status | Meaning |
| --- | --- |
| `YUME_STATUS_INVALID_ARGUMENT` | A pointer is missing, the file is empty or the code is not 25 code characters |
| `YUME_STATUS_RESOURCE_EXHAUSTED` | The file is larger than a sealed kit can be, or memory ran out |
| `YUME_STATUS_PERMISSION_DENIED` | The code is wrong or the file is not a sealed kit. The two cannot be told apart |
| `YUME_STATUS_PARSE_ERROR` | The code opened the file, but its content is not a valid kit |

A failure publishes no handle and leaves its text as the runtime handle's
diagnostic. `yume_kit_file_count` returns the number of files, at most 32,
and 0 for a null handle. `yume_kit_get_file` fills a sized `yume_kit_file`
for an index below that count and returns `YUME_STATUS_NOT_FOUND` for any
other. Files come in path order. A path is one or two components of ASCII
letters, digits, `.`, `_` and `-`, such as `credentials/admission.key`, and
`yume.json` is always present. `path` and `data` point into the kit and stay
valid until `yume_kit_destroy`, which wipes the files before it releases
them. The library validates the kit's layout, not its configuration: pass
`yume.json` to `yume_config_parse_json` before relying on it.

## Sized structures

Every extensible structure starts with `struct_size` and `abi_version`. Callers
zero the complete object, set those fields, and pass both the pointer and
allocated size where required. The library:

1. rejects a prefix smaller than the published `*_MIN_SIZE`;
2. writes only complete fields that fit in both sizes;
3. reports its known layout in `struct_size`; and
4. ignores zeroed trailing storage from a newer caller.

These are the current layout and bounds rules for build, compatibility, status,
diagnostic and peer-identity structures. They do not freeze the development
candidate: a deliberate layout change updates the header, implementation and
consumers together. No call may read or write outside its declared storage.

Sized input structures follow the same storage bounds. The library reads only
complete fields contained by `struct_size`; omitted optional suffix fields use
their documented zero/default behavior. The current service descriptor's
complete `(name, kind)` layout is required, while the destination suffix of an
OPEN may be absent and is then treated as destination kind `NONE`.

## Status and diagnostics

Machine decisions use `yume_status`; applications never parse error text.
`yume_get_status_info` maps a known status to its stable name. Retry safety is
operation-specific: a generic status never authorizes automatic replay of an
OPEN, write, or lifecycle call.

Each handle stores its own last diagnostic. A successful status-returning
operation clears the previous diagnostic on that handle; side-effect-free
queries and the diagnostic query itself do not. `yume_handle_get_diagnostic`
copies the status, truncation flags, optional JSON pointer, and bounded human
message into caller storage. It takes a runtime, config, endpoint, stream,
packet or kit handle. Diagnostics contain no private key, PSK, token,
plaintext, destination payload, or raw peer credential.

No C++ exception may cross the ABI, callback, thread entry, destructor, or
`noexcept` cleanup boundary. Unexpected exceptions are contained and reported
as `YUME_STATUS_INTERNAL_ERROR` after local state is made safe.

## Compatibility manifest

`yume_abi_version` returns `YUME_ABI_VERSION`, 1, and
`yume_get_compatibility` reports together:

- product version;
- YTP name and numeric version;
- config schema and ABI version;
- suite components and each concrete provider identity;
- cryptographic backend; and
- evidence profile name/version.

The session security provider is `openssl35.ytp1-security`, the provider the
library links. The cryptographic backend is `openssl-` followed by the loaded
OpenSSL version, such as `openssl-3.5.7`, in both the manifest and
`yume_get_build_info`.

Provider/suite mismatch is a hard `YUME_STATUS_INCOMPATIBLE`. YTP/1 never
negotiates a weaker suite and never retries through another provider.

## Export and freeze gates

`src/abi/yume.map` is the canonical 40-symbol set. CMake derives the Mach-O
list and validates the built ELF/Mach-O/PE surface from it. The same change
must update:

- `include/yume/yume.h`;
- `src/abi/yume.map`;
- `debian/libyume1.symbols`;
- CMake/pkg-config exports;
- strict-C and C++ header consumers;
- clean-prefix CMake and pkg-config consumers; and
- this document.

The build-tree gate checks the exact symbol set,
header/map/Debian-symbol agreement, strict C/C++ header consumption, metadata,
strict configuration and its refusals, lifecycle/callback containment,
diagnostics, ownership, named-stream and packet traffic, native client
destination streams against a separate daemon, a TUN device whose TCP and
UDP traffic crosses a real session, the status snapshot and message feed of
a real session, a start cancelled by a stop, a sealed kit opened and
refused, and the intentional typed
`UNSUPPORTED` boundary for declared adapters and the control socket. The clean-prefix CMake and pkg-config fixtures are future acceptance material, not
a claim that the candidate is currently installed.

Before ABI v1 freezes, the clean-prefix matrix must link without private YUME
dependencies, exchange an authenticated custom byte stream, exercise packet
lifecycle, deadlines, cancellation, and teardown, and pass sanitizer and
failure-injection qualification. Until those gates pass, the source remains
`0.3.0-dev*`, the ABI package remains disabled, and the surface must not be
described as frozen or generally installed.
