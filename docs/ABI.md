# YUME C ABI v1

`include/yume/yume.h` is the experimental candidate for YUME's future stable
cross-language interface. It defines role-neutral endpoints and handles for
authenticated named byte streams and packet channels; it does not expose CLI
commands, a JSON operation bus, private C++ classes, or provider selection. The
current implementation boundary is stated below.

The ABI line, product version, YTP version, and config schema are independent.
During `0.3.0-dev*`, this replacement surface is still allowed to break without
an ABI-version bump. The opt-in candidate is a build-tree-only, unversioned
`libyume.so`; it is not `libyume.so.1`. ABI v1 and SONAME `libyume.so.1` freeze
at `0.3.0-rc1` only after the functional and installed-consumer gates in this
document pass.

## Current development candidate

When explicitly enabled for a development build, the `0.3.0-dev1` library
currently implements build/compatibility metadata, strict schema-1 config
parsing, runtime and endpoint construction, bounded diagnostics, callback
containment, cancellation, and teardown. With the default transport-v2 graph
present, it can start client and server endpoints and carry authenticated named
byte streams through open, accept, read, write, half-close, close, and destroy.
The integration probe exercises that path against a provisioned real server.

This is not a live YTP/1 endpoint. A schema-1 endpoint still fails start with
`YUME_STATUS_UNSUPPORTED`: the opt-in TLS, H2 carrier, security, and route
provider candidates are not composed into a production front door or ABI
backend. Packet handles and destination-routed OPEN are also unsupported. The
library remains build-tree-only, unversioned, uninstalled, and unfrozen.

The remaining sections distinguish current transport-v2 behavior from the
candidate contract and gates that still must pass before installation or ABI
freeze.

## Configuration dialects and the backend seam

One runtime is attached behind a single internal seam, so the same public
symbols serve every backend and a later swap changes no exported name.

A configuration document must name its role. A document that also carries
`"schema": 1` is a YTP/1 document and is parsed by the strict schema-1 parser.
Any other role-bearing document is the runnable transport-v2 dialect. The
dialect is never inferred from which parser happens to accept the bytes:
both ignore unknown keys, so guessing would load a document against the wrong
runtime.

| Dialect | Start | Byte streams | Packets |
| --- | --- | --- | --- |
| transport-v2 | starts the runnable client or daemon | open, accept, read, write, half-close | `YUME_STATUS_UNSUPPORTED` |
| schema 1 (YTP/1) | `YUME_STATUS_UNSUPPORTED` | `YUME_STATUS_UNSUPPORTED` | `YUME_STATUS_UNSUPPORTED` |

Streams are opened by a client endpoint and accepted by a server endpoint. The
backend refuses the direction it does not own with
`YUME_STATUS_INVALID_ARGUMENT`, so neither role can silently behave like the
other. A server-initiated open is a separate reviewed capability rather than an
accident of symmetry.

`yume_endpoint_register_service` advertises a service the peer may open. On a
transport-v2 endpoint the running runtime is the authority, so registration
must follow `yume_endpoint_start` and returns `YUME_STATUS_INVALID_STATE`
before it. A successful stop discards those runtime registrations; after a
restart the caller registers them again. On a schema-1 endpoint the
registration is additionally checked against the immutable service table in
the configuration and remains attached across stop and restart.

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

A build configured with `YUME_BUILD_TRANSPORT_V2=OFF` links no runtime at all.
The library still exports the identical surface, and the transport-v2 dialect
is refused with a typed unsupported status.

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

yume_runtime* runtime = NULL;
yume_runtime_create(&options, &runtime);

/* The document must name its role. See "Configuration dialects" above. */
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

A server endpoint calls `yume_endpoint_register_service` **after**
`yume_endpoint_start`, then `yume_endpoint_accept_stream` instead of
`yume_endpoint_open_stream`.

The complete working version of both sides, including peer-identity checks and
teardown on every failure path, is
[`src/abi/stream_integration_probe.c`](../src/abi/stream_integration_probe.c).
It runs in CI as `yume_abi_stream_integration` against a real provisioned
server, so it cannot drift from the shipped surface.

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

The five opaque handle types are:

- `yume_runtime`: callback delivery and child-endpoint coordination;
- `yume_config`: one immutable, validated transport-v2 or schema-1
  configuration;
- `yume_endpoint`: a role-neutral client or server endpoint;
- `yume_stream`: one authenticated named byte stream; and
- `yume_packet`: one authenticated named packet channel.

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
the endpoint and may be called from different application threads.

A stream supports one active reader and one active writer concurrently.
Write-side shutdown belongs to the write direction. Callers must not overlap
two operations in the same direction; the handle's direction mutexes are a
defensive serialization boundary, not an extension of a caller deadline. A
packet handle will use the same one-reader/one-writer rule once packets are
implemented. The caller must otherwise synchronize operations on one handle.

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
optional log/event callbacks. Zero selects the bounded default. The ABI layer
does not expose an executor-count knob: execution resources belong to the
selected backend. Endpoint-state events are currently delivered synchronously
on the initiating lifecycle thread. The log callback field is accepted for
forward compatibility, but the current ABI backends emit no log records.

Log and event callbacks are observational and must not be used as the source of
an authentication, authorization, close, or resource-limit decision. Callback
delivery is bounded; excess simultaneous observations may be dropped. The
current event surface reports endpoint-state changes only. Secrets, raw
credentials, PSKs, plaintext, and packet contents are never callback fields.

The socket-protection callback is endpoint-scoped. It runs synchronously after
an outbound socket is created and before connect. Its `uintptr_t` argument
holds the platform-native socket value. Returning zero fails closed
and the current transport-v2 start reports `YUME_STATUS_IO_ERROR` with a
diagnostic. The callback and its user data must stay valid until cleared or
endpoint destruction finishes. No ABI re-entry is allowed from this callback.

## Strict configuration

`yume_config_parse_json` accepts a pointer plus explicit byte count; the input
does not need a trailing NUL and is copied before return. Input is limited to
1 MiB and 16 nesting levels before either parser builds its full object model.
Every document requires a `client` or `server` role. A numeric `"schema": 1`
selects the strict replacement parser, which validates closed endpoint, suite,
credential, cover, service/adapter, and resource-limit objects. Omitting
`schema` selects the transport-v2 parser.

Unknown keys, old aliases, wrong types, inline private material, unsupported
providers, and unsafe combinations are errors. No partial config handle is
published. The runtime diagnostic names the first failure with an RFC 6901
JSON pointer. A pointer or message longer than its fixed ABI field is marked by
`YUME_DIAGNOSTIC_JSON_POINTER_TRUNCATED` or
`YUME_DIAGNOSTIC_MESSAGE_TRUNCATED`. Config paths remain references;
permission and trust-material
checks that require the filesystem occur at endpoint start and in
`yume-doctor-ytp1`.

YTP/1 has exactly one provider composition, reported by
`yume_get_compatibility`. It is not selected by the application and has no
fallback.

## Endpoint lifecycle

An endpoint moves through these visible states:

```text
CREATED -> STARTING -> RUNNING -> STOPPING -> STOPPED
   |               \-> FAILED -> STOPPING -> STOPPED
   \-----------------------> STOPPING -> STOPPED
```

`yume_endpoint_start` is blocking. A transport-v2 client uses a positive
millisecond deadline; zero selects the backend's 30-second default. A
transport-v2 server accepts only zero because server startup currently has no
caller-bounded deadline. Schema-1 start accepts the descriptor but returns
`YUME_STATUS_UNSUPPORTED`. Success means the client completed authenticated
establishment or the server is accepting work. Failure never publishes a
partially started backend. `stop` is synchronous, idempotent after a start
attempt, and currently accepts only zero. A successful transport-v2 stop also
discards registrations owned by that stopped runtime, so callers re-register
services after restarting it; immutable schema-1 registrations remain.
Explicit stop, runtime destruction, or endpoint destruction may take an
endpoint directly from `CREATED` through `STOPPING` to `STOPPED` without
starting a backend.

Services are registered by a canonical name and kind. Resource controls remain
in immutable configuration and the selected runtime; the ABI descriptor does
not duplicate them. Names contain 1 through 128 bytes of lowercase ASCII
namespace segments separated by `.`; `-` and `_` are allowed only inside a
segment. Service names are unique by `(name, kind)` within an endpoint. A
schema-1 registration must match the immutable service table and occurs before
start. A transport-v2 server registers byte-stream services after start so the
running runtime remains the authority.
Registration is endpoint-local; there is no process-global provider or service
registry. A server OPEN is dispatched
only after the authenticated identity, advertised capability, service policy,
and resource reservation all succeed. Route providers are reached through the
same dispatcher and cannot bypass those checks.

## Open and accept

`yume_open_options` contains a service name, stream/packet kind, and an
optional typed destination. Custom named services omit the suffix or use
destination kind `NONE`. Hostname, IPv4, and IPv6 descriptors are validated
strictly, including a nonzero port, but destination-routed ABI OPEN currently
returns `YUME_STATUS_UNSUPPORTED` before sending anything. The opt-in direct
route provider belongs to the uncomposed YTP/1 graph and is not silently used
by the transport-v2 ABI backend. There is no generic JSON metadata channel.

Open and accept publish an output handle only on success. A timeout before an
OPEN is admitted sends nothing. A timeout after an OPEN crossed the wire
causes the transport-v2 bridge to close and permanently retire its 8-bit
service-stream identifier for that tunnel, so a late ACK or DATA frame cannot
alias a new stream. YTP/1 separately owns 31-bit odd/even identifiers in its
session engine, but that engine is not the current ABI backend.

The accepted stream exposes a sized `yume_peer_identity`: authenticated state,
peer role, an optional composite fingerprint, an opaque transport
`peer_label`, and service. The label carries no application meaning: it is not
a device, account, or enrollment record. On the transport-v2 server, the
client fingerprint is present after composite authentication. On the client,
the server is authenticated by the outer TLS channel and the composite
fingerprint field remains zero because that backend does not expose one.

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
has been returned. A local cancellation or reset is a typed non-EOF status.

Writes copy the complete input into a bounded queue before returning OK and
report the complete size in `bytes_written`. Admission is all-or-none. A zero-
timeout full queue returns `WOULD_BLOCK`; an expiring positive deadline returns
`TIMEOUT`; neither consumes the input or sends a partial record. A zero-length
write is a successful no-op on an open stream.

`shutdown_write` sends an authenticated half-close after prior writes. `close`
cancels both directions and releases retained inbound credit. Data received
after terminal close is a protocol failure and is never delivered.

## Packet I/O

Packet writes take an array of borrowed views. The implementation validates
the count, every pointer and length, total bytes, and queue capacity before it
copies or admits any packet. A successful batch preserves every packet
boundary; a failed batch admits none.

Packet reads copy complete packets into caller storage and report their
offsets/sizes in caller-owned slots. If the first queued packet does not fit,
`BUFFER_TOO_SMALL` reports the required storage and leaves it queued. Later
packets are not skipped to manufacture a partial success.

## Sized structures

Every extensible structure starts with `struct_size` and `abi_version`. Callers
zero the complete object, set those fields, and pass both the pointer and
allocated size where required. The library:

1. rejects a prefix smaller than the published `*_MIN_SIZE`;
2. writes only complete fields that fit in both sizes;
3. reports its known layout in `struct_size`; and
4. ignores zeroed trailing storage from a newer caller.

This append-only rule applies to build, compatibility, status, diagnostic, and
peer-identity structures. It is not permission to reinterpret or reorder an
existing field.

Sized input structures use the same append-only rule. The library reads only
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
message into caller storage. Diagnostics contain no private key, PSK, token,
plaintext, destination payload, or raw peer credential.

No C++ exception may cross the ABI, callback, thread entry, destructor, or
`noexcept` cleanup boundary. Unexpected exceptions are contained and reported
as `YUME_STATUS_INTERNAL_ERROR` after local state is made safe.

## Compatibility manifest

`yume_get_compatibility` reports together:

- product version;
- YTP name and numeric version;
- config schema and ABI version;
- suite components and each concrete provider identity (an unwired component
  is reported as `unwired`, never as a provider that merely exists in the
  source tree);
- cryptographic backend; and
- evidence profile name/version.

Provider/suite mismatch is a hard `YUME_STATUS_INCOMPATIBLE`. YTP/1 never
negotiates a weaker suite and never retries through another provider.

## Export and freeze gates

`src/abi/yume.map` is the canonical 32-symbol set. CMake derives the Mach-O
list and validates the built ELF/Mach-O/PE surface from it. The same change
must update:

- `include/yume/yume.h`;
- `src/abi/yume.map`;
- `debian/libyume1.symbols`;
- CMake/pkg-config exports;
- strict-C and C++ header consumers;
- clean-prefix CMake and pkg-config consumers; and
- this document.

The current opt-in gate is build-tree-only. It checks the exact symbol set,
header/map/Debian-symbol agreement, strict C/C++ header consumption, metadata,
both config dialects, lifecycle/callback containment, diagnostics, ownership,
transport-v2 start and authenticated named-stream traffic, plus the intentional
typed `UNSUPPORTED` schema-1, packet, and routed-OPEN boundaries. The
clean-prefix CMake and pkg-config fixtures are future acceptance material, not
a claim that the candidate is currently installed.

Before ABI v1 freezes, the clean-prefix matrix must link without private YUME
dependencies, exchange an authenticated custom byte stream, exercise packet
lifecycle, deadlines, cancellation, and teardown, and pass sanitizer and
failure-injection qualification. Until those gates pass, the source remains
`0.3.0-dev*`, the ABI package remains disabled, and the surface must not be
described as frozen or generally installed.
