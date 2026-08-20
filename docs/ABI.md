# YUME ABI Policy

YUME exposes a stable C ABI through `libyume.so.1` when configured with
`-DYUME_BUILD_SHARED_ABI=ON`.

The ABI is intentionally C-only. It exposes build information plus opaque
runtime handles for embedders:

- `yume_client`
- `yume_server`
- `yume_stream`
- `yume_packet`

External projects must include only `<yume/yume.h>`. They must not include
`src/client/cli/entry.hpp`, `client::Tunnel`, `facade::InProcClient`,
`server::RuntimeController`, Boost.Asio types, OpenSSL handles, STL types, or
any other private C++ implementation header.

## Project-Neutral Boundary

This ABI belongs to YUME and is not tied to any application that embeds it.
Service names and payload schemas are defined by each embedder; YUME provides
authenticated, policy-gated byte streams and does not assign application
meaning to them. Examples in this document use `example-service-v1` only as a
placeholder. No external project's names, message schemas, or authorization
rules are part of the YUME ABI contract.

## Why C ABI First

The CLI, GUI, facade, and transport internals can keep evolving without
freezing compiler, standard library, exception, allocator, or object-layout
details. A C ABI gives C and C++ embedders a stable link target while YUME keeps
its internal transport code private.

## 1.1 Runtime Surface

`libyume.so.1` supports:

- Client/server create, destroy, start, stop, and status calls.
- Start from a JSON string or a config file path.
- Caller-owned JSON output buffers. If the buffer is too small, functions
  return `YUME_STATUS_BUFFER_TOO_SMALL` and report the required byte count.
- Per-handle last-error strings with `yume_handle_last_error`.
- Per-thread free-function errors with `yume_last_error`.
- Direct named service streams with blocking timeout-based C calls:
  `yume_client_open_stream`, `yume_server_register_service`,
  `yume_server_accept_stream`, `yume_stream_peer_json`,
  `yume_stream_read`, `yume_stream_write`, `yume_stream_shutdown_write`,
  and `yume_stream_close`.
- One negotiated packet-native channel with `yume_client_open_packet`,
  `yume_packet_status_json`, `yume_packet_write_batch`,
  `yume_packet_read_batch`, `yume_packet_close`, and `yume_packet_destroy`.

The ABI v1 stream API is synchronous by design. Async callbacks can be added in
a later ABI version without forcing embedders into YUME's internal threading
model now.

`yume_stream_write` accepts `timeout_ms` for ABI stability, but ABI v1 writes
only synchronously enqueue bytes into the YUME stream and ignore the value. Pass
`0` unless a future ABI revision documents write-deadline behavior.

`yume_server_stop` and `yume_server_destroy` interrupt an in-flight
`yume_server_accept_stream` wait. The accept call returns
`YUME_STATUS_NOT_RUNNING` after the runtime begins stopping.

The packet API is additive within ABI v1 and SONAME `libyume.so.1`.
`YUME_FEATURE_PACKET_BULK` detects it; `YUME_FEATURE_PQ_MLKEM1024` accurately
reports the ML-KEM-1024 ratchet primitive while the older ML-KEM-768 bit is
retained for source compatibility. Packet write inputs are copied before
return and admitted all-or-none. Reads copy complete packets into caller-owned
contiguous storage and caller-owned offset/length arrays. If the first packet
does not fit, `YUME_STATUS_BUFFER_TOO_SMALL` reports its size without consuming
it. Zero timeout means poll, saturation returns `YUME_STATUS_WOULD_BLOCK`, and
an expired positive deadline returns `YUME_STATUS_TIMEOUT`. Client or packet
stop interrupts blocking packet calls.

`yume_client_status_json` returns:

```json
{
  "running": true,
  "ready": true,
  "message": "",
  "socket_path": "",
  "exit_code": 0,
  "server_tls_fingerprint_sha256": "lowercase-hex-sha256-of-tls-leaf",
  "server_capabilities": ["packet_bulk_v1"],
  "packet_bulk_supported": true,
  "started_unix_ms": 1780000000000
}
```

The TLS fingerprint field is the actual negotiated server leaf certificate
fingerprint. It is present as an empty string before the client is connected.

## Start JSON Schema

`yume_client_start_json` and `yume_server_start_json` parse the same JSON keys
as the facade config files. Relative path fields are resolved against the
`base_dir` argument. Unknown keys are ignored for forward compatibility.

Android and other in-process VPN embedders may configure
`yume_client_set_socket_protector` before starting a client. YUME invokes the
callback synchronously for every primary, secondary, direct, or SOCKS-proxy
carrier socket after opening it and before connecting it. Returning zero aborts
the connection with `YUME_STATUS_PERMISSION_DENIED`. The callback must be
thread-safe, must not re-enter the same client, and its callback/user-data pair
must remain valid until it is cleared or `yume_client_destroy` returns.

Android packages use the client-only ABI build profile. It preserves the ABI
v1 export surface for loaders, but server lifecycle calls report
`YUME_STATUS_PERMISSION_DENIED` or `YUME_STATUS_NOT_RUNNING`; no server runtime
is linked into the APK. Client, stream, and packet behavior is unchanged.

Minimum server-side embed shape for a named service:

```json
{
  "listen_address": "127.0.0.1",
  "listen_port": 4433,
  "tls_cert": "server.crt",
  "tls_key": "server.key",
  "auth_keys": "authorized_keys",
  "auth_keys_meta": "auth_keys.meta",
  "operator_keys": "operator_keys",
  "operator_keys_meta": "operator_keys.meta",
  "threads": 0,
  "max_sessions": 256,
  "bulk_key_max_sessions": 64,
  "accept_rate_limit": 100,
  "egress_mbps": 0,
  "allow_services": ["example-service-v1"],
  "ipc_enable": false,
  "obfuscation": true,
  "obfs_secret_file": "obfs.secret",
  "inner_psk_file": "inner.psk"
}
```

`listen_address` is optional. Empty or omitted means bind `0.0.0.0`; set
`127.0.0.1` for loopback-only tests and embedded local services.

`operator_keys` and `operator_keys_meta` are optional and physically separate
from regular user authorization. The capacity fields have the same meaning as
the daemon flags: `threads: 0` selects hardware-aware automatic sizing,
`max_sessions` is the aggregate tracked-session cap,
`bulk_key_max_sessions` is the default for explicitly shared regular keys,
`accept_rate_limit` is aggregate accepts per second, and `egress_mbps` is the
optional weighted-fair link cap (`0` disables shaping).

Minimum client-side embed shape:

```json
{
  "server": "127.0.0.1",
  "port": 4433,
  "identity": "client-auth.key",
  "socks_port": 0,
  "tunnels": 1,
  "service_streams_only": true,
  "tls_ca_cert": "server.crt",
  "tls_server_name": "embedder.local",
  "tls_pin_sha256": "lowercase-hex-sha256-of-tls-leaf",
  "accept_monitoring": false,
  "auto_attach_local": false,
  "obfuscation": true,
  "obfs_secret_file": "obfs.secret",
  "inner_psk_file": "inner.psk"
}
```

`tls_pin_sha256` is optional when `tls_ca_cert`/`tls_server_name` are sufficient,
but embedders that already have a manifest pin should pass it and may also
compare `server_tls_fingerprint_sha256` in `yume_client_status_json`.
In-process clients are non-interactive: a normal-mode server is rejected unless
`accept_monitoring` is explicitly true. Keep it false when operator identity
verification is required; no terminal consent prompt is attempted through the
ABI. The legacy `anonym_*` fields authenticate CA-authorized operator identity;
they do not prove a no-logging policy or anonymity.

`socks_bind` is optional. Empty or omitted keeps the historical wildcard bind;
set an IP literal such as `127.0.0.1`, `0.0.0.0`, `::1`, or `::` to choose the
SOCKS listener address explicitly.

For a headless packet embed, keep `socks_port` at zero, start the authenticated
client, then call `yume_client_open_packet`. The in-process runtime selects its
headless engine mode without synthesizing a SOCKS listener. `tunnels` must be
in `1..16`; a single packet-bulk carrier is the minimal embedded profile.

Per-key service authorization lives in `auth_keys.meta` under the authenticated
client key fingerprint:

```json
{
  "0123456789abcdef...": {
    "permissions": {
      "allow_services": ["example-service-v1"]
    }
  }
}
```

## Named Service Streams

Native service streams are not raw TCP forwards and do not expose `Tunnel`.
Clients open an authenticated `OPEN` payload with:

```json
{"proto":"service.v1","service":"example-service-v1"}
```

The stream then rides through the same TLS 1.3, HTTP/2/WebSocket carrier,
mandatory hybrid directional ratchet, and server policy gates as normal YUME
streams. Legacy hopping, padding, and jitter are absent from the pinned 2.0
profile.

Server-side accept is explicit and fail-closed:

- The server config must list the service in `allow_services`.
- The connected auth key must list the service in
  `permissions.allow_services`.
- The embedder must call `yume_server_register_service`.
- If any gate is missing, the server rejects the `OPEN`.

`allow_services` is separate from `allow_local_ip`, `control_full`,
application codecs, and exec permissions.

After `yume_server_accept_stream` returns a stream, the embedder can call
`yume_stream_peer_json`:

```json
{
  "service": "example-service-v1",
  "peer": "authenticated-peer-id",
  "auth_fingerprint_sha256": "composite-identity-sha256",
  "session_id": "authenticated-peer-id",
  "server_session_id": "42",
  "remote_addr": "203.0.113.10"
}
```

`auth_fingerprint_sha256` is the SHA-256 fingerprint of the domain-separated,
length-prefixed DER encodings of both authenticated public-key halves and is the
stable field to use for device binding.
`session_id` is a stable peer id for the accepted stream; `server_session_id` is
the server's internal numeric session id serialized as a string for log
correlation only.

## Compatibility Rules

- `YUME_ABI_VERSION` tracks the source-level C ABI line.
- `libyume.so.1` tracks binary runtime compatibility.
- Existing exported functions must keep their names, return conventions, and
  argument meaning for the lifetime of SONAME `1`.
- Structs that cross the ABI must start with `struct_size`.
- New fields may only be appended to public structs.
- Functions must not throw exceptions across the ABI.
- Returned strings are owned by the library and remain valid for the process
  lifetime.
- Do not expose internal C++ headers from `src/`.

## Symbol Control

`src/abi/yume.map` is the canonical list of exported symbols. Everything else
that needs to know the public surface derives from it, so the platforms cannot
drift apart:

| Platform | Mechanism |
|---|---|
| ELF | version script (`--version-script=yume.map`) |
| Mach-O | `-exported_symbols_list`, generated from `yume.map` at configure time |
| PE | nothing required: symbols are private unless declared `__declspec(dllexport)`, which only `YUME_API` carries |

This matters beyond tidiness. `libyume` absorbs YUME's internal static
libraries and may also absorb static third-party archives such as liboqs and
argon2. Without symbol control, implementation symbols can leak into the
public namespace, which breaks the "exactly these functions" contract and lets
an embedder bind to an internal implementation.

Two CTest cases enforce it:

- `yume_abi_header_matches_map` — pure text, no compiler needed. Catches a
  function declared `YUME_API` in the header but missing from the version
  script (hidden at link time, fails only for the embedder) and the reverse.
- `yume_abi_exports` — inspects the built library with `nm` and requires the
  exported set to equal the declared set exactly. Runs on ELF and Mach-O.

Both run in CI, which also builds `libyume` with `-DYUME_BUILD_SHARED_ABI=ON`.
Adding a public function therefore means editing `include/yume/yume.h` and
`src/abi/yume.map` together; the build fails otherwise.

## Handle Lifetime

Handle arguments must be live objects of the correct type returned by this ABI.
Destroy functions accept `NULL`; no other call probes arbitrary or stale
pointers. Callers must synchronize destruction with every other operation on
the same handle, including `yume_handle_last_error`.

Errors are stored per handle. `yume_handle_last_error` copies the selected
error into thread-local storage, so its return pointer remains valid until the
next `yume_handle_last_error` call on that thread, regardless of which handle
is queried next.

Free functions that can produce a detailed diagnostic, such as
`yume_generate_pq_keypair`, store it separately for `yume_last_error`. That
pointer remains valid until the next free-function error update on the same
thread.

## Build Behavior

Source builds keep the ABI library off by default:

```bash
cmake -B build
cmake --build build
```

Enable it explicitly when building SDK/install artifacts:

```bash
cmake -B build -DYUME_BUILD_SHARED_ABI=ON
cmake --build build --target yume_abi
```

Debian packaging enables the ABI library by default and installs only the C ABI
surface plus package metadata:

- `libyume1`: runtime shared library.
- `libyume-dev`: `yume.h`, CMake config, and pkg-config metadata.
- `yume`: CLI client, docs, and examples.
- `yume-daemon`: `yumed`, its disabled-by-default service, and daemon
  configuration/runtime directories.
- `yume-gui`: optional GUI, omitted by `DEB_BUILD_PROFILES=nogui`.

## Future Expansion

New public runtime features should extend the opaque C handles first. Do not
export C++ transport classes, GUI models, raw tunnel streams, or broad LAN
bridging as the native embed interface.
