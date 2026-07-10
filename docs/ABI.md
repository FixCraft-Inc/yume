# YUME ABI Policy

YUME exposes a stable C ABI through `libyume.so.1` when configured with
`-DYUME_BUILD_SHARED_ABI=ON`.

The ABI is intentionally C-only. It exposes build information plus opaque
runtime handles for embedders:

- `yume_client`
- `yume_server`
- `yume_stream`

External projects must include only `<yume/yume.h>`. They must not include
`src/client/cli/entry.hpp`, `client::Tunnel`, `facade::InProcClient`,
`server::RuntimeController`, Boost.Asio types, OpenSSL handles, STL types, or
any other private C++ implementation header.

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
- Direct named service streams with blocking timeout-based C calls:
  `yume_client_open_stream`, `yume_server_register_service`,
  `yume_server_accept_stream`, `yume_stream_peer_json`,
  `yume_stream_read`, `yume_stream_write`, `yume_stream_shutdown_write`,
  and `yume_stream_close`.

The ABI v1 stream API is synchronous by design. Async callbacks can be added in
a later ABI version without forcing embedders into YUME's internal threading
model now.

`yume_server_stop` and `yume_server_destroy` interrupt an in-flight
`yume_server_accept_stream` wait. The accept call returns
`YUME_STATUS_NOT_RUNNING` after the runtime begins stopping.

`yume_client_status_json` returns:

```json
{
  "running": true,
  "ready": true,
  "message": "",
  "socket_path": "",
  "exit_code": 0,
  "server_tls_fingerprint_sha256": "lowercase-hex-sha256-of-tls-leaf",
  "started_unix_ms": 1780000000000
}
```

The TLS fingerprint field is the actual negotiated server leaf certificate
fingerprint. It is present as an empty string before the client is connected.

## Start JSON Schema

`yume_client_start_json` and `yume_server_start_json` parse the same JSON keys
as the facade config files. Relative path fields are resolved against the
`base_dir` argument. Unknown keys are ignored for forward compatibility.

Minimum server-side embed shape for a named service:

```json
{
  "listen_address": "127.0.0.1",
  "listen_port": 4433,
  "tls_cert": "server.crt",
  "tls_key": "server.key",
  "auth_keys": "authorized_keys",
  "auth_keys_meta": "auth_keys.meta",
  "allow_services": ["example-control-v1"],
  "ipc_enable": false,
  "obfuscation": true,
  "obfs_secret": "shared-h2-token",
  "inner_crypto": true,
  "inner_required": true,
  "inner_hop": true,
  "hop_interval_ms": 500
}
```

`listen_address` is optional. Empty or omitted means bind `0.0.0.0`; set
`127.0.0.1` for loopback-only tests and embedded local services.

Minimum client-side embed shape:

```json
{
  "server": "127.0.0.1",
  "port": 4433,
  "identity": "client-auth.key",
  "socks_bind": "127.0.0.1",
  "socks_port": 1080,
  "tls_ca_cert": "server.crt",
  "tls_server_name": "embedder.local",
  "tls_pin_sha256": "lowercase-hex-sha256-of-tls-leaf",
  "accept_monitoring": false,
  "auto_attach_local": false,
  "obfuscation": true,
  "obfs_secret": "shared-h2-token",
  "inner_crypto": true,
  "inner_heavy": true,
  "inner_hop": true,
  "hop_interval_ms": 500
}
```

`tls_pin_sha256` is optional when `tls_ca_cert`/`tls_server_name` are sufficient,
but embedders that already have a manifest pin should pass it and may also
compare `server_tls_fingerprint_sha256` in `yume_client_status_json`.

`socks_bind` is optional. Empty or omitted keeps the historical wildcard bind;
set an IP literal such as `127.0.0.1`, `0.0.0.0`, `::1`, or `::` to choose the
SOCKS listener address explicitly.

Per-key service authorization lives in `auth_keys.meta` under the authenticated
client key fingerprint:

```json
{
  "0123456789abcdef...": {
    "permissions": {
      "allow_services": ["example-control-v1"]
    }
  }
}
```

## Named Service Streams

Native service streams are not raw TCP forwards and do not expose `Tunnel`.
Clients open an authenticated `OPEN` payload with:

```json
{"proto":"service.v1","service":"example-control-v1"}
```

The stream then rides through the same TLS 1.3, HTTP/2 obfs, inner crypto,
hopping, padding/jitter, and server policy gates as normal YUME streams.

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
  "service": "example-control-v1",
  "peer": "authenticated-peer-id",
  "auth_fingerprint_sha256": "ed25519-spki-sha256",
  "session_id": "authenticated-peer-id",
  "server_session_id": "42",
  "remote_addr": "203.0.113.10"
}
```

`auth_fingerprint_sha256` is the authenticated client Ed25519 public-key SPKI
SHA-256 fingerprint and is the stable field to use for device binding.
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
- `yume`: CLI client and `yumed` server daemon.
- `yume-gui`: optional GUI, omitted by `DEB_BUILD_PROFILES=nogui`.

## Future Expansion

New public runtime features should extend the opaque C handles first. Do not
export C++ transport classes, GUI models, raw tunnel streams, or broad LAN
bridging as the native embed interface.
