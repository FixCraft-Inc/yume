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
  `yume_server_accept_stream`, `yume_stream_read`, `yume_stream_write`,
  `yume_stream_shutdown_write`, and `yume_stream_close`.

The ABI v1 stream API is synchronous by design. Async callbacks can be added in
a later ABI version without forcing embedders into YUME's internal threading
model now.

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
