# YUME architecture

This page maps the source tree to CMake targets and installed binaries.
For traffic flow and routing models, see `docs/EXPLAINED.md`.

## Installed binaries

| Binary | CMake target | Role |
| --- | --- | --- |
| `yume` | `yume` | CLI client |
| `yumed` | `yumed` | Server daemon |
| `yume-gui` | `yume-gui` | Optional desktop UI (`YUME_BUILD_GUI=ON`) |
| `libyume.so` | `yume_abi` | Optional stable C ABI (`YUME_BUILD_SHARED_ABI=ON`) |

Debian packages split these into `yume`, `yume-gui`, `libyume1`, and
`libyume-dev`. See `docs/PACKAGING.md`.

## CMake target graph

```text
                    +------------------+
                    |    yume_core     |
                    | protocol/security|
                    | stealth/runtime  |
                    +--------+---------+
                             |
              +--------------+--------------+
              |                             |
    +---------v---------+         +---------v---------+
    | yume_transport_   |         |   (shared core)   |
    | core              |         +---------+---------+
    +---------+---------+                   |
              |              +--------------+--------------+
              |              |                             |
    +---------v---------+    |                 +---------v---------+
    | yume_client_lib   |    |                 |   yume_server     |
    | cli/transport/... |    |                 | session/runtime/..|
    +---------+---------+    |                 +---------+---------+
              |              |                             |
    +---------v---------+    +-------------+---------------+
    |      yume         |                  |
    |  main_client.cpp  |         +--------v--------+
    +-------------------+         |  yume_facade    |
                                  | session/config  |
    +-------------------+         +--------+--------+
    |      yumed        |                  |
    | main_server.cpp   |         +--------v--------+
    | server/cli/*      |         |    yume-gui     |
    +-------------------+         |  gui/* + ImGui  |
                                  +-----------------+
```

`yume_transport_core` is always built — Android and embedders link it
without pulling the full CLI or server stacks.

## Source layout

### `src/core/` — shared transport kernel

Used by client, server, facade, and ABI. No UI, no `main()`.

| Directory | Responsibility |
| --- | --- |
| `security/` | AUTH, identity, and the ML-KEM-1024 + X25519 + PSK ratchet with AES-GCM records |
| `protocol/` | Wire format, frames, control protocol, runtime policy |
| `stealth/` | TLS fingerprint shaping, HTTP/2 obfs carrier, disguise |
| `app_codec/` | Codec-neutral envelope and registry; `builtin/` holds one unit per codec |
| `runtime/` | Local IPC / runtime socket helpers |

`src/core/version.hpp` holds `kVersion` — protocol compatibility bump
only with a deliberate plan.

### `src/client/` — CLI client

| Directory | Responsibility |
| --- | --- |
| `cli/` | Argument parsing, config, connect handshake, commands |
| `transport/` | TLS tunnel, crypto, dispatch, tunnel pool |
| `proxy/` | SOCKS5, port forward, outbound proxy (incl. Tor) |
| `relay/` | Relay runtime, secrets, history |
| `codec/` | Client-side app codec shims (e.g. Monero RPC) |
| `runtime/` | Local runtime socket for attach/GUI |

Entry: `main_client.cpp` → `client/cli/entry.cpp`.

### `src/server/` — daemon

| Directory | Responsibility |
| --- | --- |
| `cli/` | Args, config load, keys, cluster, startup checks |
| `session/` | Per-client sessions: auth, carrier, codecs, streams |
| `runtime/` | `ServerManager`, local runtime controller, identity admission, optional weighted egress |
| `federation/` | Cluster peer links |
| `filter/` | IP / robots filtering, optional GeoIP |
| `packet/` | TUN egress for packet-bulk mode |
| `auth/` | Ed25519 key verification plus validated immutable regular/operator policy snapshots |

Entry: `main_server.cpp` → `server/cli/entry.cpp`.

### `src/facade/` — embedder API

Static library over core + client + server. Used by `yume-gui` and
automation. No Dear ImGui dependency.

### `src/gui/` — desktop UI

Dear ImGui + GLFW + ImPlot. Pages call facade sessions; does not
duplicate the transport stack.

### Other

| Path | Role |
| --- | --- |
| `src/abi/` | `libyume` C ABI (`yume_c.cpp`) |
| `src/platform/` | Per-OS executable path helpers |
| `src/tools/` | `yume-net-map`, selftest benches (optional targets) |

## Dependency direction

Edits should respect this import order:

```text
core  →  client | server  →  facade  →  gui
```

`core` must not include headers from `client/`, `server/`, `facade/`, or
`gui/`. Crypto primitives come from BaseFWX (`basefwx/`) when
`YUME_USE_BASEFWX=ON`; YUME owns wire format and transport behavior.

## Trust boundary

The standard topology is single hop: `application -> yume -> yumed -> target`.
The daemon is the terminating cryptographic peer and proxy exit, not a blind
onion relay. It authenticates the client's Ed25519 public identity from a
signed transcript, derives the hybrid session roots, decrypts YUME records, and
opens target sockets. Application-layer TLS can remain end-to-end through that
proxy. See `docs/THREAT_MODEL.md` for identity, forward-secrecy, channel-binding,
and malicious-server limits.

## Documentation and diagrams

Architecture prose lives under `docs/`. Routing diagrams use
`docs/diagrams/*.spec` rendered by `scripts/draw_pipeline.py`; see
`scripts/regen_diagrams.sh` to regenerate ASCII for paste into README or
man pages. `scripts/check_ascii_diagrams.py` enforces fixed box widths.

## Related pages

| Topic | Document |
| --- | --- |
| Traffic routes | `docs/EXPLAINED.md` |
| Stealth layers | `docs/STEALTH.md` |
| Permissions | `docs/PERMISSIONS.md` |
| Threat stance | `docs/THREAT_MODEL.md` |
| App codecs | `docs/APP_CODECS.md` |
| Packet bulk | `docs/PACKET_NATIVE_BULK.md` |
| C ABI scope | `docs/ABI.md` |
