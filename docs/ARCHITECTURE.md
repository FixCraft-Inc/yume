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

Debian packages split these into `yume`, `yume-daemon`, `yume-gui`,
`libyume1`, and `libyume-dev`. See `docs/PACKAGING.md`.

## CMake target graph

```text
                         +----------------------+
                         | yume_secure_core     |
                         | STATIC protocol, AUTH|
                         | ratchet, secret files|
                         +----------+-----------+
                                    |
                    +---------------+---------------+
                    |                               |
          +---------v---------+           +---------v---------+
          |     yume_core     |           | yume_transport_   |
          | stealth/runtime/  |           | core              |
          | shared facilities |           | reduced transport |
          +---------+---------+           +---------+---------+
                    |                               |
                    +---------------+---------------+
                                    |
                          +---------v---------+
                          | yume_outbound_    |
                          | transport         |
                          | dial/tunnel/auth  |
                          +---------+---------+
                                    |
                    +---------------+---------------+
                    |                               |
          +---------v---------+           +---------v---------+
          | yume_client_lib   |           |   yume_server     |
          | cli/runtime/share |           | session/runtime/..|
          +----+--------------+           +----+--------------+
               |    \                       /    |
               |     +---------+-----------+     |
               |               |                 |
       +-------v-------+   +----v-------------+  +v--------------+
       |     yume      |   |   yume_facade    |  |     yumed      |
       +---------------+   | session/config   |  +----------------+
                           +---------+--------+
                                     |
                           +---------v---------+
                           | yume-gui / ABI    |
                           +-------------------+
```

`yume_secure_core` is a STATIC library that gives the shared protocol,
composite-AUTH, ratchet, and secret-material sources one compiled owner.
`yume_core` and `yume_transport_core` both link it instead of compiling those
sources twice. `yume_transport_core` is always built, so Android and embedders
can link the reduced transport slice without pulling the full CLI or server
stacks. `yume_outbound_transport` owns the small client/server-common dial,
tunnel, forwarding, outbound-proxy, and authenticated-connect slice used by
both the CLI and federation. The server does not link `yume_client_lib`.

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

`src/core/version.hpp` holds the current development `kVersion` and its
authenticated `kTransportVersion` alias. AUTH, relay, ABI, and helper IPC
schema versions remain independent in their owning modules.

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
| `auth/` | Composite Ed25519 + ML-DSA-87 verification plus immutable regular/operator/admin snapshots |

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

Transport identities are schema-driven rather than selected by browser-specific
branches in consumers. `config/transport_profiles.json` registers immutable
capture fixtures, `scripts/generate_transport_profiles.py` produces the checked-in
C++ and Go helper registries, and TLS/HTTP/H2 code reads
`cover_profile::active()`. See
`docs/TRANSPORT_PROFILES.md` for the extension and evidence contract.

## Dependency direction

Edits should respect this import order:

```text
secure/core + reduced transport
                 ↓
       outbound transport
           ↙           ↘
      client           server
           ↘           ↙
              facade  →  gui / ABI
```

`core` must not include headers from `client/`, `server/`, `facade/`, or
`gui/`. Crypto primitives come from BaseFWX (`basefwx/`) when
`YUME_USE_BASEFWX=ON`; YUME owns wire format and transport behavior.

## Trust boundary

The standard topology is single hop: `application -> yume -> yumed -> target`.
The daemon is the terminating cryptographic peer and proxy exit, not a blind
onion relay. It authenticates the client's composite public identity from a
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
| Transport profiles | `docs/TRANSPORT_PROFILES.md` |
| Permissions | `docs/PERMISSIONS.md` |
| Threat stance | `docs/THREAT_MODEL.md` |
| Security modes | `docs/SECURITY_MODES.md` |
| App codecs | `docs/APP_CODECS.md` |
| Packet bulk | `docs/PACKET_NATIVE_BULK.md` |
| C ABI scope | `docs/ABI.md` |
