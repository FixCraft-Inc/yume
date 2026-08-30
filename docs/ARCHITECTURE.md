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
both the CLI and federation. Its implementation and server-consumed headers
live under `src/outbound/`; compatibility headers under `src/client/` retain
existing client include spellings without giving the client ownership of the
shared implementation. The server does not link `yume_client_lib` or include
client/CLI production headers.

## Source layout

### `src/core/`: shared transport kernel

Used by client, server, facade, and ABI. No UI, no `main()`.

| Directory | Responsibility |
| --- | --- |
| `security/` | AUTH, identity, and the ML-KEM-1024 + X25519 + PSK ratchet with AES-GCM records |
| `protocol/` | Wire format, frames, control protocol, runtime policy |
| `stealth/` | TLS fingerprint shaping, HTTP/2 obfs carrier, disguise |
| `app_codec/` | Codec-neutral envelope and registry; `builtin/` holds one unit per codec |
| `diagnostics/` | Bounded runtime diagnostics and developer-only instrumentation |
| `release/` | Version/build reports and release-facing runtime metadata |
| `runtime/` | Local IPC / runtime socket helpers |

`src/core/version.hpp` holds the current development `kVersion` and its
authenticated `kTransportVersion` alias. AUTH, relay, ABI, and helper IPC
schema versions remain independent in their owning modules.

### `src/outbound/`: neutral outbound transport

Owned by `yume_outbound_transport` and used by both client and server paths.
It contains the transport core, stream, tunnel, socket-protection callback,
SOCKS5 outbound dialer, timeout/cancellation I/O, forwarding adapter, bounded
UDP queue, and AUTH carrier establishment. Compatibility headers retain older
client include spellings. CLI-only fatal errors, option wording, and
interactive policy remain under `src/client/cli/`.

### `src/client/`: CLI client

| Directory | Responsibility |
| --- | --- |
| `cli/` | Argument parsing, config, connect handshake, commands |
| `packet/` | Client-side packet-bulk/TUN data plane |
| `transport/` | Client-owned TLS-helper/pool integration and compatibility headers for neutral outbound types |
| `proxy/` | Local SOCKS5 runtime plus compatibility headers for neutral forwarding and queue types |
| `relay/` | Relay runtime, secrets, history |
| `transfer/` | Share/import/export transfer workflows |
| `codec/` | Client-side app codec shims (e.g. Monero RPC) |
| `runtime/` | Local runtime socket for attach/GUI |

Entry: `main_client.cpp` → `client/cli/entry.cpp`.

### `src/server/`: daemon

| Directory | Responsibility |
| --- | --- |
| `cli/` | Args, config load, keys, cluster, startup checks |
| `session/` | Per-client sessions: auth, carrier, codecs, streams |
| `runtime/` | `Manager`, `RuntimeController`, identity admission, optional weighted egress |
| `federation/` | Cluster peer links, plus the topology/status document a cluster viewer reads and its text layout |
| `filter/` | IP / robots filtering, optional GeoIP |
| `packet/` | TUN egress for packet-bulk mode |
| `auth/` | Composite Ed25519 + ML-DSA-87 verification plus immutable regular/operator/admin snapshots |
| `config/` | Server configuration types and defaults |
| `host/` | Loopback cover backend, routes, and host-controller plumbing |

Entry: `main_server.cpp` → `server/cli/entry.cpp`.

### `src/facade/`: embedder API

Static library over core + client + server. Used by `yume-gui` and
automation. No Dear ImGui dependency. Its chat-history result preserves
messages, storage availability, truncation, and the storage diagnostic as
typed state; transport/envelope/schema failures remain a separate error path.

### `src/gui/`: desktop UI

Dear ImGui + GLFW + ImPlot. Pages call facade sessions; does not
duplicate the transport stack.

### `website/`: static publication site

The Jekyll/GitHub Pages site presents project documentation, status, and
release metadata. It does not link YUME libraries, control a local runtime, or
own protocol behavior. CI copies tracked `docs/*.md` into ignored generated
pages during the site build; `website/docs/index.html` remains a hand-written
landing page. Website contribution and validation rules live in
`CONTRIBUTING.md`.

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
`gui/`. BaseFWX (`basefwx/`) owns the default one-shot cryptographic
primitives when `YUME_USE_BASEFWX=ON`, including the explicit-nonce
ChaCha20-Poly1305 operation used by protected relay history. YUME owns its wire
formats, transport behavior, AUTH, and ratchet policy. A YUME-local
compatibility/security helper still contains SHA-256 identity hashing plus
residual X25519/HKDF/HMAC/RNG operations and the BaseFWX-disabled history
fallback. Live callers must not expand that raw-OpenSSL surface. The
required BaseFWX revision is recorded in `config/dependencies.json`; its public
C++ contract and regression tests own the explicit-nonce primitive. Dead or
unused helpers should be removed with reference checks and focused tests, not
preserved as a second public status register.

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
| JSON control API | `docs/CONTROL_API.md` |
| Federation transit (design only) | `docs/protocol/YUME_2_0_FEDERATION_TRANSIT.md` |
| Current implementation boundary | `docs/IMPLEMENTATION_STATUS.md` |
| Contributor entry point | `AGENTS.md`, `CONTRIBUTING.md`, `docs/README.md` |
