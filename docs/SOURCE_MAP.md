# YUME source map

Where the code is and which parts are load-bearing. Read this before
[ARCHITECTURE.md](ARCHITECTURE.md): that document describes the YTP/1
replacement contracts, which are not yet the running system.

## Vocabulary

The project's own terms, because several are used everywhere and expanded
almost nowhere.

| Term | Means |
| --- | --- |
| **YTP/1** | **YUME Transport Protocol 1.** The replacement wire protocol. Version 1 of a new protocol, not "YUME 1". Its kernel is `src/ytp/`, its contract is [protocol/YTP_1.md](protocol/YTP_1.md). |
| **transport v2** | The wire protocol that ships and works today, `0.2.0-dev6`. Independent of the product version. Contract in [protocol/YUME_2_0_WIRE.md](protocol/YUME_2_0_WIRE.md). |
| **AUTH v2** | The authentication and key-schedule layer of transport v2: composite Ed25519 + ML-DSA-87 identity, ML-KEM-1024 + X25519 + PSK establishment, then a directional AEAD ratchet. |
| **schema 1** | The strict numeric configuration schema for YTP/1 (`src/config/v1/`). Unrelated to transport-v2 JSON config. |
| **ABI v1** | The role-neutral C interface in `include/yume/yume.h`. Its version is independent of every wire and product version. |
| **admission** | The cheap, replay-protected check a client passes before the server will promote a connection to a YUME carrier. Failing it gets the ordinary cover response, not an error. |
| **cover** | The genuine website or reverse proxy a non-YUME visitor sees. Configure it, or the default stub fingerprints the deployment. |
| **carrier** | The outer connection that YUME records ride inside: TLS 1.3 plus HTTP/2, optionally WebSocket-framed. |
| **obfs secret** | The admission key. `obfs_secret_file` and `obfs_secret_material` are live. An inline `obfs_secret` key is refused by every parser and no field carries it. |
| **anonym** | Operator-authority proof and privacy-minimizing logging. It proves who runs the server, **not** that nothing is logged. |
| **BaseFWX** | A separate pinned repository providing cryptographic primitives. Not a subdirectory of this project despite living at `basefwx/`. |
| **evidence profile** | A captured browser identity such as `chrome151-node24-v1`. Geometry only. It is not a wire version and recapturing one does not change the protocol. |

Product maturity (`0.3.0-dev1`), the transport-v2 wire (`0.2.0-dev6`), YTP/1,
schema 1, the ABI, and the evidence profile are **independent version axes**.
Do not bump one to match another.

## Two stacks live here

This is the single most important thing to know, and nothing in the code tells
you which one you are looking at.

| | Shipping product | Replacement foundation |
| --- | --- | --- |
| Frame type | `protocol::Frame` (`core/protocol/protocol.hpp`) | `ytp1` codecs (`ytp/protocol.hpp`) |
| Session | `server::Session` (`server/session/`) | `engine::SessionEngine` (`engine/session_engine.cpp`) |
| Build flag | `YUME_BUILD_TRANSPORT_V2` (ON) | `YUME_BUILD_EXPERIMENTAL_YTP1_*` (all OFF) |
| Status | runs, tested, carries traffic | provider candidates and focused tests; no live YTP/1 endpoint |

If you search for "Frame" or "how is a stream opened" you will land in one of
the two depending on which file you started from. Check the directory first.

## Directories

### Transport-v2 implementation

| Path | Owns |
| --- | --- |
| `core/` | Framing, crypto, AUTH v2 ratchet, stealth (TLS/H2/WebSocket), runtime primitives, app codecs |
| `outbound/` | The client's `TransportCore`: frame dispatch, write scheduling, credit. Also, confusingly, server-side egress forwarding in `forward.cpp` |
| `client/` | CLI, SOCKS, forwards, packet/TUN, relay, transfer |
| `server/` | `yumed`: sessions, auth, host controller, federation, filters |
| `facade/` | `yume_embed` (config marshalling, in-process client, log ring, and the transport backend behind `session/endpoint_backend.hpp`) and `yume_facade` (desktop session objects, traffic meter, key management) |
| `gui/` | Optional desktop app. Links `yume_facade` only |

### Cross-stack embedding boundary

| Path | Owns |
| --- | --- |
| `abi/` | The opt-in C ABI translation unit: handles, input validation, diagnostics, callback rules, and backend leasing. It reaches transport v2 only through `yume_embed`; it parses schema 1 through `config/v1`, whose endpoint remains unsupported. |
| `include/yume/` | The public candidate C header. It is build-tree-only and unfrozen. |

### Replacement foundation

| Path | Owns |
| --- | --- |
| `engine/` | Dependency-pure contracts: `ByteChannel`, `SecureChannel`, `Carrier`, `FrontDoor`, `SessionEngine` |
| `ytp/` | YTP/1 protocol kernel and security domains. May not include the engine |
| `providers/` | Concrete candidates: OpenSSL security, TLS 1.3 channel, Asio TCP/UDP routes and client TCP ByteChannel, H2 carrier. All opt-in; none forms a live endpoint graph |
| `config/v1/` | Strict numeric schema 1 parser with RFC 6901 error pointers |

## Layering, and where it is enforced

```text
secure_core -> core -> transport_core -> outbound_transport -> {server, client_lib}
                                                                  -> embed -> facade -> gui
                                                     config_v1 + embed -> abi
```

Two mechanisms, both in [`cmake/YumeLayering.cmake`](../cmake/YumeLayering.cmake)
and run as the CTest `yume_03_layering_check`.

`yume_assert_exact_link_dependencies` pins a target's exact direct link list. It
is applied to the engine and YTP graph, to `yume_embed` and `yume_facade`, and to
the first-party transport-v2 targets whose dependencies do not vary with build
options.

`yume_check_03_source_layering` reads sources and rejects forbidden includes.
`engine/` and `ytp/` may not touch boost, OpenSSL, nghttp2, JSON, or sockets.
`core/` may not include `client/`, `server/`, `facade/`, `gui/`, or `abi/`.
`client/` may not include `server/`, and so on down the table in that file.

Both fail at configure time. Adding a GUI dependency to `yume_embed`, or a
`server/` include to `core/`, stops the build rather than being noticed later.

## Where to look

| Task | Start at |
| --- | --- |
| Wire format, frame flags | `core/protocol/protocol.hpp` |
| Handshake, ratchet, rekey | `core/security/auth_v2.hpp`, `core/security/session_ratchet.cpp` |
| Browser-shaped TLS/H2 | `core/stealth/` |
| Client connect path | `client/cli/entry.cpp` (see the caution below) |
| Server frame handling | `server/session/session.cpp`, then the sibling `.cpp` files |
| Egress and SSRF policy | `server/session/net.cpp` |
| Embedding YUME | `include/yume/yume.h`, [ABI.md](ABI.md), `abi/stream_integration_probe.c` |
| Adding a transport backend | `facade/session/endpoint_backend.hpp` |
| Config keys | `config/client_document_keys.hpp` and `config/server_document_keys.hpp` are the closed transport-v2 key sets both parsers of each role check, over the shared `config/document_keys.hpp` predicate; `facade/config/keys.hpp` holds the spellings, `config/v1/config.hpp` is schema 1 |

## Rough edges

Real, measured, and worth knowing before you go in.

- **`server::Session` is one large class across many files.** The bodies are split across `session.cpp`,
  `carrier.cpp`, `control.cpp`, `streams.cpp`, `auth.cpp`, `open.cpp`,
  `open_transport.cpp`, `codecs.cpp`, `ext.cpp`, `services.cpp`, and
  `reverse_listener.cpp`, divided by file size rather than by subsystem.
  Tracing one behaviour means jumping between several of them.
- **`Cli::run_parsed` is a large, deeply nested entry point** in
  `client/cli/entry.cpp`.
- **`src/util.hpp` is broadly included** and bundles logging,
  path resolution, terminal state, privilege dropping, randomness, base64, and
  signal handling. Touching it rebuilds most of the tree.
- **`src/core` has no `yume::core` namespace.** Every other layer mirrors its
  directory. Core's symbols sit under `yume::` or feature namespaces such as
  `yume::crypto`, `yume::runtime`, and `yume::obfs`.
- **Each transport-v2 role has two separate parsers.**
  `client/cli/config/config.cpp` and `server/cli/config_load.cpp` serve the
  CLI. `facade/config/client_config_io.cpp` and
  `facade/config/server_config_io.cpp` serve the GUI and the C ABI. Within a
  role they share only the closed key table
  (`config/client_document_keys.hpp`, `config/server_document_keys.hpp`), so a
  new key or bound has to be added to both. They still diverge on which
  numeric ranges they enforce and where, and the facade server parser reads a
  narrower set of fields than it validates.
- **Four error-handling conventions coexist.** Exceptions in core, client, and
  server. `runtime::OperationStatus`. `engine::StatusCode`. And facade's `bool`
  plus `std::string* err`. The C ABI wraps all of them at its boundary.
- **`is_blocked_literal` in `outbound/forward.cpp` is not a security filter.**
  It decides whether a client port-forward bypasses the tunnel. The egress and
  SSRF filter is `is_allowed_address` in `server/session/net.cpp`, and it
  deliberately blocks more. Do not unify them.

## Tests

C++ unit tests sit next to their source as `*_test.cpp` and are registered
individually in `src/CMakeLists.txt`. Integration and system tests live in
`tests/`. The end-to-end ABI data path is `yume_abi_stream_integration`, which
provisions a real server and client and moves bytes over a named service
stream.
