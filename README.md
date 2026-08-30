# YUME

YUME is an experimental transport for carrying TCP and UDP through one
authenticated TLS 1.3 and HTTP/2 connection. It has a client (`yume`), a
server (`yumed`), a C API, and an optional desktop GUI.

There is no stable product release yet. Linux x86-64 command-line builds are
the first qualification target. Other platforms, the GUI, and external
consumers still have open release gates. The current version comes from
`src/core/version.hpp` and the synchronized package metadata.

- Website: <https://yume.fixcraft.jp>
- Source: <https://github.com/FixCraft-Inc/yume>
- Issues: <https://github.com/FixCraft-Inc/yume/issues>

## What YUME does

A local application connects to `yume` through SOCKS, a port forward, packet
routing, or an embedded API. The client multiplexes those connections over one
carrier to `yumed`. The daemon opens the requested destination sockets and
returns the traffic on the same carrier.

The development transport currently uses:

- TLS 1.3, HTTP/2, and WebSocket framing for the outer carrier
- keyed admission before client authentication
- composite Ed25519 and ML-DSA-87 client identities
- ML-KEM-1024, X25519, a random pre-shared key, and the TLS exporter for
  session key establishment
- one-use AES-256-GCM message keys with independent directional epochs

The default transport profile follows one committed browser and cover-server
capture. It closes the currently pinned ClientHello structure checks. It has
not passed the full browser-parity, classifier, wide-area, resumption, and
long-running soak gates. YUME should not be described as identical to the
target browser, impossible to block, or anonymous by itself.

`yumed` is a terminating proxy. It knows which authenticated client opened a
stream and which destination it exits to. Application TLS can still protect
content end to end. Direct federation is implemented, but transit is limited to
one hop and is not onion routing.

## Build

```bash
git clone https://github.com/FixCraft-Inc/yume.git
cd yume
./ezbuild.sh
```

The build creates `build/bin/yume` and `build/bin/yumed`. On a fresh clone,
`ezbuild.sh` checks out the exact BaseFWX revision recorded in
`config/dependencies.json`. It also prepares the checksum-pinned OpenSSL build
required by the native Chrome-shaped TLS backend.

An existing `basefwx/` developer checkout is left on its current branch and is
not cleaned or detached. Use `BASEFWX_SYNC_MODE=pinned ./ezbuild.sh` only when
you explicitly want the recorded dependency commit.

Direct CMake builds must activate the same patched OpenSSL installation. See
[the contributor guide](CONTRIBUTING.md) before using a direct build as release
evidence.

## Set up a server and client

The setup helper generates TLS material, composite identities, the admission
secret, the inner pre-shared key, owner-only configuration, and launch scripts:

```bash
sudo cmake --install build
yume-setup init \
  --output ~/yume-kit \
  --host yume.example.com \
  --port 443 \
  --tls-name yume.example.com \
  --client-name laptop
```

For a real deployment, provide an existing operator CA with `--ca-key` and
`--ca-cert`. Otherwise the helper creates a bootstrap CA for testing. Move its
private key off the server.

The generated kit prints the server and client paths without printing secret
values. The admission and inner-PSK files each contain 32 random bytes encoded
as 64 lowercase hexadecimal characters. Distribute both files through a secure
out-of-band channel.

Read the [quick start](docs/QUICKSTART.md) for a local manual setup, the cover
server, and the exact client command. Read [operations](docs/OPERATIONS.md)
before exposing a daemon to the internet.

## Main components

| Component | Purpose |
| --- | --- |
| `yume` | Client, SOCKS endpoint, forwards, packet routing, and attached tools |
| `yumed` | TLS/H2 endpoint, authentication, policy enforcement, and proxy exit |
| `libyume.so.1` | Stable C ABI v1 for embedded native clients |
| `yume-gui` | Optional Dear ImGui desktop client and server UI, still a preview |
| `yume-setup` | Server and device-kit provisioning helper |

The static site under `website/` publishes project and release information. It
does not control a local YUME process and never handles runtime configuration
or keys.

## Documentation

Start with the [documentation map](docs/README.md). The main reader paths are:

- [YUME explained](docs/EXPLAINED.md) for the traffic path and trust model
- [quick start](docs/QUICKSTART.md) and [operations](docs/OPERATIONS.md) for use
- [implementation status](docs/IMPLEMENTATION_STATUS.md) for the current
  support and release boundary
- [threat model](docs/THREAT_MODEL.md) and [stealth transport](docs/STEALTH.md)
  for security claims and known residuals
- [architecture](docs/ARCHITECTURE.md), [C ABI](docs/ABI.md), and
  [control API](docs/CONTROL_API.md) for integration work
- [transport wire](docs/protocol/YUME_2_0_WIRE.md) for the normative protocol

Wire, AUTH, relay, ABI, helper, and product versions are separate. A `2.0` in a
protocol filename or cryptographic domain does not mean the product has a 2.0
release.

## Project status

No stable release artifact or public endpoint is available today. Current
source includes focused unit and integration coverage for the carrier, AUTH,
ratchet, permissions, ABI, services, and direct federation. Exact-candidate
release builds, sanitizer reconciliation, sustained lifecycle and network
tests, browser comparison, independent review, and platform qualification are
still required. The [implementation status](docs/IMPLEMENTATION_STATUS.md)
keeps that boundary in one place.

## License

YUME is licensed under the GNU Affero General Public License, version 3 or
later. See [LICENSE](LICENSE).
