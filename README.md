# YUME

YUME carries TCP, UDP, and packet traffic over an authenticated, browser-shaped
transport. It includes a client, daemon, optional desktop GUI, and an
experimental C API for embedding.

The product version is `0.3.0-dev1`. YUME is development software with no
stable release. Linux x86-64 is the first qualification target.

- Website: <https://yume.fixcraft.jp>
- Source: <https://github.com/FixCraft-Inc/yume>
- Issues: <https://github.com/FixCraft-Inc/yume/issues>

## What works today

A local application connects to `yume` through SOCKS, a port forward, packet
routing, or an embedded API. The client multiplexes those connections over one
carrier to `yumed`. The daemon opens the requested destination sockets and
returns the traffic on the same carrier.

The runnable transport currently uses:

- TLS 1.3, HTTP/2, and WebSocket framing for the outer carrier
- keyed admission before client authentication
- composite Ed25519 and ML-DSA-87 client identities
- ML-KEM-1024, X25519, a random pre-shared key, and the TLS exporter for
  session key establishment
- one-use AES-256-GCM message keys with independent directional epochs

The default build uses the transport-v2 wire `0.2.0-dev6`. Its profile follows
a pinned browser and cover-server capture. ClientHello structure checks pass,
but complete-session browser comparisons, classifiers, WAN tests, and soak
qualification remain open. See [implementation status](docs/IMPLEMENTATION_STATUS.md).

`yumed` terminates the tunnel and sees the authenticated client and requested
destination. Use application TLS to protect content end to end. Federation
connects directly trusted servers and is limited to one hop.

## Experimental YTP/1 work

YTP/1 (YUME Transport Protocol 1) is the replacement protocol under development.
Its engine, codecs, schema-1 configuration, and provider tests exist. They do
not yet form a working client/server endpoint. Transport v2 remains the default
until the replacement passes the [parity gates](docs/IMPLEMENTATION_STATUS.md).

The opt-in C ABI already carries authenticated named byte streams through
transport v2. Packet channels and the YTP/1 backend remain unsupported.
See the [C ABI reference](docs/ABI.md) and [YTP/1 development guide](docs/development/ytp1/README.md).

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

## Set up a tunnel

The `yume-setup` command generates a transport-v2 server and client kit:

```bash
sudo cmake --install build
yume-setup init \
  --output ~/yume-kit \
  --host yume.example.com \
  --port 443 \
  --tls-name yume.example.com \
  --client-name laptop
```

Follow the [quick start](docs/QUICKSTART.md) to configure cover traffic and
operator trust, then connect the client. The setup helper creates private
credential files. Distribute them through a trusted channel and keep the
operator CA's private key off the server.

## Main components

| Component | Purpose |
| --- | --- |
| `yume` | Client, SOCKS endpoint, forwards, packet routing, and attached tools |
| `yumed` | TLS/H2 endpoint, authentication, policy enforcement, and proxy exit |
| `libyume` | Opt-in build-tree C ABI; transport-v2 named streams work, while schema-1 start and packets remain unsupported |
| `yume-gui` | Optional Dear ImGui desktop client and server UI, still a preview |
| `yume-setup` | Runnable transport-v2 server and client-kit provisioner |
| `yume-setup-ytp1` / `yume-doctor-ytp1` | Experimental schema-1 generator and validator |

## Documentation

Start with the [documentation map](docs/README.md). The main reader paths are:

- [YUME explained](docs/EXPLAINED.md) and [why YUME](docs/WHY_YUME.md) for the
  product direction and trust boundary
- [quick start](docs/QUICKSTART.md) and [operations](docs/OPERATIONS.md) for the
  runnable transport
- [YTP/1 foundation](docs/development/ytp1/README.md) for the schema-1
  foundation
- [implementation status](docs/IMPLEMENTATION_STATUS.md) for the current
  support and release boundary
- [threat model](docs/THREAT_MODEL.md) and [stealth transport](docs/STEALTH.md)
  for security claims and known residuals
- [architecture](docs/ARCHITECTURE.md), [C ABI](docs/ABI.md), and
  [YTP/1](docs/protocol/YTP_1.md) for replacement integration work

## License

YUME is licensed under the GNU Affero General Public License, version 3 or
later. See [LICENSE](LICENSE).
