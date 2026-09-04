# YUME

YUME is an experimental embeddable stealth universal transport. The product
version is `0.3.0-dev1`. During this transition its default build keeps the
runnable `yume` client and `yumed` daemon, which speak the transport-v2 wire
`0.2.0-dev6`, available while the modular YTP/1 engine, schema-1 configuration,
and replacement C ABI are built alongside them.

There is no stable product release yet. Linux x86-64 command-line builds are
the first qualification target. Other platforms, the GUI, and external
consumers still have open release gates. The product label, runnable transport,
replacement wire, configuration, ABI, provider, and evidence-profile versions
are separate axes recorded in source and synchronized package metadata.

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

The default transport profile follows one committed browser and cover-server
capture. It closes the currently pinned ClientHello structure checks. It has
not passed the full browser-parity, classifier, wide-area, resumption, and
long-running soak gates. YUME should not be described as identical to the
target browser, impossible to block, or anonymous by itself.

`yumed` is a terminating proxy. It knows which authenticated client opened a
stream and which destination it exits to. Application TLS can still protect
content end to end. Direct federation is implemented in the 0.2 product, but
transit is limited to one hop and is not onion routing.

## Replacement transport

The YTP/1 replacement (YUME Transport Protocol 1, a new protocol whose
version is unrelated to the product version) turns the tunnel core into
authenticated named byte
streams and packet channels. Applications see peer identity and capabilities;
service authorization and resource policy run before dispatch. SOCKS5, direct
TCP/UDP routing, and packet tunnelling become included adapters on the same
public interface instead of defining the wire protocol.

The dependency direction is `ByteChannel → SecureChannel → Carrier →
SessionEngine → StreamDispatcher → StreamHandler/RouteProvider`. The
dependency-clean engine, bounded YTP/1 codecs, strict schema-1 parser, setup and
doctor tools, and replacement ABI candidate exist. Opt-in hybrid security, TLS
1.3, duplex H2 carrier, TCP ByteChannel, and direct TCP/UDP route providers
also exist as isolated candidates. They are not composed with a live YTP/1
front door, admission path, runtime, or adapters and therefore do not form an
end-to-end replacement tunnel.

The replacement deliberately breaks wire and configuration compatibility. It
does not require disabling the working product early: the 0.2 runtime remains
until the replacement passes tunnel, cover, routing, embedding, packaging, and
qualification parity gates.

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

## Provisioning during the transition

The current `yume-setup` command generates the runnable transport-v2 server and
client kit:

```bash
sudo cmake --install build
yume-setup init \
  --output ~/yume-kit \
  --host yume.example.com \
  --port 443 \
  --tls-name yume.example.com \
  --client-name laptop
```

The separate `yume-setup-ytp1` and `yume-doctor-ytp1` commands exercise the
replacement's schema-1 credential and configuration contracts. Their kits do
not yet drive the runnable `yume` or `yumed` binaries. Read the current
[quick start](docs/QUICKSTART.md) and [operations guide](docs/OPERATIONS.md) for
the tunnel, and the
[YTP/1 foundation page](docs/development/ytp1/README.md) for the YTP/1
scaffold.

The runnable setup helper retains its owner-only credential handling and
out-of-band secret-distribution rules. For a real deployment, supply the
operator CA inputs described in the current quick start and remove offline CA
material from the server host.

## Main components

| Component | Purpose |
| --- | --- |
| `yume` | Client, SOCKS endpoint, forwards, packet routing, and attached tools |
| `yumed` | TLS/H2 endpoint, authentication, policy enforcement, and proxy exit |
| replacement `libyume` | Opt-in build-tree C ABI; transport-v2 named streams work, while schema-1 start and packets remain unsupported |
| `yume-gui` | Optional Dear ImGui desktop client and server UI, still a preview |
| `yume-setup` | Runnable transport-v2 server and client-kit provisioner |
| `yume-setup-ytp1` / `yume-doctor-ytp1` | Experimental schema-1 generator and validator |

The static site under `website/` publishes project and release information. It
does not control a local YUME process and never handles runtime configuration
or keys.

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

The project declares YUME's wire and implementation original to this
repository and does not offer Xray, VLESS, or REALITY wire compatibility. The
deterministic SBOM check validates declared source dependencies; it does not
prove source ancestry.

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
