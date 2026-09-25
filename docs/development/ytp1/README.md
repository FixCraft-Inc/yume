<!-- Generated from docs/src/en_US/pages/ytp1_readme.doc by scripts/yume_docs.py. Edit that file, not this one. -->
# YTP/1 development guide

This guide is for people who build, embed or change native YUME. Operators
should start with the [quick start](../../QUICKSTART.md) and
[operations](../../OPERATIONS.md). [Implementation status](../../IMPLEMENTATION_STATUS.md)
lists what is tested and what is still open. The manuals are
[`yume.1`](../../man/yume.1) and [`yumed.8`](../../man/yumed.8).

Schema-1 kits and transport-v2 configuration are separate formats, and
nothing converts between them. Do not give a reference configuration to the
native programs.

## Component build options

The default build enables every native provider. To build or test one
component alone, set `YUME_BUILD_NATIVE_APPLICATION=OFF` and turn on only the
options it needs. CMake rejects a component whose providers are missing:

| Option | Adds |
| --- | --- |
| `YUME_BUILD_YTP1_TLS13_PROVIDER` | Chrome-shaped TLS 1.3 client and server channel (needs the patched OpenSSL) |
| `YUME_BUILD_YTP1_H2_CARRIER` | HTTP/2 extended-CONNECT carrier with WebSocket framing |
| `YUME_BUILD_YTP1_ASIO_TCP_BYTE_CHANNEL_PROVIDER` | TCP byte channel |
| `YUME_BUILD_YTP1_FRONT_DOOR` | Listener with admission, replay cache and static cover site |
| `YUME_BUILD_YTP1_OPENSSL_PROVIDER` | Hybrid session security, which composes `yume_native_endpoint` |
| `YUME_BUILD_YTP1_ASIO_ROUTE_PROVIDER` | Direct TCP/UDP routes with destination policy |

```bash
cmake -S . -B build-ingress -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DYUME_BUILD_NATIVE_APPLICATION=OFF -DYUME_BUILD_TESTING=ON \
  -DYUME_BUILD_YTP1_TLS13_PROVIDER=ON \
  -DYUME_BUILD_YTP1_H2_CARRIER=ON \
  -DYUME_BUILD_YTP1_ASIO_TCP_BYTE_CHANNEL_PROVIDER=ON \
  -DYUME_BUILD_YTP1_FRONT_DOOR=ON \
  -DYUME_WARNINGS_AS_ERRORS=ON
cmake --build build-ingress --target yume_ytp1_front_door -j2
```

Set `YUME_NATIVE_TEST_OPENSSL` to the pinned installation's `bin/openssl` when
configuring tests. `yume_native_credentials_test` and `yume_native_endpoint_test`
provision temporary kits and run real loopback TLS/HTTP/2 sessions.

`YUME_BUILD_BASEFWX_MODULES=ON` adds the module libraries built on BaseFWX and
their tests. So far that is `yume_module_relay`, the end-to-end relay channel
in `src/modules/relay`. It needs the BaseFWX checkout at the revision
`config/dependencies.json` pins and liboqs, which configuration requires in
this mode. Core targets never link BaseFWX, so a plain `yume` and `yumed`
build needs neither.

A few rules hold across the native graph:

- The front door serves ordinary cover over TLS 1.2 or 1.3 and HTTP/1.1 or
  HTTP/2, but promotes a connection to YTP only on TLS 1.3 with HTTP/2, once
  per TLS connection. The cover site is loaded once from a confined root, and
  requests never touch the file system. There is no built-in fallback site.
- Destination policy runs after service authorization and before DNS or
  socket work. The route provider checks every resolved address again. An
  embedding callback can refuse more, never allow more.
- Host names resolve in a separate helper process. `yume` and `yumed` start
  their own image as `yume-resolver`. Closing the runtime kills the helper,
  so a stuck system lookup cannot hold shutdown. SDK hosts pass
  `resolver_program`, and there is no in-process fallback.
- Each endpoint runs on one caller-owned execution context. Close cancels
  owners, drains completions, then returns.
- The ABI backend refuses adapter declarations. An embedding application
  removes them from a generated kit and lists the named services it uses.

## Build the C ABI

The native application and schema-1 tools are selected by default. The shared
ABI remains an explicit build-tree opt-in:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DYUME_BUILD_TESTING=ON \
  -DYUME_BUILD_SHARED_ABI=ON \
  -DYUME_WARNINGS_AS_ERRORS=ON
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/install"
```

The build tree contains an unversioned `src/libyume.so` and its contract
tests. The install contains `yume`, `yumed`, `yume-setup` and `yume-doctor`.
SDK files install only with `YUME_INSTALL_EXPERIMENTAL_SDK=ON` (see
[ABI installation](../../ABI.md)). The schema-1 ABI backend needs every native
provider and returns `YUME_STATUS_UNSUPPORTED` without them. A build with the
transport-v2 reference graph also carries named streams over v2, but not
packets or routed traffic.

## Provision a kit and validate it

```bash
install/bin/yume-setup init \
  --host tunnel.example.com \
  --output "$PWD/yume-kit" \
  --client-name laptop
install/bin/yume-doctor --config yume-kit/server/yumed.json
install/bin/yume-doctor --config yume-kit/client/yume.json
```

The output path must not exist. Setup builds the tree in a private staging
directory and publishes it atomically. It writes owner-only server and
per-identity composite Ed25519 + ML-DSA-87 keys, ML-KEM-1024 server material,
one 32-byte access PSK per client identity, an `authorized_keys` traffic
store plus a separate and initially empty `admin_keys` store, separate client
references for the server identity, TLS trust, and ML-KEM public material, a
separate admission key with P-256 TLS CA and leaf material, strict schema-1 server
and client configurations, a static default cover site with an explicit
`404.html` page and linked profile CSS/JavaScript assets, and service and
adapter manifests. Doctor requires both complete HTML pages and the ordinary
asset files used by the selected browser profile. Private values are never
printed. Generate one kit per deployment and one bundle per client, move a
bundle over an authenticated channel, remove offline CA material from the
server host, and never commit a kit, capture, profile, or diagnostic artifact.

Outer TLS certificates are independent of the composite YTP identity. Setup
uses ECDSA with SHA-256 because the browser signature profile does not offer
Ed25519 TLS signatures. Doctor accepts named P-256/P-384/P-521 or RSA leaf
keys of at least 2048 bits and validates the server chain and key match.
These offline checks do not prove that a supplied chain negotiates with the
actual browser profile. A locally issued certificate is development material;
it does not establish a credible public HTTPS cover identity.

Use a DNS name for the authenticated endpoint. To reach it at a fixed IP,
set the client's `endpoint.connect_address` to that numeric address. TLS and
admission still authenticate `endpoint.host`. Setup can encode an IP as `host`,
but the native TLS/H2 client requires a DNS server name, so such a kit cannot
start a native session.

Run doctor as the identity that will run YUME. It rejects unknown schema
keys, provider or profile mismatch, unsafe limits, missing cover content,
unsupported or mismatched key algorithms, symlink and file-race conditions,
and permissive secret modes, and it reports the first failing RFC 6901 JSON
pointer or credential path. It rechecks file identity, size, timestamps,
permissions, and bounds around reads so a replaced secret fails closed. It
does not inspect file ownership, consume a separate compatibility manifest,
or print private material. Fix the reported location; there is no CLI
override for a doctor failure.

## Run yume and yumed

The default build produces `bin/yumed` and `bin/yume`:

```bash
build/bin/yumed --config kit/server/yumed.json --validate
build/bin/yumed --config kit/server/yumed.json
build/bin/yume --config kit/client/yume.json
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

A generated kit runs as written. It declares a `tcp` stream service and a
`udp` packet service. The daemon serves them through `direct_tcp` and
`direct_udp` adapters that permit public destinations, and the client's SOCKS5
adapter names `udp` for UDP ASSOCIATE. Add an explicit network such as
`10.0.0.0/8` to reach private or loopback destinations. The daemon needs a
direct, module or packet adapter for every configured service. The packet adapter
requires the managed network configuration below. The kit's `start-server` and `start-client` launchers
run `yumed` and `yume` from `PATH`, or the programs that `YUMED_BIN`
and `YUME_BIN` name.

A normal user can listen on port 443 once the daemon binary holds only the
bind capability. Install a root-owned copy and grant it there:

```bash
sudo install -o root -g root -m 0755 build/bin/yumed /usr/local/bin/yumed
sudo setcap cap_net_bind_service=+ep /usr/local/bin/yumed
```

Replacing the file drops the capability, so repeat both commands after each
build. Running the daemon as root or lowering the system's unprivileged port
range is not needed. A port above 1023 needs neither step.

The client runs its SOCKS5 listeners and keeps one session. When that session
ends, its endpoint notifies the client to start a replacement. Failed attempts,
and sessions that end within 30 seconds of authenticating, wait with backoff
from 1 to 30 seconds, so a path that drops every session after AUTH cannot
cause a tight reconnect loop. SOCKS5 offers only the
no-authentication method, CONNECT and UDP ASSOCIATE, and refuses requests while
no session is active. Stop either process with SIGINT or SIGTERM.
An unrecoverable reconnect timer or SOCKS listener retry failure closes the
runtime and exits with failure after cleanup. A runner exception likewise
closes all owners through reserved control dispatch and drains completions.

Clients may send payload with CONNECT before reading its reply. The adapter
reads only the handshake fields, leaving payload in the socket until the
daemon accepts the destination and the shared route bridge starts forwarding.
Closing the client's write side still allows the destination's response back.
The greeting and CONNECT request must arrive within 10 seconds. A CONNECT then
has 30 seconds to receive remote acceptance; expiry cancels it, returns SOCKS5
0x06 (TTL expired) and closes that local connection. Other requests can keep
using the authenticated session.

SOCKS5 names resolve on the daemon. Every selected address must be permitted
by the service's configured destinations before a socket opens. A refused
address rejects the whole OPEN, including mixed allowed and denied answers,
with SOCKS5 reply 0x02. Other requests can continue on the same session.

UDP ASSOCIATE needs the adapter's `udp_service`. The reply names a loopback
relay socket, and the association lasts as long as the client's TCP
connection. The relay accepts datagrams only from that connection's address,
and from the port the request announced or the first datagram used. Each
destination becomes its own authenticated packet OPEN, which the daemon checks
against the client's identity grant and the `direct_udp` destinations, as it
does for CONNECT. Replies return with that destination as their source address.
Datagrams waiting for a destination's OPEN and replies waiting for the local
socket each have a budget of 64 datagrams and 1 MiB per association, and a full
budget drops the newest datagram. One association uses at most 32 destinations
at once, closes a destination after 60 idle seconds, and drops datagrams to a
refused or ended destination for one second before opening it again. Fragments
and empty datagrams are dropped, because a YTP packet cannot be empty.

A client `forward` adapter listens on a loopback TCP port or a UNIX socket
path and turns every connection into an authenticated byte-stream OPEN on its
service. An optional `destination` travels with each OPEN, and the server's
`direct_tcp` destinations decide whether it is reachable. Without one, the
server's handler for the service decides where the stream goes. Payload sent
before the server accepts waits in the socket. A connection made while no
session is active, or whose OPEN is refused or takes longer than 30 seconds,
is closed. A UNIX socket's directory must belong to the client's user and be
closed to writes by group and others. The socket file is mode 0600, a
connection from another user is closed, and the file is removed on exit. A
file left by an earlier run is replaced, while a live listener or any other
file at the path stops startup. Like SOCKS5, forward TCP listeners accept only
127.0.0.1 or ::1.

A server `module` adapter serves its stream service with a program that
`yumed` starts before its listeners accept and restarts with backoff. Each
authorized stream reaches the program as one connection on a private UNIX
socket, after a header line naming the client identity. A stream that names a
destination is refused. [Modules](../../MODULES.md) describes what the program
receives and its trust boundary.

`scripts/yume_ndpi_smoke.py` runs one loopback session inside a rootless
network namespace with Ethernet-sized frames and records what nDPI reports.
`scripts/ensure-ndpi.sh` builds the pinned release, or newer sources such as
`--ref dev` under a prefix named by their commit. `scripts/yume_ethernet_smoke.py`
runs the client on this machine and the daemon on a directly connected host,
after a link preflight that fails when the direct route is unavailable. It
alternates untunnelled and tunnelled fetches of one payload. The daemon reaches
the tunnel destination on its own host, and the untunnelled fetch crosses the
link to `--baseline-port`, which a firewall on that host must allow. With
`--capture-ssh` naming a root login on that host, the runner records the tunnel
with tcpdump, which drops to the normal user once the interface is open, and
`--remote-ndpi-reader` runs nDPI on the capture as that user. `--wire-frames`
turns segmentation and receive offloads off for the run and restores them, so
the capture holds frames as they crossed the wire. Neither result is a
classifier verdict or a qualified benchmark.

## Managed Linux TUN networking

A `packet` adapter binds one authenticated packet service to a new Linux TUN.
YUME owns the interface's lifetime, addresses, routes and optional per-link DNS.
It requires `/dev/net/tun` and `CAP_NET_ADMIN` in its network namespace. It
refuses an existing interface name. The Linux networking target also requires
`libsystemd` for the systemd-resolved D-Bus interface; no shell command changes
networking and `/etc/resolv.conf` is not rewritten.

For a client with local address `10.71.0.2` and peer address `10.71.0.1`, declare
an `ip` service with kind `packet`, authorize it in the server's traffic-key
store, and add this adapter:

```json
{
  "kind": "packet",
  "service": "ip",
  "interface_name": "yume0",
  "mtu": 1420,
  "network": {
    "addresses": ["10.71.0.2/32"],
    "routes": ["10.71.0.1/32"],
    "local_networks": ["10.71.0.2/32"],
    "peer_networks": ["10.71.0.1/32"],
    "dns": {"servers": [], "domains": []}
  }
}
```

Reverse the addresses and policies for the server's matching adapter. The
interface name is local to each machine and is at most 15 bytes. `addresses`
contains 1–16 canonical interface addresses with prefix lengths; it preserves
host bits. `routes` contains up to 64 disjoint canonical networks. Address
assignment does not create an implicit connected-prefix route: declare each
route explicitly. IPv6 requires an MTU of at least 1280. Before assigning
addresses or bringing the link up, YUME disables automatic IPv6 link-local
address generation on its TUN. This does not change host-wide RA policy.

`local_networks` and `peer_networks` each contain 1–64 canonical prefixes.
A packet leaving the local TUN must have its source in `local_networks` and
its destination in `peer_networks`; receive reverses those checks. Interface
addresses must belong to `local_networks`. Loopback, unspecified, multicast,
reserved and IPv4-mapped IPv6 addresses are refused regardless of the prefixes.
The packet wrapper checks IP lengths, MTU, IPv4 options and bounded IPv6
extension chains. Source routing, IPv6 Routing/Home Address/Jumbo forms and
unsupported opaque extensions fail closed. IPv6 fragments may directly name
an upper-layer protocol; fragmented extension chains are refused. These checks
do not perform transport checksum validation, reassembly or nested-IP filtering.
Source/destination restrictions are separate from credential authorization of the named service. Plan distinct
services and address policies where different peers have different grants.

A client supplies a numeric `endpoint.connect_address` (or a numeric endpoint
host) so route management can exclude the transport itself. The route plan
splits covering prefixes around that one address; it does not add or replace
routes on the physical interface. Default routing requires this numeric address.
An assigned TUN address or DNS server cannot equal it. A server's managed
routes must stay within its `peer_networks`, must not cover a configured
listener address, and cannot select default routing. Conflicting route adds
fail startup and remove the newly owned link and its routes.

To manage DNS, set 1–16 numeric `dns.servers` and 1–16 `dns.domains`. Domains
are routing domains, without a `~` prefix; `"."` routes all DNS names to the
link. DNS servers must fall within both a managed route and `peer_networks`.
Both arrays must be empty to leave DNS untouched. YUME requires an authorized
systemd-resolved service in the same network namespace, pins its D-Bus owner,
and refuses cross-namespace system-bus use. Cleanup attempts per-link DNS
reversion and link deletion, reports any failure, and closes the ephemeral device. Cleanup is terminal: it never retries a cached
interface index after a possibly successful deletion. Configuration validation
does not establish D-Bus authorization or resolver availability.

The native runtime keeps the owned interface and routes during reconnects
so selected packets wait or drop until an authenticated packet stream is
available. Shutdown removes them and restores the prior route selection. This
is not a persistent firewall kill switch: process death closes the ephemeral
TUN. YUME does not enable forwarding, install NAT, or change a host firewall;
an operator providing routed Internet access must configure those policies
explicitly.

With `YUME_TEST_LINUX_NAMESPACES=ON`, `tests/run_native_tun_test.py` runs the
native client and daemon in isolated Linux network namespaces. It checks
IPv4/IPv6 traffic, MTU refusal, TCP transfer, transport exclusion from client
default routes, reconnect with retained networking, shutdown cleanup and
rollback after a competing route refuses startup. This fixture leaves DNS
unconfigured. With `YUME_NATIVE_TEST_RESOLVED` set to the real resolved
executable, the namespace suite also registers `yume_native_resolved_test`.
It starts a private bus and resolved service, verifies the per-link policy,
queries DNS through the tunnel before and after reconnect, and checks that
shutdown removes the DNS settings. The host service and network remain outside
these namespaces. The test requires `busctl`, `dbus-daemon` and Linux namespace
utilities; unavailable prerequisites fail instead of silently skipping.

## Configuration authority

Schema 1 is role tagged and contains these sections only:

- `endpoint`: one client target or bounded server listeners. A client may add
  `connect_address`, a numeric address dialled instead of resolving `host`,
  while TLS and admission still authenticate `host`;
- `suite`: the exact mandatory provider composition;
- `credentials`: references to files, never inline private material;
- `cover`: the qualified profile and server cover root;
- `services` and `adapters`: explicit named-service exposure, unique by
  `(name, kind)`. Several adapters of one kind are valid when their concrete
  resources differ; exact resource collisions are rejected;
- `destinations` on each server `direct_tcp` or `direct_udp` adapter:
  `public` permits globally reachable unicast addresses, and `networks` lists
  up to 64 canonical prefixes such as `10.0.0.0/8` or `fd00::/8`. At least one
  destination must be permitted. Public space excludes private, shared,
  loopback, link-local, documentation, benchmarking, 6to4, Teredo and NAT64
  prefixes. Unspecified, multicast and reserved addresses are always refused,
  IPv4-mapped IPv6 is evaluated as IPv4, and ports and hostnames are not policy
  inputs. A network that no destination could match is rejected. Optional
  `lists` hold up to 16 egress lists, each `{"action": "deny" or "allow",
  "format": "json" or "vpdb", "file": path}`. They only narrow what `public`
  and `networks` permit: the most specific entry decides and a deny wins a
  tie, so an allow entry exempts an address from a broader deny and nothing
  more. A JSON list holds `ips`, addresses or networks with zero host bits,
  and `countries`, two-letter codes. A `vpdb` file is the binary VPN provider
  database, format 1. Lists that name countries need `country_database`, a
  MaxMind DB file such as GeoLite2-Country, and a country entry loses to any
  address entry. List files resolve like credential references, must not be
  symbolic links and are read when `yumed` starts or validates. A JSON list may
  hold 16 MiB, the other files 128 MiB, and all lists together
  2,097,152 ranges;
- `udp_service` on a client `socks5` adapter: the packet service that UDP
  ASSOCIATE opens. Without it the adapter refuses UDP ASSOCIATE;
- a client `forward` adapter: a stream `service`, either `listen_address` (127.0.0.1
  or ::1) with `listen_port` or an absolute, normalized `listen_path` of at most
  107 bytes, and an optional `destination` with `host` and `port`. SOCKS5 and
  forward listeners may not share an address and port;
- a server `module` adapter: a stream `service`, an absolute, normalized
  `program` and optional `arguments` of at most 32 strings of up to 1024
  bytes. A stream service has at most one `direct_tcp` or `module` adapter;
- `limits`: bounded frames, streams, queues, opens, rekeys, controls, and
  packets. Frames allow 1676–1048576 bytes so hybrid rekey INIT fits;
  concurrent rekey jobs allow 2–64 so crossed rotation has both slots. A
  server may also set `max_egress_mbps`, from 1 to 1000000: the rate in
  megabits per second that stream payload shares between busy identities by
  their `weight`.

Schema 1 rejects inline secrets, aliases, unknown keys, unsupported providers,
and unsafe combinations. The development CLIs accept config selection,
validation, version, and help only; network and security
policy have no CLI override. Once the runtime gate closes, a service manager
should invoke only `yumed --config /etc/yume/yumed.json` as a dedicated
unprivileged identity, prefer a high port or grant only
`CAP_NET_BIND_SERVICE`, and restrict filesystem access to the generated
server tree and the cover root.

## Identity and authorization

Authentication, advertised capabilities, and authorization are separate
gates. YUME uses two key classes, and the split is permanent: `authorized_keys`
holds ordinary traffic identities, and `admin_keys` is a physically separate
store of distinct second-factor identities carrying no policy metadata. Admin
is proved by one authorized traffic identity plus a different identity from
`admin_keys`, never by a flag in the traffic store, and no schema-1 field can
grant it. The second-factor AUTH exchange is not implemented yet; until it
is, the capability manifest carries only named services and kinds, while
`admin_keys` is parsed, validated, and overlap-checked so the store boundary
exists before the capability does.

The traffic store accepts 1 through 1024 identities, matching the native
security factory's bound. `yume-setup add-client` issues another client bundle
for an existing server tree and appends its identity, and `remove-client`
takes one out again. An entry's optional
`max_sessions`, from 1 to 1024, bounds that identity's concurrent sessions: a
newer session replaces the identity's oldest. Without it the daemon's session
capacity is the only bound. An optional `weight`, from 0.1 to 100 and 1 by
default, is the identity's share of `limits.max_egress_mbps` against the other
busy identities. SIGHUP reloads both stores and the server's own
keys: removed identities' sessions end, changed grants apply to the next OPEN,
a changed weight applies to the next transfer,
and an invalid store leaves the previous credentials in force. The independent admin store accepts 0 through 4096
identities. Both stores reject duplicate names and composite identities;
an admin identity must not appear in the traffic store.

Each authorized key receives a composite Ed25519 + ML-DSA-87 identity and its
own 32-byte access PSK; one deployment-wide PSK is forbidden. Both signature
components and all establishment contributions must verify, with no partial
mode and no provider fallback. After AUTH the peer advertises a bounded
canonical capability manifest, but a capability is not a grant: every OPEN is
checked against the authenticated identity and role, the exact authenticated
capability bytes, the registered service kind and policy, destination policy
for the built-in TCP/UDP encodings, and stream, pending-open, queue, packet,
and route limits. A `RouteProvider` receives only an `AuthorizedRouteRequest`
built after those checks. Federation, directory, relay applications, reverse
administration, the reserved, disabled transport-v2 EXEC relay-policy
surface, host-controller modes, product codecs, and dynamic plugins are outside
the first YTP/1 path and have no schema-1 aliases.

## Packet channels

Packet channels are a first-class YTP/1 service kind, not a byte stream
carrying a private subprotocol. OPEN names a bounded packet service and may
carry the strict built-in UDP destination; each write is one opaque packet
with boundaries preserved end to end; the native packet ABI batches views while
keeping individual boundaries and all-or-none write admission; packet size,
batch count, stream count, queued bytes, pending opens, and outer and
in-session credit are bounded before allocation; and every packet OPEN is
independently authorized. Direct UDP uses an explicit `RouteProvider`.
NativeEndpoint composes the Asio provider and configured `direct_udp` handlers
into an authenticated connected-UDP path with destination policy and preserved
packet boundaries. The native ABI supports named packet handles and routed UDP
I/O; the standalone Linux runtimes compose managed TUN adapters with directional
IP policy. See [ABI](../../ABI.md) and the managed Linux TUN section above for
their bounds and ownership. Production qualification remains open.

## Diagnostics and evidence

Diagnostics are typed and scoped to the object that failed; they are not a
second control channel. Every ABI operation returns a stable `yume_status`,
`yume_get_status_info()` gives its name and retry class, and
`yume_handle_get_diagnostic()` returns bounded text and the relevant JSON
pointer for a runtime, config, endpoint, stream, or packet handle. Never
parse diagnostic prose to recover a status. Callbacks receive borrowed
records valid only during the call; the only handle operation permitted
inside one is diagnostic lookup, lifecycle and I/O re-entry fail with
`YUME_STATUS_INVALID_STATE`, and void destroy calls are ignored.

Captures, NetLogs, browser profiles, sanitizer logs, fuzz crashes, and
benchmark traces are evidence artifacts: keep them in approved private
locations, redact secrets, record exact tool and profile versions, and keep
immutable hashes with candidate results. Production timing and metrics must
be bounded, off unless configured, and must never expose plaintext, keys,
nonces, AUTH messages, identity-to-PSK mappings, secret paths, or full
peer-controlled strings.

## Verification gates

Focused local checks:

```bash
cmake -S . -B build-test -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DYUME_BUILD_TESTING=ON -DYUME_BUILD_SHARED_ABI=ON \
  -DYUME_WARNINGS_AS_ERRORS=ON
cmake --build build-test -j"$(nproc)"
ctest --test-dir build-test --output-on-failure
python3 -m unittest tests.test_yume_setup tests.test_yume_doctor
python3 tests/test_project_metadata.py
python3 scripts/generate_transport_profiles.py --check
python3 scripts/check_website_catalog.py
python3 scripts/check_dependency_sbom.py --check
git diff --check
```

These cover the engine contracts, YTP/1 codecs and vectors, the strict
config parser, the build-tree ABI and its C/C++ consumers, source layering,
setup and doctor, metadata, the documentation catalog, and the source SBOM.
The opt-in security provider additionally has focused tests for both
signatures being required; X25519, ML-KEM-1024, access PSK, TLS exporter,
role, transcript, identities, parameters, and both capability manifests being
bound; component stripping, mutation, role confusion, replay, and exporter
mismatch; and directional one-use keys, nonce uniqueness, bounded pending
epochs, rekey races, and secure cancellation. Known-answer vectors use only
`yume/ytp/1/...` domains; transport-v2 vectors are never renamed into YTP/1
vectors.

Before the tunnel can be described as usable, tests must exercise the real
TLS 1.3 front door, genuine HTTP/2 cover behavior, replay-protected admission,
duplex carrier flow control, direct TCP/UDP routes, SOCKS5, named services,
packet batches, and the public ABI data path, and invalid admission must
receive the same website or reverse-proxy behavior as ordinary traffic. Clean
Linux environments must run setup through the first authenticated stream,
including permission failures and a normal non-YUME browser request.
Resource and failure qualification exercises slow consumers, stalled front
doors, handshake and stream floods, malformed lengths, queue pressure, packet
batches, rekey pressure, cancellation, and teardown at every asynchronous
boundary, with ASan, UBSan, TSan, soak, failure-injection, and fuzz suites
run detached on the private build host.

Performance claims against transport v2 need matched runs of the reference
build: throughput, p50/p99 latency, CPU
per byte, allocations, peak memory, and fairness at 1, 32, and 256 streams
over at least five runs, with environment, raw runs, summary method, and
uncertainty reported. Ingress claims must name the exact qualified profile
and environment and link immutable captures, TLS/H2 semantic gates,
active-probe cover results, and a held-out classifier evaluation; YUME does
not claim universal indistinguishability or DPI resistance.

`0.3.0-rc1` requires clean cross-platform builds, protocol vectors,
sanitizer and fuzz evidence, installed ABI consumers, setup smoke,
documentation drift checks, ingress evidence, and an external protocol and
cryptography review. Treat provider, suite, exporter, identity, capability,
and credential mismatches as terminal; treat exhaustion as a bounded failure
whose limits change only after a measured resource review; rotate a
compromised key by issuing a new per-identity bundle; and retain only
redacted logs and reproducible evidence.
