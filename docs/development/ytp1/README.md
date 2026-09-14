<!-- Generated from docs/src/en_US/pages/ytp1_readme.doc by scripts/yume_docs.py. Edit that file, not this one. -->
# YTP/1 foundation: setup, contracts, and gates

YUME 0.3 is being rebuilt around an experimental C ABI and YTP/1. This page
is the one development reference for that replacement: what the schema-1
tools do today, the contracts the runtime must meet, and the gates that
separate a passing foundation test from a usable tunnel. It is a design
input, not an installed contract and not evidence that the product runtime is
qualified.
[IMPLEMENTATION_STATUS.md](../../IMPLEMENTATION_STATUS.md) is the
authoritative boundary; the runnable transport-v2 product keeps its own
[quick start](../../QUICKSTART.md), [operations](../../OPERATIONS.md),
[permissions](../../PERMISSIONS.md), [diagnostics](../../DIAGNOSTICS.md),
[packet mode](../../PACKET_NATIVE_BULK.md), and
[benchmarks](../../SELFTEST.md) pages. The intended narrow client and
front-door daemon manuals are sketched in [`man/`](man/) and are not
installed.

## What exists and what does not

Implemented: the schema-1 provisioning and validation tools, the strict
numeric config parser, the dependency-pure engine and YTP/1 codecs, and the
opt-in TLS 1.3, HTTP/2 duplex carrier, hybrid session-security, TCP
byte-channel, and direct-route provider candidates, each with focused tests.
The client carrier generates exporter-bound admission proofs. The native
FrontDoor combines accepted TCP ownership, actual TLS SNI/exporter verification,
shared replay protection and genuine configured static cover, then transfers
the live connection into the H2 carrier once per TLS lifetime. Ordinary cover
accepts TLS 1.2/1.3 and HTTP/1.1/H2; YTP promotion requires TLS 1.3 and H2.

The source-level `runtime::NativeEndpoint` now composes schema-1 credentials,
the native provider graph, per-identity named-service authorization and bounded
bootstrap/session lifetimes on a caller-owned execution context. Configured
direct TCP/UDP adapters enforce their schema-1 destinations before resolution,
and a route provider built with the same policy checks every resolved address.
The native integration test uses generated setup credentials and real loopback
TLS/H2.
When the shared ABI is built with the same providers, an experimental schema-1
backend drives that endpoint behind the C ABI and carries named byte streams.

Not implemented: the final `yume` and `yumed` runtimes, SOCKS5 UDP, public ABI
packet handles, TUN adapters, and production qualification of the complete
endpoint. The development processes are described under running the
development runtimes below.
A schema-1 kit is not valid
input for the runnable transport-v2 binaries, and nothing converts between
the two dialects. A generated kit declares adapters, which the ABI backend
refuses instead of dropping. An embedding application removes them and lists
the named services it uses.

The opt-in native TLS client uses the same browser-profile emitter as the
runnable transport. Prepare the pinned patched OpenSSL through `ezbuild.sh`
or the [documented direct-CMake setup](../../CONTRIBUTING.md#build).
Stock OpenSSL remains sufficient for the isolated session-security provider;
it is not sufficient for the native TLS provider. The profile's broader TLS
and ALPN offer never permits a YTP channel below TLS 1.3 or without H2.

### Build the native ingress candidate

The source-level listener target `yume::ytp1_front_door` is enabled with all
four options below; CMake rejects the FrontDoor option without its providers:

```bash
cmake -S . -B build-ingress -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DYUME_BUILD_TRANSPORT_V2=OFF -DYUME_BUILD_TESTING=ON \
  -DYUME_BUILD_EXPERIMENTAL_YTP1_TLS13_PROVIDER=ON \
  -DYUME_BUILD_EXPERIMENTAL_YTP1_H2_CARRIER=ON \
  -DYUME_BUILD_EXPERIMENTAL_YTP1_ASIO_TCP_BYTE_CHANNEL_PROVIDER=ON \
  -DYUME_BUILD_EXPERIMENTAL_YTP1_FRONT_DOOR=ON \
  -DYUME_WARNINGS_AS_ERRORS=ON
cmake --build build-ingress --target yume_ytp1_front_door -j2
```

Use the pinned patched OpenSSL installation described above and libnghttp2.
This builds a provider library, not a standalone daemon or public C ABI backend.
The caller loads credentials and an immutable `Ytp1CoverSite` from an operator
site root with an index and explicit not-found file. The site uses confined
`FileRoot` reads at load time; requests perform no file access or resolution.
There is no built-in fallback site or reverse-proxy implementation here.

Add `-DYUME_BUILD_EXPERIMENTAL_YTP1_OPENSSL_PROVIDER=ON` to compose
`yume_native_endpoint`. With tests enabled, `yume_native_credentials_test` and
`yume_native_endpoint_test` exercise protected loading and native session traffic
on POSIX. The endpoint test provisions temporary named-service kits; enabling
the route provider also exercises configured direct adapters. These tests do not
establish that the generated SOCKS/packet kit can run in the CLI.
Set `YUME_NATIVE_TEST_OPENSSL` to the pinned
installation's `bin/openssl` when configuring tests. Native startup requires a
frame budget of at least 64 KiB for the AUTH envelope and applies the engine's
queue bounds before opening listeners. Enabling
`YUME_BUILD_EXPERIMENTAL_YTP1_ASIO_ROUTE_PROVIDER` also tests authenticated TCP
and connected-UDP destinations through the native endpoint, including packet
boundaries and refusal before socket creation. The caller supplies
`NativeEndpointOptions::route_provider`. Configured `direct_tcp`/`direct_udp`
declarations enforce their `destinations` through `NativeEgressPolicy` after
credential service authorization and before DNS or socket work. An optional
`route_authorization` callback can only refuse more. The engine supplies the
selected provider to handlers, and an Asio provider built with the same policy
checks every selected numeric address before connecting. Explicit
policy-bearing handlers remain available for other services. The ABI backend
still refuses adapter declarations, and packet/TUN adapters are not
implemented.

The caller retains a single-runner `AsioExecutionContext` through the promoted
carrier lifetimes. The front door supplies H2 dispatch from its context,
including reserved control tasks for close, cancellation and credit return. It initiates on that context,
contains runner exceptions and resumes execution, closes owners, calls
`finish()` and drains completions. Promotion settles cover output and its
timer before transferring the same TLS/H2 state; published carriers preserve
ordinary cover handling after listener destruction. Ingress resolves no names.
Any wider runtime adding system DNS must account for resolver shutdown that
can outlive the application deadline.

## Build the ABI candidate and the schema-1 tools

The replacement ABI and the schema-1 operator tools are explicit opt-ins that
do not disable the current transport:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DYUME_BUILD_TESTING=ON \
  -DYUME_BUILD_SHARED_ABI=ON \
  -DYUME_INSTALL_EXPERIMENTAL_YTP1_TOOLS=ON \
  -DYUME_WARNINGS_AS_ERRORS=ON
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/install"
```

The build tree contains an unversioned `src/libyume.so` and its contract
tests. The install contains `yume-setup-ytp1` and `yume-doctor-ytp1` only:
no ABI library, header, CMake package, or pkg-config metadata is installed.
Transport-v2 configurations start and move authenticated named-stream bytes
through the build-tree ABI. A schema-1 endpoint does the same when the build
also enables every `YUME_BUILD_EXPERIMENTAL_YTP1_*` option, including the
FrontDoor, and otherwise fails closed with `YUME_STATUS_UNSUPPORTED`. Packet and
destination-routed paths are unsupported in both dialects.

## Provision a kit and validate it

```bash
install/bin/yume-setup-ytp1 init \
  --host tunnel.example.com \
  --output "$PWD/yume-kit" \
  --client-name laptop
install/bin/yume-doctor-ytp1 --config yume-kit/server/yumed.json
install/bin/yume-doctor-ytp1 --config yume-kit/client/yume.json
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

Setup can encode an IP endpoint, but the candidate native TLS/H2 client
currently requires a DNS server name. Configuring a connection address
separately from the authenticated DNS name remains an integration gap; an
IP-address kit is not a working native endpoint.

Run doctor as the identity that will run YUME. It rejects unknown schema
keys, provider or profile mismatch, unsafe limits, missing cover content,
unsupported or mismatched key algorithms, symlink and file-race conditions,
and permissive secret modes, and it reports the first failing RFC 6901 JSON
pointer or credential path. It rechecks file identity, size, timestamps,
permissions, and bounds around reads so a replaced secret fails closed. It
does not inspect file ownership, consume a separate compatibility manifest,
or print private material. Fix the reported location; there is no CLI
override for a doctor failure.

## Run the development runtimes

With every native provider option enabled, including
`YUME_BUILD_EXPERIMENTAL_YTP1_ASIO_ROUTE_PROVIDER`, the build produces
`bin/yumed-ytp1` and `bin/yume-ytp1`. They are development programs, not the
installed product:

```bash
build/bin/yumed-ytp1 --config kit/server/yumed.json --validate
build/bin/yumed-ytp1 --config kit/server/yumed.json
build/bin/yume-ytp1 --config kit/client/yume.json
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

The daemon needs a `direct_tcp` or `direct_udp` adapter for every configured
service, and neither program implements packet/TUN adapters. Before starting
them, remove the generated `packet` service and adapter from both
configurations and the `packet` capability from
`server/credentials/authorized-keys.json`. Listening on port 443 needs the
matching bind capability, or choose a high port. The client runs its SOCKS5 listeners and keeps one session, reconnecting
with backoff. SOCKS5 offers only the no-authentication method and CONNECT, and
refuses requests while no session is active. Stop either process with SIGINT or
SIGTERM.

`scripts/yume_ndpi_smoke.py` runs one loopback session inside a rootless
network namespace with Ethernet-sized frames and records what nDPI reports.
`scripts/ensure-ndpi.sh` builds the pinned release, or newer sources such as
`--ref dev` under a prefix named by their commit. `scripts/yume_ethernet_smoke.py`
runs the client on this machine and the daemon on a directly connected host,
after a link preflight that fails when the direct route is unavailable. It
alternates untunnelled and tunnelled fetches of one payload. The daemon reaches
the tunnel destination on its own host, and the untunnelled fetch crosses the
link to `--baseline-port`, which a firewall on that host must allow. Neither
result is a classifier verdict or a qualified benchmark.

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
  inputs. A network that no destination could match is rejected;
- `limits`: bounded frames, streams, queues, opens, rekeys, controls, and
  packets.

Schema 1 rejects inline secrets, aliases, unknown keys, unsupported providers,
and unsafe combinations. Runtime CLIs will accept config selection,
validation, version, and diagnostic controls only; network and security
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
security factory's bound. The independent admin store accepts 0 through 4096
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
with boundaries preserved end to end; the intended packet ABI batches views while
keeping individual boundaries and all-or-none write admission; packet size,
batch count, stream count, queued bytes, pending opens, and outer and
in-session credit are bounded before allocation; and every packet OPEN is
independently authorized. Direct UDP is an explicit `RouteProvider`, and a
future TUN adapter is an ordinary ABI consumer that cannot bypass route
policy. The codec and ABI declarations exist. NativeEndpoint composes the
opt-in Asio provider and configured `direct_udp` handlers into an authenticated
connected-UDP path with explicit policy and preserved packet boundaries.
Public ABI packet handle creation and I/O, standalone packet/TUN adapters, and
production qualification remain unfinished.

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
  -DYUME_INSTALL_EXPERIMENTAL_YTP1_TOOLS=ON -DYUME_WARNINGS_AS_ERRORS=ON
cmake --build build-test -j"$(nproc)"
ctest --test-dir build-test --output-on-failure
python3 -m unittest tests.test_yume_setup_transport_v2 \
  tests.test_yume_setup_ytp1 tests.test_yume_doctor_ytp1
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

Performance claims need the signed 0.2 baseline kept runnable and matched
evidence captured before any switch-over: throughput, p50/p99 latency, CPU
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
