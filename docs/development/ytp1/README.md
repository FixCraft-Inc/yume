# YTP/1 foundation: setup, contracts, and gates

YUME 0.3 is being rebuilt around an experimental C ABI and YTP/1. This page
is the one development reference for that replacement: what the schema-1
tools do today, the contracts the runtime must meet, and the gates that
separate a passing foundation test from a usable tunnel. It is a design
input, not an installed contract and not evidence that a runtime exists.
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

Not implemented: their composition into a YTP/1 endpoint, the genuine
HTTP/2 front door and replay-protected admission, the replacement `yume` and
`yumed` runtimes, the authenticated setup-to-SOCKS path, packet handles and
adapters, and every qualification gate below. A schema-1 kit is not valid
input for the runnable transport-v2 binaries, and nothing converts between
the two dialects.

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
through the build-tree ABI; a schema-1 endpoint fails closed with
`YUME_STATUS_UNSUPPORTED`, and packet and destination-routed paths are
unsupported on both.

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
separate admission key with TLS CA and leaf material, strict schema-1 server
and client configurations, a static default cover site, and service and
adapter manifests. Private values are never printed. Generate one kit per
deployment and one bundle per client, move a bundle over an authenticated
channel, remove offline CA material from the server host, and never commit a
kit, capture, profile, or diagnostic artifact.

Run doctor as the identity that will run YUME. It rejects unknown schema
keys, provider or profile mismatch, unsafe limits, missing cover content,
unsupported or mismatched key algorithms, symlink and file-race conditions,
and permissive secret modes, and it reports the first failing RFC 6901 JSON
pointer or credential path. It rechecks file identity, size, timestamps,
permissions, and bounds around reads so a replaced secret fails closed. It
does not inspect file ownership, consume a separate compatibility manifest,
or print private material. Fix the reported location; there is no CLI
override for a doctor failure.

## Configuration authority

Schema 1 is role tagged and contains these sections only:

- `endpoint`: one client target or bounded server listeners;
- `suite`: the exact mandatory provider composition;
- `credentials`: references to files, never inline private material;
- `cover`: the qualified profile and server cover root;
- `services` and `adapters`: explicit named-service exposure, unique by
  `(name, kind)`. Several adapters of one kind are valid when their concrete
  resources differ; exact resource collisions are rejected;
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
with boundaries preserved end to end; the ABI batches packet views while
keeping individual boundaries and all-or-none write admission; packet size,
batch count, stream count, queued bytes, pending opens, and outer and
in-session credit are bounded before allocation; and every packet OPEN is
independently authorized. Direct UDP is an explicit `RouteProvider`, and a
future TUN adapter is an ordinary ABI consumer that cannot bypass route
policy. The codec and ABI surface exist and an opt-in Asio candidate
implements bounded connected-UDP egress, but packet handle creation, adapters,
and the authenticated data path are not implemented.

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
