# Why YUME exists

YUME is an embeddable stealth universal transport: one authenticated,
browser-shaped carrier that moves TCP, UDP, and packet traffic, plus a C ABI so
applications can embed it. Its wire protocol and implementation are original
to this project. Comparisons with other transports evaluate YUME's goals;
they do not define its architecture or feature set.

The runnable transport-v2 client and daemon provide a hybrid tunnel. The
YTP/1 replacement (YUME Transport Protocol 1) generalizes that transport into
authenticated named byte streams and packet channels, with identity and
destination policy checked before dispatch.

The current build-tree C ABI carries named byte streams through transport v2.
Its packet operations and a live YTP/1 endpoint remain unsupported. The
[connection explanation](EXPLAINED.md) separates the runnable path from the
replacement graph.

SOCKS5, direct TCP/UDP routing, and the packet adapter share the same transport.
YUME handles connection establishment, authentication, multiplexing, flow
control, and routing. The [permission model](PERMISSIONS.md) defines access to
destinations, services, and administration. Administrative access requires a
distinct second identity from `admin_keys`.

## Security contract

The YTP/1 contract has one mandatory composition. Both Ed25519 and ML-DSA-87
authenticate a client identity. X25519, ML-KEM-1024, a per-identity access PSK, and the TLS 1.3
exporter contribute to establishment. The transcript binds the exact suite,
roles, identities, authenticated capabilities, and fixed security parameters.
Directional ratchets use one-use AEAD message keys and bounded rekey work. A
missing component or provider mismatch is a hard failure; there is no suite
fallback or cryptographic mode switch.

Independent protocol and cryptography review remains a release gate. See the
[threat model](THREAT_MODEL.md) for the assumptions and limits of this design.

## A genuine application front door

The replacement's first provider will use TLS 1.3 and HTTP/2. Requests without valid cheap,
replay-protected admission continue through a real website or configured
reverse proxy. YTP records exist only after promotion to the authenticated
carrier. Browser-shaped TLS/H2 geometry is a separately versioned evidence
profile, not part of YTP semantics; recapturing a browser profile therefore
does not revise the application wire protocol.

Claims about a profile name the exact capture, implementation, environment,
active-probe checks, and held-out classifier evidence. A short functional
smoke, ALPN match, or fingerprint string is not whole-session evidence.

## Independent implementation and reproducible dependencies

The repository pins source dependencies and records them in a deterministic
SPDX 2.3 software bill of materials (SBOM):

```bash
SOURCE_DATE_EPOCH=0 python3 scripts/check_dependency_sbom.py --check
```

The checked-in result is
[`docs/release/SBOM.spdx.json`](release/SBOM.spdx.json). It records source and
package-manager inputs. A release artifact must also publish its exact
binary hashes, compiler/toolchain identity, linked-library inventory, and
signature manifest.

## Replacement boundary

YTP/1 uses one security suite and source-linked providers. Its next integration
step is a working client/server endpoint with cover traffic, routing, and
embedding support. The current client and daemon remain the default build
until that endpoint passes the [parity gates](IMPLEMENTATION_STATUS.md).
