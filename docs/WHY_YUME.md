# Why YUME exists

YUME is an embeddable stealth universal transport: one authenticated,
browser-shaped carrier that moves TCP, UDP, and packet traffic, plus a C ABI so
any program can embed it. It sits in the same category as Xray or OpenVPN, with
its own original wire protocol and implementation.

The working 0.2 client and daemon already provide a complete hybrid tunnel. The
YTP/1 replacement (YUME Transport Protocol 1) generalizes that transport into
authenticated named byte streams and packet channels, with identity and
destination policy checked before dispatch.

YUME does not accumulate proxy wire formats, impersonate another project's
protocol, or offer compatibility with Xray, VLESS, or REALITY. SOCKS5, direct
TCP/UDP routing, and the packet adapter are adapters over one transport rather
than special cases in the wire protocol.

## What YUME owns, and what it does not

YUME owns transport I/O, secure establishment, carrier admission, streams,
datagrams, multiplexing, flow control, routing adapters, and transport-level
credentials.

Applications can embed YUME through the C ABI. Client identities and access
PSKs authenticate their transport sessions.

The one deliberate exception is a minimal, build-flag-gated administrative
capability so an operator can reach their own machine over the transport
without a second product. It is off in stock builds, requires an explicit
server flag, and requires the distinct `admin_keys` second factor described in
[the permission model](PERMISSIONS.md). It is a transport feature, not a
management platform.

## Security contract

The YTP/1 contract has one mandatory composition. Both Ed25519 and ML-DSA-87
authenticate a client identity. X25519, ML-KEM-1024, a per-identity access PSK, and the TLS 1.3
exporter contribute to establishment. The transcript binds the exact suite,
roles, identities, authenticated capabilities, and fixed security parameters.
Directional ratchets use one-use AEAD message keys and bounded rekey work. A
missing component or provider mismatch is a hard failure; there is no suite
fallback or cryptographic mode switch.

These are concrete design properties, not a certification. Until independent
protocol and cryptography review closes, YUME describes its ratchet as
post-compromise-oriented and does not claim to be quantum-proof, DPI-proof, or
universally indistinguishable from a browser.

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

YUME declares its wire design and implementation to be original to this
repository, with no Xray, VLESS, or REALITY wire compatibility or inherited
implementation. That is a project provenance statement, not something a word
scan or generated inventory can prove.

The repository check validates declared source-pinned dependencies and
regenerates a deterministic SPDX 2.3 source-dependency SBOM:

```bash
SOURCE_DATE_EPOCH=0 python3 scripts/check_dependency_sbom.py --check
```

The checked-in result is
[`docs/release/SBOM.spdx.json`](release/SBOM.spdx.json). It records source and
package-manager inputs; it does not establish source ancestry. A release
artifact must additionally publish its exact
binary hashes, compiler/toolchain identity, linked-library inventory, and
signature manifest.

## Replacement boundary

YTP/1 has no suite negotiation or dynamic in-process plugins. Federation,
multi-hop relay, chat/file products, reverse administration, command execution,
and the GUI are not prerequisites for the first modular tunnel path. Existing
working surfaces are not removed merely because they are outside that first
path; each is retained or archived until a reviewed replacement or retirement
milestone. A trusted C++20 provider SDK may be used at source level while it is
experimental. Cross-language embedding targets the installed C ABI after its
functional gates pass. New wire suites or out-of-process plugins require a real
consumer and their own reviewed compatibility boundary.
