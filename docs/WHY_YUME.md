<!-- Generated from docs/src/en_US/pages/why_yume.doc by scripts/yume_docs.py. Edit that file, not this one. -->
# Why YUME exists

YUME is a transport you can run on its own or embed: one authenticated,
browser-shaped connection that carries TCP, UDP and IP packets. Its protocol,
YTP/1, and its implementation are written for this project. Other transports
are useful for comparison, but they do not set YUME's design or feature list.

When goals conflict, YUME picks stealth first, then security, then speed. It
still has to be fast enough for everyday use, including HD video.

## What a client gets

A client reaches the server through SOCKS5, a managed Linux TUN device, or the
[C ABI](ABI.md) for named byte streams, packets and routed TCP/UDP. All of them
share one session. The server checks each client's identity and destination
policy before it opens anything. Administrative access needs a second, separate
identity from the admin list. See [operations](OPERATIONS.md#client-identities-and-limits).

## Security contract

YTP/1 has one fixed cryptographic composition. A client identity is signed by
both Ed25519 and ML-DSA-87. Session keys combine X25519, ML-KEM-1024, a
per-identity pre-shared key and the TLS 1.3 exporter. The handshake transcript
binds the suite, roles, identities, capabilities and security parameters.
Records use one-use AES-256-GCM keys from directional ratchets. A missing
component or provider mismatch fails the connection. There is no fallback
suite and no weaker mode.

No independent protocol or cryptography review has happened yet, and one is
required before a release. The [threat model](THREAT_MODEL.md) states the
assumptions and limits.

## A real website at the front door

`yumed` serves TLS 1.3 and HTTP/2. A request without a valid, replay-protected
admission proof gets the configured static website. YTP records appear only
after admission. The browser-shaped TLS and HTTP/2 geometry is a separately
versioned profile, so recapturing a newer browser does not change YTP/1.

A stealth claim must name the capture, the implementation, the environment,
the active-probe checks and a held-out classifier result. A matching
fingerprint string or a short smoke test does not show that a whole session
blends in. [Stealth](STEALTH.md) lists what has been measured.

## Pinned dependencies

Source dependencies are pinned and listed in a deterministic SPDX 2.3 SBOM,
[`docs/release/SBOM.spdx.json`](release/SBOM.spdx.json):

```bash
SOURCE_DATE_EPOCH=0 python3 scripts/check_dependency_sbom.py --check
```

A release must also publish binary hashes, the toolchain, the linked-library
inventory and a signed manifest.
