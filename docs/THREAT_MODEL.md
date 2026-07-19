# YUME 2.0 desktop threat model

This page describes the fixed Linux desktop 2.0 slice. Read it with
`docs/STEALTH.md`, `docs/protocol/YUME_2_0_WIRE.md`, and
`docs/PERMISSIONS.md`. It does not upgrade Android, federation, admin control,
or other out-of-scope subsystems to 2.0 status.

## Trust boundaries

| Actor | Capability and visibility |
| --- | --- |
| Path observer | Sees the TLS ClientHello, server certificate metadata, encrypted record sizes, timing, and volume. |
| Active prober | Can open TLS/H1/H2 requests to the public endpoint and sees the genuine Node cover path unless it proves admission. |
| YUME server operator | Holds TLS material, admission and inner PSK files, authorized client keys, and sees requested targets and traffic metadata. |
| Loopback Node process | Receives bounded ordinary GET/HEAD cover requests only; it must never receive tunnel records, client identities, or YUME secrets. |
| Client host | Holds both shared secret files and the client Ed25519 private key; compromise exposes local plaintext and live session state. |
| Target service | Sees the server egress identity, or another configured routing exit. |

YUME is a stealth transport and relay, not an anonymity system. Additional
routing changes who sees traffic; it does not remove trust from compromised
endpoints.

## Mandatory out-of-band secrets

Every client must receive two independent 32-byte random files out of band:

- an admission secret used before AUTH;
- an inner PSK mixed with ML-KEM-1024 and X25519.

This operational cost is intentional. There is no “connect with only the
server public key,” empty-secret, or 1.x fallback mode. File parsing is strict:
exactly 64 lowercase hex characters, no newline, and no group/world permissions.

The secrets serve different purposes and must not be reused. Compromise of one
does not by itself satisfy admission, Ed25519 identity, and the hybrid inner
handshake, but compromise of the endpoint can expose all live material.

## Carrier admission boundary

The HMAC admission token covers exact version `2.0`, normalized SNI, UTC hour,
and a 32-byte nonce. SNI and HTTP/2 authority must match. The server accepts only
the bounded clock window and stores authenticated nonces in a bounded replay
cache.

Missing, malformed, expired, replayed, wrong-secret, version-mismatched, or
authority-mismatched requests do not cross the admission boundary and never
receive AUTH. They render the ordinary captured Node cover path. A 1.x client
receives cover behavior, not a downgrade offer or recognizable protocol error.

After admission, the server verifies the Ed25519 signature over the complete
canonical AUTH transcript before KEM decapsulation or other avoidable expensive
work. Unknown critical fields, duplicates, out-of-order fields, trailing bytes,
and oversized records fail closed.

## Inner channel and blast radius

An accepted connection combines ephemeral ML-KEM-1024, ephemeral X25519, and
the mandatory high-entropy PSK with salted HKDF. Argon2 is intentionally absent:
it adds no brute-force resistance to a uniform 256-bit secret and would create a
memory/CPU denial-of-service surface.

Each direction has independent root, chain, epoch, and sequence state. Every
encrypted frame derives one AES-256-GCM key, uses it once, and erases it. AAD
binds the protocol version, direction, epoch, sequence, frame type, stream ID,
and flags. Replays, gaps, old epochs, altered metadata, and counter wrap are
fatal.

Before another application frame would cross 256 KiB, 512 encrypted data
frames, or 500 ms since the epoch’s first active data frame, that direction
performs a fresh ML-KEM-1024 + X25519 hybrid rekey. The PSK contribution is a
cheap epoch-labeled HKDF from the connection PSK key; no memory-hard operation
runs at establishment or per epoch.

Application data waits behind a bounded rekey barrier. Timeout closes the
session rather than using an expired epoch. The previous receiving chain is
retained only until the first authenticated new-epoch frame and then erased
with retired roots and ephemeral/shared material.

The approximately 500 ms claim is an epoch-local containment goal. It does not
protect data present in live endpoint memory or survive simultaneous compromise
of ML-KEM, X25519, the PSK, and an endpoint.

## Cover-backend containment

The configured backend must be a loopback IP literal; DNS names, redirects,
peer-selected destinations, and non-loopback addresses are rejected. Request
headers, response headers, bodies, connection time, and response time are
bounded, and hop-by-hop headers are removed. These controls limit the reverse
proxy’s server-side request forgery and memory-exhaustion surface.

The public TLS/H2 endpoint remains `yumed`. Node is separately supervised and
never terminates YUME admission or inner encryption. A failed backend produces
ordinary cover failure behavior, never a plaintext YUME diagnostic.

## What YUME does not protect

- Endpoint compromise, key theft, malicious server operators, or plaintext
  already exposed on the client or server.
- Traffic volume and timing analysis; shaping is capture-derived and bounded by
  the 5% bulk-overhead gate, not constant-rate padding.
- Application traffic that bypasses the local tunnel.
- The target from the direct YUME server operator.
- Availability against an attacker who can exhaust the network, TLS handshakes,
  or all configured connection limits.
- Byte-identical Chrome TLS. OpenSSL’s ClientHello/GREASE ordering remains a
  classifier-visible residual; BoringSSL is the likely future mitigation.

## Existing permission gates outside this slice

Command execution, LAN/private-address bridging, unrestricted bridging, and
privileged application codecs remain gated by compile-time switches, server
runtime settings, and per-key metadata as documented in
`docs/PERMISSIONS.md`. The 2.0 transport does not broaden those permissions.

Preauth service lanes, admin attach, federation, anonym mode, and packet egress
retain their existing authorization boundaries and are outside this focused
wire change. They must not be described as 2.0-validated without their own
integration and runtime evidence.

## Release claims

The transport stays `2.0-dev1` or `2.0-rc1` until the release gates in
`docs/YUME_2.0_IMPLEMENTATION_STATUS.md` pass. Unit tests and a short loopback
smoke are not evidence for WAN behavior, a 30-minute lifetime, sanitizer safety,
external conformance, or sustained overhead. Release documentation must separate
implemented behavior from those pending validations.
