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
| YUME server operator | Terminates TLS and the inner YUME channel; holds TLS material, admission and inner PSK files, and public-key stores; sees requested targets and decrypted YUME stream bytes unless the application independently encrypts them. |
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

## Client identity and channel binding

The client loads an Ed25519 private key from its local identity path. AUTH sends
the corresponding public PEM and a signature, never the private key. The
signature input is domain-separated and contains the complete canonical server
challenge plus unsigned response: transport version, fresh server challenge,
server ML-KEM/X25519 public keys, salts, both rekey-window advertisements,
client X25519 public key, ML-KEM ciphertext, and client public identity. The
server accepts it only when the signature verifies and the public identity is
authorized.

Under Ed25519's security assumption, a recorded public key and signature do not
let the server derive the client private key or forge a new signature.

Key files are owner-only as a creation and loading invariant. Both halves of a
generated pair are created exclusively at mode `0600`, so there is no window in
which the private PEM sits at the process umask, and an existing path is never
silently replaced. `crypto::load_keypair()` reads the private key through a
descriptor it has already validated: a regular non-symlink file, owned by the
effective user, with no group or world permission bits, and within a bounded
size. A key that fails any of those checks cannot sign an AUTH transcript.
This is enforced on Linux/POSIX; Windows has no equivalent enforcement yet and
loading fails closed there rather than accepting whatever the ACL allows.

Provisioning workflows that generate a client kit on an operator machine still
expose the private key there before delivery; clients requiring strict origin
isolation must generate and retain the identity on the client. Client host
compromise remains outside what file modes can protect.

The signature input also includes a 32-byte TLS 1.3 exporter that each endpoint
computes from its own live connection and never transmits. AUTH is therefore
cryptographically bound to the exact TLS session it ran on, on top of
certificate and hostname verification and optional leaf pinning/operator proof.
A malicious terminating node with compatible admission and PSK material can
still terminate TLS with a client, but forwarding that live exchange to another
endpoint no longer works: the two connections have independent exporters, so
the relayed signature does not verify at the far server. The same value is
folded into the establishment root, so the two sides of a relay would not share
keys even if the transcript check were bypassed.

This closes live cross-connection forwarding of a client's identity. It does
not make the terminating node trustworthy — see the endpoint sections below —
and it is not an independent-audit claim.

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

Receivers independently reject authenticated byte/frame overruns. The active
time limit is sender-local because delayed delivery is indistinguishable from
late sealing without a wire timestamp, so the 500 ms part assumes a conforming
sender.

Up to the AUTH-negotiated window (1..64, default 8) of strictly contiguous
future epochs may be authenticated and prepared while application data still
fits in the current epoch. This overlaps hybrid round trips without extending
any epoch's byte, frame, or sender-time boundary. An ACK prepares an epoch; the
sender enters it only when the current epoch cannot carry the next application
frame. The negotiated depth bounds outstanding ML-KEM work and retained future
roots. Data waits in a bounded queue if no prepared epoch is available at a
hard boundary, and timeout closes the session rather than using an expired
epoch. The previous receiving chain is retained only until the first
authenticated next-epoch frame and then erased with retired roots and
ephemeral/shared material. Ordered H2/TCP prevents an honest sender's old-epoch
frames from arriving after that commit; any such frame is fatal.

The approximately 500 ms claim is an honest-sender, active-epoch containment
goal, not a twice-per-second wall-clock schedule. Byte/frame use may rotate
sooner and idle connections do not rotate. It does not protect data present in
live endpoint memory or survive simultaneous compromise of ML-KEM, X25519, the
PSK, and an endpoint.

Compromise scope depends on which material is exposed. One erased per-message
key does not reveal another message key. Exposure of the current directional
chain/root can expose more traffic, and process-memory compromise can include
plaintext plus current and prepared state. The negotiated window retains up to
`w` future roots. Break-in recovery begins only after fresh, uncompromised
rekey contributions; no blanket “the key is useless after 500 ms” statement
applies to all of these cases.

### Forward-secrecy scope

The initial root and each directional epoch transition mix fresh ephemeral
ML-KEM-1024 and X25519 contributions. The implementation destroys the
per-exchange private keys after derivation and stores roots/chains/PSK
derivatives in self-wiping RAII containers. Consequently, capture of past wire
traffic followed only by later theft of long-term server files is not enough to
reconstruct historical session keys, assuming ML-KEM, X25519, HKDF, the random
generator, and erasure behavior hold.

This is a forward-secrecy design, not an unconditional guarantee. A malicious
server is already an endpoint and may retain plaintext or key material.
Compromise during a session exposes the current roots and up to the negotiated
window of prepared future roots. Best-effort wiping cannot erase allocator,
library, swap, core-dump, or prior process-memory copies. A stolen server TLS
private key and still-valid certificate/pin, plus deployment secrets, can also
enable future server impersonation until those credentials are revoked and
rotated; client Ed25519 authentication does not authenticate the server.

## Single-hop server boundary

The normal route is `application -> yume -> yumed -> target`. YUME does not
apply onion routing between several mutually independent relays. The server
sees the client network address unless another transport such as Tor precedes
YUME, receives the requested destination, decrypts the YUME transport records,
and controls the outbound socket.

For plaintext application protocols, the server can read, modify, inject,
drop, delay, or redirect bytes. For HTTPS or another independently
authenticated end-to-end protocol carried through YUME, the server still sees
metadata and can disrupt or redirect the connection, but it cannot silently
read or modify protected application contents without defeating that protocol.
The ratchet protects the path to the server; it does not sandbox the server from
the traffic it is asked to proxy.

## Cover-backend containment

The configured backend must be a loopback IP literal; DNS names, redirects,
peer-selected destinations, and non-loopback addresses are rejected. Request
headers, response headers, bodies, connection time, and response time are
bounded, and hop-by-hop headers are removed. These controls limit the reverse
proxy’s server-side request forgery and memory-exhaustion surface.

The public TLS/H2 endpoint remains `yumed`. Node is separately supervised and
never terminates YUME admission or inner encryption. A failed backend produces
ordinary cover failure behavior, never a plaintext YUME diagnostic.

## Identity admission and resource containment

Regular user identities and operator/controller identities live in physically
separate trust stores. A public key present in both stores is rejected. Only an
individual operator key with explicit operator metadata may receive outbound
admin policy; regular keys cannot acquire it through metadata alone.

Regular keys are individual by default and therefore admit one authenticated
session. An administrator can explicitly create a bounded `bulk` key when
issuing one credential per client is impractical. A bulk credential does not
identify which human holds it: theft or abuse by any holder affects the whole
shared identity. YUME limits that blast radius by applying a per-key cap,
counting each connection separately in the global cap, giving each connection
its own fair-egress identity, and rejecting privileged bulk policy. It cannot
distinguish an authorized holder from a thief who possesses the same private
key and both shared secret files.

The global tracked-session cap defaults to 256, the per-bulk-key cap defaults
to 64, and one accept-rate budget covers all listeners. Queues and protected
frame sizes are bounded. Administrators can additionally place aggregate
weighted egress below the physical link rate and apply service-manager CPU,
memory, task, and file-descriptor ceilings. These controls bound supported
work; they do not make the public TLS socket available against an attacker who
can saturate the link, exhaust external kernel state, or consume TLS handshake
capacity before authenticated admission.

## What YUME does not protect

- Endpoint compromise, key theft, malicious server operators, or plaintext
  already exposed on the client or server.
- Reading or modification by the terminating YUME server when the application
  itself provides no end-to-end encryption/authentication.
- Traffic volume and timing analysis; shaping is capture-derived and bounded by
  the 5% bulk-overhead gate, not constant-rate padding.
- Application traffic that bypasses the local tunnel.
- The target from the direct YUME server operator.
- Availability against an attacker who can exhaust the network, TLS handshakes,
  or all configured connection limits.
- Byte-identical Chrome TLS. OpenSSL’s ClientHello/GREASE ordering remains a
  classifier-visible residual, and the current implementation also mixes
  Chrome 131/Windows TLS/User-Agent identity with Chrome 150/Linux carrier
  hints. BoringSSL is a candidate experiment, not proof of Chrome parity.
- Protected identity-file loading on Windows. The POSIX ownership/mode
  invariant has no Windows equivalent yet, so identity loading fails closed
  there instead of accepting an arbitrary ACL.

## Existing permission gates outside this slice

Command execution, LAN/private-address bridging, unrestricted bridging, and
privileged application codecs remain gated by compile-time switches, server
runtime settings, and per-key metadata as documented in
`docs/PERMISSIONS.md`. The 2.0 transport does not broaden those permissions.

Preauth service lanes, admin attach, federation, the legacy-named `anonym`
privacy/operator-identity mode, and packet egress
retain their existing authorization boundaries and are outside this focused
wire change. They must not be described as 2.0-validated without their own
integration and runtime evidence.

## Release claims

The transport stays `2.0-dev4` or a later development/RC version until the release gates in
`docs/YUME_2_0_IMPLEMENTATION_STATUS.md` pass. Unit tests and a short loopback
smoke are not evidence for WAN behavior, a 30-minute lifetime, sanitizer safety,
external conformance, or sustained overhead. Release documentation must separate
implemented behavior from those pending validations.

“Hybrid post-quantum key establishment” is the supported terminology.
“Quantum-proof,” “uncrackable,” and guaranteed future-proof are not supported
claims: TLS certificates and Ed25519 authentication remain classical, endpoint
compromise is in scope, and the complete design has not received an independent
formal proof or security audit.
