# YUME Transport Protocol 1 kernel

Status: normative development contract for the implemented dependency-pure
YTP/1 kernel, in-memory session engine, and opt-in native provider candidates.
YUME is `0.3.0-dev1` development software; this document is not a
production-readiness, cryptographic-proof, or interoperability claim.

The authority for this contract is `src/ytp/`,
`src/engine/session_engine.*`, and the `src/providers/ytp1_*` and Asio provider
sources, together with their focused tests and the checked-in kernel vectors.
Source and executable tests outrank this document if they disagree.

This contract remains narrower than a complete transport product. The kernel
implements canonical encodings, structural validation, bounds, stream rules,
fixed suite metadata, domains, and key-schedule input encoding. The session
engine implements the authenticated record lifecycle and multiplexing over a
carrier. Opt-in candidates implement the fixed hybrid handshake, a memory-BIO
TLS 1.3 secure channel, duplex H2 carrier behavior, client TCP ByteChannel, and
direct TCP/connected-UDP routing. They are not composed with a genuine front
door, admission path, YTP/1 ABI backend, or runnable YTP/1 tunnel. The exact
unfinished boundary is listed below.

## Conventions and compatibility

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** describe the
behavior accepted or emitted by the current kernel.

All multibyte integers are unsigned and big-endian. Lengths count octets.
Decoders require exact input consumption: missing bytes are truncated input
and extra bytes are trailing data. Reserved values and bits fail closed.
Bounds are checked before variable-length data is copied or returned.

YTP/1 is wire version `1`. It has no compatibility path, downgrade, alias, or
suite negotiation for YUME transport v2, AUTH v2, relay v2, or their domains.
Product version, configuration schema 1, C ABI v1, provider versions, and
YTP/1 are independent version axes.

## Streams and frames

### Stream identifiers

A stream identifier is an unsigned 31-bit integer in the range `0` through
`0x7fffffff`.

- Stream `0` is the session-control stream.
- A client owns odd application stream identifiers, beginning with `1`.
- A server owns even application stream identifiers, beginning with `2`.
- Each endpoint advances its locally owned identifier by two. Advancing past
  the 31-bit range is exhaustion and MUST fail.
- OPEN ownership validation rejects stream zero and an application stream not
  owned by the opener.

Frame decoding enforces control-versus-application stream class. It does not
infer the peer role and therefore does not itself enforce OPEN ownership; the
caller MUST apply the separate ownership check when admitting an OPEN.

### Frame header

Every frame begins with this canonical 12-octet header:

```text
u8  version = 1
u8  record_type
u16 flags = 0
u32 stream_id
u32 payload_length
```

The stream identifier's high bit and every flag bit are reserved and MUST be
zero. `payload_length` MUST NOT exceed the bound supplied by the caller. The
kernel default is 1 MiB (`1 << 20`), but a runtime MAY impose a smaller bound.
The record decoder accepts exactly `12 + payload_length` octets and returns a
borrowed view of the payload.

### H2-duplex carrier framing v1

The fixed YTP/1 suite carries each record through a carrier-private framing
envelope before WebSocket and HTTP/2 encoding:

```text
u8  magic[4] = "YCR\\0"
u8  envelope_version = 1
u8  flags = 0
u16 reserved = 0
u32 record_length
u8  record[record_length]
```

`record_length` is unsigned big-endian, must be nonzero, and must not exceed
the carrier's immutable record bound. The receiver validates all 12 header
octets before allocating or retaining the record payload and rejects wrong
magic/version, nonzero flags/reserved bytes, oversize lengths, truncated
records, and terminal trailing state. The header's HTTP/2 receive credit may
be retired after validation; payload credit stays move-owned by the resulting
`ReceivedRecord` until the engine or application releases it.

This envelope preserves one complete Carrier record across arbitrary secure
channel reads and WebSocket message fragmentation/coalescing. WebSocket
message boundaries and captured browser geometry are never YTP semantics and
may change with an independently qualified profile. This framing is not a
cryptographic or KDF domain and does not provide authentication by itself.

The implemented record type and stream-class assignments are:

| Value | Record | Required stream class |
| ---: | --- | --- |
| 1 | `AUTH` | control (`0`) |
| 2 | `AUTH_RESULT` | control (`0`) |
| 3 | `CAPABILITIES` | control (`0`) |
| 4 | `OPEN` | application (nonzero) |
| 5 | `DATA` | application (nonzero) |
| 6 | `PACKET` | application (nonzero) |
| 7 | `CLOSE` | application (nonzero) |
| 8 | `CONNECTION_CREDIT` | control (`0`) |
| 9 | `STREAM_CREDIT` | application (nonzero) |
| 10 | `REKEY_INIT` | control (`0`) |
| 11 | `REKEY_ACK` | control (`0`) |
| 12 | `PING` | control (`0`) |
| 13 | `PONG` | control (`0`) |

Unknown record types are rejected. The kernel defines payload codecs only for
OPEN, CAPABILITIES, credit updates, and the standalone AUTH TLV format below.
It does not yet define or validate complete payload semantics for every record
in this table.

### Post-AUTH record protection

AUTH and AUTH_RESULT flights use the canonical frame directly. After AUTH,
the carrier record for every frame except REKEY_ACK has this envelope:

```text
u8  envelope_schema = 1
u24 reserved = 0
u32 directional_epoch
u64 directional_sequence
u8  aead_ciphertext_and_tag[]
```

The AEAD plaintext is exactly one canonical YTP/1 frame. Epoch and sequence
form the provider's record-key token and are bound into its AAD. Sequence is
global and strictly increasing for each direction; it does not restart when
the epoch advances. A token is accepted exactly once and the provider derives
a fresh AES-256-GCM key and nonce for it. A malformed envelope, wrong epoch,
replayed or out-of-order sequence, invalid tag, or malformed plaintext is a
terminal protocol failure.

REKEY_ACK is the sole post-AUTH exception: it is carried as one bare canonical
YTP/1 control frame in Active state. Its fixed provider payload contains a
candidate-new-root HMAC described under directional rekey below, and the TLS
carrier still protects the outer channel. A protected REKEY_ACK and every
other bare post-AUTH frame are rejected. The exception permits opposite
directions to rekey simultaneously without retaining a retired root merely to
open a crossed acknowledgement.

## OPEN payload

An OPEN payload is at most 512 octets:

```text
u8  schema = 1
u8  service_kind
u8  transport
u8  address_kind
u16 service_name_length
u16 destination_length
u8  service_name[service_name_length]
u8  destination[destination_length]
```

`service_kind` is `1` for a byte stream or `2` for a packet channel.
`transport` is `0` for none, `1` for TCP, or `2` for UDP. `address_kind` is
`0` for none, `1` for IPv4, `2` for IPv6, or `3` for DNS.

The service name MUST contain 1 through 128 octets in canonical lowercase
ASCII namespace form. A name is one or more segments separated by `.`. Every
segment begins and ends with an ASCII lowercase letter or digit; `-` and `_`
MAY occur only inside a segment. Uppercase, Unicode, empty segments, control
bytes, `/`, and `:` are invalid. Names are compared as exact octets with no
case folding or normalization.

A named service with no destination MUST set both transport and address kind
to zero and use a zero-length destination. Otherwise the transport and address
kind MUST both be nonzero, the port MUST be nonzero, and:

- a byte-stream destination MUST use TCP;
- a packet-channel destination MUST use UDP;
- IPv4 is `u16 port || 4 address octets` and has destination length 6;
- IPv6 is `u16 port || 16 address octets` and has destination length 18;
- DNS is `u16 port || u8 dns_length || dns_name`, and `dns_length` MUST equal
  `destination_length - 3`.

A DNS name contains 1 through 253 ASCII octets. It MUST be lowercase, consist
only of `a` through `z`, `0` through `9`, hyphen, and dot, and contain labels
of 1 through 63 octets. A label MUST NOT begin or end with a hyphen. Empty
labels, a leading or trailing dot, uppercase, non-ASCII input, and a trailing
root dot are rejected. The kernel performs no IDNA conversion.

## CLOSE payload

A CLOSE payload is exactly one octet:

```text
u8 close_code
```

The codes are:

| Code | Meaning | Effect |
| ---: | --- | --- |
| 0 | directional FIN | The sender will transmit no more DATA or PACKET records on this stream. The peer may continue writing in the other direction. |
| 1 | unauthorized | Terminal OPEN rejection or stream abort. |
| 2 | unsupported | Terminal OPEN rejection or stream abort. |
| 3 | handler failure | Terminal service failure and stream abort. |
| 4 | application abort | Terminal abort requested by the application. |

Code 0 closes only the sender's write side. Already accepted inbound records
remain readable, and the stream retires only after both write sides are closed
and inbound data is drained. Codes 1 through 4 close the stream in both
directions and fail pending I/O. A repeated FIN, a CLOSE for a retired stream,
an unknown code, or application data sent after the corresponding close is a
protocol failure.

## Capability manifest

A canonical capability manifest is at most 64 KiB and contains at most 256
entries:

```text
u8  schema = 1
u8  flags = 0
u16 entry_count
repeat entry_count:
    u8  service_kind
    u8  flags = 0
    u16 service_name_length
    u32 max_concurrent_streams
    u8  service_name[service_name_length]
```

Service kinds and names have the same rules as OPEN.
`max_concurrent_streams` MUST be in `1..1048576` inclusive.

Entries are ordered first by unsigned service-name octets and then by numeric
service kind. The encoder sorts entries into that order. The decoder rejects
out-of-order entries and duplicate `(service_name, service_kind)` keys. The
same name MAY appear once for each distinct service kind. An empty manifest is
the four-octet value `01 00 00 00`.

A capability is authenticated advertisement, not authorization. A runtime
MUST still apply its resource and per-OPEN authorization policy.

## Flow-credit update

Both connection-credit and stream-credit updates use exactly one big-endian
`u32` increment. An increment MUST be in `1..1073741824` (`1..2^30`)
inclusive. Zero, a larger value, a shorter payload, and a longer payload are
rejected.

The kernel encodes individual increments only. Window accounting, overflow
handling, backpressure, and when credit is returned are runtime responsibilities
and are not specified by this codec.

## Fixed security composition

YTP/1 exposes one exact suite identifier:

```text
YTP/1:TLS13:H2:ED25519+ML-DSA-87:X25519+ML-KEM-1024:HKDF-SHA256:AES-256-GCM
```

This is a protocol constant, not a negotiation offer or provider-selection
string. The required 24-octet security-parameter value is:

```text
01 01 01 01 01 01 01 01 01 20 0c 10 20 20 20 20
06 20 06 20 00 40 01 00
```

In order, these octets declare parameter schema 1; composite authentication;
Ed25519; ML-DSA-87; hybrid establishment; X25519; ML-KEM-1024;
HKDF-SHA256; AES-256-GCM; a 32-octet AEAD key; a 12-octet nonce; a 16-octet
tag; 32-octet access PSK, exporter, X25519 shared secret, and ML-KEM
shared secret; 1568-octet ML-KEM-1024 public key and ciphertext; at most 64
prepared/in-flight ratchet epochs; mandatory one-use message keys; and a zero
reserved octet. Every octet MUST match exactly.

The build-tree-only provider `openssl35.ytp1-security` enforces this exact
composition when explicitly enabled with
`YUME_BUILD_EXPERIMENTAL_YTP1_OPENSSL_PROVIDER=ON`. It creates a private
OpenSSL library context, loads only the instance-local default provider,
requires every named algorithm, and has no provider fallback or suite
negotiation. This target is an experimental implementation, not a production
YTP/1 path or installed runtime contract.

### Domains

These byte strings are fixed, case-sensitive constants:

```text
yume/ytp/1/auth-signature/v1
yume/ytp/1/composite-identity/v1
yume/ytp/1/auth-role/v1
yume/ytp/1/transcript/v1
yume/ytp/1/root/v1
yume/ytp/1/psk/v1
yume/ytp/1/handshake-confirmation/v1
yume/ytp/1/c2s-root/v1
yume/ytp/1/s2c-root/v1
yume/ytp/1/message/v1
yume/ytp/1/aad/v1
yume/ytp/1/ratchet/v1
EXPORTER-yume/ytp/1/channel-binding/v1
```

The kernel embeds the root domain in the key-schedule input and checks the
domain constants in its focused test. The opt-in provider uses these domains
for composite identity, transcript, signatures, PSK authentication, hybrid
handshake confirmation, directional roots, per-record material and AAD, and
directional rekey. Implementations MUST NOT substitute formulas or
`yume/2.0/...` labels from the transport-v2 design.

## AUTH TLV encoding

The standalone canonical AUTH encoding is at most 64 KiB:

```text
u8  schema = 1
u8  message_type
u16 field_count
u32 field_bytes
repeat field_count:
    u16 field_id
    u16 flags
    u32 value_length
    u8  value[value_length]
```

`field_bytes` MUST equal the exact remaining payload size. Field IDs MUST be
nonzero and strictly increasing. Duplicate or out-of-order fields are
rejected. At most 32 fields are permitted.

Flag bit 0 (`0x0001`) marks a critical field; all other bits are reserved.
Unknown critical fields are rejected. A bounded unknown noncritical field is
retained by decode and survives re-encoding. Every implemented known field is
critical.

The accepted message-type values are:

| Value | Name |
| ---: | --- |
| 1 | `CHALLENGE` |
| 2 | `RESPONSE` |
| 3 | `ACCEPTED` |
| 4 | `REKEY_INIT` |
| 5 | `REKEY_ACK` |

The encoder inserts fields 1 through 3; callers MUST NOT supply them:

| ID | Field | Required value |
| ---: | --- | --- |
| 1 | suite ID | exact suite string above |
| 2 | security parameters | exact 24-octet value above |
| 3 | sender role | one octet: client `1` or server `2` |
| 4 | transcript hash | 32 octets |
| 5 | identity | 1 through 16384 opaque octets |
| 6 | composite signature | 4691 octets: Ed25519 64 plus ML-DSA-87 4627 |
| 7 | ML-KEM public key | 1568 octets |
| 8 | ML-KEM ciphertext | 1568 octets |
| 9 | X25519 public key | 32 octets |
| 10 | capability manifest | a canonical manifest as specified above |
| 11 | nonce | 32 octets |
| 12 | PSK authenticator | 32 octets |
| 13 | hybrid key confirmation | 32 octets |

The codec validates field widths and canonical capability bytes. It treats an
identity as bounded opaque bytes and does not parse a composite identity. It
does not itself enforce a message-specific set of required or forbidden
fields: an encoding containing only fields 1 through 3 is structurally valid
for any known message type.

The OpenSSL provider accepts only these exact critical caller-field sets, in
addition to mandatory fields 1 through 3:

| Message | Sender | Exact caller field IDs |
| --- | --- | --- |
| CHALLENGE | server | 4, 5, 6, 7, 9, 10, 11 |
| RESPONSE | client | 4, 5, 6, 8, 9, 10, 12, 13 |
| ACCEPTED | server | 4, 6, 13 |

It rejects missing, additional, noncritical, reordered, noncanonical,
wrong-role, and wrong-flight fields. Both Ed25519 and ML-DSA-87 signatures
must verify. RESPONSE also requires the authorized key's access-PSK authenticator,
X25519 and ML-KEM-1024 contributions, and hybrid-root confirmation; ACCEPTED
requires a distinct server confirmation. The provider uses the fixed binary
rekey payload below rather than AUTH TLV message types 4 and 5.

## Canonical key-schedule input

The kernel validates and encodes, but does not derive a key from, a canonical
key-schedule input. The encoding is at most 128 KiB:

```text
u8  schema = 1
u8  reserved = 0
u16 field_count = 18
repeat 18:
    u16 field_id
    u32 value_length
    u8  value[value_length]
```

The fields are fixed and emitted in this order:

| ID | Value |
| ---: | --- |
| 1 | `yume/ytp/1/root/v1` |
| 2 | exact suite ID |
| 3 | initiator role, one octet |
| 4 | responder role, one octet |
| 5 | 32-octet transcript hash |
| 6 | 32-octet TLS exporter |
| 7 | client identity, 1 through 16384 octets |
| 8 | server identity, 1 through 16384 octets |
| 9 | canonical client capability manifest |
| 10 | canonical server capability manifest |
| 11 | exact required security parameters |
| 12 | 32-octet access PSK |
| 13 | 32-octet client X25519 public key |
| 14 | 32-octet server X25519 public key |
| 15 | 32-octet X25519 shared contribution |
| 16 | 1568-octet ML-KEM-1024 public key |
| 17 | 1568-octet ML-KEM-1024 ciphertext |
| 18 | 32-octet ML-KEM shared contribution |

The initiator and responder roles MUST each be known and MUST differ. Both
capability manifests MUST already be canonical. There are no optional security
contributors. The encoder writes into caller-owned output, reports the exact
number of octets written, rejects undersized output, and rejects overlap
between that output and any input field so secret material is not silently
aliased or copied through an unsafe buffer.

The kernel does not provide a decoder or perform cryptography for this
encoding. The opt-in provider supplies the checked operations: it requires
exact key algorithms and canonical public DER, rejects all-zero hybrid shared
contributions, compares authentication values with OpenSSL's constant-time
primitive, and runs the fixed HKDF before publishing peer evidence or
directional roots.

## Directional rekey

REKEY_INIT and REKEY_ACK frame payloads begin with an engine-visible
big-endian `u32 next_epoch`, followed by a fixed provider message that repeats
and cryptographically binds the epoch. The duplicate is intentional: the
engine can enforce lifecycle and resource policy without parsing provider
private fields, while the provider independently rejects a mismatched epoch.

The 1672-octet INIT provider message is:

```text
u8  schema = 1
u8  kind = 1
u8  direction = initiating sender role (client 1 or server 2)
u8  reserved = 0
u32 next_epoch
u8  ml_kem_1024_public_key[1568]
u8  x25519_public_key[32]
u8  nonce[32]
u8  old_root_hmac_sha256[32]
```

INIT is a protected YTP record under the old directional epoch. Its HMAC input
binds the ratchet domain, exact suite, session/transcript binding, direction,
epoch, ML-KEM public key, X25519 public key, and nonce. Acceptance requires the
next exact inbound epoch, valid old-root HMAC, nonzero X25519 and ML-KEM
contributions, and the fixed message shape.

The 1640-octet ACK provider message is:

```text
u8  schema = 1
u8  kind = 2
u8  direction = original initiating sender role (client 1 or server 2)
u8  reserved = 0
u32 next_epoch
u8  ml_kem_1024_ciphertext[1568]
u8  responder_x25519_public_key[32]
u8  new_root_hmac_sha256[32]
```

ACK is the bare control-frame exception described above. Its confirmation is
computed under the candidate new directional root and binds the ratchet
domain, exact suite, direction, epoch, session/transcript binding, the full
canonical INIT context excluding its old-root authenticator, ML-KEM
ciphertext, and responder X25519 key. The initiator commits its outbound root
only after that confirmation succeeds. The responder commits its inbound root
only after INIT succeeds. INIT consumes the next old-epoch record sequence;
ACK consumes none; the first subsequent protected record uses the new epoch
and the next global directional sequence.

At most the configured bounded number of directional rekeys may be in flight.
Skipped epochs, repeated INIT or ACK, an ACK without a pending outbound rekey,
a protected ACK, a bare non-ACK post-AUTH frame, component mutation, or
post-failure reuse terminates the session. This design supports crossed
opposite-direction rekeys without retaining old directional roots.

## Canonical vectors

`src/ytp/testdata/ytp1_vectors.txt` contains public synthetic encoding
fixtures, not credentials or cryptographic test keys. The focused executable
test checks:

- frame header `010500000000000100000003`;
- named OPEN `01010000000400006563686f`;
- TCP/DNS OPEN
  `01010103000a000e6469726563742e74637001bb0b6578616d706c652e636f6d`;
- capability manifest
  `0100000201000004000000086563686f0200000300000004756470`;
- the mandatory-only accepted AUTH encoding recorded in the vector file; and
- a 3657-octet synthetic key-schedule input whose FNV-1a-64 encoding checksum
  is `6ab12ea0049e3c94`.

FNV-1a is used only as an encoding-regression checksum and makes no
cryptographic claim.

## Implemented and unfinished boundary

Implemented in the dependency-pure `yume_ytp1` static library and exercised by
`yume_ytp1_kernel_test`:

- stream identifier construction, ownership helpers, and exhaustion checks;
- exact frame-header and whole-record length validation;
- bounded OPEN, destination, capability-manifest, and credit codecs;
- bounded canonical AUTH TLV encoding and decoding;
- exact suite, security-parameter, width, and domain constants;
- key-schedule input validation, sizing, and canonical encoding; and
- canonical encoding vectors and malformed-input tests.

Implemented in the dependency-pure session engine and its in-memory tests:

- strict AUTH flight ordering, authenticated capability confirmation, and
  fail-closed provider/suite/exporter checks;
- the protected-record envelope, exact directional epoch and global sequence,
  one-use provider-token handoff, and the sole raw REKEY_ACK admission rule;
- 31-bit odd/even multiplexing, named stream and packet services, destination
  policy handoff, bounded connection/stream credit, queues, control work,
  opens, packets, and rekeys; and
- crossed and sequential directional rekey lifecycle, cancellation, teardown,
  half-close, backpressure, and allocation-failure contracts.

Implemented in the opt-in `yume_ytp1_openssl_security` target and exercised by
`yume_ytp1_openssl_security_test` with freshly generated real keys:

- private OpenSSL context and exact Ed25519, ML-DSA-87, X25519,
  ML-KEM-1024, SHA-256, HMAC, HKDF, and AES-256-GCM algorithm requirements;
- canonical unencrypted PKCS#8 private keys, canonical SubjectPublicKeyInfo
  public keys, per-identity access PSKs, duplicate-identity rejection,
  exact role factories, and bounded public peer labels;
- exact three-flight hybrid authentication, transcript/exporter/capability
  binding, both signature components, PSK precheck, and distinct response and
  accepted key confirmations;
- directional roots, fresh per-record keys and nonces, exact token ordering,
  constant-time authentication comparisons, secret wiping, and cancellation;
  and
- fixed hybrid rekey INIT/ACK processing, crossed-direction operation, and
  mutation, mismatch, component-stripping, replay, epoch, and post-failure
  negative tests.

Implemented as separate opt-in provider candidates with focused tests:

- `yume_ytp1_tls13_secure_channel` wraps an engine ByteChannel with OpenSSL
  memory BIOs, enforces TLS 1.3 and ALPN `h2`, verifies client-side trust and
  hostname, bounds peer evidence, and exports channel binding;
- `yume_ytp1_h2_carrier` implements client priming and extended CONNECT,
  bounded private record framing, flow-credit ownership, and a typed server
  promotion seam for an already-admitted live H2 connection;
- `yume_asio_tcp_byte_channel_provider` supplies bounded client DNS/connect,
  socket protection, ordered operations, cancellation, and TCP half-close; and
- `yume_asio_direct_route_provider` supplies bounded TCP and connected-UDP
  egress behind the dependency-pure route-handler contract.

Not implemented or not qualified as a production YTP/1 path:

- a genuine HTTP/2 web front door, replay-protected admission and promotion,
  or live composition of the TLS, H2, security, session, and route providers;
- runtime wiring for the direct-route candidates and SOCKS/named-service/
  packet adapters on YTP/1, plus a functional schema-1 ABI endpoint, stream,
  and packet data path;
- deterministic cryptographic known-answer vectors and published rekey
  vectors; the provider test currently uses generated keys rather than a
  reproducible interoperability corpus;
- full connection/stream lifecycle integration against real carriers and
  production resource-exhaustion qualification; and
- production runtime, interoperability, fuzz, soak, sanitizer, active-probe,
  performance, or independent security-review qualification.

The provider candidates remain build-tree-only and are not created by a live
YTP/1 endpoint. Schema-1 ABI endpoint start fails with a typed unsupported
status and never silently dispatches into transport v2. An explicitly selected
transport-v2 configuration can use the same ABI symbols and carry named byte
streams, but it is a separate backend and does not qualify YTP/1. The runnable
transport-v2 product remains a separate default-build lane during the
transition; its presence does not make transport v2, AUTH v2, federation,
relay, GUI, or other product-specific surfaces part of YTP/1.

Until live provider/runtime wiring, deterministic executable vectors, and the
qualification gates land, the fixed composition is an implemented
experimental candidate, not a production security claim. It is not an
independent security proof, audit, post-quantum-security certification,
anonymity claim, or production support statement.
