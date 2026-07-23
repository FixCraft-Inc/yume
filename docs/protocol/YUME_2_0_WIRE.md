# YUME 2.0 desktop wire contract

Status: current `2.0-dev2` development contract for the first Linux x86-64 desktop slice.
The release version remains gated on capture, conformance, soak, and throughput
evidence. This document intentionally does not describe a 1.x compatibility
mode because none exists.

## Fixed cover stack

- Client fixture: Chrome `150.0.7871.114`, Debian 13, TLS 1.3, ALPN `h2`.
- Cover fixture: Node.js `24.18.x` LTS HTTP/2.
- Public endpoint: `yumed` terminates TLS and HTTP/2.
- Genuine site: a separately supervised Node process bound to a configured
  loopback IP literal. It receives ordinary GET/HEAD traffic only.
- Carrier: priming `GET /`, CSS, and JavaScript requests on streams 1, 3, and
  5, followed by RFC 8441 extended `CONNECT` with `:protocol = websocket` on
  stream 7.
- Tunnel bytes: WebSocket binary messages in HTTP/2 DATA frames. Client
  WebSocket frames are masked; server frames are not.

The session remains valid HTTP/2 until GOAWAY/close. SETTINGS/ACK,
WINDOW_UPDATE, PING/PONG, RST_STREAM, fragmented WebSocket messages, partial
socket writes, and backpressure are protocol behavior, not tunnel payload.
YUME emits no synthetic traffic while idle. During an active connection it
mirrors capture-backed behavior: Chrome originates an HTTP/2 PING immediately
before its WebSocket close and Node acknowledges it. No periodic PING cadence
is invented. Separately, the Node WebSocket fixture sends one `fixture-ping`
PING immediately after the first client binary message and Chrome returns a
masked PONG.

The captured SETTINGS, request headers/order, priorities, window update,
WebSocket behavior, and component versions are recorded under
`tests/fixtures/chrome150-node24/`.

OpenSSL cannot reproduce Chrome's ClientHello extension/GREASE ordering
byte-for-byte. The first release records that as a residual classifier-visible
gap. BoringSSL is the likely follow-up if capture evidence shows that matching
Chrome JA4 without byte parity is insufficient.

## Integers and envelopes

All integers are unsigned big-endian. All lengths count bytes. Integer wrap is
fatal. `record` below is the payload of a YUME AUTH, AUTH_OK, REKEY_INIT, or
REKEY_ACK frame:

```
u8  schema = 2
u8  record_kind
u16 field_count
repeat field_count:
    u8  field_flags       # bit 0 = critical; other bits must be zero
    u8  field_id
    u32 field_length
    u8  field[field_length]
```

Fields are emitted in strictly increasing `field_id` order. Duplicate fields,
out-of-order fields, an unknown critical field, unknown flag bits, oversized
lengths, truncated values, and trailing bytes are fatal. AUTH records are
limited to 64 KiB before allocation.

### AUTH challenge (`record_kind = 1`)

| ID | Critical | Value |
| -- | -- | -- |
| 1 | yes | UTF-8 exact transport version `2.0-dev2` |
| 2 | yes | 32-byte server challenge |
| 3 | yes | ephemeral ML-KEM-1024 public key |
| 4 | yes | 32-byte ephemeral X25519 public key |
| 5 | yes | 32-byte PSK salt |
| 6 | yes | 32-byte root/transcript salt |

### AUTH response (`record_kind = 2`)

| ID | Critical | Value |
| -- | -- | -- |
| 1 | yes | 32-byte client ephemeral X25519 public key |
| 2 | yes | ML-KEM-1024 ciphertext |
| 3 | yes | existing Ed25519 public identity encoding |
| 4 | yes | Ed25519 signature |

The signature input is:

```
"yume/2.0/auth-signature/v1" ||
u32(len(challenge_record)) || challenge_record ||
u32(len(response_without_signature)) || response_without_signature
```

Admission and this signature are verified before KEM decapsulation or any
other avoidable expensive operation. `AUTH_OK` is sent only after the inner
channel is active. Its encrypted payload contains the exact version and
negotiated limits.

## Admission

Both secret files contain exactly 64 lowercase hexadecimal characters (no
newline), decode to 32 random bytes, and must have no group/world permission
bits.

The carrier request carries a 32-byte random nonce and an hour bucket. Its
token is:

```
HMAC-SHA256(obfs_secret,
  len("2.0-dev2") || "2.0-dev2" ||
  len(lowercase_sni) || lowercase_sni ||
  hour_u64 || nonce_32)
```

SNI and `:authority` must match after the configured listener-port rules. The
server accepts the current or previous UTC hour and records the authenticated
nonce in a bounded expiry cache before emitting AUTH. Missing, wrong,
malformed, expired, replayed, or authority-mismatched attempts take the ordinary
captured Node cover path.

## Initial key schedule

The mandatory PSK is a uniformly random 32-byte file secret. Argon2 is not used
in this protocol: it adds no brute-force resistance to a 256-bit random value
and would add an avoidable admission and memory-exhaustion surface.

```
psk_key = HKDF-SHA256(file_psk, psk_salt,
                      "yume/2.0/psk/v1", 32)       # once per connection
root_0 = HKDF-SHA256(
  len(mlkem_ss) || mlkem_ss ||
  len(x25519_ss) || x25519_ss ||
  len(psk_key) || psk_key,
  transcript_salt, "yume/2.0/root/v1", 32)
```

Independent directional roots and chains use distinct versioned labels. Every
message derives and erases a one-use AES-256-GCM key. AAD is:

```
"yume/2.0/aad/v1" || direction_u8 || epoch_u64 || sequence_u64 ||
frame_type_u8 || stream_id_u8 || flags_u16
```

The deterministic 96-bit nonce is `direction_u8 || 0x000000 || sequence_u64`.
The message key is unique, and both epoch and sequence must exactly equal the
receiver's expected values.

## Directional epoch change

Before the hard boundary, a direction pipelines preparation of the next epoch.
The current implementation starts once an application frame reaches 64 KiB of
the 256 KiB epoch, leaves 64 of 512 frame slots, or reaches 400 ms of the 500 ms
active interval. A maximum-sized first frame therefore sends `REKEY_INIT`
immediately before that frame. Idle time alone sends nothing.

While the authenticated exchange is pending, the sender may continue sealing
old-epoch application frames only while they fit within the unchanged 256 KiB,
512-frame, and 500 ms limits. If the ACK is not ready at the hard boundary,
later writes wait in the bounded rekey queue. Ordered H2/TCP guarantees that
old-epoch frames already queued after `REKEY_INIT` arrive before any new-epoch
frame. The first authenticated new-epoch frame permanently retires the old
receiving chain.

The receiver independently rejects an authenticated inbound epoch that would
exceed the 256 KiB or 512-frame usage boundary. The 500 ms boundary is
sender-local: a conforming sender rekeys before sealing later application data,
but a receiver cannot distinguish late network delivery of an already sealed
frame from late sealing without adding a timestamp to the wire. The time-based
containment claim therefore still assumes a conforming sender; byte and frame
containment do not.

`REKEY_INIT = 13` contains the next epoch number, a fresh ML-KEM-1024 public
key, and a fresh X25519 public key. `REKEY_ACK = 14`, sent through the independent
reverse-direction chain, contains that epoch, the ML-KEM ciphertext, and the
responder's fresh X25519 public key.

For direction `d` and epoch `e+1`:

```
epoch_psk = HKDF-SHA256(psk_key, d || u64(e+1),
                        "yume/2.0/epoch-psk/v1", 32)
root_e+1 = HKDF-SHA256(
  len(root_e) || root_e ||
  len(mlkem_ss) || mlkem_ss ||
  len(x25519_ss) || x25519_ss ||
  len(epoch_psk) || epoch_psk,
  root_e, "yume/2.0/epoch-root/v1", 32)
```

The responder derives a pending receiving direction before queueing the ACK;
the initiator advances its sending direction after authenticating the ACK. The
responder commits the pending direction on the first authenticated new-epoch
frame. The old receiving chain, ephemeral keys, and shared material are then
erased. Rekey timeout is fatal; expired-epoch application data is never sent.
