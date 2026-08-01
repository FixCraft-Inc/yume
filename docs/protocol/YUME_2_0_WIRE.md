# YUME 2.0 desktop wire contract

Status: current `2.0-dev6` development contract for the first Linux x86-64 desktop slice.
The release version remains gated on capture, conformance, soak, and throughput
evidence. This document intentionally does not describe a 1.x compatibility
mode because none exists.

## Reference cover stack

- Client fixture: Chrome `151.0.7922.71`, Debian 13, TLS 1.3, ALPN `h2`.
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
`tests/fixtures/chrome151-node24/`.

This is the normative target, not a statement that the current emitter has
complete identity parity. One immutable Chrome 151/Debian 13 + Node 24 profile
now supplies the production TLS selection, User-Agent/client hints, H2
settings/priorities/header order, assets, and cover-server identity. Stock
OpenSSL still cannot reproduce Chrome/BoringSSL extension/GREASE ordering.
That classifier-visible TLS difference and the remaining external conformance
and traffic-shape work are release gates; `docs/STEALTH.md` records the
required acceptance evidence.

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
| 1 | yes | UTF-8 exact transport version `2.0-dev6` |
| 2 | yes | 32-byte server challenge |
| 3 | yes | ephemeral ML-KEM-1024 public key |
| 4 | yes | 32-byte ephemeral X25519 public key |
| 5 | yes | 32-byte PSK salt |
| 6 | yes | 32-byte root/transcript salt |
| 7 | yes | `u16` concurrent directional epoch offers the server accepts (1..64) |
| 8 | yes | 20-byte accepted ratchet policy: `epoch_bytes_u64 || epoch_frames_u64 || epoch_active_ms_u32` |

### AUTH response (`record_kind = 2`)

| ID | Critical | Value |
| -- | -- | -- |
| 1 | yes | 32-byte client ephemeral X25519 public key |
| 2 | yes | ML-KEM-1024 ciphertext |
| 3 | yes | existing Ed25519 public identity encoding |
| 4 | yes | `u16` concurrent directional epoch offers the client accepts (1..64) |
| 5 | yes | 20-byte accepted ratchet policy: `epoch_bytes_u64 || epoch_frames_u64 || epoch_active_ms_u32` |
| 6 | yes | Ed25519 signature |

Fields 4 and 5 are part of the record the client signs, while the complete
challenge is also in the signature input. The two window advertisements and
both ratchet policies are therefore covered by the same transcript signature
as the key exchange. Each endpoint sends no deeper than the peer's advertised
window and applies the component-wise stricter local/peer epoch policy. Values
outside the documented bounds in `docs/SECURITY_MODES.md` are fatal on build
and parse.

The signature input is:

```
"yume/2.0/auth-signature/v2" ||
u32(len(challenge_record)) || challenge_record ||
u32(len(response_without_signature)) || response_without_signature ||
u32(32) || channel_binding
```

Admission and this signature are verified before KEM decapsulation or any
other avoidable expensive operation. `AUTH_OK` is sent only after the inner
channel is active. Its encrypted payload contains the exact version and
negotiated limits.

### AUTH channel binding

`channel_binding` is a 32-byte RFC 8446 section 7.5 exporter that each
endpoint computes from its own live TLS object:

```
channel_binding = TLS-Exporter(
  label   = "EXPORTER-yume/2.0/auth-channel-binding/v1",
  context = none,
  length  = 32)
```

It has no field id because it is never transmitted. The client signs over its
locally derived value and the server rebuilds the signature input from its
own, so the two only agree when both are on the same TLS connection.

This is what bounds the relay case. A malicious endpoint holding compatible
admission and PSK material can terminate TLS with a client and open a second
connection to a real server, but the exporter on those two connections is
derived from two independent TLS 1.3 handshakes. The forwarded response
therefore carries a signature over the wrong binding and the far server
rejects it.

Both endpoints require TLS 1.3 and a finished handshake before computing the
value. There is no unbound mode and no negotiation to disable it: a peer that
cannot produce a 32-byte binding fails AUTH. The same value is also folded
into the establishment transcript (see the key schedule below), so a bypassed
transcript check still yields unrelated roots on the two sides of a relay.

Channel binding does not authenticate the endpoint by itself. Certificate and
hostname verification, optional pinning, admission, and the Ed25519 trust
store remain the mechanisms that decide which server a client will talk to.

## Admission

Both secret files contain exactly 64 lowercase hexadecimal characters (no
newline), decode to 32 random bytes, and must have no group/world permission
bits.

The carrier request carries a 32-byte random nonce and an hour bucket. Its
token is:

```
HMAC-SHA256(obfs_secret,
  len("2.0-dev6") || "2.0-dev6" ||
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
  len(psk_key) || psk_key ||
  len(channel_binding) || channel_binding,
  transcript_salt, "yume/2.0/root/v2", 32)
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
The current implementation begins preparation once the next application frame
would reach one quarter of the negotiated byte budget, once one eighth of the
frame slots remain, or at four fifths of the sender-active interval. Under the
default Extreme policy these are the existing 64 KiB, 448-frame, and 400 ms
thresholds. Idle time alone sends nothing.

While the authenticated exchange is pending, the sender may continue sealing
old-epoch application frames only while they fit within the negotiated byte,
frame, and sender-active limits. If no prepared epoch is available at the hard
boundary, later writes wait in the bounded rekey queue. Ordered H2/TCP
guarantees that old-epoch frames already queued after `REKEY_INIT` arrive
before any new-epoch frame. The first authenticated new-epoch frame permanently
retires the old receiving chain.

### Bounded multi-epoch window

A direction may keep up to the negotiated number of offers in flight or
prepared, all for strictly contiguous epochs. Offers carry only fresh public
keys, so `REKEY_INIT` for `e+2` may be sent before the ACK for `e+1` arrives.
Nothing else about the exchange changes:

- An ACK **prepares** the next sending epoch; it does not enter it. The epoch
  is entered by the first application frame the current epoch can no longer
  carry, so each prepared epoch delivers its whole negotiated budget and the
  receiver never has to accept a gap.
- ACKs are matched to offers in strict order. A wrong or reordered epoch is
  fatal, as is an ACK with no matching offer.
- The receiver prepares each offered epoch by chaining from the newest prepared
  one and answers with its ACK. An offer that is not exactly the next
  contiguous epoch, or that exceeds the receiver's advertised depth, is fatal.
- Only the immediately next prepared receiving epoch may be committed.
- Offers are paced by application progress: at most one offer per epoch usage
  step, so the window fills over several frames instead of emitting a burst of
  rekey records.

Depth `w` therefore permits up to `w * epoch_bytes` per rekey round trip while
every negotiated per-epoch limit remains enforced. It also bounds what a peer
can force — at most `w` ML-KEM
encapsulations and `w` retained epoch roots per session — and it bounds the
break-in recovery gap: an endpoint compromise exposes at most `w` prepared
future epochs.

The receiver independently rejects an authenticated inbound epoch that would
exceed the negotiated byte or frame boundary. The active-time boundary is
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
the initiator prepares its next sending direction after authenticating the ACK
and enters it when the current epoch is spent. The responder commits the
pending direction on the first authenticated new-epoch frame. The old receiving
chain, ephemeral keys, and shared material are then erased. The rekey timeout
is measured from the oldest outstanding offer and is fatal; expired-epoch
application data is never sent.
