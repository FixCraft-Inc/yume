<!-- Generated from docs/src/en_US/pages/relay_channel.doc by scripts/yume_docs.py. Edit that file, not this one. -->
# Relay channel protocol

Status: normative contract for the relay channel library in
`src/modules/relay`, which builds only with `YUME_BUILD_BASEFWX_MODULES=ON`.
No shipped program speaks it yet. The planned chat and file modules will.
This page is not a cryptographic proof or a production-readiness claim.

A relay channel protects traffic between two YUME users whose bytes a server
relays. The server sees the handshake records, which carry both identities and
the invite context in the clear, and after that only ciphertext, lengths and
timing. It never holds a channel key. The channel is its own protocol: it
runs end to end inside each user's session with the server, and
[YTP/1](YTP_1.md) neither negotiates nor changes it.

Every label, field number and value on this page is the relay v2 definition
that transport v2 used, and all of them are frozen. A semantic change needs a
new protocol version and new labels, with every writer, reader and test vector
changed together.

## Primitives

- Identity: a composite Ed25519 and ML-DSA-87 key pair. It travels as two PEM
  public keys, Ed25519 first. A receiver re-encodes it and refuses any other
  spelling, so one key has one transcript representation.
- Signature: Ed25519 (64 bytes) followed by ML-DSA-87 (4,627 bytes) over the
  same message, 4,691 bytes in all. Both halves must verify.
- Key exchange: ML-KEM-1024 and X25519 together, with an optional 32-byte PSK
  agreed out of band.
- HKDF-SHA256, SHA-256, and AES-256-GCM with a 16-byte tag.

Integers are big-endian. Below, `lp(x)` is `x` behind its length as a u32.
The library takes ML-KEM-1024, X25519, HKDF and AES-GCM from the pinned BaseFWX
build and the signatures and SHA-256 from OpenSSL.

## Handshake

The initiator sends one request record and the responder answers with one
response record. The layer that routes invites supplies the public context:
the channel kind, both endpoint ids, a 32-byte nonce, the PSK policy and a
32-byte digest of the invite metadata. The handshake binds that digest and
does not interpret the metadata. Each side also names the identity it expects
from the other, which it learns and trusts through the invite and peer-trust
layer, and the handshake fails for any other key.

```text
record = "YRV2" | schema u8 = 1 | kind u8 | field_count u16 | fields
field  = id u8 | length u16 | value
```

The request is kind 1 and the response kind 2. A record holds exactly the ids
its kind defines, in increasing order, with nothing after the last field, and
is at most 32 KiB. Fields 1 to 11 are the same in both:

| Id | Field | Value |
| ---: | --- | --- |
| 1 | Protocol version | u16, always 2 |
| 2 | Channel kind | 1 chat, 2 file, 3 bytes, 4 admin |
| 3 | Initiator endpoint id | 1 to 255 bytes from `A-Z`, `a-z`, `0-9`, `-`, `_`, `.` and `:` |
| 4 | Responder endpoint id | The same alphabet, different from field 3 |
| 5 | Nonce | 32 bytes, not all zero |
| 6 | PSK policy | 1 not required, 2 required |
| 7 | Metadata digest | 32 bytes |
| 8 | Initiator identity | Canonical composite identity, at most 16 KiB |
| 9 | Responder identity | Canonical composite identity, at most 16 KiB |
| 10 | Initiator ML-KEM-1024 public key | 1,568 bytes |
| 11 | Initiator X25519 public key | 32 bytes |

The request adds field 12, the initiator's signature. The response adds field
12, the ML-KEM-1024 ciphertext (1,568 bytes), field 13, the responder's X25519
public key (32 bytes), field 14, the request digest (32 bytes), and field 15,
the responder's signature.

Each side signs its record without its signature field. The responder's
signature also covers the complete request it answers:

```text
request_sig    = Sign(initiator, "yume/relay/v2/request-signature/v1" ||
                      lp(request fields 1-11))
response_sig   = Sign(responder, "yume/relay/v2/response-signature/v1" ||
                      lp(request) || lp(response fields 1-14))
request_digest = SHA-256("yume/relay/v2/request-digest/v1" || lp(request))
```

The responder decodes the request within those bounds and compares the
context and both identities with what the invite layer expects. Only then does
it verify the signature and encapsulate to the initiator's ML-KEM key. The
initiator requires the response to repeat the request's context, identities
and public keys, compares the request digest in constant time, verifies the
responder's signature and only then decapsulates.

With policy 2 each side supplies a 32-byte PSK, and the channel keys agree only
when both supplied the same one. With policy 1 neither may supply one. The handshake never processes a password. Turning a
password into the PSK happens outside it, so a record cannot select a KDF or
its cost.

Both sides then derive the channel's two seeds:

```text
transcript   = SHA-256("yume/relay/v2/transcript-hash/v1" ||
                       lp(request) || lp(response))
input        = "yume/relay/v2/hybrid-input/v1" ||
               lp(mlkem_ss) || lp(x25519_ss) || lp(psk)
initial_root = HKDF-SHA256(input, salt = transcript,
                           info = "yume/relay/v2/initial-root/v1", 32)
epoch_psk    = HKDF-SHA256(input, salt = transcript,
                           info = "yume/relay/v2/epoch-psk/v1", 32)
```

`psk` is empty under policy 1. The two seeds must differ. They stay in wiping
storage and move into the ratchet without a copy.

## Ratchet

Each end takes a role, client or server, and the integration maps initiator
and responder onto them. Direction 0 runs from client to server and direction
1 from server to client. Each direction has its own root and chain, so either
side can rekey its sending direction without waiting for the other.

```text
root[0] = HKDF-SHA256(initial_root, salt = "", "yume/2.0/c2s-root/v1", 32)
root[1] = HKDF-SHA256(initial_root, salt = "", "yume/2.0/s2c-root/v1", 32)
chain   = HKDF-SHA256(root,  salt = "", "yume/2.0/chain/v1", 32)
key     = HKDF-SHA256(chain, salt = "", "yume/2.0/message/v1", 32)
chain'  = HKDF-SHA256(chain, salt = "", "yume/2.0/chain-next/v1", 32)
```

Every protected frame gets its own AES-256-GCM key, which is wiped after one
use, and then the chain steps. The sequence starts at zero in every epoch.

```text
nonce = direction u8 || 0x000000 || sequence u64
aad   = "yume/2.0/aad/v2" || lp("chrome151-node24-v1") ||
        direction u8 || epoch u64 || sequence u64 ||
        type u8 || stream u8 || flags u16
```

`chrome151-node24-v1` was transport v2's evidence profile when the relay
ratchet was defined. Here it is a fixed label. YUME's evidence profile has its
own version and can change without changing relay keys.

A protected payload is `epoch u64 || sequence u64 || ciphertext`, and the
ciphertext ends with the GCM tag. The receiver accepts only the epoch and
sequence it expects next, so a replayed, reordered or skipped frame fails.
A protected frame holds at most 256 KiB of plaintext.

## Frames and records

The channel carries three frame types. Their numbers come from transport v2
and are part of the associated data:

| Type | Frame | Counts against the epoch |
| ---: | --- | --- |
| 3 | DATA | yes |
| 13 | REKEY_INIT | no |
| 14 | REKEY_ACK | no |

Any other type is refused before a key is used. Every sealed frame uses stream
0 and sets flag `0x8000`. Each relayed message carries exactly one record,
which holds one sealed frame:

```text
"YRR2" | schema u8 = 1 | reserved u8 = 0 | protocol u16 = 2 |
total_len u32 | payload_len u32 | type u8 | stream u8 | flags u16 |
protected payload
```

The header is 20 bytes. Both lengths must be exact, the protected payload is
32 bytes to 64 KiB plus 32 bytes, and nothing may follow it. An application
plaintext is at most 64 KiB, which fits a 32 KiB file chunk after base64
together with its JSON fields.

## Epoch limits

Relay channels use one fixed policy in both directions. An epoch protects at
most 256 KiB of DATA plaintext, 512 DATA frames or 500 ms of sending,
whichever runs out first. Both peers enforce the byte and frame limits on
authenticated plaintext. Only the sender enforces the time limit, because a
receiver cannot tell late delivery from late sealing without a timestamp on
the wire. The time limit starts with the epoch's first DATA frame, and an idle
channel sends nothing.

The limits bound how much traffic one epoch's keys protect, and so what a
compromise of the current chain exposes. They do not change the algorithms,
the per-frame keys or the record format.

A direction starts preparing its next epoch before it needs one: when the next
DATA frame would bring the epoch to a quarter of its bytes (64 KiB), when it
would leave only an eighth of its frames (the 448th frame), or at four fifths
of its time (400 ms).

## Rekey

A direction reaches its next epoch through a fresh ML-KEM-1024 and X25519
exchange. The sending side offers with REKEY_INIT on its own chain, and the
peer answers with REKEY_ACK on its sending chain, the reverse direction. Both
payloads use this record:

```text
record = schema u8 = 3 | kind u8 | field_count u16 | fields
field  = flags u8 (0x01 critical) | id u8 | length u32 | value
```

REKEY_INIT is kind 4 and REKEY_ACK kind 5. Each carries field 1, the next
epoch as a nonzero u64, field 2, the ML-KEM-1024 public key in an INIT or the
ciphertext in an ACK (1,568 bytes), and field 3, a fresh X25519 public key (32
bytes). All three are critical. Ids increase strictly, a record holds at most
64 fields and 64 KiB, an unknown critical field is refused and an unknown
non-critical field is accepted and not used.

```text
psk[d][e+1] = HKDF-SHA256(epoch_psk, salt = d || (e+1) u64,
                          "yume/2.0/epoch-psk/v1", 32)
root[e+1]   = HKDF-SHA256(lp(root[e]) || lp(mlkem_ss) || lp(x25519_ss) ||
                          lp(psk[d][e+1]),
                          salt = root[e], "yume/2.0/epoch-root/v1", 32)
```

The new epoch starts a fresh chain from its root, with its sequence at zero.

Offers are ordered. The receiver prepares an offered epoch only when it is the
next one after its newest prepared epoch and its window has room, and it
answers each offer in order. The sender accepts an ACK only for its oldest
outstanding offer. Any mismatch is fatal.

A prepared epoch is used only when the current one cannot carry the next DATA
frame, so every epoch delivers its whole budget and the receiver never sees a
gap. The receiver moves to the prepared epoch on its first authenticated frame
and wipes the old chain. Frames already sealed under the old epoch still
arrive first, because each direction is one ordered stream. When the epoch is
spent, nothing is prepared and an offer is in flight, DATA waits.

The window is how many future epochs a direction may have offered or
prepared. The relay default is 1 in both directions, and the library accepts 1
to 64. A deeper window hides ACK latency but keeps more prepared roots, which
an endpoint compromise would expose. After one offer, the library allows the
next only once another DATA frame has been sealed, so a window never goes out
as a burst.

Every offer has an ACK deadline, and passing it is fatal. The first offer on a
channel gets 5 seconds. Later offers get the smoothed round trip plus four
times its deviation, with RFC 6298 gains, measured only from authenticated
ACKs and clamped to 5 to 30 seconds. A later offer's deadline is never earlier
than the one before it. Deadlines bound liveness and how long ephemeral keys
live, not the epoch limits.

## Failure

Every decoding, authentication, ordering and limit failure is fatal to the
channel. Once a frame reaches the ratchet, an error may already have advanced
a chain, so the integration closes the channel and never retries on the same
ratchet.

## Tests

`yume_module_relay_vectors_test` checks known answers for every label on this
page, the nonce, associated data and envelope layouts, and the DATA record
header. Its fixture, `src/modules/relay/testdata/relay_vectors.txt`, comes
from `generate_relay_vectors.py` beside it, which implements these formulas
without YUME code. Before it writes anything, the generator reproduces the
answers the transport-v2 ratchet computed, which `ratchet_test.cpp` also
keeps. Check the fixture with:

```bash
python3 src/modules/relay/testdata/generate_relay_vectors.py \
  --check src/modules/relay/testdata/relay_vectors.txt
```

`yume_module_relay_handshake_test`, `yume_module_relay_record_test`,
`yume_module_relay_rekey_record_test`, `yume_module_relay_ratchet_test` and
`yume_module_relay_session_ratchet_test` cover parsing, bounds, ordering and
failure paths. All of them run in builds with `YUME_BUILD_BASEFWX_MODULES=ON`.
