<!-- Generated from docs/src/en_US/pages/circuit_1.doc by scripts/yume_docs.py. Edit that file, not this one. -->
# Circuit 1

Status: normative contract for the codec in `circuit/`, the constructions in
`providers/circuit_crypto.*` with their vectors, and the node service and
client builder in `runtime/circuit_node.*` and `runtime/circuit_client.*`.
`yumed` serves circuits over its [cluster links](CLUSTER_1.md), and `yume`
builds them for a client with a `circuits` section
([implementation status](../IMPLEMENTATION_STATUS.md)). This page is not a
cryptographic proof or an anonymity claim.

## Purpose

A circuit carries one client's streams through two or three servers of one
operator's cluster. The first server, the entry, knows the client but not the
destinations. The last, the exit, reaches the destinations but does not know
the client. A middle server knows only its two neighbours. The client
encrypts each message once for every server on the path, and each server can
remove only its own layer, so it reads only what is meant for it.

This protects against observers outside the servers and against any one
server that has been broken into. It does not protect against the operator,
who runs every server and can match what they see, or against an observer who
watches both the client and the exit and matches the timing of their traffic.
The exit sees each destination and any content not protected by TLS or
another end-to-end layer.

## Conventions

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** describe what the
codec and constructions accept and produce. Integers are unsigned and
big-endian. Decoders consume their whole input: missing bytes are truncated
input and extra bytes are trailing data. Reserved fields, padding and filler
MUST be zero. A receiver that finds any violation MUST end the circuit.

Circuit 1 is its own protocol with its own labels. It runs inside YTP/1
streams and shares no label or key with [YTP/1](YTP_1.md), the relay
channel or the cluster list.

## Circuits on links

A circuit is one YTP/1 packet stream on the client's session to its entry and
one on each link after it, so the YTP/1 stream identifies the circuit on
that hop and cells carry no circuit number. The packet service keeps each
cell a single record, and YTP/1 credit paces every hop. A node extends a
circuit by opening a stream on its own outbound link to the next node, as
[cluster 1](CLUSTER_1.md) requires. Ending the stream ends the circuit on
that hop, and the stream's close carries no reason.

A circuit has 1 to 3 hops. The hop's *depth* is its position: 1 for the entry,
which the client reaches over its own session, then 2 and 3.

## Cells

A cell is exactly 512, 4096 or 16384 bytes, its *bucket*:

```text
u8  version = 1
u8  command            1 CREATE, 2 CREATED, 3 RELAY
u16 body_length
u8  body[body_length]
u8  filler[bucket - 4 - body_length] = 0
```

A receiver MUST refuse a cell of another size, another version, an unknown
command, a body longer than the bucket allows or a nonzero filler byte. The
command fixes the body:

- CREATE carries a CREATE body of 1638 bytes and MUST use the 4096-byte
  bucket.
- CREATED carries a hop handshake of 6327 bytes and MUST use the 16384-byte
  bucket.
- RELAY carries 1 to 3 layers around a relay message. Its body is the
  bucket's relay capacity plus 16 bytes for each layer, so its length MUST be
  that capacity plus 16, 32 or 48. The number of layers is the cell's *layer
  count*.

The relay capacity of a bucket is the bucket less 52 bytes, the 4-byte cell
header and room for three 16-byte layer tags: 460, 4044 or 16332 bytes. A
relay message is padded to exactly this capacity before the first layer is
applied, so a body's length depends only on its bucket and layer count and
no hop learns a message's true length. A layer count does tell a hop how many
layers remain.

The first cell a node sends forward on a circuit's stream is CREATE, the
first it receives back is CREATED, and every later cell in either direction
is RELAY. A relay forwards a cell in the bucket it arrived in. A sender
SHOULD use the smallest bucket that holds its message.

## Handshake

The client runs one handshake with each hop, through the part of the circuit
already built. Both sides use fresh X25519 and ML-KEM-1024 keys for every
circuit. The hop signs with its composite Ed25519 and ML-DSA-87 identity, which
the operator's signed list pins, and the client proves nothing to any hop.

```text
client handshake, 1636 bytes          hop handshake, 6327 bytes
u8  schema = 1                        u8  schema = 1
u8  reserved[3] = 0                   u8  reserved[3] = 0
u8  nonce[32]                         u8  x25519_public[32]
u8  x25519_public[32]                 u8  mlkem_ciphertext[1568]
u8  mlkem_public[1568]                u8  confirmation[32]
                                      u8  signature[4691]
```

The CREATE body is the hop's depth, a reserved byte and the client
handshake:

```text
u8  depth              1, 2 or 3
u8  reserved = 0
u8  client_handshake[1636]
```

The client builds the handshake and knows each hop's depth. The node that
sends CREATE sets the depth: the client sets 1 on its own session, and a node
extending a circuit sets its own depth plus one. A hop MUST refuse depth 1 on
a link from another node and any depth but 1 on a client's session.

The labels below are ASCII byte strings. *Tagged* means YUME's
length-prefixed encoding: every item, the label first, is written as a
four-byte length and its bytes.

```text
transcript = SHA-256(tagged("yume/circuit/1/transcript/v1",
                            hop_fingerprint[32], predecessor_fingerprint[32],
                            depth[1], client_handshake[1636],
                            hop_x25519_public[32], mlkem_ciphertext[1568]))
secret     = x25519_shared[32] || mlkem_shared[32]
key(label, n) = HKDF-SHA256(secret, salt = transcript, info = label, n bytes)
forward_key      = key("yume/circuit/1/forward-key/v1", 32)
backward_key     = key("yume/circuit/1/backward-key/v1", 32)
forward_iv       = key("yume/circuit/1/forward-iv/v1", 12)
backward_iv      = key("yume/circuit/1/backward-iv/v1", 12)
confirmation_key = key("yume/circuit/1/confirmation/v1", 32)
confirmation     = HMAC-SHA256(confirmation_key, transcript)
signed           = tagged("yume/circuit/1/hop-signature/v1",
                          transcript, confirmation)
signature        = Ed25519(signed) || ML-DSA-87(signed)
```

A fingerprint is the 32-byte composite identity digest of
[cluster 1](CLUSTER_1.md), in binary. The predecessor fingerprint is the
identity of the node the hop's stream arrived from, as that link
authenticated it, or 32 zero bytes at depth 1, where the predecessor is a
client. Depth and predecessor MUST agree: zeros exactly at depth 1. The
ML-DSA-87 signature uses the pure mode with an empty context, as YTP/1 does.

The hop decodes the client handshake, makes its X25519 key and encapsulates to
the client's ML-KEM key, derives the keys, and sends the hop handshake. It
MUST refuse an all-zero X25519 shared secret and an ML-KEM key that fails
OpenSSL's input check.

The client decodes the hop handshake, decapsulates, derives the X25519 secret
and the keys, verifies both halves of the signature with the identity it
expects at that position, and then compares the confirmation with its own in
constant time. It keeps no key and sends nothing on the circuit until all of
these pass. The signed predecessor lets the client notice a node that routes
the circuit through a node the client did not choose: the next hop signs that
node's fingerprint, not the one the client expects.

## Layers

Every hop has one AES-256-GCM key and 12-byte IV for each direction. Forward
is from the client toward the exit, backward the reverse.

```text
nonce = iv XOR (0x00000000 || u64 counter)
aad   = tagged("yume/circuit/1/layer-aad/v1", direction[1], bucket[2])
```

The counter counts the cells of that hop and direction, starting at zero, and
is never sent. Direction is 1 forward and 2 backward, and the bucket is the
cell's size as a u16. A layer's ciphertext is its plaintext followed by the
16-byte tag.

Forward, the client pads the relay message to the relay capacity and applies
the layers of the hops from the one it addresses back to the entry, the
addressed hop's innermost. Each hop removes its own layer. A hop that removes
the last layer reads the relay message, and one that leaves layers forwards
them in a RELAY cell of the same bucket. A cell with more than one layer at a
hop that has no next hop ends the circuit.

Backward, a hop that sends a relay message applies its own layer to the padded
message. Each hop before it adds its own layer to whatever arrives from its
next hop, and the client removes them all. The layer count tells the client
which hop sent the message. A hop MUST end the circuit rather than add a
fourth layer.

A replayed, reordered, rebucketed or altered cell fails its tag, and a hop or
client that finds a failed tag MUST end the circuit. A layer protects at most
2^32 cells in each direction, and the circuit then ends. Layer keys last as
long as the circuit and are never rekeyed. The YTP/1 links underneath keep
their own ratchets.

## Relay messages

A relay message fills exactly the relay capacity:

```text
u8  type
u8  flags = 0
u16 length
u32 stream
u8  payload[length]
u8  padding[capacity - 8 - length] = 0
```

| Type | Name | Direction | Stream | Payload |
| ---: | --- | --- | --- | --- |
| 1 | `BEGIN` | forward | nonzero | a destination, below |
| 2 | `DATA` | both | nonzero | 1 or more bytes |
| 3 | `END` | both | nonzero | one stream reason byte |
| 4 | `STREAM_CREDIT` | both | nonzero | u32 increment from 1 to 2^30 |
| 5 | `EXTEND` | forward | 0 | next node's fingerprint[32], client handshake[1636] |
| 6 | `CONNECTED` | backward | nonzero | empty |
| 7 | `EXTENDED` | backward | 0 | hop handshake[6327] |
| 8 | `EXTEND_FAILED` | backward | 0 | one circuit reason byte |
| 9 | `CIRCUIT_FAILED` | backward | 0 | one circuit reason byte |

A decoder MUST refuse an unknown type, a type sent in the wrong direction, a
stream of 0 where the table requires a nonzero one or the reverse, nonzero
flags, a length that does not fit the capacity, a payload of the wrong shape
and nonzero padding. The client picks stream numbers, and one stream's
messages carry the same number for its whole life.

The BEGIN payload is an address kind followed by the destination bytes of a
YTP/1 OPEN. The destination is TCP and meets YTP/1's destination rules:

```text
u8  address_kind       1 IPv4, 2 IPv6, 3 DNS
u16 port               nonzero
u8  address[4]         IPv4
u8  address[16]        IPv6
u8  dns_length, u8 dns_name[dns_length]    DNS, canonical lowercase
```

| Circuit reason | Value | Meaning |
| --- | ---: | --- |
| unreachable | 1 | No live link to the next node, or it refused the circuit |
| busy | 2 | A bound was reached, try another route later |
| timeout | 3 | The next node did not answer in time |
| protocol | 4 | A malformed cell or a failed check |
| refused | 5 | Depth, a loop or a node the sender does not know |
| closing | 6 | The node is stopping or its list has expired |

| Stream reason | Value | Meaning |
| --- | ---: | --- |
| done | 0 | The stream finished |
| policy | 1 | The exit's egress policy refused the destination |
| connection refused | 2 | The destination refused the connection |
| unreachable | 3 | The destination could not be reached |
| name not found | 4 | The destination's name did not resolve, or none of its addresses connected |
| timeout | 5 | Resolving or connecting took too long |
| resources | 6 | The exit reached a bound |
| protocol | 7 | A malformed message or a broken rule |
| closed | 8 | The other end closed the stream |

Reasons name no node. A hop reports why a circuit failed only in its own
layer, so no other hop can read it.

## Streams

A stream starts when the client sends BEGIN. The exit answers CONNECTED once
it has reached the destination, or END with the reason it could not. An
exit that cannot tell a failed lookup from a failed connection answers name
not found for a name and unreachable for an address. The client sends DATA
only after CONNECTED. Messages for a stream the receiver has already ended
are ignored, because they may have crossed its END.

Each end grants the other a window of 262144 bytes for every stream's DATA
when the stream starts and returns it with STREAM_CREDIT as it delivers the
bytes, so neither end holds more of one stream than the window it granted.
A receiver may grow a window by returning more than it delivered. A
receiver MUST end the circuit when DATA exceeds the window it granted or
when STREAM_CREDIT would let its sender hold more than 2^30 bytes.

END with reason done finishes one direction: its sender will send no more
DATA, and the receiver delivers what it holds and then ends the stream toward
its reader or destination. The stream is gone once both ends have sent
done. END with any other reason ends both directions at once, also from an
end that already sent done, and DATA after its sender's END is a protocol
error.

EXTEND_FAILED leaves the circuit open at the hop that sent it, so the client
may extend to another node. CIRCUIT_FAILED comes from the hop that saw the
circuit break, and that hop then ends the circuit.

## Vectors

`src/circuit/testdata/circuit1_vectors.txt` holds public synthetic vectors,
written by `src/circuit/testdata/generate_circuit_vectors.py`, which uses
only Python's `hashlib` and `hmac` and the `cryptography` package's X25519
and AES-GCM. They cover cell and relay message encodings, the BEGIN
destination forms, the transcript, the key schedule, the confirmation, the
signed bytes, the layer nonces and a three-hop cell in both directions layer
by layer. Large values are given by their SHA-256. X25519 uses the key pair of
RFC 7748 section 6.1. The file also lists negative vectors: a valid cell or
message with one mutation and the error its decoder must report.

`yume_circuit1_codec_test` checks the encodings and negative vectors, and
`yume_circuit_crypto_test` checks the constructions against the same file
and runs real handshakes with freshly generated keys, including mutated and
stripped signatures, ciphertexts, depths and predecessors. ML-KEM and the
signatures have no vectors here, because their keys are random.

## Limits

- Timing is not hidden. An observer of both the client's session and the
  exit's connections can match them, and nodes forward cells without delay.
- The entry learns how many hops a circuit has from its layer count and from
  the rounds of the build. Middle and exit learn nothing new from theirs with
  at most three hops.
- Layer tags cost 16 bytes per hop. A length-preserving layer would hide the
  layer count but lets a malicious entry mark cells for a colluding exit, and
  the construction that avoids that is not available in OpenSSL.
- This page defines no route choice, bounds, consent or exits. The node
  service's bounds and exits, and the client's route choice and consent, are
  in [cluster 1](CLUSTER_1.md).
