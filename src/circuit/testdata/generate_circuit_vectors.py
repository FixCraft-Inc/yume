#!/usr/bin/env python3
"""Regenerate the public circuit 1 vectors without loading YUME code.

The reference follows docs/protocol/CIRCUIT_1.md with hashlib and hmac for
SHA-256, HMAC and HKDF, and Python cryptography's X25519 and AESGCM. The
cryptography package is needed only to regenerate or check this file, not to
build YUME or run its tests. Every input is a public synthetic byte pattern
except the X25519 pair, which is RFC 7748's. Nothing here is a key for use.

Negative vectors name a base encoding, one mutation and the error its decoder
must report. A mutation is xor:OFFSET:BYTE, which XORs one byte, or resize:N,
which truncates or extends with zeros.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
from pathlib import Path
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# The largest bucket differs by direction (CIRCUIT_1.md, Cells).
FORWARD_BUCKETS = (512, 4096, 16311)
BACKWARD_BUCKETS = (512, 4096, 16315)
CELL_HEADER = 4
MAX_HOPS = 3
TAG = 16
RELAY_HEADER = 8
FORWARD = 1
BACKWARD = 2
CREATE, CREATED, RELAY = 1, 2, 3
BEGIN, DATA, END, CREDIT, EXTEND, CONNECTED, EXTENDED, EXTEND_FAILED, CIRCUIT_FAILED = range(1, 10)

# RFC 7748 section 6.1.
ALICE_PRIVATE = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
ALICE_PUBLIC = bytes.fromhex(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
BOB_PRIVATE = bytes.fromhex(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
BOB_PUBLIC = bytes.fromhex(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
SHARED = bytes.fromhex(
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")


def label(name: str) -> bytes:
    return f"yume/circuit/1/{name}/v1".encode("ascii")


def pattern(seed: int, size: int = 32) -> bytes:
    return bytes((seed + index) % 256 for index in range(size))


def tagged(*items: bytes) -> bytes:
    return b"".join(struct.pack("!I", len(item)) + item for item in items)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def mac(key: bytes, message: bytes) -> bytes:
    return hmac.digest(key, message, "sha256")


def hkdf(secret: bytes, salt: bytes, info: bytes, size: int) -> bytes:
    """RFC 5869 extract then expand."""
    prk = mac(salt, secret)
    previous = b""
    output = bytearray()
    for counter in range(1, (size + 31) // 32 + 1):
        previous = mac(prk, previous + info + bytes([counter]))
        output.extend(previous)
    return bytes(output[:size])


def self_test() -> None:
    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865")
    if hkdf(b"\x0b" * 22, bytes(range(13)), bytes(range(0xF0, 0xFA)), 42) != expected:
        raise ValueError("reference HKDF self-test failed")
    if AESGCM(bytes(32)).encrypt(bytes(12), b"", b"") != bytes.fromhex(
            "530f8afbc74536b9a963b4f1c4cb738b"):
        raise ValueError("reference AES-GCM self-test failed")
    alice = X25519PrivateKey.from_private_bytes(ALICE_PRIVATE)
    bob = X25519PrivateKey.from_private_bytes(BOB_PRIVATE)
    if (alice.public_key().public_bytes_raw() != ALICE_PUBLIC
            or bob.public_key().public_bytes_raw() != BOB_PUBLIC
            or alice.exchange(X25519PublicKey.from_public_bytes(BOB_PUBLIC)) != SHARED
            or bob.exchange(X25519PublicKey.from_public_bytes(ALICE_PUBLIC)) != SHARED):
        raise ValueError("reference X25519 self-test failed")


def capacity(bucket: int) -> int:
    return bucket - CELL_HEADER - MAX_HOPS * TAG


def cell(command: int, bucket: int, body: bytes) -> bytes:
    head = bytes([1, command]) + struct.pack("!H", len(body))
    return head + body + bytes(bucket - CELL_HEADER - len(body))


def relay_message(kind: int, stream: int, payload: bytes, bucket: int) -> bytes:
    head = bytes([kind, 0]) + struct.pack("!HI", len(payload), stream)
    body = head + payload
    return body + bytes(capacity(bucket) - len(body))


def nonce(iv: bytes, counter: int) -> bytes:
    mask = bytes(4) + struct.pack("!Q", counter)
    return bytes(a ^ b for a, b in zip(iv, mask))


def aad(direction: int, bucket: int) -> bytes:
    return tagged(label("layer-aad"), bytes([direction]), struct.pack("!H", bucket))


def seal(key: bytes, iv: bytes, counter: int, direction: int, bucket: int,
         plaintext: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce(iv, counter), plaintext, aad(direction, bucket))


def transcript(hop: bytes, predecessor: bytes, depth: int, client: bytes,
               hop_x: bytes, ciphertext: bytes) -> bytes:
    return sha256(tagged(label("transcript"), hop, predecessor, bytes([depth]),
                         client, hop_x, ciphertext))


def generate() -> list[tuple[str, str]]:
    self_test()
    out: list[tuple[str, str]] = []

    def put(key: str, value: bytes | int | str) -> None:
        if isinstance(value, bytes):
            value = value.hex()
        out.append((key, str(value)))

    # Handshake encodings.
    client_nonce = pattern(0x50)
    mlkem_public = pattern(0x70, 1568)
    client_handshake = bytes([1, 0, 0, 0]) + client_nonce + ALICE_PUBLIC + mlkem_public
    mlkem_ciphertext = pattern(0x90, 1568)
    hop_confirmation = pattern(0xA0)
    hop_signature = pattern(0xC0, 4691)
    hop_handshake = (bytes([1, 0, 0, 0]) + BOB_PUBLIC + mlkem_ciphertext
                     + hop_confirmation + hop_signature)
    assert len(client_handshake) == 1636 and len(hop_handshake) == 6327
    put("x25519.alice_private", ALICE_PRIVATE)
    put("x25519.alice_public", ALICE_PUBLIC)
    put("x25519.bob_private", BOB_PRIVATE)
    put("x25519.bob_public", BOB_PUBLIC)
    put("x25519.shared", SHARED)
    put("handshake.client", client_handshake)
    put("handshake.hop", hop_handshake)

    create_body = bytes([2, 0]) + client_handshake
    put("create.body_sha256", sha256(create_body))
    put("cell.create_sha256", sha256(cell(CREATE, 4096, create_body)))
    put("cell.created_sha256", sha256(cell(CREATED, BACKWARD_BUCKETS[2], hop_handshake)))

    # Transcript, key schedule, confirmation and signed bytes, at depth 2 and
    # at depth 1 with a client predecessor.
    hop_fp = pattern(0x10)
    predecessor = pattern(0x30)
    mlkem_shared = pattern(0xB0)
    put("hop_fingerprint", hop_fp)
    put("predecessor_fingerprint", predecessor)
    put("mlkem_shared", mlkem_shared)
    for name, pred, depth in (("depth2", predecessor, 2), ("depth1", bytes(32), 1)):
        digest = transcript(hop_fp, pred, depth, client_handshake, BOB_PUBLIC,
                            mlkem_ciphertext)
        secret = SHARED + mlkem_shared
        keys = {
            "forward_key": hkdf(secret, digest, label("forward-key"), 32),
            "backward_key": hkdf(secret, digest, label("backward-key"), 32),
            "forward_iv": hkdf(secret, digest, label("forward-iv"), 12),
            "backward_iv": hkdf(secret, digest, label("backward-iv"), 12),
            "confirmation_key": hkdf(secret, digest, label("confirmation"), 32),
        }
        confirmation = mac(keys["confirmation_key"], digest)
        signed = tagged(label("hop-signature"), digest, confirmation)
        put(f"{name}.transcript", digest)
        for key, value in keys.items():
            put(f"{name}.{key}", value)
        put(f"{name}.confirmation", confirmation)
        put(f"{name}.signed", signed)

    # Nonces and associated data.
    iv = pattern(0xE0, 12)
    put("nonce.iv", iv)
    for counter in (0, 1, 0xFFFFFFFF):
        put(f"nonce.{counter}", nonce(iv, counter))
    put("aad.forward_512", aad(FORWARD, 512))
    put("aad.forward_16311", aad(FORWARD, FORWARD_BUCKETS[2]))
    put("aad.backward_16315", aad(BACKWARD, BACKWARD_BUCKETS[2]))

    # A three-hop circuit with layer keys given directly, one forward DATA
    # cell at counter 0 and one at counter 1, and one backward CONNECTED cell.
    hops = []
    for index in range(1, 4):
        hop = {
            "forward_key": pattern(0x11 * index),
            "forward_iv": pattern(0x21 * index, 12),
            "backward_key": pattern(0x31 * index),
            "backward_iv": pattern(0x41 * index, 12),
        }
        hops.append(hop)
        for key, value in hop.items():
            put(f"layers.hop{index}.{key}", value)
    data = b"circuit 1 public vector"
    for counter in (0, 1):
        message = relay_message(DATA, 7, data + bytes([counter]), 512)
        body = message
        for index in (3, 2, 1):
            hop = hops[index - 1]
            body = seal(hop["forward_key"], hop["forward_iv"], counter, FORWARD, 512, body)
            put(f"layers.forward{counter}.after_hop{index}_sha256", sha256(body))
        put(f"layers.forward{counter}.message", message)
        put(f"layers.forward{counter}.cell", cell(RELAY, 512, body))
    message = relay_message(CONNECTED, 7, b"", 512)
    body = message
    for index in (3, 2, 1):
        hop = hops[index - 1]
        body = seal(hop["backward_key"], hop["backward_iv"], 0, BACKWARD, 512, body)
        put(f"layers.backward0.after_hop{index}_sha256", sha256(body))
    put("layers.backward0.message", message)
    put("layers.backward0.cell", cell(RELAY, 512, body))
    # EXTENDED from hop 2 in the largest backward cell, two layers.
    large = BACKWARD_BUCKETS[2]
    message = relay_message(EXTENDED, 0, hop_handshake, large)
    body = message
    for index in (2, 1):
        hop = hops[index - 1]
        body = seal(hop["backward_key"], hop["backward_iv"], 1, BACKWARD, large, body)
    put("layers.extended.message_sha256", sha256(message))
    put("layers.extended.cell_sha256", sha256(cell(RELAY, large, body)))

    # Relay message encodings: type, stream, payload and direction, and the
    # message's bytes before padding.
    extend_payload = hop_fp + client_handshake
    begin_forms = {
        "begin_ipv4": bytes([1]) + struct.pack("!H", 443) + bytes([192, 0, 2, 7]),
        "begin_ipv6": bytes([2]) + struct.pack("!H", 22) + bytes.fromhex(
            "20010db8000000000000000000000007"),
        "begin_dns": bytes([3]) + struct.pack("!H", 443) + bytes([11]) + b"example.org",
    }
    messages = [
        *[(name, BEGIN, 5, payload, FORWARD, 512) for name, payload in begin_forms.items()],
        ("data", DATA, 7, b"hello", FORWARD, 512),
        ("end", END, 7, bytes([1]), BACKWARD, 512),
        ("credit", CREDIT, 7, struct.pack("!I", 65536), FORWARD, 512),
        ("connected", CONNECTED, 7, b"", BACKWARD, 512),
        ("extend", EXTEND, 0, extend_payload, FORWARD, 4096),
        ("extended", EXTENDED, 0, hop_handshake, BACKWARD, BACKWARD_BUCKETS[2]),
        ("extend_failed", EXTEND_FAILED, 0, bytes([2]), BACKWARD, 512),
        ("circuit_failed", CIRCUIT_FAILED, 0, bytes([6]), BACKWARD, 512),
    ]
    for name, kind, stream, payload, direction, bucket in messages:
        put(f"relay.{name}.type", kind)
        put(f"relay.{name}.stream", stream)
        put(f"relay.{name}.direction", "forward" if direction == FORWARD else "backward")
        put(f"relay.{name}.bucket", bucket)
        put(f"relay.{name}.payload", payload)
        encoded = relay_message(kind, stream, payload, bucket)
        put(f"relay.{name}.sha256", sha256(encoded))
        if bucket == 512:
            put(f"relay.{name}.message", encoded)

    # Negative vectors. Bases: cell.forward (layers.forward0.cell) and
    # cell.create, both decoded forward, cell.backward (layers.backward0.cell),
    # decoded backward, handshake.client, handshake.hop, create.body,
    # relay.NAME padded, and begin.NAME payloads.
    negatives = [
        ("cell_version", "cell.forward", "xor:0:01", "UnsupportedVersion"),
        ("cell_command_zero", "cell.forward", "xor:1:03", "InvalidCommand"),
        ("cell_command_four", "cell.forward", "xor:1:07", "InvalidCommand"),
        ("cell_length_over_bucket", "cell.forward", "xor:2:ff", "InvalidLength"),
        ("cell_length_not_layers", "cell.forward", "xor:3:08", "InvalidLength"),
        ("cell_layer_relabelled", "cell.forward", "xor:3:10", "NonzeroFiller"),
        ("cell_size", "cell.forward", "resize:513", "InvalidBucket"),
        ("cell_short", "cell.forward", "resize:511", "InvalidBucket"),
        ("cell_old_largest", "cell.forward", "resize:16384", "InvalidBucket"),
        ("cell_backward_size_forward", "cell.forward", "resize:16315", "InvalidBucket"),
        ("cell_forward_size_backward", "cell.backward", "resize:16311", "InvalidBucket"),
        ("cell_created_forward", "cell.forward", "xor:1:01", "WrongDirection"),
        ("cell_create_backward", "cell.backward", "xor:1:02", "WrongDirection"),
        ("create_filler", "cell.create", "xor:4095:01", "NonzeroFiller"),
        ("create_bucket", "cell.create", "resize:16311", "InvalidBucket"),
        ("create_length", "cell.create", "xor:3:01", "InvalidLength"),
        ("client_schema", "handshake.client", "xor:0:03", "UnsupportedVersion"),
        ("client_reserved", "handshake.client", "xor:2:01", "NonzeroReserved"),
        ("client_short", "handshake.client", "resize:1635", "Truncated"),
        ("client_long", "handshake.client", "resize:1637", "TrailingData"),
        ("hop_schema", "handshake.hop", "xor:0:03", "UnsupportedVersion"),
        ("hop_reserved", "handshake.hop", "xor:3:80", "NonzeroReserved"),
        ("hop_short", "handshake.hop", "resize:6326", "Truncated"),
        ("create_depth_zero", "create.body", "xor:0:02", "InvalidDepth"),
        ("create_depth_four", "create.body", "xor:0:06", "InvalidDepth"),
        ("create_reserved", "create.body", "xor:1:01", "NonzeroReserved"),
        ("create_schema", "create.body", "xor:2:03", "UnsupportedVersion"),
        ("relay_type_zero", "relay.data", "xor:0:02", "InvalidType"),
        ("relay_type_ten", "relay.data", "xor:0:08", "InvalidType"),
        ("relay_wrong_direction", "relay.data", "xor:0:04", "WrongDirection"),
        ("relay_flags", "relay.data", "xor:1:01", "NonzeroReserved"),
        ("relay_length", "relay.data", "xor:2:ff", "InvalidLength"),
        ("relay_data_empty", "relay.data", "xor:3:05", "InvalidLength"),
        ("relay_stream_zero", "relay.data", "xor:7:07", "InvalidStream"),
        ("relay_circuit_stream", "relay.extend_failed", "xor:7:01", "InvalidStream"),
        ("relay_padding", "relay.data", "xor:459:01", "NonzeroFiller"),
        ("relay_end_reason", "relay.end", "xor:8:08", "InvalidReason"),
        ("relay_failed_reason_zero", "relay.extend_failed", "xor:8:02", "InvalidReason"),
        ("relay_credit_zero", "relay.credit", "xor:9:01", "InvalidCredit"),
        ("relay_credit_large", "relay.credit", "xor:8:41", "InvalidCredit"),
        ("relay_extend_length", "relay.extend", "xor:3:01", "InvalidLength"),
        ("relay_connected_payload", "relay.connected", "xor:3:01", "InvalidLength"),
        ("relay_capacity", "relay.data", "resize:461", "InvalidLength"),
        ("begin_kind", "begin.begin_ipv4", "xor:0:07", "InvalidDestination"),
        ("begin_port_zero", "begin.begin_ipv6", "xor:2:16", "InvalidDestination"),
        ("begin_ipv4_long", "begin.begin_ipv4", "resize:8", "TrailingData"),
        ("begin_dns_upper", "begin.begin_dns", "xor:4:20", "InvalidDestination"),
        ("begin_dns_length", "begin.begin_dns", "xor:3:04", "Truncated"),
        ("begin_dns_short_length", "begin.begin_dns", "xor:3:01", "TrailingData"),
    ]
    for name, base, mutation, error in negatives:
        out.append((f"negative.{name}", f"{base} {mutation} {error}"))
    return out


HEADER = """\
# Circuit 1 public synthetic vectors (docs/protocol/CIRCUIT_1.md).
# Generated by generate_circuit_vectors.py independently of YUME code.
# Byte values are lowercase hexadecimal. The X25519 pair is RFC 7748's, every
# other input a public pattern, never a key for use. A negative line holds a
# base, one mutation and the error its decoder reports.
"""


def render() -> str:
    return HEADER + "".join(f"{key}={value}\n" for key, value in generate())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", type=Path, help="compare with an existing file")
    parser.add_argument("--output", type=Path, help="write the vectors here")
    arguments = parser.parse_args()
    text = render()
    if arguments.check:
        if arguments.check.read_text() != text:
            print(f"{arguments.check} differs from the generator", file=sys.stderr)
            return 1
        return 0
    if arguments.output:
        arguments.output.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
