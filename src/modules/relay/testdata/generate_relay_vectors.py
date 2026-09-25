#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Regenerate the relay channel's known-answer vectors without loading YUME code.

The formulas are the ones docs/protocol/RELAY_CHANNEL.md states. HKDF-SHA256
comes from hashlib and hmac, and record protection from Python cryptography's
AESGCM, which is needed only to regenerate or check this fixture. Every input
is a public synthetic octet string. The shared secrets stand in for ML-KEM and
X25519 outputs and are not keys for any deployment.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
from pathlib import Path
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PROFILE_LABEL = b"chrome151-node24-v1"
FRAME_DATA = 3
FRAME_REKEY_INIT = 13
FLAG_INNER_ENCRYPTED = 0x8000
CLIENT_TO_SERVER = 0
SERVER_TO_CLIENT = 1


def pattern(seed: int, size: int = 32) -> bytes:
    return bytes((seed + index) % 256 for index in range(size))


def lp(value: bytes) -> bytes:
    return struct.pack("!I", len(value)) + value


def hkdf(key: bytes, salt: bytes, info: bytes, size: int = 32) -> bytes:
    """RFC 5869 extract then expand. An empty salt is HashLen zero bytes."""
    if not 0 < size <= 255 * 32:
        raise ValueError("invalid reference HKDF output length")
    prk = hmac.digest(salt, key, "sha256")
    previous = b""
    output = bytearray()
    for counter in range(1, (size + 31) // 32 + 1):
        previous = hmac.digest(prk, previous + info + bytes([counter]), "sha256")
        output.extend(previous)
    return bytes(output[:size])


# The handshake.

def request_signature_input(unsigned_request: bytes) -> bytes:
    return b"yume/relay/v2/request-signature/v1" + lp(unsigned_request)


def response_signature_input(request: bytes, unsigned_response: bytes) -> bytes:
    return b"yume/relay/v2/response-signature/v1" + lp(request) + lp(unsigned_response)


def request_digest(request: bytes) -> bytes:
    return hashlib.sha256(b"yume/relay/v2/request-digest/v1" + lp(request)).digest()


def derive_seeds(request: bytes, response: bytes, mlkem_ss: bytes,
                 x25519_ss: bytes, psk: bytes) -> tuple[bytes, bytes]:
    transcript = hashlib.sha256(
        b"yume/relay/v2/transcript-hash/v1" + lp(request) + lp(response)).digest()
    material = b"yume/relay/v2/hybrid-input/v1" + lp(mlkem_ss) + lp(x25519_ss) + lp(psk)
    return (hkdf(material, transcript, b"yume/relay/v2/initial-root/v1"),
            hkdf(material, transcript, b"yume/relay/v2/epoch-psk/v1"))


# The ratchet.

def direction_root(initial_root: bytes, direction: int) -> bytes:
    label = b"yume/2.0/c2s-root/v1" if direction == CLIENT_TO_SERVER else b"yume/2.0/s2c-root/v1"
    return hkdf(initial_root, b"", label)


def epoch_psk_contribution(epoch_psk: bytes, direction: int, next_epoch: int) -> bytes:
    return hkdf(epoch_psk, bytes([direction]) + struct.pack("!Q", next_epoch),
                b"yume/2.0/epoch-psk/v1")


def next_epoch_root(root: bytes, mlkem_ss: bytes, x25519_ss: bytes,
                    epoch_psk: bytes, direction: int, next_epoch: int) -> bytes:
    contribution = epoch_psk_contribution(epoch_psk, direction, next_epoch)
    material = lp(root) + lp(mlkem_ss) + lp(x25519_ss) + lp(contribution)
    return hkdf(material, root, b"yume/2.0/epoch-root/v1")


class Chain:
    """One direction's epoch: a root, its chain and the next sequence."""

    def __init__(self, direction: int, root: bytes, epoch: int = 0) -> None:
        self.direction = direction
        self.epoch = epoch
        self.sequence = 0
        self.chain = hkdf(root, b"", b"yume/2.0/chain/v1")

    def seal(self, frame_type: int, stream: int, flags: int, plaintext: bytes) -> bytes:
        key = hkdf(self.chain, b"", b"yume/2.0/message/v1")
        nonce = bytes([self.direction, 0, 0, 0]) + struct.pack("!Q", self.sequence)
        aad = (b"yume/2.0/aad/v2" + lp(PROFILE_LABEL) + bytes([self.direction]) +
               struct.pack("!QQBBH", self.epoch, self.sequence, frame_type, stream, flags))
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        self.chain = hkdf(self.chain, b"", b"yume/2.0/chain-next/v1")
        self.sequence += 1
        return ciphertext

    def record(self, plaintext: bytes) -> bytes:
        """One DATA frame as the YRR2 record a relayed message carries."""
        epoch, sequence = self.epoch, self.sequence
        ciphertext = self.seal(FRAME_DATA, 0, FLAG_INNER_ENCRYPTED, plaintext)
        payload = struct.pack("!QQ", epoch, sequence) + ciphertext
        header = b"YRR2" + struct.pack("!BBHIIBBH", 1, 0, 2, 20 + len(payload), len(payload),
                                       FRAME_DATA, 0, FLAG_INNER_ENCRYPTED)
        return header + payload


def reference_self_test() -> None:
    # RFC 5869 SHA-256 case 1 and the AES-256-GCM empty-message vector.
    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    if hkdf(b"\x0b" * 22, bytes(range(13)), bytes(range(0xf0, 0xfa)), 42) != expected:
        raise ValueError("reference HKDF self-test failed")
    if AESGCM(bytes(32)).encrypt(bytes(12), b"", b"") != bytes.fromhex(
            "530f8afbc74536b9a963b4f1c4cb738b"):
        raise ValueError("reference AES-GCM self-test failed")
    # Answers the transport-v2 ratchet computed before the relay copy existed.
    # ratchet_test.cpp keeps them too. Matching them shows this reference and
    # the old implementation read the formulas the same way.
    root = bytes.fromhex("2aaed7289f27db3197d4cb0b47197c132a53402d688cb544190dd724258e8b48")
    c2s = direction_root(root, CLIENT_TO_SERVER)
    if c2s.hex() != "91ac5244bb48d9ffffd23b927c42a9a1f8ecacfff28b2726ae999e19f9396308":
        raise ValueError("reference direction root disagrees with transport v2")
    if Chain(CLIENT_TO_SERVER, c2s).seal(FRAME_DATA, 7, 0x0042, b"hello").hex() != \
            "185d299a151e660b0b56088b937ccc358ea22ee6c5":
        raise ValueError("reference frame disagrees with transport v2")
    psk = b"\x73" * 32
    if epoch_psk_contribution(psk, CLIENT_TO_SERVER, 1).hex() != \
            "4ebc5a195e5d8008dc11a967fb5c681a6ea5814c5ea44de6a33ad8373ae0df18":
        raise ValueError("reference epoch PSK disagrees with transport v2")
    advanced = next_epoch_root(b"\x61" * 32, b"\x71" * 32, b"\x72" * 32, psk,
                               CLIENT_TO_SERVER, 1)
    if Chain(CLIENT_TO_SERVER, advanced, 1).seal(FRAME_DATA, 1, 0, bytes([9, 8, 7])).hex() != \
            "f289ddb2a79e2f232fad37ebed3538020762d3":
        raise ValueError("reference epoch root disagrees with transport v2")


def generate() -> dict[str, bytes]:
    reference_self_test()
    values: dict[str, bytes] = {
        "unsigned_request": b"SYNTHETIC UNSIGNED RELAY REQUEST" + pattern(0x10, 24),
        "request": b"SYNTHETIC SIGNED RELAY REQUEST" + pattern(0x20, 40),
        "unsigned_response": b"SYNTHETIC UNSIGNED RELAY RESPONSE" + pattern(0x30, 24),
        "response": b"SYNTHETIC SIGNED RELAY RESPONSE" + pattern(0x40, 40),
        "mlkem_shared": pattern(0x50),
        "x25519_shared": pattern(0x70),
        "relay_psk": pattern(0x90),
    }
    values["request_signature_input"] = request_signature_input(values["unsigned_request"])
    values["response_signature_input"] = response_signature_input(
        values["request"], values["unsigned_response"])
    values["request_digest"] = request_digest(values["request"])
    root, epoch_psk = derive_seeds(values["request"], values["response"],
                                   values["mlkem_shared"], values["x25519_shared"],
                                   values["relay_psk"])
    values["initial_root"], values["epoch_psk"] = root, epoch_psk
    values["initial_root_without_psk"], values["epoch_psk_without_psk"] = derive_seeds(
        values["request"], values["response"], values["mlkem_shared"],
        values["x25519_shared"], b"")

    values["c2s_root"] = direction_root(root, CLIENT_TO_SERVER)
    values["s2c_root"] = direction_root(root, SERVER_TO_CLIENT)
    values["plaintext_0"] = b"relay channel vector frame 0"
    values["plaintext_1"] = b"relay channel vector frame 1"
    client = Chain(CLIENT_TO_SERVER, values["c2s_root"])
    values["c2s_record_0"] = client.record(values["plaintext_0"])
    values["c2s_record_1"] = client.record(values["plaintext_1"])
    server = Chain(SERVER_TO_CLIENT, values["s2c_root"])
    values["s2c_record_0"] = server.record(values["plaintext_0"])

    values["rekey_payload"] = b"SYNTHETIC REKEY RECORD" + pattern(0xb0, 10)
    values["c2s_rekey_ciphertext"] = Chain(CLIENT_TO_SERVER, values["c2s_root"]).seal(
        FRAME_REKEY_INIT, 0, FLAG_INNER_ENCRYPTED, values["rekey_payload"])

    values["rekey_mlkem_shared"] = pattern(0xd0)
    values["rekey_x25519_shared"] = pattern(0xf0)
    values["c2s_epoch_psk_1"] = epoch_psk_contribution(epoch_psk, CLIENT_TO_SERVER, 1)
    values["s2c_epoch_psk_1"] = epoch_psk_contribution(epoch_psk, SERVER_TO_CLIENT, 1)
    epoch_1 = next_epoch_root(values["c2s_root"], values["rekey_mlkem_shared"],
                              values["rekey_x25519_shared"], epoch_psk, CLIENT_TO_SERVER, 1)
    values["c2s_epoch_1_ciphertext"] = Chain(CLIENT_TO_SERVER, epoch_1, 1).seal(
        FRAME_DATA, 0, FLAG_INNER_ENCRYPTED, values["plaintext_0"])
    return values


def render() -> str:
    return (
        "# Relay channel public synthetic known-answer vectors.\n"
        "# Generated by generate_relay_vectors.py independently of YUME code.\n"
        "# Inputs are octet patterns, not keys for any deployment.\n"
        "# All values are lowercase hexadecimal.\n"
        + "".join(f"{name}={value.hex()}\n" for name, value in generate().items())
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", type=Path, help="verify an existing fixture")
    args = parser.parse_args()
    output = render()
    if args.check is None:
        sys.stdout.write(output)
    elif args.check.read_text(encoding="ascii") != output:
        print(f"relay channel vector drift: {args.check}", file=sys.stderr)
        return 1
    else:
        print("relay channel vectors match the reference")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
