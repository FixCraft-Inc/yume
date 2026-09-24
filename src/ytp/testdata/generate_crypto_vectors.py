#!/usr/bin/env python3
"""Regenerate public YTP/1 construction vectors without loading YUME code.

This reference uses hashlib/hmac for HKDF-SHA256 and Python cryptography's
AESGCM for record protection. cryptography is needed only to regenerate/check
this fixture, not to build YUME or run its C++ known-answer tests. All inputs
are public synthetic octet strings, including the shared-contribution inputs;
they are not provisionable keys or an asymmetric primitive test corpus.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
from pathlib import Path
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SUITE = (
    b"YTP/1:TLS13:H2:ED25519+ML-DSA-87:X25519+ML-KEM-1024:"
    b"HKDF-SHA256:AES-256-GCM"
)
PARAMETERS = bytes.fromhex("010101010101010101200c10202020200620062000400100")


def pattern(seed: int, size: int = 32) -> bytes:
    return bytes((seed + index) % 256 for index in range(size))


def domain(name: str) -> bytes:
    return f"yume/ytp/1/{name}/v1".encode("ascii")


def tagged(label: bytes, *fields: bytes) -> bytes:
    return b"".join(struct.pack("!I", len(item)) + item for item in (label, *fields))


def mac(key: bytes, message: bytes) -> bytes:
    return hmac.digest(key, message, "sha256")


def hkdf(key: bytes, salt: bytes, info: bytes, size: int = 32) -> bytes:
    """RFC 5869 extract then expand, with an explicit SHA-256 block count."""
    if not 0 < size <= 255 * 32:
        raise ValueError("invalid reference HKDF output length")
    prk = mac(salt, key)
    previous = b""
    output = bytearray()
    for counter in range(1, (size + 31) // 32 + 1):
        previous = mac(prk, previous + info + bytes([counter]))
        output.extend(previous)
    return bytes(output[:size])


def reference_self_test() -> None:
    # RFC 5869 SHA-256 case 1 and the AES-256-GCM empty-message vector.
    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    if hkdf(b"\x0b" * 22, bytes(range(13)), bytes(range(0xf0, 0xfa)), 42) != expected:
        raise ValueError("reference HKDF self-test failed")
    if AESGCM(bytes(32)).encrypt(bytes(12), b"", b"") != bytes.fromhex(
        "530f8afbc74536b9a963b4f1c4cb738b"
    ):
        raise ValueError("reference AES-GCM self-test failed")


def generate() -> dict[str, bytes]:
    reference_self_test()
    values = {
        "client_identity": b"PUBLIC SYNTHETIC CLIENT IDENTITY",
        "server_identity": b"PUBLIC SYNTHETIC SERVER IDENTITY",
        "client_capabilities": bytes.fromhex("0100000101000004000000086563686f"),
        "server_capabilities": bytes.fromhex("0100000101000004000000106563686f"),
        "exporter": pattern(0x10),
        "access_contribution": pattern(0x30),
        "client_x_public": pattern(0x50),
        "server_x_public": pattern(0x70),
        "x_shared_contribution": pattern(0x90),
        "ml_public": pattern(0xb0, 1568),
        "ml_ciphertext": pattern(0xd0, 1568),
        "ml_shared_contribution": pattern(0xf0),
        "challenge_nonce": pattern(0x20),
        "challenge_signature_octets": pattern(0x44, 64 + 4627),
        "plaintext": b"YTP/1 public construction vector\x00\xff\x80\x01",
        "rekey_ml_public": pattern(0x40, 1568),
        "rekey_ml_ciphertext": pattern(0x60, 1568),
        "rekey_initiator_x_public": pattern(0x80),
        "rekey_responder_x_public": pattern(0xa0),
        "rekey_nonce": pattern(0xc0),
        "rekey_x_shared_contribution": pattern(0xe0),
        "rekey_ml_shared_contribution": pattern(0x01),
    }
    challenge = tagged(
        domain("transcript"), b"\x01", b"\x02", SUITE, PARAMETERS,
        values["exporter"], values["server_identity"], values["ml_public"],
        values["server_x_public"], values["server_capabilities"],
        values["challenge_nonce"],
    )
    values["challenge_context_sha256"] = hashlib.sha256(challenge).digest()
    # AUTH has a synthetic signature of the exact required width. Its bytes
    # participate in the transcript; no asymmetric verification is claimed.
    challenge_fields = (
        (1, SUITE), (2, PARAMETERS), (3, b"\x02"),
        (4, values["challenge_context_sha256"]), (5, values["server_identity"]),
        (6, values["challenge_signature_octets"]), (7, values["ml_public"]),
        (9, values["server_x_public"]), (10, values["server_capabilities"]),
        (11, values["challenge_nonce"]),
    )
    challenge_tlvs = b"".join(
        struct.pack("!HHI", field_id, 1, len(value)) + value
        for field_id, value in challenge_fields
    )
    challenge_wire = struct.pack("!BBHI", 1, 1, len(challenge_fields),
                                 len(challenge_tlvs)) + challenge_tlvs
    values["challenge_wire_sha256"] = hashlib.sha256(challenge_wire).digest()
    response = tagged(
        domain("transcript"), b"\x02", b"\x01", SUITE, PARAMETERS, challenge_wire,
        values["client_identity"], values["ml_ciphertext"],
        values["client_x_public"], values["client_capabilities"],
    )
    values["response_context_sha256"] = hashlib.sha256(response).digest()
    # Challenge signature binds the context digest; subsequent flights bind
    # the complete canonical challenge and the unsigned response context.
    transcript = hashlib.sha256(tagged(
        domain("transcript"), SUITE, values["exporter"], challenge_wire, response,
    )).digest()
    values["transcript"] = transcript
    fields = [
        domain("root"), SUITE, b"\x01", b"\x02", transcript,
        values["exporter"], values["client_identity"], values["server_identity"],
        values["client_capabilities"], values["server_capabilities"], PARAMETERS,
        values["access_contribution"], values["client_x_public"],
        values["server_x_public"], values["x_shared_contribution"],
        values["ml_public"], values["ml_ciphertext"], values["ml_shared_contribution"],
    ]
    schedule = struct.pack("!BBH", 1, 0, len(fields)) + b"".join(
        struct.pack("!HI", index, len(value)) + value
        for index, value in enumerate(fields, 1)
    )
    values["schedule_sha256"] = hashlib.sha256(schedule).digest()
    master = hkdf(schedule, transcript, domain("root"))
    values["master_root"] = master
    for name in ("c2s", "s2c"):
        values[f"{name}_root"] = hkdf(master, transcript, domain(f"{name}-root"))

    values["response_psk_authenticator"] = mac(values["access_contribution"], tagged(
        domain("psk"), SUITE, b"\x01", transcript,
    ))
    for name, purpose in (("response", 1), ("accepted", 2)):
        values[f"{name}_confirmation"] = mac(master, tagged(
            domain("handshake-confirmation"), SUITE, bytes([purpose]), transcript,
        ))
    for name, message_type, role, digest, confirmation in (
        ("challenge", 1, 2, values["challenge_context_sha256"], b""),
        ("response", 2, 1, transcript, tagged(domain("auth-signature"),
         values["response_psk_authenticator"], values["response_confirmation"])),
        ("accepted", 3, 2, transcript, values["accepted_confirmation"]),
    ):
        values[f"{name}_signature_input_sha256"] = hashlib.sha256(tagged(
            domain("auth-signature"), domain("auth-role"), SUITE, PARAMETERS,
            values["exporter"], bytes([message_type]), bytes([role]), digest,
            confirmation,
        )).digest()

    def record(name: str, direction: int, root: bytes, epoch: int, sequence: int,
               plaintext: bytes) -> None:
        aad = tagged(domain("aad"), SUITE, bytes([direction]),
                     struct.pack("!IQ", epoch, sequence))
        # The message domain deliberately occurs as both domain and first field.
        info = tagged(domain("message"), domain("message"), transcript, aad)
        material = hkdf(root, transcript, info, 44)
        values[f"{name}_aad"] = aad
        values[f"{name}_material"] = material
        values[f"{name}_ciphertext"] = AESGCM(material[:32]).encrypt(
            material[32:], plaintext, aad,
        )

    for name, direction in (("c2s", 1), ("s2c", 2)):
        old_root = values[f"{name}_root"]
        record(f"{name}_first", direction, old_root, 0, 0, values["plaintext"])
        record(f"{name}_wide", direction, old_root, 0x01020304,
               0x0102030405060708, values["plaintext"])
        record(f"{name}_empty", direction, old_root, 0, 1, b"")
        # Next directional epoch after the initial root. Both directions use
        # the same public contributions, so any direction-binding drift is seen.
        epoch = struct.pack("!I", 1)
        prefix = struct.pack("!BBBBI", 1, 1, direction, 0, 1)
        init_context = prefix + values["rekey_ml_public"] + \
            values["rekey_initiator_x_public"] + values["rekey_nonce"]
        init_input = tagged(
            domain("ratchet"), SUITE, transcript, bytes([direction]), epoch,
            values["rekey_ml_public"], values["rekey_initiator_x_public"],
            values["rekey_nonce"],
        )
        ack_input = tagged(
            domain("ratchet"), SUITE, transcript, bytes([direction]), epoch,
            init_context, values["rekey_ml_ciphertext"],
            values["rekey_responder_x_public"],
        )
        new_root = hkdf(values["rekey_x_shared_contribution"] +
                        values["rekey_ml_shared_contribution"], old_root, ack_input)
        init_auth = mac(old_root, init_input)
        ack_auth = mac(new_root, ack_input)
        values[f"{name}_rekey_init_context"] = init_context
        values[f"{name}_rekey_init_input_sha256"] = hashlib.sha256(init_input).digest()
        values[f"{name}_rekey_ack_input_sha256"] = hashlib.sha256(ack_input).digest()
        values[f"{name}_rekey_init_authenticator"] = init_auth
        values[f"{name}_rekey_root"] = new_root
        values[f"{name}_rekey_ack_authenticator"] = ack_auth
        values[f"{name}_rekey_init_sha256"] = hashlib.sha256(init_context + init_auth).digest()
        ack = struct.pack("!BBBBI", 1, 2, direction, 0, 1) + \
            values["rekey_ml_ciphertext"] + values["rekey_responder_x_public"] + ack_auth
        values[f"{name}_rekey_ack_sha256"] = hashlib.sha256(ack).digest()
        record(f"{name}_rekey_first", direction, new_root, 1, 2, values["plaintext"])
    return values


def render() -> str:
    return (
        "# YTP/1 public synthetic cryptographic construction vectors.\n"
        "# Generated by generate_crypto_vectors.py independently of YUME code.\n"
        "# Inputs are octet patterns, not keys for deployment or asymmetric KATs.\n"
        "# All values are lowercase hexadecimal; SHA-256 entries hash exact bytes.\n"
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
        print(f"YTP/1 cryptographic vector drift: {args.check}", file=sys.stderr)
        return 1
    else:
        print("YTP/1 cryptographic construction vectors match the reference")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
