#!/usr/bin/env python3
"""Write the seed corpora for the YUME fuzz harnesses.

Seeds are generated rather than checked in so each one is readable as code:
a reviewer can see what shape it encodes without opening a hex editor. The
hostile HPACK encodings here are the same ones the obfs_test regressions pin,
so a fuzz run always starts from the inputs that once broke the decoder.
"""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import sys

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def h2_frame(length: int, kind: int, flags: int, stream_id: int,
             payload: bytes = b"") -> bytes:
    return bytes([
        (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF,
        kind, flags,
        (stream_id >> 24) & 0x7F, (stream_id >> 16) & 0xFF,
        (stream_id >> 8) & 0xFF, stream_id & 0xFF,
    ]) + payload


def wrapping_varint(opcode: int, mask: int, target: int) -> bytes:
    """An HPACK integer that reaches `target` only by wrapping past 2**64.

    Digits 0..8 carry bits 0..62 and the tenth carries bit 63, so the encoding
    always terminates on the tenth continuation byte, the last position the
    decoder's shift guard admits.
    """
    out = bytes([opcode | mask])
    x = (target - mask) % (1 << 64)
    out += bytes([((x >> (7 * i)) & 0x7F) | 0x80 for i in range(9)])
    return out + bytes([(x >> 63) & 0x7F])


def headers_wire(block: bytes) -> bytes:
    """Preface, empty SETTINGS, then HEADERS on stream 1 carrying `block`.

    This is what an unauthenticated peer can present to the carrier probe
    before any admission check runs.
    """
    return (H2_PREFACE
            + h2_frame(0, 0x04, 0, 0)
            + h2_frame(len(block), 0x01, 0x05, 1, block))


def write_h2_seeds(out: pathlib.Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    blocks = {
        # A plausible request: indexed :method/:scheme/:path plus a literal
        # :authority.
        "indexed": b"\x82\x86\x84\x41\x0bexample.com",
        # Declared string length of 2**64 - 11, which makes an unchecked
        # `prefix_consumed + str_len` bound wrap to zero and pass.
        "wrap_strlen": b"\x40" + wrapping_varint(0x00, 0x7F, (1 << 64) - 11),
        # Accumulates to static index 2 (":method: GET") only by wrapping.
        "wrap_index": wrapping_varint(0x80, 0x7F, 2),
        # One-byte indexed fields expand ~30x into retained pairs.
        "expansion": b"\x82" * 512,
        "literal": b"\x40\x04path\x05/a/b/",
        # Huffman-coded literal, which the decoder refuses outright.
        "huffman": b"\x40\x85\x00\x00\x00\x00\x00",
    }
    for name, block in blocks.items():
        (out / f"h2_{name}").write_bytes(headers_wire(block))

    (out / "h2_preface_only").write_bytes(H2_PREFACE)
    (out / "h2_settings_payload").write_bytes(
        H2_PREFACE + h2_frame(6, 0x04, 0, 0, b"\x00\x05\xff\xff\xff\xff"))
    (out / "h2_data").write_bytes(
        H2_PREFACE + h2_frame(0, 0x04, 0, 0) + h2_frame(4, 0x00, 1, 1, b"body"))
    (out / "h2_window_update").write_bytes(
        H2_PREFACE + h2_frame(0, 0x04, 0, 0)
        + h2_frame(4, 0x08, 0, 1, b"\x00\x00\x00\x01"))
    (out / "h2_empty").write_bytes(b"")
    return len(list(out.iterdir()))


def write_config_seeds(out: pathlib.Path, role: str) -> int:
    out.mkdir(parents=True, exist_ok=True)
    shared = {
        "empty_object": {},
        "empty_array": [],
        "null": None,
        "unknown_key": {"definitely_not_a_key": 1},
    }
    for name, value in shared.items():
        (out / name).write_text(json.dumps(value))

    if role == "client":
        (out / "minimal").write_text(json.dumps({
            "host": "server.example", "port": 8443, "tls_pin": "00" * 32}))
        (out / "typed_wrong").write_text(json.dumps({
            "host": 1, "port": "eight", "threads": -1}))
    else:
        (out / "minimal").write_text(json.dumps({
            "listen": "0.0.0.0:8443", "threads": 4}))
        (out / "typed_wrong").write_text(json.dumps({
            "listen": [], "threads": 1 << 40}))

    # Real documents shipped with the tree exercise the accepting paths.
    root = pathlib.Path(__file__).resolve().parents[2]
    copied = 0
    for candidate in sorted(root.glob("docs/**/*.json")) + \
            sorted(root.glob("config/*.json")):
        if candidate.stat().st_size > 32 * 1024:
            continue
        (out / f"tree_{candidate.name}").write_bytes(candidate.read_bytes())
        copied += 1
        if copied >= 24:
            break
    return len(list(out.iterdir()))


def write_ytp1_seeds(protocol_out: pathlib.Path, auth_out: pathlib.Path) -> None:
    """Reuse canonical public encoding vectors, including AUTH suite bytes."""
    protocol_out.mkdir(parents=True, exist_ok=True)
    auth_out.mkdir(parents=True, exist_ok=True)
    root = pathlib.Path(__file__).resolve().parents[2]
    vectors: dict[str, bytes] = {}
    for line in (root / "src/ytp/testdata/ytp1_vectors.txt").read_text().splitlines():
        if "=" not in line:
            continue
        name, encoded = (piece.strip() for piece in line.split("=", 1))
        if name.startswith(("frame_", "open_", "capabilities_", "auth_")):
            vectors[name] = bytes.fromhex(encoded)
    for name, encoded in vectors.items():
        target = auth_out if name.startswith("auth_") else protocol_out
        (target / name).write_bytes(encoded)
        (target / f"{name}_truncated").write_bytes(encoded[:-1])
        (target / f"{name}_trailing").write_bytes(encoded + b"\0")
        if name.startswith("open_"):
            header = b"\x01\x04\0\0\0\0\0\x01" + len(encoded).to_bytes(4, "big")
            (protocol_out / f"record_{name}").write_bytes(header + encoded)
    (protocol_out / "data_record").write_bytes(
        vectors["frame_header_data_stream_1_payload_3"] + b"abc")
    for value in (0, 1, 1 << 30, (1 << 30) + 1, (1 << 32) - 1):
        (protocol_out / f"credit_{value}").write_bytes(value.to_bytes(4, "big"))
    mandatory = vectors["auth_accepted_client_mandatory_fields"]
    for message_type in range(1, 6):
        (auth_out / f"message_type_{message_type}").write_bytes(
            mandatory[:1] + bytes([message_type]) + mandatory[2:])
    # Synthetic opaque bytes exercise the TLV grammar and fixed widths only;
    # no signature, key establishment or identity verification is performed.
    fields = {
        4: bytes(32), 5: b"synthetic-identity", 6: bytes(64 + 4627),
        7: bytes(1568), 8: bytes(1568), 9: bytes(32),
        10: vectors["capabilities_echo_8_udp_4"],
        11: bytes(32), 12: bytes(32), 13: bytes(32),
    }
    body = mandatory[8:]
    for field_id, value in fields.items():
        body += (field_id.to_bytes(2, "big") + b"\0\x01"
                 + len(value).to_bytes(4, "big") + value)
    complete = b"\x01\x02\0\x0d" + len(body).to_bytes(4, "big") + body
    (auth_out / "all_known_fields").write_bytes(complete)
    for critical in (0, 1):
        optional = b"\x80\0" + critical.to_bytes(2, "big") + b"\0\0\0\x01x"
        extended = body + optional
        (auth_out / f"unknown_critical_{critical}").write_bytes(
            b"\x01\x02\0\x0e" + len(extended).to_bytes(4, "big") + extended)
    for name, value in {"empty": b"", "wrong_version": b"\xff"}.items():
        (protocol_out / name).write_bytes(value)
        (auth_out / name).write_bytes(value)


def write_config_v1_seeds(out: pathlib.Path) -> None:
    """Use shipped schema-1 documents without opening their file references."""
    out.mkdir(parents=True, exist_ok=True)
    root = pathlib.Path(__file__).resolve().parents[2]
    for role, filename in (("client", "yume.json"), ("server", "yumed.json")):
        source = root / "config/ytp1" / filename
        document = json.loads(source.read_text())
        (out / role).write_bytes(source.read_bytes())
        packet = copy.deepcopy(document)
        packet["services"] = [{"name": "packet", "kind": "packet",
                               "max_concurrent_streams": 1}]
        packet["adapters"] = [{
            "kind": "packet", "service": "packet", "interface_name": "ytpfuzz0", "mtu": 1280,
            "network": {
                "addresses": ["10.71.0.1/32"], "routes": ["10.71.0.2/32"],
                "local_networks": ["10.71.0.1/32"], "peer_networks": ["10.71.0.2/32"],
                "dns": {"servers": [], "domains": []},
            },
        }]
        if role == "client":
            packet["endpoint"]["connect_address"] = "192.0.2.10"
        (out / f"{role}_packet").write_text(json.dumps(packet))
    malformed = {
        "empty": b"", "object": b"{}", "array": b"[]", "null": b"null",
        "duplicate": b'{"schema":1,"schema":1}',
        "nested_duplicate": b'{"endpoint":{"host":"a","host":"b"}}',
        "nesting_limit": b"[" * 18 + b"0" + b"]" * 18,
        "number_overflow": b'{"schema":1e999}',
        "invalid_utf8": b'{"role":"\xff"}',
    }
    for name, value in malformed.items():
        (out / name).write_bytes(value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out_dir", type=pathlib.Path,
                        help="directory to write per-harness seed directories into")
    args = parser.parse_args()

    write_ytp1_seeds(args.out_dir / "seeds_ytp1_protocol", args.out_dir / "seeds_ytp1_auth")
    write_config_v1_seeds(args.out_dir / "seeds_config_v1")

    counts = {
        "seeds_h2": write_h2_seeds(args.out_dir / "seeds_h2"),
        "seeds_client": write_config_seeds(args.out_dir / "seeds_client", "client"),
        "seeds_server": write_config_seeds(args.out_dir / "seeds_server", "server"),
        **{name: len(list((args.out_dir / name).iterdir())) for name in
           ("seeds_ytp1_protocol", "seeds_ytp1_auth", "seeds_config_v1")},
    }
    for name, count in counts.items():
        print(f"{name}: {count} seeds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
