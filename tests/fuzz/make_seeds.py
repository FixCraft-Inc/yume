#!/usr/bin/env python3
"""Write the seed corpora for the YUME fuzz harnesses.

Seeds are generated rather than checked in so each one is readable as code:
a reviewer can see what shape it encodes without opening a hex editor. The
hostile HPACK encodings here are the same ones the obfs_test regressions pin,
so a fuzz run always starts from the inputs that once broke the decoder.
"""

from __future__ import annotations

import argparse
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out_dir", type=pathlib.Path,
                        help="directory to write seeds_h2/seeds_client/seeds_server into")
    args = parser.parse_args()

    counts = {
        "seeds_h2": write_h2_seeds(args.out_dir / "seeds_h2"),
        "seeds_client": write_config_seeds(args.out_dir / "seeds_client", "client"),
        "seeds_server": write_config_seeds(args.out_dir / "seeds_server", "server"),
    }
    for name, count in counts.items():
        print(f"{name}: {count} seeds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
