#!/usr/bin/env python3
"""Write the seed corpora for the YUME fuzz harnesses.

Seeds are generated rather than checked in so each one is readable as code:
a reviewer can see what shape it encodes without opening a hex editor.
"""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import sys

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
        source = root / "config" / filename
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

    counts = {name: len(list((args.out_dir / name).iterdir())) for name in
              ("seeds_ytp1_protocol", "seeds_ytp1_auth", "seeds_config_v1")}
    for name, count in counts.items():
        print(f"{name}: {count} seeds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
