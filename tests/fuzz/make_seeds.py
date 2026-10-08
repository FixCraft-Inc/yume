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


def write_circuit1_seeds(out: pathlib.Path) -> None:
    """Cells, relay messages, handshakes and BEGIN payloads from the vectors."""
    out.mkdir(parents=True, exist_ok=True)
    root = pathlib.Path(__file__).resolve().parents[2]
    text = (root / "src/circuit/testdata/circuit1_vectors.txt").read_text()
    for line in text.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        name, value = line.split("=", 1)
        wanted = (name.endswith((".cell", ".message"))
                  or name in ("handshake.client", "handshake.hop")
                  or (name.startswith("relay.begin_") and name.endswith(".payload")))
        if not wanted:
            continue
        encoded = bytes.fromhex(value)
        (out / name).write_bytes(encoded)
        (out / f"{name}_truncated").write_bytes(encoded[:-1])
        (out / f"{name}_trailing").write_bytes(encoded + b"\0")


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


def write_h2_admission_seeds(out: pathlib.Path) -> None:
    """Paths, :authority and server names, then two bytes of listener port."""
    out.mkdir(parents=True, exist_ok=True)
    token = bytes(range(32)).hex()
    nonce = bytes(range(32, 64)).hex()
    port = (443).to_bytes(2, "big")
    cases = {
        "valid": f"/{token}/{nonce}\nexample.com\nexample.com",
        "valid_port": f"/{token}/{nonce}\nexample.com:443\nexample.com",
        "uppercase": f"/{token.upper()}/{nonce}\nexample.com\nexample.com",
        "short": f"/{token}/\nexample.com\nexample.com",
        "authority_mismatch": f"/{token}/{nonce}\nother.example\nexample.com",
        "ipv6_authority": f"/{token}/{nonce}\n[2001:db8::1]:443\n2001:db8::1",
    }
    for name, text in cases.items():
        (out / name).write_bytes(text.encode() + port)


def write_cover_site_seeds(out: pathlib.Path) -> None:
    """A method, a newline and a request target."""
    out.mkdir(parents=True, exist_ok=True)
    cases = {
        "index": "GET\n/", "head": "HEAD\n/style.css", "nested": "GET\n/notes/",
        "query": "GET\n/style.css?v=1", "encoded": "GET\n/st%79le.css",
        "dot_segment": "GET\n/notes/../style.css", "encoded_slash": "GET\n/notes%2Findex.html",
        "post": "POST\n/", "absolute": "GET\nhttp://example.com/",
    }
    for name, text in cases.items():
        (out / name).write_bytes(text.encode())


def websocket_frame(opcode: int, payload: bytes, final: bool = True, masked: bool = True) -> bytes:
    """One RFC 6455 frame, masked with a fixed key as a client sends it."""
    head = bytes([(0x80 if final else 0) | opcode])
    size = len(payload)
    mask_bit = 0x80 if masked else 0
    if size < 126:
        head += bytes([mask_bit | size])
    elif size < 1 << 16:
        head += bytes([mask_bit | 126]) + size.to_bytes(2, "big")
    else:
        head += bytes([mask_bit | 127]) + size.to_bytes(8, "big")
    if not masked:
        return head + payload
    key = b"\x37\xfa\x21\x3d"
    return head + key + bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))


def write_websocket_seeds(out: pathlib.Path) -> None:
    """Role byte, limit byte, then chunks each behind one length byte."""
    out.mkdir(parents=True, exist_ok=True)

    def chunks(stream: bytes, size: int) -> bytes:
        pieces = [stream[index:index + size] for index in range(0, len(stream), size)]
        return b"".join(bytes([len(piece) - 1]) + piece for piece in pieces)

    server = b"\x01\x10"
    client = b"\x00\x10"
    binary = websocket_frame(0x2, b"ytp record")
    cases = {
        "binary": server + chunks(binary, 200),
        "binary_split": server + chunks(binary, 3),
        "fragments": server + chunks(websocket_frame(0x2, b"first", final=False)
                                     + websocket_frame(0x9, b"ping")
                                     + websocket_frame(0x0, b"second"), 200),
        "close": server + chunks(websocket_frame(0x8, b"\x03\xe8bye"), 200),
        "unmasked_to_server": server + chunks(websocket_frame(0x2, b"x", masked=False), 200),
        "to_client": client + chunks(websocket_frame(0x2, b"from server", masked=False), 200),
        "long_length": server + chunks(websocket_frame(0x2, bytes(300)), 200),
        "text": server + chunks(websocket_frame(0x1, b"text"), 200),
    }
    for name, value in cases.items():
        (out / name).write_bytes(value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out_dir", type=pathlib.Path,
                        help="directory to write per-harness seed directories into")
    args = parser.parse_args()

    write_ytp1_seeds(args.out_dir / "seeds_ytp1_protocol", args.out_dir / "seeds_ytp1_auth")
    write_config_v1_seeds(args.out_dir / "seeds_config_v1")
    write_circuit1_seeds(args.out_dir / "seeds_circuit1")
    write_h2_admission_seeds(args.out_dir / "seeds_h2_admission")
    write_cover_site_seeds(args.out_dir / "seeds_cover_site")
    write_websocket_seeds(args.out_dir / "seeds_websocket")

    counts = {name: len(list((args.out_dir / name).iterdir())) for name in
              ("seeds_ytp1_protocol", "seeds_ytp1_auth", "seeds_config_v1",
               "seeds_circuit1", "seeds_h2_admission", "seeds_cover_site",
               "seeds_websocket")}
    for name, count in counts.items():
        print(f"{name}: {count} seeds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
