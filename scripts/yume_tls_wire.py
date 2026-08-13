#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Unprivileged TLS first-flight capture, normalization, and comparison.

The relay uses ordinary loopback TCP sockets and needs no packet-capture
capabilities. It records complete TLS handshake records in each direction,
forwards all bytes unchanged, and writes a sanitized structural report.
"""

from __future__ import annotations

import argparse
import dataclasses
import errno
import hashlib
import json
import os
import pathlib
import selectors
import socket
import sys
import time
from collections import Counter
from typing import Any, Iterable


MAX_CAPTURE_BYTES = 128 * 1024
MAX_RECORD_BYTES = (1 << 14) + 2048
MAX_HANDSHAKE_BYTES = 64 * 1024
IO_CHUNK_BYTES = 64 * 1024


EXTENSION_NAMES = {
    0: "server_name",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    16: "alpn",
    18: "signed_certificate_timestamp",
    21: "padding",
    23: "extended_master_secret",
    27: "compress_certificate",
    35: "session_ticket",
    41: "pre_shared_key",
    43: "supported_versions",
    45: "psk_key_exchange_modes",
    51: "key_share",
    17513: "application_settings_draft",
    17613: "application_settings",
    65037: "encrypted_client_hello",
    65281: "renegotiation_info",
}


def is_grease(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def code(value: int) -> str:
    return "GREASE" if is_grease(value) else f"0x{value:04x}"


class ParseError(ValueError):
    pass


@dataclasses.dataclass
class Cursor:
    data: bytes
    offset: int = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.offset > len(self.data) or size > len(self.data) - self.offset:
            raise ParseError("truncated TLS structure")
        value = self.data[self.offset:self.offset + size]
        self.offset += size
        return value

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def vector8(self) -> bytes:
        return self.take(self.u8())

    def vector16(self) -> bytes:
        return self.take(self.u16())

    def done(self) -> None:
        if self.offset != len(self.data):
            raise ParseError(f"trailing TLS bytes: {len(self.data) - self.offset}")


def split_u16(data: bytes) -> list[int]:
    if len(data) % 2:
        raise ParseError("odd u16 vector length")
    return [int.from_bytes(data[index:index + 2], "big")
            for index in range(0, len(data), 2)]


def tls_records(data: bytes) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    offset = 0
    while len(data) - offset >= 5:
        content_type = data[offset]
        legacy_version = int.from_bytes(data[offset + 1:offset + 3], "big")
        length = int.from_bytes(data[offset + 3:offset + 5], "big")
        if length > MAX_RECORD_BYTES:
            raise ParseError(f"TLS record length exceeds cap: {length}")
        if len(data) - offset - 5 < length:
            break
        payload = data[offset + 5:offset + 5 + length]
        records.append({
            "content_type": content_type,
            "legacy_version": f"0x{legacy_version:04x}",
            "length": length,
            "payload": payload,
        })
        offset += 5 + length
    return records


def first_handshake(records: Iterable[dict[str, Any]],
                    kind: int) -> tuple[bytes, list[dict[str, Any]]]:
    stream = bytearray()
    used: list[dict[str, Any]] = []
    for record in records:
        if record["content_type"] != 22:
            if stream:
                break
            continue
        used.append(record)
        stream.extend(record["payload"])
        if len(stream) < 4:
            continue
        message_kind = stream[0]
        length = int.from_bytes(stream[1:4], "big")
        if length > MAX_HANDSHAKE_BYTES:
            raise ParseError(f"TLS handshake length exceeds cap: {length}")
        if len(stream) < 4 + length:
            continue
        if message_kind != kind:
            raise ParseError(
                f"first TLS handshake message is {message_kind}, expected {kind}"
            )
        return bytes(stream[4:4 + length]), used
    raise ParseError(f"TLS handshake message {kind} not found")


def parse_protocol_vector(data: bytes) -> list[str]:
    cursor = Cursor(data)
    values: list[str] = []
    while cursor.offset < len(data):
        value = cursor.vector8()
        values.append(value.decode("ascii", errors="strict"))
    return values


def parse_server_names(data: bytes) -> list[dict[str, Any]]:
    cursor = Cursor(data)
    names = Cursor(cursor.vector16())
    cursor.done()
    values: list[dict[str, Any]] = []
    while names.offset < len(names.data):
        name_type = names.u8()
        name = names.vector16()
        values.append({
            "type": name_type,
            "value": "<server-name>" if name_type == 0 else name.hex(),
            "length": len(name),
        })
    return values


def parse_key_shares(data: bytes, client: bool) -> list[dict[str, Any]]:
    cursor = Cursor(data)
    shares = Cursor(cursor.vector16()) if client else cursor
    if client:
        cursor.done()
    values: list[dict[str, Any]] = []
    while shares.offset < len(shares.data):
        group = shares.u16()
        key_exchange = shares.vector16()
        values.append({
            "group": code(group),
            "key_exchange_length": len(key_exchange),
            "key_exchange": "<entropy>",
        })
    return values


def normalize_extension(extension_type: int, payload: bytes,
                        *, client: bool) -> dict[str, Any]:
    normalized: dict[str, Any] = {
        "type": code(extension_type),
        "name": "grease" if is_grease(extension_type)
        else EXTENSION_NAMES.get(extension_type, "unknown"),
        "length": len(payload),
    }
    if is_grease(extension_type):
        normalized["data"] = "<grease>"
    elif extension_type == 0:
        normalized["server_names"] = parse_server_names(payload)
    elif extension_type in (10, 13):
        values = split_u16(Cursor(payload).vector16())
        normalized["values"] = [code(value) for value in values]
    elif extension_type == 11:
        normalized["values"] = list(Cursor(payload).vector8())
    elif extension_type in (16, 17513, 17613):
        normalized["protocols"] = parse_protocol_vector(Cursor(payload).vector16())
    elif extension_type == 21:
        normalized["padding_bytes"] = len(payload)
    elif extension_type == 27:
        algorithms = Cursor(payload).vector8()
        normalized["algorithms"] = [code(value) for value in split_u16(algorithms)]
    elif extension_type == 43:
        values = split_u16(Cursor(payload).vector8()) if client else [Cursor(payload).u16()]
        normalized["versions"] = [code(value) for value in values]
    elif extension_type == 45:
        normalized["modes"] = list(Cursor(payload).vector8())
    elif extension_type == 51:
        normalized["shares"] = parse_key_shares(payload, client)
    elif extension_type == 65037:
        # Chrome sends GREASE ECH bytes whose contents are intentionally
        # ephemeral. Type, position, and geometry remain classifier-visible.
        normalized["data"] = "<grease-ech>"
    elif extension_type in (5, 18, 23, 35, 65281):
        normalized["data_sha256"] = hashlib.sha256(payload).hexdigest()
    else:
        normalized["data_sha256"] = hashlib.sha256(payload).hexdigest()
    return normalized


def parse_extensions(data: bytes, *, client: bool) -> list[dict[str, Any]]:
    cursor = Cursor(data)
    extensions: list[dict[str, Any]] = []
    while cursor.offset < len(data):
        extension_type = cursor.u16()
        payload = cursor.vector16()
        extensions.append(normalize_extension(extension_type, payload, client=client))
    return extensions


def normalize_client_hello(data: bytes) -> dict[str, Any]:
    records = tls_records(data)
    handshake, first_records = first_handshake(records, 1)
    body = Cursor(handshake)
    legacy_version = body.u16()
    body.take(32)  # random
    session_id = body.vector8()
    cipher_suites = split_u16(body.vector16())
    compression_methods = list(body.vector8())
    extensions = parse_extensions(body.vector16(), client=True)
    body.done()
    return {
        "kind": "client_hello",
        "legacy_version": f"0x{legacy_version:04x}",
        "random": "<entropy>",
        "session_id_length": len(session_id),
        "session_id": "<entropy>" if session_id else "",
        "cipher_suites": [code(value) for value in cipher_suites],
        "compression_methods": compression_methods,
        "extensions": extensions,
        "tls_records": [
            {key: record[key] for key in ("content_type", "legacy_version", "length")}
            for record in first_records
        ],
    }


def normalize_server_hello(data: bytes) -> dict[str, Any]:
    records = tls_records(data)
    handshake, first_records = first_handshake(records, 2)
    body = Cursor(handshake)
    legacy_version = body.u16()
    body.take(32)  # random
    session_id = body.vector8()
    cipher_suite = body.u16()
    compression_method = body.u8()
    extensions = parse_extensions(body.vector16(), client=False)
    body.done()
    return {
        "kind": "server_hello",
        "legacy_version": f"0x{legacy_version:04x}",
        "random": "<entropy>",
        "session_id_length": len(session_id),
        "session_id": "<entropy>" if session_id else "",
        "cipher_suite": code(cipher_suite),
        "compression_method": compression_method,
        "extensions": extensions,
        "tls_records": [
            {key: record[key] for key in ("content_type", "legacy_version", "length")}
            for record in first_records
        ],
    }


def write_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=False)
        stream.write("\n")
    temporary.replace(path)


def parse_endpoint(value: str) -> tuple[str, int]:
    host, separator, port_text = value.rpartition(":")
    if not separator or not host:
        raise argparse.ArgumentTypeError("endpoint must be HOST:PORT")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("endpoint port must be an integer") from exc
    if port < 1 or port > 65535:
        raise argparse.ArgumentTypeError("endpoint port must be in 1..65535")
    return host, port


def relay_once(listen: tuple[str, int], target: tuple[str, int],
               output: pathlib.Path, timeout: float,
               ready_file: pathlib.Path | None) -> None:
    captures = {"client_to_server": bytearray(), "server_to_client": bytearray()}
    with socket.create_server(listen, family=socket.AF_INET, backlog=1) as listener:
        listener.settimeout(timeout)
        if ready_file is not None:
            write_json(ready_file, {"listen": f"{listen[0]}:{listen[1]}"})
        client, _ = listener.accept()
        with client, socket.create_connection(target, timeout=timeout) as server:
            client.setblocking(False)
            server.setblocking(False)
            selector = selectors.DefaultSelector()
            selector.register(client, selectors.EVENT_READ, (server, "client_to_server"))
            selector.register(server, selectors.EVENT_READ, (client, "server_to_client"))
            deadline = time.monotonic() + timeout
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("TLS relay timed out")
                events = selector.select(min(remaining, 1.0))
                for key, _ in events:
                    source: socket.socket = key.fileobj
                    destination, direction = key.data
                    try:
                        chunk = source.recv(IO_CHUNK_BYTES)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(source)
                        try:
                            destination.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    deadline = time.monotonic() + timeout
                    if len(captures[direction]) < MAX_CAPTURE_BYTES:
                        available = MAX_CAPTURE_BYTES - len(captures[direction])
                        captures[direction].extend(chunk[:available])
                    destination.setblocking(True)
                    try:
                        try:
                            destination.sendall(chunk)
                        except OSError as exc:
                            if exc.errno not in (errno.EPIPE, errno.ECONNRESET):
                                raise
                            # The parent may close its helper IPC side before
                            # the TLS peer's final alert arrives. The complete
                            # first flights are already captured; treat this
                            # late half-close as end-of-direction rather than
                            # discarding the structural report.
                            try:
                                selector.unregister(source)
                            except KeyError:
                                pass
                    finally:
                        destination.setblocking(False)

    client_bytes = bytes(captures["client_to_server"])
    server_bytes = bytes(captures["server_to_client"])
    report = {
        "schema": 1,
        "normalization": [
            "ClientHello and ServerHello random bytes",
            "session identifier bytes but not length",
            "GREASE values but not position or geometry",
            "key-exchange bytes but not group or length",
            "GREASE ECH bytes but not type, position, or length",
            "server name value but not type or length",
        ],
        "client_hello": normalize_client_hello(client_bytes),
        "server_hello": normalize_server_hello(server_bytes),
        "captured_byte_counts": {
            "client_to_server": len(client_bytes),
            "server_to_client": len(server_bytes),
        },
    }
    write_json(output, report)


def comparable(value: dict[str, Any], ignore_record_lengths: bool) -> dict[str, Any]:
    result = json.loads(json.dumps(value))
    if ignore_record_lengths:
        result.pop("tls_records", None)
    return result


def extension_by_type(hello: dict[str, Any], extension_type: str) -> dict[str, Any]:
    matches = [item for item in hello["extensions"] if item["type"] == extension_type]
    if len(matches) != 1:
        raise ParseError(
            f"expected one {extension_type} extension, found {len(matches)}"
        )
    return matches[0]


def expect_equal(actual: Any, expected: Any, field: str) -> None:
    if actual != expected:
        raise ParseError(f"{field}: expected {expected!r}, got {actual!r}")


def expect_extension_geometry(hello: dict[str, Any],
                              profile: dict[str, Any]) -> int:
    extensions = hello["extensions"]
    if len(extensions) < 2:
        raise ParseError("ClientHello has fewer than two extensions")

    first = extensions[0]
    last = extensions[-1]
    expect_equal(first["type"], "GREASE", "first extension type")
    expect_equal(first["length"], profile["first_grease_length"],
                 "first GREASE extension length")
    expect_equal(last["type"], "GREASE", "last extension type")
    expect_equal(last["length"], profile["last_grease_length"],
                 "last GREASE extension length")

    middle = extensions[1:-1]
    expected_types = profile["middle_extension_types"]
    actual_types = [item["type"] for item in middle]
    if Counter(actual_types) != Counter(expected_types):
        raise ParseError(
            "middle extension multiset differs: "
            f"expected {expected_types!r}, got {actual_types!r}"
        )

    exact_lengths = profile["exact_extension_lengths"]
    for item in middle:
        if item["type"] in exact_lengths:
            expect_equal(item["length"], exact_lengths[item["type"]],
                         f"{item['type']} extension length")

    ech = extension_by_type(hello, profile["ech_extension_type"])
    allowed_ech_lengths = profile["allowed_ech_lengths"]
    if ech["length"] not in allowed_ech_lengths:
        raise ParseError(
            f"ECH extension length {ech['length']} is not in "
            f"{allowed_ech_lengths!r}"
        )
    return ech["length"]


def validate_client_hello(
        hello: dict[str, Any],
        profile: dict[str, Any]) -> tuple[tuple[str, ...], int]:
    for field in ("kind", "legacy_version", "session_id_length",
                  "cipher_suites", "compression_methods"):
        expect_equal(hello[field], profile[field], f"ClientHello {field}")

    ech_length = expect_extension_geometry(hello, profile)
    records = hello["tls_records"]
    expect_equal(len(records), 1, "ClientHello first-flight record count")
    expect_equal(records[0]["content_type"], 22,
                 "ClientHello TLS record content type")
    expect_equal(records[0]["legacy_version"], profile["record_legacy_version"],
                 "ClientHello TLS record legacy version")
    expect_equal(records[0]["length"], profile["record_length_base"] + ech_length,
                 "ClientHello TLS record length")

    structured = profile["structured_extensions"]
    for extension_type, expected in structured.items():
        actual = extension_by_type(hello, extension_type)
        for field, expected_value in expected.items():
            expect_equal(actual.get(field), expected_value,
                         f"ClientHello extension {extension_type} {field}")
    middle_order = tuple(item["type"] for item in hello["extensions"][1:-1])
    return middle_order, ech_length


def validate_server_hello(hello: dict[str, Any], profile: dict[str, Any]) -> None:
    for field in ("kind", "legacy_version", "session_id_length", "cipher_suite",
                  "compression_method", "extensions", "tls_records"):
        expect_equal(hello[field], profile[field], f"ServerHello {field}")


def validate_profile(profile_path: pathlib.Path,
                     candidate_paths: list[pathlib.Path]) -> int:
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    expect_equal(profile.get("schema"), 1, "TLS wire profile schema")
    expected_runs = profile["qualification"]["required_runs"]
    if len(candidate_paths) != expected_runs:
        raise ParseError(
            f"profile requires {expected_runs} candidate runs, got {len(candidate_paths)}"
        )

    middle_orders: set[tuple[str, ...]] = set()
    ech_lengths: set[int] = set()
    for candidate_path in candidate_paths:
        report = json.loads(candidate_path.read_text(encoding="utf-8"))
        order, ech_length = validate_client_hello(
            report["client_hello"], profile["client_hello"]
        )
        validate_server_hello(report["server_hello"], profile["server_hello"])
        middle_orders.add(order)
        ech_lengths.add(ech_length)

    minimum_orders = profile["qualification"]["minimum_distinct_middle_orders"]
    if len(middle_orders) < minimum_orders:
        raise ParseError(
            f"stable extension-order marker: expected at least {minimum_orders} "
            f"middle orders, got {len(middle_orders)}"
        )
    minimum_ech_lengths = profile["qualification"]["minimum_distinct_ech_lengths"]
    if len(ech_lengths) < minimum_ech_lengths:
        raise ParseError(
            f"stable ECH geometry marker: expected at least {minimum_ech_lengths} "
            f"lengths, got {len(ech_lengths)}"
        )
    print(
        f"PARITY chrome151_tls_first_flights runs={len(candidate_paths)} "
        f"middle_orders={len(middle_orders)} ech_lengths={sorted(ech_lengths)}"
    )
    return 0


def compare_reports(reference: pathlib.Path, candidate: pathlib.Path,
                    side: str, ignore_record_lengths: bool) -> int:
    left = json.loads(reference.read_text(encoding="utf-8"))[side]
    right = json.loads(candidate.read_text(encoding="utf-8"))[side]
    if comparable(left, ignore_record_lengths) == comparable(right, ignore_record_lengths):
        print(f"PARITY {side} reference={reference} candidate={candidate}")
        return 0
    print(f"DRIFT {side} reference={reference} candidate={candidate}", file=sys.stderr)
    left_extensions = [(item["type"], item["length"]) for item in left["extensions"]]
    right_extensions = [(item["type"], item["length"]) for item in right["extensions"]]
    print(f"reference_extensions={left_extensions}", file=sys.stderr)
    print(f"candidate_extensions={right_extensions}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    relay = subparsers.add_parser("relay")
    relay.add_argument("--listen", required=True, type=parse_endpoint)
    relay.add_argument("--target", required=True, type=parse_endpoint)
    relay.add_argument("--output", required=True, type=pathlib.Path)
    relay.add_argument("--ready-file", type=pathlib.Path)
    relay.add_argument("--timeout", type=float, default=120.0)

    normalize = subparsers.add_parser("normalize")
    normalize.add_argument("--client", type=pathlib.Path)
    normalize.add_argument("--server", type=pathlib.Path)
    normalize.add_argument("--output", required=True, type=pathlib.Path)

    compare = subparsers.add_parser("compare")
    compare.add_argument("--reference", required=True, type=pathlib.Path)
    compare.add_argument("--candidate", required=True, type=pathlib.Path)
    compare.add_argument("--side", choices=("client_hello", "server_hello"),
                         required=True)
    compare.add_argument("--ignore-record-lengths", action="store_true")

    profile = subparsers.add_parser("check-profile")
    profile.add_argument("--profile", required=True, type=pathlib.Path)
    profile.add_argument("--candidate", required=True, action="append",
                         type=pathlib.Path)

    args = parser.parse_args()
    try:
        if args.command == "relay":
            relay_once(args.listen, args.target, args.output, args.timeout,
                       args.ready_file)
            return 0
        if args.command == "normalize":
            report: dict[str, Any] = {"schema": 1}
            if args.client:
                report["client_hello"] = normalize_client_hello(args.client.read_bytes())
            if args.server:
                report["server_hello"] = normalize_server_hello(args.server.read_bytes())
            if len(report) == 1:
                raise ValueError("normalize requires --client or --server")
            write_json(args.output, report)
            return 0
        if args.command == "compare":
            return compare_reports(args.reference, args.candidate, args.side,
                                   args.ignore_record_lengths)
        return validate_profile(args.profile, args.candidate)
    except (OSError, ParseError, TimeoutError, ValueError,
            json.JSONDecodeError) as exc:
        print(f"DRIFT {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
