#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Observe one real YTP/1 session with nDPI inside a rootless network namespace.

The script re-executes itself under `unshare -rn`, where root in the user
namespace can bring up loopback, bind port 443 and capture packets without
host privileges. Two ndpiReader captures run at once: the default one and a
DPI-only one (`-d`) without guessing by port. Raw CSV, logs and a summary are
written to a new output directory.

This is a smoke observation of one loopback session. It is not a classifier
result and supports no claim that YUME is undetectable.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yume_native_session as session  # noqa: E402

INSIDE = "YUME_NDPI_SMOKE_INSIDE"
DOES_NOT_PROVE = [
    "That DPI, JA3/JA4 or machine-learning classifiers cannot identify YUME.",
    "Anything about real networks, other vantage points, timing or volume.",
    "Anything about other nDPI versions, settings or protocol lists.",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def flows_on_port(csv_path: Path, port: int) -> list[dict[str, str]]:
    if not csv_path.is_file():
        return []
    with csv_path.open(newline="", encoding="utf-8", errors="replace") as stream:
        text = stream.read().lstrip("#")
    rows = []
    for row in csv.DictReader(text.splitlines()):
        ports = {row.get(key, "").strip() for key in ("src_port", "dst_port")}
        if str(port) in ports:
            rows.append({key.strip(): (value or "").strip() for key, value in row.items() if key})
    return rows


def run_inside(arguments: argparse.Namespace) -> int:
    output = arguments.output
    output.mkdir(parents=True, exist_ok=False)
    ip = shutil.which("ip") or "/sbin/ip"
    subprocess.run([ip, "link", "set", "lo", "up"], check=True, timeout=10)
    environment = session.openssl_environment(arguments.openssl)
    kit = output / "kit"
    session.provision_kit(kit, arguments.server_name, arguments.port, environment)
    socks_port = session.free_port()
    target_port = session.free_port()
    session.configure_kit(kit, listen_address="127.0.0.1", networks=["127.0.0.1/32"],
                          connect_address="127.0.0.1", socks_port=socks_port)

    captures = {}
    for name, extra in (("default", []), ("dpi-only", ["-d"])):
        captures[name] = subprocess.Popen(
            [str(arguments.ndpi_reader), "-i", "lo", "-s", str(arguments.duration),
             "-f", f"tcp port {arguments.port}", "-C", str(output / f"ndpi-{name}.csv"), *extra],
            stdout=(output / f"ndpi-{name}.txt").open("wb"), stderr=subprocess.STDOUT)
    time.sleep(2.0)

    target = session.serve_payload("127.0.0.1", target_port, arguments.payload_bytes)
    logs = {name: (output / f"{name}.log").open("wb") for name in ("yumed", "yume")}
    server = subprocess.Popen([str(arguments.yumed), "--config", str(kit / "server/yumed.json")],
                              env=environment, stdout=logs["yumed"], stderr=subprocess.STDOUT)
    client = None
    transfers = []
    try:
        deadline = time.monotonic() + 30
        session.wait_for_port("127.0.0.1", arguments.port, server, deadline)
        client = subprocess.Popen([str(arguments.yume), "--config", str(kit / "client/yume.json")],
                                  env=environment, stdout=logs["yume"], stderr=subprocess.STDOUT)
        session.wait_for_port("127.0.0.1", socks_port, client, deadline)
        expected = session.payload_digest(arguments.payload_bytes)
        for _ in range(arguments.requests):
            length, digest, seconds = session.get_through_socks(
                socks_port, "127.0.0.1", target_port, time.monotonic() + 30)
            if length != arguments.payload_bytes or digest != expected:
                raise session.SessionFailure("tunnelled payload differs from the served payload")
            transfers.append({"bytes": length, "seconds": round(seconds, 4)})
        session.stop_process(client, "yume-ytp1")
        client = None
        session.stop_process(server, "yumed-ytp1")
    finally:
        for process in (client, server):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        target.shutdown()
        for handle in logs.values():
            handle.close()

    for name, capture in captures.items():
        capture.wait(timeout=arguments.duration + 30)
    for name in ("yumed", "yume"):
        session.reject_secret_output(name, (output / f"{name}.log").read_text(errors="replace"))
    shutil.rmtree(kit)

    summary = {
        "schema": "yume.ndpi-smoke/1",
        "ndpi_reader": {"path": str(arguments.ndpi_reader), "sha256": sha256_file(arguments.ndpi_reader)},
        "binaries": {name: sha256_file(path) for name, path in
                     (("yumed-ytp1", arguments.yumed), ("yume-ytp1", arguments.yume))},
        "server_name": arguments.server_name,
        "server_port": arguments.port,
        "transfers": transfers,
        "flows": {name: flows_on_port(output / f"ndpi-{name}.csv", arguments.port) for name in captures},
        "does_not_prove": DOES_NOT_PROVE,
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    for name, rows in summary["flows"].items():
        for row in rows:
            keys = [key for key in row if any(part in key.lower() for part in
                    ("proto", "sni", "server_name", "ja4", "risk", "category", "confidence"))]
            print(name + ": " + ", ".join(f"{key}={row[key]}" for key in keys))
    if not any(summary["flows"].values()):
        print("no flow on the server port was recorded", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--yumed", type=Path, required=True)
    parser.add_argument("--yume", type=Path, required=True)
    parser.add_argument("--ndpi-reader", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new directory for results")
    parser.add_argument("--server-name", default="cdn.example.test")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--requests", type=int, default=3)
    parser.add_argument("--payload-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--duration", type=int, default=25, help="capture seconds")
    arguments = parser.parse_args()
    for name in ("yumed", "yume", "ndpi_reader", "openssl"):
        setattr(arguments, name, getattr(arguments, name).resolve(strict=True))
    arguments.output = arguments.output.resolve()
    if not 1 <= arguments.requests <= 100 or not 1 <= arguments.payload_bytes <= 1 << 30:
        parser.error("requests must be 1..100 and payload bytes 1..1 GiB")
    if os.environ.get(INSIDE) != "1":
        unshare = shutil.which("unshare")
        if not unshare:
            parser.error("unshare is required")
        environment = dict(os.environ, **{INSIDE: "1"})
        return subprocess.run([unshare, "-rn", sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:]], env=environment, check=False).returncode
    try:
        return run_inside(arguments)
    except (session.SessionFailure, OSError, subprocess.SubprocessError) as error:
        print(f"nDPI smoke: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
