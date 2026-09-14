#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Observe one real YTP/1 session with nDPI inside a rootless network namespace.

The script re-executes itself under `unshare -rn`, where root in the user
namespace can configure loopback, bind port 443 and capture packets without
host privileges. Loopback gets an Ethernet-sized MTU and one segment per packet,
so every frame fits the reader's 1536-byte snap length as it would on a real
link. Two ndpiReader captures run at once: the default one and a DPI-only one
(`-d`) without guessing by port. Raw CSV, reader output, logs and a summary are
written to a new output directory. The generated kit stays in a temporary
directory and never reaches the output.

This is a smoke observation of one loopback session. It is not a classifier
result and supports no claim that YUME is undetectable.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yume_native_session as session  # noqa: E402

INSIDE = "YUME_NDPI_SMOKE_INSIDE"
# ndpiReader opens live captures with this snap length and discards longer frames.
READER_SNAPLEN = 1536
DOES_NOT_PROVE = [
    "That DPI, JA3/JA4 or machine-learning classifiers cannot identify YUME.",
    "Anything about real networks, other vantage points, timing or volume.",
    "Anything about other nDPI versions, settings or protocol lists.",
]


def configure_loopback(mtu: int) -> dict[str, object]:
    """Ethernet-sized segments, one per packet, as a capture on a link sees them."""
    ip = shutil.which("ip") or "/sbin/ip"
    subprocess.run([ip, "link", "set", "lo", "mtu", str(mtu), "gso_max_segs", "1", "up"],
                   check=True, timeout=10)
    shown = subprocess.run([ip, "-json", "-details", "link", "show", "lo"],
                           capture_output=True, text=True, timeout=10, check=True)
    link = json.loads(shown.stdout)[0]
    return {key: link.get(key) for key in ("mtu", "gso_max_segs", "gso_max_size")}


def wait_for_log(path: Path, marker: str, process: subprocess.Popen, deadline: float) -> None:
    """Readiness from the daemon's own report, so no probe connection enters the capture."""
    while time.monotonic() < deadline:
        if marker in path.read_text(encoding="utf-8", errors="replace"):
            return
        if process.poll() is not None:
            raise session.SessionFailure(f"process exited with {process.returncode} before listening")
        time.sleep(0.1)
    raise session.SessionFailure(f"'{marker}' did not appear in {path.name}")


def flows_on_port(csv_path: Path, port: int) -> list[dict[str, str]]:
    if not csv_path.is_file():
        return []
    lines = csv_path.read_text(encoding="utf-8", errors="replace").lstrip("#").splitlines()
    if not lines:
        return []
    # nDPI 6.0 separates CSV fields with '|'.
    delimiter = "|" if "|" in lines[0] else ","
    rows = []
    for row in csv.DictReader(lines, delimiter=delimiter):
        if str(port) in {(row.get("src_port") or "").strip(), (row.get("dst_port") or "").strip()}:
            rows.append({key.strip(): (value or "").strip() for key, value in row.items() if key})
    return rows


def reader_report(path: Path, port: int) -> dict[str, object]:
    """Totals and per-flow lines from ndpiReader's text output, which carries JA4 and risks."""
    text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""

    def total(label: str) -> int | None:
        match = re.search(rf"^\s*{label}:\s+(\d+)", text, re.MULTILINE)
        return int(match.group(1)) if match else None

    flows = [line.strip() for line in text.splitlines()
             if re.match(r"^\s+\d+\s+(TCP|UDP)\s", line) and f":{port} " in line]
    return {"ip_bytes": total("IP bytes"), "discarded_bytes": total("Discarded bytes"), "flows": flows}


def observe(arguments: argparse.Namespace, kit: Path, environment: dict[str, str]) -> list[dict[str, object]]:
    output = arguments.output
    session.provision_kit(kit, arguments.server_name, arguments.port, environment)
    socks_port = session.free_port()
    target_port = session.free_port()
    session.configure_kit(kit, listen_address="127.0.0.1", networks=["127.0.0.1/32"],
                          connect_address="127.0.0.1", socks_port=socks_port)

    captures = {}
    for name, extra in (("default", []), ("dpi-only", ["-d"])):
        with (output / f"ndpi-{name}.txt").open("wb") as log:
            captures[name] = subprocess.Popen(
                [str(arguments.ndpi_reader), "-i", "lo", "-s", str(arguments.duration),
                 "-f", f"tcp port {arguments.port}", "-C", str(output / f"ndpi-{name}.csv"), *extra],
                stdout=log, stderr=subprocess.STDOUT)
    time.sleep(2.0)

    target = session.serve_payload("127.0.0.1", target_port, arguments.payload_bytes)
    logs = {name: (output / f"{name}.log").open("wb") for name in ("yumed", "yume")}
    server = subprocess.Popen([str(arguments.yumed), "--config", str(kit / "server/yumed.json")],
                              env=environment, stdout=logs["yumed"], stderr=subprocess.STDOUT)
    client = None
    transfers: list[dict[str, object]] = []
    completed = False
    try:
        deadline = time.monotonic() + 30
        wait_for_log(output / "yumed.log", "listening on", server, deadline)
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
        completed = True
    finally:
        for process in (client, server):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        target.shutdown()
        for handle in logs.values():
            handle.close()
        for capture in captures.values():
            if not completed and capture.poll() is None:
                capture.terminate()
            try:
                capture.wait(timeout=arguments.duration + 30)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.wait(timeout=5)
    for name in ("yumed", "yume"):
        session.reject_secret_output(name, (output / f"{name}.log").read_text(errors="replace"))
    return transfers


def run_inside(arguments: argparse.Namespace) -> int:
    output = arguments.output
    output.mkdir(parents=True, exist_ok=False)
    loopback = configure_loopback(arguments.mtu)
    environment = session.openssl_environment(arguments.openssl)
    with tempfile.TemporaryDirectory(prefix="yume-ndpi-kit-") as temporary:
        transfers = observe(arguments, Path(temporary) / "kit", environment)

    captures = {}
    failures = []
    for name in ("default", "dpi-only"):
        capture = reader_report(output / f"ndpi-{name}.txt", arguments.port)
        capture["csv_flows"] = flows_on_port(output / f"ndpi-{name}.csv", arguments.port)
        captures[name] = capture
        if not capture["csv_flows"]:
            failures.append(f"{name}: no flow on port {arguments.port} was recorded")
        if capture["discarded_bytes"]:
            failures.append(f"{name}: the reader discarded {capture['discarded_bytes']} bytes "
                            f"of frames longer than its {READER_SNAPLEN}-byte snap length")
    summary = {
        "schema": "yume.ndpi-smoke/2",
        "ndpi_reader": {"path": str(arguments.ndpi_reader), "sha256": session.file_digest(arguments.ndpi_reader)},
        "binaries": {name: session.file_digest(path) for name, path in
                     (("yumed-ytp1", arguments.yumed), ("yume-ytp1", arguments.yume))},
        "server_name": arguments.server_name,
        "server_port": arguments.port,
        "loopback": loopback,
        "transfers": transfers,
        "captures": captures,
        "failures": failures,
        "does_not_prove": DOES_NOT_PROVE,
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    for name, capture in captures.items():
        for line in capture["flows"]:
            print(f"{name}: {line}")
    for failure in failures:
        print(failure, file=sys.stderr)
    return 1 if failures else 0


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
    parser.add_argument("--mtu", type=int, default=1500, help="loopback MTU, 1280..1500")
    arguments = parser.parse_args()
    for name in ("yumed", "yume", "ndpi_reader", "openssl"):
        setattr(arguments, name, getattr(arguments, name).resolve(strict=True))
    arguments.output = arguments.output.resolve()
    if not 1 <= arguments.requests <= 100 or not 1 <= arguments.payload_bytes <= 1 << 30:
        parser.error("requests must be 1..100 and payload bytes 1..1 GiB")
    if not 1280 <= arguments.mtu <= 1500:
        parser.error("mtu must be 1280..1500 so frames fit the reader's snap length")
    if os.environ.get(INSIDE) != "1":
        unshare = shutil.which("unshare")
        if not unshare:
            parser.error("unshare is required")
        environment = dict(os.environ, **{INSIDE: "1"})
        return subprocess.run([unshare, "-rn", sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:]], env=environment, check=False).returncode
    try:
        return run_inside(arguments)
    except (session.SessionFailure, OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"nDPI smoke: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
