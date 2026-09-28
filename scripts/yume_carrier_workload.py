#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Run the frozen cover-page WebSocket workload through native yume.

The browser arm of the matched capture loads a page whose script sends 64
16-KiB WebSocket messages, has them echoed, holds the socket idle for 42
seconds and closes it. The YUME arm replaces that page with this driver: it
sends the same application bytes through yume's SOCKS5 port to an echo
target behind yumed, closes its stream, holds the tunnel idle for the same
interval and records what it measured. The carrier's own behavior comes from
yume --outer-carrier-evidence, not from this script.

configure-kit  point a yume-setup kit at loopback capture ports and serve the
               workload's page assets as yumed's cover site
echo           accept one connection and echo it until the peer ends it
drive          move the workload through SOCKS5, then hold the idle interval

Nothing here records payload bytes, keys or credential paths.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from typing import Any

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from yume_capture_manifest import WORKLOAD_PATH, ManifestError, load_workload  # noqa: E402
import yume_native_session as session  # noqa: E402

WORKLOAD_MODULE = ROOT / "tools/cover-node/workload.mjs"
MESSAGE_BYTE = 0x59
# Node's reference server answers unknown paths with this body.
NOT_FOUND_BODY = b"Not Found\n"
MAX_ECHO_BYTES = 4 * 1024 * 1024
# yumed binds the port the client dials, because admission requires the
# :authority port to be the listener's. The capture relay takes that port on
# 127.0.0.1 and forwards to yumed on this second loopback address.
SERVER_ADDRESS = "127.0.0.2"
TRANSFER_TIMEOUT_SECONDS = 60.0
NODE_TIMEOUT_SECONDS = 30


class WorkloadError(RuntimeError):
    """The workload could not run as frozen. The message names the step."""


def _endpoint(value: str) -> tuple[str, int]:
    host, separator, port = value.rpartition(":")
    if not separator or host != "127.0.0.1" or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise argparse.ArgumentTypeError("expected 127.0.0.1:PORT")
    return host, int(port)


def _port(value: str) -> int:
    if not value.isdigit() or not 1 <= int(value) <= 65535:
        raise argparse.ArgumentTypeError("expected a port in 1..65535")
    return int(value)


def _write_json(path: Path, value: dict[str, Any], *, exclusive: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
    flags |= os.O_EXCL if exclusive else os.O_TRUNC
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


def _contract() -> tuple[dict[str, Any], str, dict[str, Any]]:
    try:
        document, digest = load_workload(WORKLOAD_PATH)
    except ManifestError as error:
        raise WorkloadError(f"workload manifest rejected: {error}") from error
    return document, digest, document["contract"]


def workload_assets(node: Path) -> dict[str, tuple[str, bytes]]:
    """The page assets exactly as the Node reference server serves them."""
    script = (
        "import(process.argv[1]).then(m => process.stdout.write(JSON.stringify("
        "[...m.assets].map(([path, asset]) => [path, asset.contentType, "
        "asset.body.toString('base64')]))))"
    )
    try:
        result = subprocess.run(
            [str(node), "--input-type=module", "-e", script, WORKLOAD_MODULE.as_uri()],
            capture_output=True, timeout=NODE_TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired as error:
        raise WorkloadError("node did not render the workload assets in time") from error
    if result.returncode != 0:
        raise WorkloadError("node could not render the workload assets: " +
                            result.stderr.decode("utf-8", "replace").strip()[:500])
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise WorkloadError("node returned malformed workload assets") from error
    assets: dict[str, tuple[str, bytes]] = {}
    for row in rows:
        if (not isinstance(row, list) or len(row) != 3 or
                not all(isinstance(item, str) for item in row)):
            raise WorkloadError("node returned a malformed workload asset")
        assets[row[0]] = (row[1], base64.b64decode(row[2], validate=True))
    _, _, contract = _contract()
    if list(assets) != contract["asset_paths"]:
        raise WorkloadError("rendered assets differ from the workload's asset paths")
    return assets


def configure_kit(kit: Path, port: int, node: Path) -> None:
    """Adapts a capture-only kit in place. Credentials are left untouched.

    The client dials 127.0.0.1 and yumed listens on SERVER_ADDRESS, both on
    port, so the capture relay can sit between them on 127.0.0.1.
    """
    server_path = kit / "server/yumed.json"
    client_path = kit / "client/yume.json"
    try:
        server = json.loads(server_path.read_text(encoding="utf-8"))
        client = json.loads(client_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise WorkloadError(f"cannot read the kit's configurations: {error}") from error
    if server.get("role") != "server" or client.get("role") != "client":
        raise WorkloadError("the kit's configurations have unexpected roles")

    cover = kit / "server/capture-cover"
    if cover.exists():
        raise WorkloadError("the kit already has a capture cover site")
    cover.mkdir(mode=0o700)
    (cover / "assets").mkdir(mode=0o700)
    for path, (_, body) in workload_assets(node).items():
        target = cover / ("index.html" if path == "/" else path.lstrip("/"))
        target.write_bytes(body)
    (cover / "404.html").write_bytes(NOT_FOUND_BODY)

    server["endpoint"]["listen_addresses"] = [SERVER_ADDRESS]
    server["endpoint"]["port"] = port
    server["cover"]["root"] = {"file": "capture-cover"}
    for adapter in server.get("adapters", []):
        if adapter.get("kind") in {"direct_tcp", "direct_udp"}:
            adapter["destinations"] = {"public": False, "networks": ["127.0.0.1/32"]}
    client["endpoint"]["port"] = port
    client["endpoint"]["connect_address"] = "127.0.0.1"
    _write_json(server_path, server, exclusive=False)
    _write_json(client_path, client, exclusive=False)


def echo(listen: tuple[str, int], ready: Path, timeout: float) -> int:
    """Echoes one connection until its peer ends it, then ends its own side."""
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(listen)
        listener.listen(1)
        listener.settimeout(timeout)
        _write_json(ready, {"listening": f"{listen[0]}:{listen[1]}"}, exclusive=True)
        connection, _ = listener.accept()
    with connection:
        total = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WorkloadError("the echo connection outlived its timeout")
            connection.settimeout(remaining)
            chunk = connection.recv(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ECHO_BYTES:
                raise WorkloadError("the echo connection exceeded its byte bound")
            connection.sendall(chunk)
        connection.shutdown(socket.SHUT_WR)
    return total


def drive(socks: tuple[str, int], target: tuple[str, int], settle_ms: int) -> dict[str, Any]:
    document, digest, contract = _contract()
    messages = contract["client_binary_messages"]["count"]
    message_bytes = contract["client_binary_messages"]["payload_bytes"]
    expected = messages * message_bytes
    started = time.monotonic()
    code, connection = session.socks_connect(socks[1], target[0], target[1])
    with connection:
        if code != session.REPLY_SUCCEEDED:
            raise WorkloadError(f"SOCKS5 CONNECT to the echo target returned reply {code}")
        connection.settimeout(TRANSFER_TIMEOUT_SECONDS)
        failure: list[BaseException] = []

        def send() -> None:
            try:
                message = bytes([MESSAGE_BYTE]) * message_bytes
                for _ in range(messages):
                    connection.sendall(message)
            except BaseException as error:  # reported by the reader below
                failure.append(error)

        writer = threading.Thread(target=send, name="workload-writer")
        writer.start()
        received = 0
        try:
            while received < expected:
                chunk = connection.recv(min(64 * 1024, expected - received))
                if not chunk:
                    raise WorkloadError(f"the echo ended after {received} of {expected} bytes")
                if chunk.count(MESSAGE_BYTE) != len(chunk):
                    raise WorkloadError("the echoed bytes differ from the sent bytes")
                received += len(chunk)
        finally:
            writer.join(TRANSFER_TIMEOUT_SECONDS)
        if writer.is_alive() or failure:
            raise WorkloadError("sending the workload failed or did not finish")
        transfer_ms = round((time.monotonic() - started) * 1000)
        # End the stream before the idle, so the carrier is quiet until the
        # close, as the browser page's socket was.
        connection.shutdown(socket.SHUT_WR)
        if connection.recv(1):
            raise WorkloadError("the echo target sent bytes after the workload")
    time.sleep(settle_ms / 1000)
    time.sleep(contract["idle_ms"] / 1000)
    return {
        "schema": 1,
        "workload_id": document["id"],
        "workload_sha256": digest,
        "application_bytes_each_direction": expected,
        "echoed_bytes": received,
        "client_messages": messages,
        "message_bytes": message_bytes,
        "stream_closed_before_idle": True,
        "transfer_ms": transfer_ms,
        "settle_ms": settle_ms,
        "idle_ms": contract["idle_ms"],
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = result.add_subparsers(dest="command", required=True)
    kit = commands.add_parser("configure-kit")
    kit.add_argument("--kit", required=True, type=Path)
    kit.add_argument("--port", required=True, type=_port)
    kit.add_argument("--node", required=True, type=Path)
    listener = commands.add_parser("echo")
    listener.add_argument("--listen", required=True, type=_endpoint)
    listener.add_argument("--ready-file", required=True, type=Path)
    listener.add_argument("--timeout", type=float, default=180.0)
    driver = commands.add_parser("drive")
    driver.add_argument("--socks", required=True, type=_endpoint)
    driver.add_argument("--target", required=True, type=_endpoint)
    driver.add_argument("--output", required=True, type=Path)
    # The browser page closes its socket 42 s after the echo completed. Nothing
    # follows the stream close on an idle tunnel, so no settle time is needed.
    driver.add_argument("--settle-ms", type=int, default=0)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "configure-kit":
            configure_kit(arguments.kit, arguments.port, arguments.node)
        elif arguments.command == "echo":
            if not 1 <= arguments.timeout <= 600:
                raise WorkloadError("the echo timeout must be 1 to 600 seconds")
            echo(arguments.listen, arguments.ready_file, arguments.timeout)
        else:
            if not 0 <= arguments.settle_ms <= 10_000:
                raise WorkloadError("the settle interval must be 0 to 10000 ms")
            result = drive(arguments.socks, arguments.target, arguments.settle_ms)
            _write_json(arguments.output, result, exclusive=True)
    except (WorkloadError, session.SessionFailure, OSError) as error:
        print(f"carrier workload: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
