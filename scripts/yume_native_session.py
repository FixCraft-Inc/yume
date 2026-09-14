#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Shared helpers for real yume-ytp1 and yumed-ytp1 sessions.

The native runtime test, the nDPI smoke observation and the Ethernet runner use
these helpers so kit layout, SOCKS5 handling and process shutdown have one
owner. Nothing here prints or copies credential material.
"""

from __future__ import annotations

import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
SETUP_TOOL = ROOT / "tools" / "yume_setup_ytp1.py"
PATTERN = bytes(range(256))
REPLY_SUCCEEDED = 0x00
REPLY_NOT_ALLOWED = 0x02
REPLY_HOST_UNREACHABLE = 0x04


class SessionFailure(RuntimeError):
    """A session step failed. The message carries no secret material."""


def free_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((host, 0))
        return probe.getsockname()[1]


def recv_exact(connection: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise SessionFailure(f"connection closed after {len(data)} of {size} bytes")
        data += chunk
    return bytes(data)


def wait_for_port(host: str, port: int, process: subprocess.Popen, deadline: float) -> None:
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SessionFailure(f"process exited with {process.returncode} before listening")
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise SessionFailure(f"{host} port {port} did not open")


def socks_connect(socks_port: int, host: str, port: int,
                  timeout: float = 20.0) -> tuple[int, socket.socket]:
    """CONNECT through SOCKS5, leaving name resolution to the remote daemon."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        name = host.encode("ascii")
        if not 1 <= len(name) <= 255:
            raise SessionFailure("SOCKS5 destination name must contain 1 through 255 bytes")
        destination = b"\x03" + bytes([len(name)]) + name
    else:
        if address.version == 6 and address.scope_id is not None:
            raise SessionFailure("SOCKS5 destinations cannot carry an IPv6 scope")
        destination = (b"\x01" if address.version == 4 else b"\x04") + address.packed
    connection = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    try:
        connection.sendall(b"\x05\x01\x00")
        if recv_exact(connection, 2) != b"\x05\x00":
            raise SessionFailure("SOCKS5 method selection failed")
        connection.sendall(b"\x05\x01\x00" + destination + port.to_bytes(2, "big"))
        reply = recv_exact(connection, 10)
        if reply[0] != 0x05:
            raise SessionFailure("SOCKS5 reply has the wrong version")
        return reply[1], connection
    except BaseException:
        connection.close()
        raise


def read_http_body(connection: socket.socket) -> tuple[int, str]:
    """Reads one HTTP/1.x response to EOF, returning body length and SHA-256."""
    header = bytearray()
    while b"\r\n\r\n" not in header:
        chunk = connection.recv(4096)
        if not chunk:
            raise SessionFailure("response ended before its headers")
        header += chunk
        if len(header) > 64 * 1024:
            raise SessionFailure("response headers exceed 64 KiB")
    head, _, rest = bytes(header).partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0]
    if not (status.startswith(b"HTTP/1.0 200") or status.startswith(b"HTTP/1.1 200")):
        raise SessionFailure("destination did not answer 200")
    digest = hashlib.sha256(rest)
    length = len(rest)
    while True:
        chunk = connection.recv(1 << 20)
        if not chunk:
            return length, digest.hexdigest()
        digest.update(chunk)
        length += len(chunk)


def get_through_socks(socks_port: int, host: str, port: int, deadline: float) -> tuple[int, str, float]:
    """GET /payload through SOCKS5, retrying until a session is ready.

    The client listener opens before its first session authenticates, and a
    request without an active session is refused rather than queued.
    Returns body length, SHA-256 and transfer seconds after the reply.
    """
    last = None
    while time.monotonic() < deadline:
        code, connection = socks_connect(socks_port, host, port)
        with connection:
            if code == REPLY_SUCCEEDED:
                started = time.monotonic()
                connection.sendall(b"GET /payload HTTP/1.1\r\nHost: " + host.encode() +
                                   b"\r\nConnection: close\r\n\r\n")
                length, digest = read_http_body(connection)
                return length, digest, time.monotonic() - started
            last = code
        time.sleep(0.2)
    raise SessionFailure(f"no successful SOCKS5 CONNECT, last reply {last}")


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def payload_digest(size: int) -> str:
    digest = hashlib.sha256()
    whole, remainder = divmod(size, len(PATTERN))
    for _ in range(whole):
        digest.update(PATTERN)
    digest.update(PATTERN[:remainder])
    return digest.hexdigest()


def serve_payload(host: str, port: int, size: int) -> http.server.ThreadingHTTPServer:
    """Serves GET /payload with a deterministic body of `size` bytes."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - http.server API
            self.send_response(200)
            self.send_header("Content-Length", str(size))
            self.send_header("Connection", "close")
            self.end_headers()
            remaining = size
            block = PATTERN * 4096
            while remaining:
                piece = block[:remaining]
                self.wfile.write(piece)
                remaining -= len(piece)

        def log_message(self, *_: object) -> None:
            return

    server = http.server.ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def provision_kit(kit: Path, server_name: str, port: int, environment: dict[str, str]) -> None:
    result = subprocess.run(
        [sys.executable, str(SETUP_TOOL), "init", "--host", server_name,
         "--port", str(port), "--output", str(kit)],
        env=environment, capture_output=True, text=True, timeout=120, check=False)
    if result.returncode:
        raise SessionFailure("setup failed: " + result.stderr.strip())


def configure_kit(kit: Path, *, listen_address: str, networks: Iterable[str],
                  connect_address: str, socks_port: int) -> None:
    """One TCP service, one direct adapter with explicit networks, one SOCKS5 listener."""
    service = [{"name": "tcp", "kind": "stream", "max_concurrent_streams": 64}]
    server_path = kit / "server/yumed.json"
    server = json.loads(server_path.read_text(encoding="utf-8"))
    server["endpoint"]["listen_addresses"] = [listen_address]
    server["services"] = service
    server["adapters"] = [{
        "kind": "direct_tcp", "service": "tcp",
        "destinations": {"public": False, "networks": list(networks)},
    }]
    server_path.write_text(json.dumps(server, indent=2), encoding="utf-8")

    client_path = kit / "client/yume.json"
    client = json.loads(client_path.read_text(encoding="utf-8"))
    client["endpoint"]["connect_address"] = connect_address
    client["services"] = service
    client["adapters"] = [{
        "kind": "socks5", "service": "tcp",
        "listen_address": "127.0.0.1", "listen_port": socks_port,
    }]
    client_path.write_text(json.dumps(client, indent=2), encoding="utf-8")

    authorization = kit / "server/credentials/authorized-keys.json"
    store = json.loads(authorization.read_text(encoding="utf-8"))
    for entry in store["keys"]:
        entry["capabilities"] = [{"service": "tcp", "kind": "stream"}]
    authorization.write_text(json.dumps(store, indent=2), encoding="utf-8")


def openssl_environment(openssl: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["PATH"] = str(openssl.resolve(strict=True).parent) + os.pathsep + environment.get("PATH", "")
    return environment


def stop_process(process: subprocess.Popen, name: str, timeout: float = 15.0) -> None:
    """SIGTERM, then require a clean exit within the timeout."""
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        raise SessionFailure(f"{name} did not stop after SIGTERM") from None
    if code != 0:
        raise SessionFailure(f"{name} exited with {code} after SIGTERM")


def reject_secret_output(name: str, text: str) -> None:
    if "PRIVATE KEY" in text:
        raise SessionFailure(f"{name} output contains private key material")
