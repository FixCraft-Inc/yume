#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Focused tests for the native capture arm's workload driver."""

from __future__ import annotations

import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import yume_carrier_workload as workload  # noqa: E402
from yume_capture_manifest import WORKLOAD_PATH, load_workload  # noqa: E402


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class FakeSocks5:
    """Accepts one no-auth CONNECT to an IPv4 target and pipes both ways."""

    def __init__(self) -> None:
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        with self.listener:
            client, _ = self.listener.accept()
        with client:
            client.recv(3)
            client.sendall(b"\x05\x00")
            request = client.recv(10)
            host = socket.inet_ntoa(request[4:8])
            port = int.from_bytes(request[8:10], "big")
            upstream = socket.create_connection((host, port))
            client.sendall(b"\x05\x00\x00\x01" + bytes(6))

            def pipe(source: socket.socket, target: socket.socket) -> None:
                while chunk := source.recv(65536):
                    target.sendall(chunk)
                target.shutdown(socket.SHUT_WR)

            upward = threading.Thread(target=pipe, args=(client, upstream))
            upward.start()
            pipe(upstream, client)
            upward.join()
            upstream.close()


class CarrierWorkloadTest(unittest.TestCase):
    def test_drive_moves_the_frozen_volume_and_holds_the_idle(self) -> None:
        document, digest = load_workload(WORKLOAD_PATH)
        contract = document["contract"]
        with tempfile.TemporaryDirectory() as tmp:
            ready = Path(tmp) / "ready.json"
            echo_port = free_port()
            echoed: list[int] = []
            echo = threading.Thread(
                target=lambda: echoed.append(
                    workload.echo(("127.0.0.1", echo_port), ready, 30)))
            echo.start()
            while not ready.exists():
                echo.join(0.01)
            socks = FakeSocks5()
            sleeps: list[float] = []
            with mock.patch.object(workload.time, "sleep", sleeps.append):
                result = workload.drive(("127.0.0.1", socks.port),
                                        ("127.0.0.1", echo_port), 1000)
            echo.join(10)
        expected = contract["websocket_bytes_each_direction"]
        self.assertEqual(echoed, [expected])
        self.assertEqual(result["application_bytes_each_direction"], expected)
        self.assertEqual(result["echoed_bytes"], expected)
        self.assertEqual(result["workload_sha256"], digest)
        self.assertEqual(result["idle_ms"], contract["idle_ms"])
        self.assertTrue(result["stream_closed_before_idle"])
        # The settle interval, then the workload's idle.
        self.assertEqual(sleeps, [1.0, contract["idle_ms"] / 1000])

    def test_echo_refuses_more_than_its_bound(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ready = Path(tmp) / "ready.json"
            port = free_port()
            failure: list[BaseException] = []

            def serve() -> None:
                try:
                    workload.echo(("127.0.0.1", port), ready, 30)
                except workload.WorkloadError as error:
                    failure.append(error)

            thread = threading.Thread(target=serve)
            thread.start()
            while not ready.exists():
                thread.join(0.01)
            with socket.create_connection(("127.0.0.1", port)) as client:
                reader = threading.Thread(
                    target=lambda: [None for _ in iter(lambda: client.recv(65536), b"")])
                reader.start()
                try:
                    client.sendall(bytes(workload.MAX_ECHO_BYTES + 1))
                except OSError:
                    pass
                thread.join(10)
            self.assertEqual(len(failure), 1)
            self.assertIn("byte bound", str(failure[0]))

    def test_configure_kit_points_a_kit_at_the_capture_ports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kit = Path(tmp)
            (kit / "server").mkdir()
            (kit / "client").mkdir()
            (kit / "server/yumed.json").write_text(json.dumps({
                "role": "server",
                "endpoint": {"listen_addresses": ["0.0.0.0"], "port": 443},
                "cover": {"profile": "chrome151-node24-v1", "root": {"file": "cover-site"}},
                "adapters": [{"kind": "direct_tcp", "service": "tcp",
                              "destinations": {"public": True, "networks": []}}],
            }))
            (kit / "client/yume.json").write_text(json.dumps({
                "role": "client", "endpoint": {"host": "cover.test", "port": 443},
            }))
            assets = {"/": ("text/html", b"<p>page</p>"),
                      "/assets/site.css": ("text/css", b"css"),
                      "/assets/site.js": ("text/javascript", b"js")}
            with mock.patch.object(workload, "workload_assets", return_value=assets):
                workload.configure_kit(kit, 39445, Path("/unused/node"))
            server = json.loads((kit / "server/yumed.json").read_text())
            client = json.loads((kit / "client/yume.json").read_text())
            # Admission needs the dialed port on the listener itself.
            self.assertEqual(server["endpoint"],
                             {"listen_addresses": ["127.0.0.2"], "port": 39445})
            self.assertEqual(server["cover"]["root"], {"file": "capture-cover"})
            self.assertEqual(server["adapters"][0]["destinations"],
                             {"public": False, "networks": ["127.0.0.1/32"]})
            self.assertEqual(client["endpoint"]["port"], 39445)
            self.assertEqual(client["endpoint"]["connect_address"], "127.0.0.1")
            cover = kit / "server/capture-cover"
            self.assertEqual((cover / "index.html").read_bytes(), b"<p>page</p>")
            self.assertEqual((cover / "assets/site.js").read_bytes(), b"js")
            self.assertEqual((cover / "404.html").read_bytes(), b"Not Found\n")
            with mock.patch.object(workload, "workload_assets", return_value=assets):
                with self.assertRaisesRegex(workload.WorkloadError, "already has"):
                    workload.configure_kit(kit, 39445, Path("/unused/node"))


if __name__ == "__main__":
    unittest.main()
