#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Circuit tool ownership under failed teardown and relay construction."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import yume_circuit_capture as capture
import yume_circuit_wan as circuit

REAL_POPEN = subprocess.Popen
REAL_SOCKET = socket.socket
REAL_CREATE_SERVER = socket.create_server
REAL_MKDTEMP = tempfile.mkdtemp
REAL_THREAD_START = threading.Thread.start
REAL_RECV_FDS = socket.recv_fds


class CleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.children: list[subprocess.Popen] = []
        self.addCleanup(self.reap_children)

    def child(self) -> subprocess.Popen:
        process = REAL_POPEN(
            [sys.executable, "-c", "import signal,time;signal.signal(signal.SIGINT,signal.SIG_IGN);"
             "print('ready',flush=True);time.sleep(60)"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.children.append(process)
        self.assertTrue(select.select([process.stdout], [], [], 3)[0], "child did not start")
        self.assertEqual(process.stdout.readline(), b"ready\n")
        process.stdout.close()
        return process

    def reap_children(self) -> None:
        for process in self.children:
            if process.poll() is None:
                process.kill()
            # A test may temporarily wrap wait to inject its failure.
            subprocess.Popen.wait(process, timeout=5)

    def test_capture_timeout_reaps_every_child_and_closes_mesh(self) -> None:
        arguments = argparse.Namespace(output=self.root / "capture", openssl=Path("openssl"),
                                       yumed=Path("yumed"), yume=Path("yume"), condition="rtt=0")
        mesh = mock.Mock()
        mesh.shape.return_value = []
        handles = []

        def spawn(*_: object, **kwargs: object) -> subprocess.Popen:
            process = self.child()
            handles.append(kwargs["stderr"])
            kwargs["stderr"].write(b"0 packets dropped by kernel\n")
            wait = process.wait
            process.wait = lambda timeout=None: wait(timeout=0.05 if timeout == 10 else timeout)
            return process

        error = None
        result = None
        with contextlib.ExitStack() as patches:
            patches.enter_context(mock.patch.object(capture.session, "openssl_environment", return_value={}))
            patches.enter_context(mock.patch.object(capture.session, "file_digest", return_value="digest"))
            patches.enter_context(mock.patch.object(capture.session, "free_port", return_value=12345))
            patches.enter_context(mock.patch.object(capture.session, "setup_program", return_value=Path("setup")))
            patches.enter_context(mock.patch.object(circuit, "Mesh", return_value=mesh))
            patches.enter_context(mock.patch.object(capture, "CAPTURED", ("client", "node-a")))
            patches.enter_context(mock.patch.object(circuit, "NODES", ()))
            patches.enter_context(mock.patch.object(circuit, "Cluster", side_effect=OSError("fixture startup failed")))
            patches.enter_context(mock.patch.object(capture.subprocess, "Popen", side_effect=spawn))
            patches.enter_context(mock.patch.object(capture.time, "sleep"))
            try:
                result = capture.run_inside(arguments)
            except subprocess.TimeoutExpired as failure:
                error = failure
        self.assertIsNone(error, "capture timeout escaped before completing cleanup")
        self.assertEqual(result, 1)
        self.assertTrue(all(process.poll() is not None for process in self.children), "capture leaked children")
        self.assertTrue(all(handle.closed for handle in handles), "capture leaked logs")
        mesh.close.assert_called_once()
        report = json.loads((arguments.output / "report.json").read_text())
        self.assertIn("cleanup_error", report)
        self.assertNotIn("analysis", report)

    def test_mesh_teardown_failure_does_not_skip_other_holders(self) -> None:
        first, second = self.child(), self.child()
        mesh = object.__new__(circuit.Mesh)
        mesh.holders = {"router": first, "node": second}
        wait = first.wait
        attempts = 0

        def fail_once(timeout: float | None = None) -> int:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise subprocess.TimeoutExpired("injected holder wait", timeout)
            return wait(timeout=timeout)

        with mock.patch.object(first, "wait", side_effect=fail_once):
            with self.assertRaises(subprocess.TimeoutExpired):
                mesh.close()
        self.assertTrue(all(process.poll() is not None for process in self.children),
                        "a failed holder wait skipped another holder")


class RelayConstructionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.sockets: list[socket.socket] = []
        self.threads: list[threading.Thread] = []
        self.addCleanup(self.cleanup_relays)

    def cleanup_relays(self) -> None:
        for server in self.sockets:
            try:
                server.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            server.close()
        for worker in self.threads:
            if worker.ident is not None:
                worker.join(timeout=2)

    def test_host_relay_thread_start_failure_releases_listener_and_directory(self) -> None:
        directories: list[Path] = []

        def directory(**_: object) -> str:
            path = REAL_MKDTEMP(dir=self.root)
            directories.append(Path(path))
            return path

        def listener(*args: object, **kwargs: object) -> socket.socket:
            server = REAL_CREATE_SERVER(*args, **kwargs)
            self.sockets.append(server)
            return server

        with mock.patch.object(circuit.tempfile, "mkdtemp", side_effect=directory), \
                mock.patch.object(circuit.socket, "create_server", side_effect=listener), \
                mock.patch.object(circuit.threading.Thread, "start", side_effect=RuntimeError("thread refused")):
            with self.assertRaisesRegex(RuntimeError, "thread refused"):
                circuit.HostRelay("127.0.0.1")
        self.assertTrue(all(not path.exists() for path in directories), "host relay leaked its directory")
        self.assertTrue(all(server.fileno() == -1 for server in self.sockets), "host relay leaked its listener")

    def namespace_failure(self, failed_start: bool) -> None:
        occupied = self.root / "destination.sock"
        if not failed_start:
            occupied.write_text("existing path must survive")

        def listener(*args: object, **kwargs: object) -> socket.socket:
            server = REAL_SOCKET(*args, **kwargs)
            self.sockets.append(server)
            return server

        def start(worker: threading.Thread) -> None:
            self.threads.append(worker)
            if failed_start and len(self.threads) == 2:
                raise RuntimeError("second thread refused")
            REAL_THREAD_START(worker)

        with mock.patch.object(circuit.socket, "socket", side_effect=listener), \
                mock.patch.object(circuit.threading.Thread, "start", new=start):
            with self.assertRaises(RuntimeError if failed_start else OSError):
                circuit.NamespaceRelay(self.root, {"entry": ("127.0.0.1", 1),
                                                   "destination": ("127.0.0.1", 2)})
        self.assertTrue(all(server.fileno() == -1 for server in self.sockets), "namespace relay leaked listeners")
        self.assertTrue(all(not worker.is_alive() for worker in self.threads), "namespace relay leaked listener threads")
        self.assertFalse((self.root / "entry.sock").exists(), "namespace relay leaked a socket path")
        if failed_start:
            self.assertFalse(occupied.exists(), "failed thread left its socket path")
        else:
            self.assertEqual(occupied.read_text(), "existing path must survive")

    def test_namespace_second_bind_failure_rolls_back_earlier_listener(self) -> None:
        self.namespace_failure(False)

    def test_namespace_second_thread_failure_rolls_back_all_listeners(self) -> None:
        self.namespace_failure(True)

    def test_namespace_idle_handoff_does_not_block_close(self) -> None:
        accepting = threading.Event()

        def receive(*args: object, **kwargs: object) -> tuple:
            accepting.set()
            return REAL_RECV_FDS(*args, **kwargs)

        def start(worker: threading.Thread) -> None:
            self.threads.append(worker)
            REAL_THREAD_START(worker)

        with mock.patch.object(circuit.threading.Thread, "start", new=start), \
                mock.patch.object(circuit.socket, "recv_fds", side_effect=receive):
            relay = circuit.NamespaceRelay(self.root, {"entry": ("127.0.0.1", 1)})
            self.sockets.extend(relay.servers)
            with REAL_SOCKET(socket.AF_UNIX, socket.SOCK_STREAM) as idle:
                idle.connect(str(self.root / "entry.sock"))
                self.assertTrue(accepting.wait(2), "relay never accepted the idle handoff")
                relay.close()
                self.assertTrue(all(not worker.is_alive() for worker in self.threads),
                                "idle handoff kept a listener alive after close")

    def fail_first_connection_worker(self, worker: threading.Thread) -> None:
        self.threads.append(worker)
        if len(self.threads) == 2:
            raise RuntimeError("connection thread refused")
        REAL_THREAD_START(worker)

    def test_namespace_idle_handoff_expires(self) -> None:
        with mock.patch.object(circuit.NamespaceRelay, "HANDOFF_SECONDS", 0.1, create=True):
            relay = circuit.NamespaceRelay(self.root, {"entry": ("127.0.0.1", 1)})
            self.sockets.extend(relay.servers)
            try:
                with REAL_SOCKET(socket.AF_UNIX, socket.SOCK_STREAM) as idle:
                    idle.settimeout(1)
                    idle.connect(str(self.root / "entry.sock"))
                    expired = False
                    try:
                        expired = idle.recv(1) == b""
                    except TimeoutError:
                        pass
                    self.assertTrue(expired, "idle descriptor handoff missed its deadline")
            finally:
                relay.close()

    def test_host_worker_failure_closes_connection_and_keeps_accepting(self) -> None:
        served = threading.Event()

        def hand_in(_: circuit.HostRelay, connection: socket.socket) -> None:
            connection.close()
            served.set()

        errors = io.StringIO()
        with contextlib.redirect_stderr(errors), \
                mock.patch.object(circuit.threading.Thread, "start", new=lambda worker: self.fail_first_connection_worker(worker)), \
                mock.patch.object(circuit.HostRelay, "hand_in", new=hand_in):
            relay = circuit.HostRelay("127.0.0.1")
            self.sockets.append(relay.listener)
            try:
                address = relay.listener.getsockname()
                with socket.create_connection(address, timeout=1) as first:
                    closed = False
                    try:
                        closed = first.recv(1) == b""
                    except TimeoutError:
                        pass
                    self.assertTrue(closed, "refused worker kept its connection")
                with socket.create_connection(address, timeout=1):
                    self.assertTrue(served.wait(1), "host relay stopped accepting after worker refusal")
            finally:
                relay.close()
        self.assertIn("connection worker refused", errors.getvalue())

    def test_namespace_worker_failure_closes_descriptor_and_keeps_accepting(self) -> None:
        served = threading.Event()

        def joined(descriptor: int, _: tuple[str, int]) -> None:
            with REAL_SOCKET(fileno=descriptor):
                served.set()

        def handoff(descriptor: int) -> None:
            with REAL_SOCKET(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.connect(str(self.root / "entry.sock"))
                socket.send_fds(connection, [b"c"], [descriptor])

        errors = io.StringIO()
        with contextlib.redirect_stderr(errors), \
                mock.patch.object(circuit.threading.Thread, "start", new=lambda worker: self.fail_first_connection_worker(worker)), \
                mock.patch.object(circuit.NamespaceRelay, "join", new=staticmethod(joined)):
            relay = circuit.NamespaceRelay(self.root, {"entry": ("127.0.0.1", 1)})
            self.sockets.extend(relay.servers)
            try:
                with contextlib.ExitStack() as pairs:
                    outside, peer = socket.socketpair()
                    pairs.enter_context(outside)
                    pairs.enter_context(peer)
                    peer.settimeout(1)
                    handoff(outside.fileno())
                    outside.close()
                    closed = False
                    try:
                        closed = peer.recv(1) == b""
                    except TimeoutError:
                        pass
                    self.assertTrue(closed, "refused worker leaked its received descriptor")
                    outside2, peer2 = socket.socketpair()
                    pairs.enter_context(outside2)
                    pairs.enter_context(peer2)
                    handoff(outside2.fileno())
                    self.assertTrue(served.wait(1), "namespace relay stopped accepting after worker refusal")
            finally:
                relay.close()
        self.assertIn("connection worker refused", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
