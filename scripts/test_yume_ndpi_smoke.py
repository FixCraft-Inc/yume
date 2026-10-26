#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Capture ownership and evidence refusal, without nDPI or namespace setup."""
from __future__ import annotations

import argparse
import contextlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yume_ndpi_smoke as smoke
import yume_ndpi_report as report

REAL_POPEN = subprocess.Popen


class SmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.arguments = argparse.Namespace(
            output=self.root, server_name="example.test", port=443, yume=Path("client"),
            yumed=Path("server"), ndpi_reader=Path("reader"), duration=1,
            payload_bytes=1, requests=1)
        self.processes: list[subprocess.Popen] = []
        self.target = mock.Mock()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in {"provision_kit": None, "setup_program": Path("setup"),
                            "free_ports": [1, 2], "configure_kit": None,
                            "serve_payload": self.target, "wait_for_port": None,
                            "payload_digest": "digest", "get_through_socks": (1, "digest", 0.1),
                            "reject_secret_output": None}.items():
            self.stack.enter_context(mock.patch.object(smoke.session, name, return_value=value))
        self.stack.enter_context(mock.patch.object(smoke, "wait_for_log"))
        self.stack.enter_context(mock.patch.object(smoke.time, "sleep"))
        self.stack.enter_context(mock.patch.object(smoke.session, "stop_process", side_effect=self.stop))
        self.addCleanup(self.reap)

    @staticmethod
    def stop(process: subprocess.Popen, *_: object) -> None:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)

    def reap(self) -> None:
        for process in self.processes:
            self.stop(process)

    def observe(self) -> None:
        smoke.observe(self.arguments, self.root / "kit", {})

    def test_partial_startup_reaps_every_child(self) -> None:
        for failed_spawn in (2, 3, 4):
            with self.subTest(failed_spawn=failed_spawn):
                self.processes.clear()
                calls = 0

                def spawn(*args: object, **kwargs: object) -> subprocess.Popen:
                    nonlocal calls
                    calls += 1
                    if calls == failed_spawn:
                        raise OSError("injected spawn failure")
                    child = REAL_POPEN([sys.executable, "-c", "import time;time.sleep(60)"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.processes.append(child)
                    return child

                with mock.patch.object(smoke.subprocess, "Popen", side_effect=spawn):
                    with self.assertRaisesRegex(OSError, "spawn failure"):
                        self.observe()
                alive = [child.pid for child in self.processes if child.poll() is None]
                self.reap()
                self.assertEqual(alive, [], "partial startup leaked children")
        self.target.shutdown.assert_called()
        self.target.server_close.assert_called()

    def run_capture(self, exit_code: int | None) -> None:
        def spawn(argv: list[str], **kwargs: object) -> subprocess.Popen:
            capture = argv[0] == "reader"
            program = f"raise SystemExit({exit_code})" if capture and exit_code is not None \
                else "import time;time.sleep(60)"
            child = REAL_POPEN([sys.executable, "-c", program], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            self.processes.append(child)
            if capture and exit_code is None:
                wait = child.wait
                child.wait = lambda timeout=None: wait(timeout=min(timeout or 5, 0.1))
            return child

        with mock.patch.object(smoke.subprocess, "Popen", side_effect=spawn):
            self.observe()
        self.assertTrue(all(child.poll() is not None for child in self.processes))

    def test_failed_capture_refuses_evidence(self) -> None:
        with self.assertRaisesRegex(smoke.session.SessionFailure, "capture exited with 7"):
            self.run_capture(7)
        self.assertTrue(all(child.poll() is not None for child in self.processes))

    def test_timed_out_capture_refuses_evidence(self) -> None:
        with self.assertRaisesRegex(smoke.session.SessionFailure, "capture timed out"):
            self.run_capture(None)
        self.assertTrue(all(child.poll() is not None for child in self.processes))

    def test_success_reaps_children_and_closes_payload_server(self) -> None:
        self.run_capture(0)
        self.target.shutdown.assert_called_once()
        self.target.server_close.assert_called_once()


class ReportTests(unittest.TestCase):
    def test_missing_or_invalid_accounting_refuses_partial_csv(self) -> None:
        valid = {"csv_flows": [{"dst_port": "443"}], "ip_bytes": 100,
                 "discarded_bytes": 0, "max_packet_bytes": 100}
        self.assertEqual(report.capture_failures("valid", valid, 443), [])
        for field in ("ip_bytes", "discarded_bytes", "max_packet_bytes"):
            for value in (None, -1, True, "0"):
                with self.subTest(field=field, value=value):
                    self.assertTrue(report.capture_failures("partial", {**valid, field: value}, 443))


if __name__ == "__main__":
    unittest.main()
