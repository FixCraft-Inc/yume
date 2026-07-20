#!/usr/bin/env python3
"""Focused tests for external benchmark resource accounting."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from yume_bench_common import run_streamed_command  # noqa: E402
from yume_bench_lan import wall_throughput  # noqa: E402
from yume_bench_resources import (  # noqa: E402
    ProcessResourceSampler,
    _parse_proc_stat,
    host_resource_info,
)


class ResourceSamplerTest(unittest.TestCase):
    def test_proc_stat_parser_handles_live_process(self) -> None:
        raw = Path("/proc/self/stat").read_text(encoding="ascii")
        parsed = _parse_proc_stat(raw)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed["pid"], os.getpid())
        self.assertGreater(parsed["rss_pages"], 0)
        self.assertGreaterEqual(parsed["threads"], 1)

    def test_host_report_has_absolute_capacity(self) -> None:
        host = host_resource_info()
        self.assertGreaterEqual(host["logical_cpus"], 1)
        self.assertGreaterEqual(host["available_logical_cpus"], 1)
        self.assertGreater(host["memory_total_bytes"], 0)
        self.assertIn("hardware_max", host["frequency_mhz"])

    def test_wall_throughput_uses_total_payload_and_elapsed_time(self) -> None:
        rate = wall_throughput(256, 2.0)
        self.assertEqual(rate["mib_per_second"], 128.0)
        self.assertEqual(rate["mbit_per_second"], 1073.742)

    def test_sampler_records_cpu_memory_and_concurrency(self) -> None:
        workload = """
import os
import time

child = os.fork()
if child == 0:
    data = bytearray(12 * 1024 * 1024)
    end = time.monotonic() + 0.5
    value = 0
    while time.monotonic() < end:
        value = (value + 1) % 1000003
    os._exit(value < 0)
os.waitpid(child, 0)
"""
        process = subprocess.Popen(
            [sys.executable, "-c", workload],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        sampler = ProcessResourceSampler(process.pid, interval_ms=100)
        sampler.start()
        self.assertEqual(process.wait(timeout=5), 0)
        sampler.stop()
        summary = sampler.summary()
        self.assertTrue(summary["available"])
        self.assertGreater(summary["cpu"]["total_seconds"], 0)
        self.assertGreater(summary["memory"]["peak_rss_mib"], 8)
        self.assertGreaterEqual(summary["concurrency"]["peak_threads"], 1)
        self.assertGreaterEqual(summary["concurrency"]["peak_processes"], 2)

    def test_streamed_command_captures_short_process_exit(self) -> None:
        result = run_streamed_command(
            [
                sys.executable,
                "-c",
                "value=0\nfor i in range(3000000): value += i\nprint(value)",
            ],
            timeout=5,
            echo=False,
            resource_sample_ms=250,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIsNotNone(result.resources)
        assert result.resources is not None
        self.assertGreater(result.resources["cpu"]["total_seconds"], 0)

    def test_streamed_command_timeout_stops_process_group(self) -> None:
        started = time.monotonic()
        result = run_streamed_command(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout=0.2,
            echo=False,
            resource_sampling=False,
        )
        self.assertEqual(result.returncode, 124)
        self.assertTrue(result.timed_out)
        self.assertLess(time.monotonic() - started, 3)

    def test_streamed_command_cancel_stops_process_group(self) -> None:
        cancel = threading.Event()
        timer = threading.Timer(0.2, cancel.set)
        timer.start()
        try:
            result = run_streamed_command(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                timeout=10,
                echo=False,
                resource_sampling=False,
                cancel_event=cancel,
            )
        finally:
            timer.cancel()
        self.assertEqual(result.returncode, 130)
        self.assertTrue(result.interrupted)


if __name__ == "__main__":
    unittest.main()
