#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Tests for the constrained-host tier runner.

The runner's job is to refuse to overstate what a tier proved, so the cases that
matter most are the ones where it must *not* report a pass: a workload that was
OOM-killed, one whose accounting is missing, and one whose output shows the
cryptographic stack was reduced to fit.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import signal
import subprocess
import tempfile
import sys
import unittest
from unittest import mock
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yume_constrained_host as tier_runner  # noqa: E402
from yume_constrained_host import (  # noqa: E402
    TIERS,
    Usage,
    check_no_downgrade,
    collect_evidence,
    evaluate,
    extract_metric,
    percentiles,
    user_delegation_available,
)

TIER = TIERS["1v1g"]


def completed(returncode: int = 0, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(["workload"], returncode, stdout, stderr)


def healthy_usage(**overrides) -> Usage:
    base = dict(memory_peak_bytes=256 * 1024 * 1024, memory_events={},
                pids_peak=40, cpu_usage_usec=1_000_000,
                cpu_throttled_usec=0, cpu_nr_throttled=0)
    base.update(overrides)
    return Usage(**base)


GOOD_OUTPUT = "handshake: ML-KEM-1024 + X25519\nratchet epoch window send=8\n"


class DowngradeTest(unittest.TestCase):
    def test_expected_markers_accepted(self) -> None:
        self.assertEqual(check_no_downgrade(GOOD_OUTPUT), [])

    def test_missing_pq_evidence_is_a_downgrade(self) -> None:
        problems = check_no_downgrade("ratchet epoch window send=8\n")
        self.assertTrue(any("kem" in p.lower() for p in problems), problems)

    def test_missing_ratchet_evidence_is_a_downgrade(self) -> None:
        problems = check_no_downgrade("handshake: ML-KEM-1024 + X25519\n")
        self.assertTrue(any("ratchet" in p.lower() for p in problems), problems)

    def test_explicit_fallback_is_rejected(self) -> None:
        """Silence is one failure mode; announcing the fallback is the other."""
        for line in ("falling back to hkdf", "no-inner mode active", "downgraded"):
            problems = check_no_downgrade(GOOD_OUTPUT + line)
            self.assertTrue(problems, line)


class VerdictTest(unittest.TestCase):
    def test_clean_run_passes(self) -> None:
        verdict, reasons = evaluate(TIER, completed(stdout=GOOD_OUTPUT), healthy_usage())
        self.assertEqual(verdict, "PASS", reasons)

    def test_oom_kill_fails_even_with_zero_exit(self) -> None:
        """A restarted-and-recovered workload still did not fit the tier."""
        verdict, reasons = evaluate(
            TIER, completed(stdout=GOOD_OUTPUT),
            healthy_usage(memory_events={"oom_kill": 1, "max": 12}))
        self.assertEqual(verdict, "FAIL")
        self.assertTrue(any("OOM" in r for r in reasons), reasons)

    def test_missing_accounting_is_not_a_pass(self) -> None:
        """Without accounting the tier is unproven, which is not the same as met."""
        verdict, reasons = evaluate(
            TIER, completed(stdout=GOOD_OUTPUT),
            healthy_usage(memory_peak_bytes=None))
        self.assertEqual(verdict, "FAIL")
        self.assertTrue(any("not proven" in r for r in reasons), reasons)

    def test_peak_above_limit_fails(self) -> None:
        verdict, reasons = evaluate(
            TIER, completed(stdout=GOOD_OUTPUT),
            healthy_usage(memory_peak_bytes=TIER.memory_bytes + 1))
        self.assertEqual(verdict, "FAIL")

    def test_nonzero_exit_fails(self) -> None:
        verdict, reasons = evaluate(TIER, completed(returncode=1, stdout=GOOD_OUTPUT),
                                    healthy_usage())
        self.assertEqual(verdict, "FAIL")

    def test_downgrade_fails_a_run_that_otherwise_fit(self) -> None:
        """Fitting the tier by weakening the crypto is the outcome to prevent."""
        verdict, reasons = evaluate(
            TIER, completed(stdout="ratchet on, falling back to hkdf"), healthy_usage())
        self.assertEqual(verdict, "FAIL")
        self.assertTrue(any("falling back" in r for r in reasons), reasons)


class TierDefinitionTest(unittest.TestCase):
    def test_cpu_quota_matches_the_named_tier(self) -> None:
        self.assertEqual(TIERS["1v1g"].cpu_quota_percent, 100)
        self.assertEqual(TIERS["2v2g"].cpu_quota_percent, 200)

    def test_memory_matches_the_named_tier(self) -> None:
        self.assertEqual(TIERS["1v1g"].memory_bytes, 1024 * 1024 * 1024)
        self.assertEqual(TIERS["2v2g"].memory_bytes, 2048 * 1024 * 1024)


class PercentileTest(unittest.TestCase):
    def test_nearest_rank_reports_observed_values(self) -> None:
        """p99 must be a value that actually occurred, not an interpolation."""
        sample = [float(i) for i in range(1, 101)]
        result = percentiles(sample)
        self.assertEqual(result["p50"], 50.0)
        self.assertEqual(result["p95"], 95.0)
        self.assertEqual(result["p99"], 99.0)
        self.assertEqual(result["max"], 100.0)

    def test_single_sample_is_its_own_percentiles(self) -> None:
        result = percentiles([7.0])
        self.assertEqual((result["p50"], result["p99"], result["n"]), (7.0, 7.0, 1))

    def test_empty_sample_reports_nothing(self) -> None:
        self.assertEqual(percentiles([]), {})


class MetricExtractionTest(unittest.TestCase):
    def test_dotted_path_and_index(self) -> None:
        doc = {"results": [{"breakdown": {"connect_ms": 12.5}}]}
        self.assertEqual(
            extract_metric(doc, "results[0].breakdown.connect_ms"), 12.5)

    def test_missing_path_returns_none(self) -> None:
        self.assertIsNone(extract_metric({"a": 1}, "a.b.c"))
        self.assertIsNone(extract_metric({"a": [1]}, "a[9]"))

    def test_non_numeric_is_rejected(self) -> None:
        """A string or bool must not be silently treated as a measurement."""
        self.assertIsNone(extract_metric({"a": "12"}, "a"))
        self.assertIsNone(extract_metric({"a": True}, "a"))


class EvidenceTest(unittest.TestCase):
    def test_stale_files_are_ignored(self) -> None:
        """Evidence from an earlier run must not satisfy this run's check."""
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "old.log"
            log.write_text("ML-KEM-1024 ratchet")
            os.utime(log, (1000, 1000))
            text, used = collect_evidence([f"{tmp}/*.log"], not_before=2000)
            self.assertEqual(text, "")
            self.assertEqual(used, [])

    def test_fresh_files_are_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "new.log"
            log.write_text("ML-KEM-1024 ratchet")
            text, used = collect_evidence([f"{tmp}/*.log"], not_before=0)
            self.assertIn("ML-KEM", text)
            self.assertEqual(len(used), 1)


class SteadyDriftTest(unittest.TestCase):
    def test_startup_ramp_is_not_reported_as_drift(self) -> None:
        """Climbing to a working set then holding it is not a leak."""
        from yume_constrained_host import _steady_drift
        self.assertEqual(_steady_drift([0, 10, 30, 36, 36, 36, 36, 36]), 0)

    def test_steady_growth_is_reported(self) -> None:
        from yume_constrained_host import _steady_drift
        self.assertGreater(_steady_drift([10, 12, 14, 16, 30, 34, 38, 42]), 0)

    def test_too_few_samples_reports_nothing(self) -> None:
        """Three samples have no steady state to compare against."""
        from yume_constrained_host import _steady_drift
        self.assertIsNone(_steady_drift([1, 2, 3]))


class DelegationTest(unittest.TestCase):
    def test_probe_reports_a_reason(self) -> None:
        """Either answer is valid on a build host; an explanation is mandatory."""
        available, detail = user_delegation_available()
        self.assertIsInstance(available, bool)
        self.assertTrue(detail.strip())


class RepeatedWorkloadTest(unittest.TestCase):
    """Run the entry point with a fake scope launcher and harmless workloads."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="yume-tier-fixture-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        launcher = self.root / "systemd-run"
        launcher.write_text(
            f"#!{sys.executable}\nimport os, sys\n"
            "command = sys.argv[sys.argv.index('--') + 1:]\n"
            "os.execvp(command[0], command)\n", encoding="utf-8")
        launcher.chmod(0o700)
        self.workload = self.root / "workload.py"
        self.workload.write_text('''import json, os, pathlib, sys, time
iteration = int(os.environ['YUME_TIER_ITERATION'])
root, mode = pathlib.Path(sys.argv[1]), sys.argv[2]
print('ML-KEM-1024 ratchet on')
if mode != 'missing' or iteration != 2:
    path = root / 'result.json'
    value = float('nan') if mode == 'nonfinite' else iteration * 10
    path.write_text(json.dumps({'elapsed': value}))
    stamp = time.time_ns() + iteration * 1_000_000_000
    os.utime(path, ns=(stamp, stamp))
    if mode == 'multiple':
        older = root / 'older.json'
        older.write_text(json.dumps({'elapsed': 999}))
        os.utime(older, ns=(stamp - 1, stamp - 1))
sys.exit(7 if mode == 'failed' and iteration == 2 else 0)
''', encoding="utf-8")

    def run_workload(self, mode: str) -> tuple[int, dict]:
        output = self.root / "report.txt"
        arguments = ["--tier", "1v1g", "--repeat", "3", "--timeout-sec", "10",
                     "--output", str(output), "--collect",
                     f"latency={self.root}/*.json:elapsed", "--",
                     sys.executable, str(self.workload), str(self.root), mode]
        with mock.patch.dict(os.environ, {"PATH": f"{self.root}:{os.environ['PATH']}"}), \
                mock.patch.object(tier_runner, "user_delegation_available",
                                  return_value=(True, "fixture delegation")), \
                mock.patch.object(tier_runner, "_poll_usage"), \
                mock.patch.object(tier_runner, "collect_usage", return_value=healthy_usage()), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = tier_runner.main(arguments)
        return result, json.loads(output.read_text(encoding="utf-8"))

    def test_overwritten_result_is_sampled_after_every_iteration(self) -> None:
        result, report = self.run_workload("overwrite")
        self.assertEqual(result, 0, report["reasons"])
        self.assertEqual(report["metrics"]["latency"], percentiles([10, 20, 30]))

    def test_only_newest_changed_file_counts_for_each_iteration(self) -> None:
        result, report = self.run_workload("multiple")
        self.assertEqual(result, 0, report["reasons"])
        self.assertEqual(report["metrics"]["latency"], percentiles([10, 20, 30]))

    def test_missing_iteration_cannot_reuse_the_previous_result(self) -> None:
        result, report = self.run_workload("missing")
        self.assertEqual(result, 1)
        self.assertEqual(report["metrics"]["latency"]["n"], 2)
        self.assertIn("expected 3 iteration samples, got 2", " ".join(report["reasons"]))

    def test_nonfinite_samples_cannot_pass(self) -> None:
        result, report = self.run_workload("nonfinite")
        self.assertEqual(result, 1)
        self.assertIn("expected 3 iteration samples, got 0", " ".join(report["reasons"]))

    def test_failed_iteration_stops_the_series_and_reports_missing_samples(self) -> None:
        result, report = self.run_workload("failed")
        self.assertEqual(result, 1)
        self.assertEqual(report["exit_code"], 7)
        self.assertEqual(report["metrics"]["latency"]["n"], 2)
        self.assertIn("expected 3 iteration samples, got 2", " ".join(report["reasons"]))


class ScopeCleanupTest(unittest.TestCase):
    """No systemd or process signalling occurs in these failure injections."""

    def check_cleanup(self, interrupted: bool = False, stop_failed: bool = False) -> None:
        process = mock.Mock(pid=12345, returncode=None)
        failure = KeyboardInterrupt() if interrupted else subprocess.TimeoutExpired("fixture", 1)
        process.communicate.side_effect = failure
        stops = []

        def run(arguments: list[str], **options: object) -> subprocess.CompletedProcess:
            # The old runner used run() for systemd-run. Its failure must also
            # reach the cleanup assertion in the removed-fix control.
            if arguments[0] == "systemd-run":
                raise failure
            self.assertEqual(arguments[:3], ["systemctl", "--user", "stop"])
            self.assertTrue(arguments[3].startswith("yume-tier-"))
            self.assertTrue(arguments[3].endswith(".scope"))
            self.assertLessEqual(options["timeout"], 10)
            stops.append(arguments[3])
            if stop_failed:
                raise subprocess.TimeoutExpired(arguments, 10)
            return completed()

        with mock.patch.object(tier_runner.subprocess, "Popen", return_value=process) as launch, \
                mock.patch.object(tier_runner.subprocess, "run", side_effect=run), \
                mock.patch.object(tier_runner.os, "killpg") as kill, \
                mock.patch.object(tier_runner, "_poll_usage"):
            expected = KeyboardInterrupt if interrupted else (tier_runner.TierError, subprocess.TimeoutExpired)
            with self.assertRaises(expected):
                tier_runner.run_in_tier(TIER, ["fixture"], 1)
            self.assertEqual(len(stops), 1)
            self.assertTrue(launch.call_args.kwargs["start_new_session"])
            self.assertIn(f"--unit={stops[0]}", launch.call_args.args[0])
            kill.assert_called_once_with(process.pid, signal.SIGKILL)
            process.wait.assert_called_once_with(timeout=5)
            process.stdout.close.assert_called_once()
            process.stderr.close.assert_called_once()

    def test_timeout_stops_the_scope_and_reaps_the_launcher(self) -> None:
        self.check_cleanup()

    def test_interrupt_stops_the_scope_and_reaps_the_launcher(self) -> None:
        self.check_cleanup(interrupted=True)

    def test_failed_scope_stop_still_kills_and_reaps_the_launcher(self) -> None:
        self.check_cleanup(stop_failed=True)


if __name__ == "__main__":
    unittest.main(verbosity=1)
