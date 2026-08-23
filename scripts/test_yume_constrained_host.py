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

import json
import os
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

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


if __name__ == "__main__":
    unittest.main(verbosity=1)
