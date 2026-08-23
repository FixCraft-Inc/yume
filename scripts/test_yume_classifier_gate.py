#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Calibration tests for the classifier-resistance gate.

A gate that always passes is worse than no gate, so these tests pin both
directions: synthetic arms drawn from one distribution must pass, separable
arms must fail, and the group-aware machinery must not manufacture advantage
from structure an observer cannot see.
"""

from __future__ import annotations

import json
import math
import random
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from yume_classifier_gate import (  # noqa: E402
    Dataset,
    GateError,
    Session,
    average_precision,
    check_preconditions,
    evaluate,
    load_dataset,
    roc_auc,
    tpr_at_fpr,
)

PROTOCOL = json.loads(
    (Path(__file__).resolve().parents[1] / "config/classifier_gate_v1.json")
    .read_text(encoding="utf-8"))
DIGEST = "0" * 64
GROUP_KEYS = PROTOCOL["split"]["group_keys"]


def make_dataset(shift: float, groups: int = 6, per_group: int = 24,
                 seed: int = 7, group_offset: float = 0.0) -> Dataset:
    """Two arms of Gaussian features separated by `shift` standard deviations.

    `group_offset` adds a per-group bias applied to *both* arms, standing in for
    capture-day or host effects that shift everything without distinguishing
    the arms.
    """
    rng = random.Random(seed)
    dataset = Dataset(feature_names=("a", "b", "c"))
    for g in range(groups):
        bias = rng.gauss(0.0, group_offset) if group_offset else 0.0
        for i in range(per_group):
            label = i % 2
            features = tuple(
                rng.gauss(0.0, 1.0) + bias + (shift if label == 1 else 0.0)
                for _ in range(3))
            dataset.sessions.append(Session(label, f"group={g}", features))
    return dataset


class MetricTest(unittest.TestCase):
    def test_auc_handles_constant_scores(self) -> None:
        """A classifier that says nothing must score 0.5, not 1.0."""
        self.assertAlmostEqual(roc_auc([1.0] * 6, [1, 0, 1, 0, 1, 0]), 0.5)

    def test_auc_matches_known_values(self) -> None:
        self.assertAlmostEqual(roc_auc([0.1, 0.2, 0.3, 0.4], [0, 0, 1, 1]), 1.0)
        self.assertAlmostEqual(roc_auc([0.4, 0.3, 0.2, 0.1], [0, 0, 1, 1]), 0.0)
        self.assertAlmostEqual(roc_auc([0.1, 0.3, 0.2, 0.4], [0, 0, 1, 1]), 0.75)

    def test_average_precision_bounds(self) -> None:
        self.assertAlmostEqual(average_precision([0.9, 0.8, 0.2, 0.1], [1, 1, 0, 0]), 1.0)
        self.assertLess(average_precision([0.1, 0.2, 0.8, 0.9], [1, 1, 0, 0]), 0.6)

    def test_tpr_at_fpr_respects_ties(self) -> None:
        """Tied scores move as one group; a threshold cannot split them."""
        self.assertAlmostEqual(tpr_at_fpr([1.0] * 4, [1, 1, 0, 0], 0.01), 0.0)
        self.assertAlmostEqual(tpr_at_fpr([9.0, 8.0, 1.0, 0.5], [1, 1, 0, 0], 0.01), 1.0)


class GateCalibrationTest(unittest.TestCase):
    def test_identical_arms_pass(self) -> None:
        """No real difference means no advantage: the null case must pass."""
        result = evaluate(make_dataset(shift=0.0), PROTOCOL, DIGEST)
        self.assertEqual(result["verdict"], "PASS", result["reasons"])
        for name, entry in result["classifiers"].items():
            self.assertLess(abs(entry["roc_auc"] - 0.5), 0.15, f"{name}: {entry}")
            self.assertLessEqual(entry["roc_auc_ci"][0], 0.5 + 1e-9)

    def test_separable_arms_fail(self) -> None:
        """A blatant difference must be caught by every classifier."""
        result = evaluate(make_dataset(shift=3.0), PROTOCOL, DIGEST)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(result["reasons"])
        for name, entry in result["classifiers"].items():
            self.assertGreater(entry["roc_auc"], 0.9, f"{name}: {entry}")

    def test_subtle_difference_is_detected(self) -> None:
        """Sensitivity, not just the extremes: a modest shift must not pass."""
        result = evaluate(make_dataset(shift=1.0, per_group=40), PROTOCOL, DIGEST)
        self.assertEqual(result["verdict"], "FAIL", result)

    def test_group_structure_alone_creates_no_advantage(self) -> None:
        """Per-group offsets shift both arms together.

        This is the failure mode the leave-one-group-out split exists to
        prevent: a random split lets a model learn the capture day and report
        an advantage no observer has.
        """
        result = evaluate(
            make_dataset(shift=0.0, group_offset=2.0, per_group=40),
            PROTOCOL, DIGEST)
        self.assertEqual(result["verdict"], "PASS", result["reasons"])

    def test_verdict_uses_the_strongest_classifier(self) -> None:
        """The adversary picks the best model, so one failing model fails all."""
        result = evaluate(make_dataset(shift=3.0), PROTOCOL, DIGEST)
        self.assertGreater(result["worst_roc_auc_upper_ci"],
                           PROTOCOL["decision"]["roc_auc_upper_ci_max"])


class PreconditionTest(unittest.TestCase):
    def test_too_few_groups_is_insufficient_not_pass(self) -> None:
        """An unusable dataset must never be scripted as a pass."""
        result = evaluate(make_dataset(shift=0.0, groups=2), PROTOCOL, DIGEST)
        self.assertEqual(result["verdict"], "INSUFFICIENT")
        self.assertTrue(any("groups" in r for r in result["reasons"]))

    def test_too_few_sessions_is_insufficient(self) -> None:
        result = evaluate(make_dataset(shift=0.0, groups=6, per_group=4),
                          PROTOCOL, DIGEST)
        self.assertEqual(result["verdict"], "INSUFFICIENT")

    def test_single_group_arm_is_rejected(self) -> None:
        """An arm captured on one host cannot support a held-out claim."""
        dataset = make_dataset(shift=0.0)
        dataset.sessions = [
            Session(s.label, "group=0" if s.label == 1 else s.group, s.features)
            for s in dataset.sessions
        ]
        failures = check_preconditions(dataset, PROTOCOL)
        self.assertTrue(any("spans" in f for f in failures), failures)


class LoaderTest(unittest.TestCase):
    def _write(self, document: dict) -> Path:
        path = Path(self.tmp.name) / "features.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _valid_row(self, **overrides) -> dict:
        row = {"label": 1, "features": [0.0, 1.0]}
        row.update({key: "x" for key in GROUP_KEYS})
        row.update(overrides)
        return row

    def test_round_trip(self) -> None:
        path = self._write({"feature_names": ["a", "b"],
                            "sessions": [self._valid_row(), self._valid_row(label=0)]})
        dataset = load_dataset(path, GROUP_KEYS)
        self.assertEqual(len(dataset.sessions), 2)
        self.assertEqual(dataset.feature_names, ("a", "b"))

    def test_missing_group_key_is_rejected(self) -> None:
        row = self._valid_row()
        del row[GROUP_KEYS[0]]
        path = self._write({"feature_names": ["a", "b"], "sessions": [row]})
        with self.assertRaises(GateError):
            load_dataset(path, GROUP_KEYS)

    def test_feature_width_mismatch_is_rejected(self) -> None:
        path = self._write({"feature_names": ["a", "b"],
                            "sessions": [self._valid_row(features=[1.0])]})
        with self.assertRaises(GateError):
            load_dataset(path, GROUP_KEYS)

    def test_non_finite_feature_is_rejected(self) -> None:
        path = self._write({"feature_names": ["a", "b"],
                            "sessions": [self._valid_row(features=[1.0, float("inf")])]})
        with self.assertRaises(GateError):
            load_dataset(path, GROUP_KEYS)

    def test_unknown_label_is_rejected(self) -> None:
        path = self._write({"feature_names": ["a", "b"],
                            "sessions": [self._valid_row(label=2)]})
        with self.assertRaises(GateError):
            load_dataset(path, GROUP_KEYS)


class DeterminismTest(unittest.TestCase):
    def test_same_inputs_give_the_same_verdict(self) -> None:
        """A frozen protocol is only meaningful if the score reproduces."""
        first = evaluate(make_dataset(shift=0.4), PROTOCOL, DIGEST)
        second = evaluate(make_dataset(shift=0.4), PROTOCOL, DIGEST)
        self.assertEqual(json.dumps(first, sort_keys=True),
                         json.dumps(second, sort_keys=True))


if __name__ == "__main__":
    unittest.main(verbosity=1)
