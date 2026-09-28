#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Focused tests for the passive-observer feature stage."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import yume_classifier_features as features  # noqa: E402
import yume_classifier_gate as gate  # noqa: E402

GROUP = {"capture_day": "2026-09-28", "host": "h", "network": "lo", "provider": "p"}


def timeline(up: list[list[int]], down: list[list[int]]) -> dict[str, object]:
    return {
        "client_to_server": {"records": up, "truncated": False, "malformed": False},
        "server_to_client": {"records": down, "truncated": False, "malformed": False},
    }


SAMPLE = timeline(
    [[0, 22, 512], [3_000, 23, 16384], [2_500_000, 23, 24]],
    [[1_000, 22, 4000], [4_000, 23, 30]],
)


class ClassifierFeaturesTest(unittest.TestCase):
    def test_session_features_follow_the_timeline(self) -> None:
        values = dict(zip(features.FEATURE_NAMES, features.session_features(SAMPLE)))
        self.assertEqual(values["up.records"], 3)
        self.assertEqual(values["up.bytes"], 512 + 16384 + 24)
        self.assertEqual(values["up.application_records"], 2)
        self.assertEqual(values["up.max_length"], 16384)
        self.assertAlmostEqual(values["up.full_share"], 1 / 3)
        self.assertEqual(values["up.small_records"], 1)
        self.assertEqual(values["down.small_records"], 1)
        self.assertEqual(values["session.duration_ms"], 2500.0)
        self.assertEqual(values["session.longest_gap_ms"], 2496.0)
        self.assertEqual(values["session.gaps_over_1s"], 1)
        # up, down, up, down, up
        self.assertEqual(values["session.direction_switches"], 4)
        self.assertEqual(values["session.first_download_ms"], 4.0)

    def test_incomplete_timelines_are_refused(self) -> None:
        for mutate in (
            lambda value: value["client_to_server"].update(truncated=True),
            lambda value: value["server_to_client"].update(malformed=True),
            lambda value: value["client_to_server"].update(records=[]),
            lambda value: value["client_to_server"]["records"].append([1, 23, 5]),
            lambda value: value["server_to_client"]["records"].append([9_000, 99, 5]),
        ):
            broken = copy.deepcopy(SAMPLE)
            mutate(broken)
            with self.subTest(broken=broken), self.assertRaises(features.FeatureError):
                features.session_features(broken)
        with self.assertRaises(features.FeatureError):
            features.session_features(None)

    def test_one_campaign_is_insufficient_for_the_gate(self) -> None:
        document = features.feature_document(((0, [{"record_timeline": SAMPLE}] * 5),
                                              (1, [{"record_timeline": SAMPLE}] * 5)), GROUP)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "features.json"
            path.write_text(json.dumps(document))
            protocol = json.loads(gate.DEFAULT_PROTOCOL.read_text())
            dataset = gate.load_dataset(path, protocol["split"]["group_keys"])
            result = gate.evaluate(dataset, protocol, "0" * 64)
        self.assertEqual(result["verdict"], "INSUFFICIENT")
        with self.assertRaises(features.FeatureError):
            features.feature_document(((0, []),), {"host": "h"})

    def test_describe_names_only_non_overlapping_features(self) -> None:
        longer = copy.deepcopy(SAMPLE)
        longer["client_to_server"]["records"][2][0] = 9_000_000
        document = features.feature_document(
            ((0, [{"record_timeline": SAMPLE}] * 2), (1, [{"record_timeline": longer}] * 2)),
            GROUP)
        summary = features.describe(document)
        self.assertIn("session.duration_ms", summary["non_overlapping"])
        self.assertNotIn("up.records", summary["non_overlapping"])
        self.assertIn("Not a held-out classifier result", summary["boundary"])


if __name__ == "__main__":
    unittest.main()
