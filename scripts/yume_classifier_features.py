#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Extract passive-observer features from matched capture arms.

The classifier gate (scripts/yume_classifier_gate.py) scores features that a
separate stage extracts, so its decision rules stay frozen. This is that
stage for the TLS record timeline the capture relay records: per session, the
sizes, counts and timing of TLS records in each direction, which is what an
observer of the encrypted connection sees. Nothing here reads payload.

Each session carries the gate's group keys. A single capture campaign is one
group, so its document cannot reach a gate verdict on its own. --describe
prints each feature's range per arm and names features whose ranges do not
overlap. That is a description of these sessions, not a classifier result.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics
import sys
from typing import Any, Sequence

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from yume_classifier_evidence import EvidenceError, load_arm  # noqa: E402

APPLICATION_DATA = 23
FULL_RECORD_BYTES = 16000
SMALL_RECORD_BYTES = 64
DIRECTIONS = ("client_to_server", "server_to_client")
GROUP_KEYS = ("capture_day", "host", "network", "provider")

FEATURE_NAMES: tuple[str, ...] = tuple(
    f"{prefix}.{name}"
    for prefix in ("up", "down")
    for name in ("records", "bytes", "application_records", "mean_length",
                 "max_length", "full_share", "small_records")
) + (
    "session.duration_ms",
    "session.longest_gap_ms",
    "session.gaps_over_1s",
    "session.direction_switches",
    "session.first_download_ms",
)


class FeatureError(ValueError):
    """A timeline is missing, truncated or malformed."""


def _records(timeline: Any, direction: str) -> list[tuple[int, int, int]]:
    if not isinstance(timeline, dict):
        raise FeatureError("the TLS report has no record timeline")
    side = timeline.get(direction)
    if not isinstance(side, dict) or side.get("truncated") is not False or \
            side.get("malformed") is not False:
        raise FeatureError(f"the {direction} timeline is truncated or malformed")
    records = side.get("records")
    if not isinstance(records, list) or not records:
        raise FeatureError(f"the {direction} timeline has no records")
    result = []
    previous = -1
    for record in records:
        if (not isinstance(record, list) or len(record) != 3 or
                not all(isinstance(value, int) and not isinstance(value, bool)
                        for value in record) or record[0] < previous or
                record[1] not in (20, 21, 22, 23) or not 0 <= record[2] <= 18432):
            raise FeatureError(f"the {direction} timeline has a malformed record")
        previous = record[0]
        result.append((record[0], record[1], record[2]))
    return result


def session_features(timeline: Any) -> list[float]:
    """The FEATURE_NAMES values of one session."""
    per_direction = {direction: _records(timeline, direction) for direction in DIRECTIONS}
    values: list[float] = []
    for direction in DIRECTIONS:
        records = per_direction[direction]
        lengths = [length for _, _, length in records]
        values.extend([
            float(len(records)),
            float(sum(lengths)),
            float(sum(1 for _, kind, _ in records if kind == APPLICATION_DATA)),
            statistics.fmean(lengths),
            float(max(lengths)),
            sum(1 for length in lengths if length >= FULL_RECORD_BYTES) / len(lengths),
            float(sum(1 for length in lengths if length < SMALL_RECORD_BYTES)),
        ])
    merged = sorted(
        (time, direction)
        for direction in DIRECTIONS
        for time, _, _ in per_direction[direction]
    )
    times = [time for time, _ in merged]
    gaps = [later - earlier for earlier, later in zip(times, times[1:])]
    switches = sum(1 for (_, a), (_, b) in zip(merged, merged[1:]) if a != b)
    first_download = next(
        (time for time, kind, _ in per_direction["server_to_client"]
         if kind == APPLICATION_DATA), times[-1])
    values.extend([
        (times[-1] - times[0]) / 1000.0,
        (max(gaps) if gaps else 0) / 1000.0,
        float(sum(1 for gap in gaps if gap > 1_000_000)),
        float(switches),
        (first_download - times[0]) / 1000.0,
    ])
    return values


def feature_document(arms: Sequence[tuple[int, Sequence[Any]]],
                     group: dict[str, str]) -> dict[str, Any]:
    """label 0 is the browser arm and 1 the YUME arm, as the gate expects."""
    if set(group) != set(GROUP_KEYS) or not all(group.values()):
        raise FeatureError(f"the group needs exactly {', '.join(GROUP_KEYS)}")
    sessions = []
    for label, reports in arms:
        for report in reports:
            if not isinstance(report, dict):
                raise FeatureError("a TLS report is not an object")
            sessions.append({
                "label": label,
                "features": session_features(report.get("record_timeline")),
                **group,
            })
    return {
        "schema": "yume.classifier-features/1",
        "source": "tls-record-timeline",
        "feature_names": list(FEATURE_NAMES),
        "sessions": sessions,
    }


def describe(document: dict[str, Any]) -> dict[str, Any]:
    """Per-feature ranges for each arm, and which ranges do not overlap."""
    rows = {0: [], 1: []}
    for session in document["sessions"]:
        rows[session["label"]].append(session["features"])
    features = []
    for index, name in enumerate(document["feature_names"]):
        normal = [row[index] for row in rows[0]]
        yume = [row[index] for row in rows[1]]
        features.append({
            "feature": name,
            "browser": [min(normal), statistics.fmean(normal), max(normal)],
            "yume": [min(yume), statistics.fmean(yume), max(yume)],
            "ranges_overlap": not (max(normal) < min(yume) or max(yume) < min(normal)),
        })
    return {
        "sessions": {"browser": len(rows[0]), "yume": len(rows[1])},
        "features": features,
        "non_overlapping": [item["feature"] for item in features
                            if not item["ranges_overlap"]],
        "boundary": "Ranges over these sessions only. Not a held-out classifier result.",
    }


def _group(value: str) -> dict[str, str]:
    result = {}
    for item in value.split(","):
        key, separator, text = item.partition("=")
        if not separator:
            raise argparse.ArgumentTypeError("expected key=value pairs")
        result[key] = text
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--normal", required=True, type=Path)
    parser.add_argument("--yume", required=True, type=Path)
    parser.add_argument("--group", required=True, type=_group,
                        help="capture_day=...,host=...,network=...,provider=...")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--describe", type=Path,
                        help="also write per-feature ranges for each arm")
    args = parser.parse_args()
    try:
        normal = load_arm(args.normal, normal=True)
        yume = load_arm(args.yume, normal=False)
        document = feature_document(((0, normal.tls_runs), (1, yume.tls_runs)), args.group)
        args.output.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")
        if args.describe:
            args.describe.write_text(json.dumps(describe(document), indent=1) + "\n",
                                     encoding="utf-8")
    except (EvidenceError, FeatureError, OSError) as error:
        print(f"classifier features: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
