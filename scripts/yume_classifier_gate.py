#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Scores the YUME classifier-resistance gate under a frozen protocol.

The gate answers one question: how much advantage does an observer gain from
the features we hand it, measured on capture groups the classifier never
trained on. It does not decide what those features are; feature extraction is a
separate stage on purpose, so that the decision rules here can be frozen before
any candidate capture exists and cannot be tuned once results are visible.

The protocol document is hashed and pinned. `evaluate` refuses to score against
a protocol whose digest does not match the one recorded in the result, which is
what makes "frozen" mean something after the fact.

Pure standard library, deterministic for a given seed: a qualified capture host
needs no dependency matrix to reproduce a verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

sys.dont_write_bytecode = True

MAX_INPUT_BYTES = 64 * 1024 * 1024
DEFAULT_PROTOCOL = Path(__file__).resolve().parents[1] / "config/classifier_gate_v1.json"


class GateError(ValueError):
    """The inputs or the protocol are unusable."""


# --------------------------------------------------------------------------
# Inputs


@dataclass(frozen=True)
class Session:
    """One complete captured session, the unit the gate scores."""

    label: int          # 1 = YUME arm, 0 = cover arm
    group: str          # capture day / host / network / provider tuple
    features: tuple[float, ...]


@dataclass
class Dataset:
    feature_names: tuple[str, ...]
    sessions: list[Session] = field(default_factory=list)

    def groups(self) -> list[str]:
        seen: dict[str, None] = {}
        for s in self.sessions:
            seen.setdefault(s.group, None)
        return list(seen)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_json(path: Path) -> dict:
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise GateError(f"{path} exceeds {MAX_INPUT_BYTES} bytes")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_dataset(path: Path, group_keys: Sequence[str]) -> Dataset:
    """Reads the feature document produced by the extraction stage."""
    document = _load_json(path)
    names = document.get("feature_names")
    if not isinstance(names, list) or not names:
        raise GateError("feature document needs a non-empty feature_names list")
    rows = document.get("sessions")
    if not isinstance(rows, list) or not rows:
        raise GateError("feature document needs a non-empty sessions list")

    dataset = Dataset(feature_names=tuple(str(n) for n in names))
    width = len(dataset.feature_names)
    for index, row in enumerate(rows):
        try:
            label = int(row["label"])
            values = row["features"]
        except (KeyError, TypeError, ValueError) as error:
            raise GateError(f"session {index} is malformed: {error}") from error
        if label not in (0, 1):
            raise GateError(f"session {index} has label {label}; expected 0 or 1")
        if not isinstance(values, list) or len(values) != width:
            raise GateError(
                f"session {index} has {len(values) if isinstance(values, list) else '?'} "
                f"features; expected {width}")
        numbers = []
        for value in values:
            number = float(value)
            if not math.isfinite(number):
                raise GateError(f"session {index} has a non-finite feature")
            numbers.append(number)
        # The group is the unit of independence. Sessions sharing a capture day,
        # host, network and provider are correlated, so they must never be split
        # across train and test, and the bootstrap resamples them together.
        missing = [key for key in group_keys if key not in row]
        if missing:
            raise GateError(f"session {index} is missing group keys: {missing}")
        group = "|".join(f"{key}={row[key]}" for key in group_keys)
        dataset.sessions.append(Session(label, group, tuple(numbers)))
    return dataset


# --------------------------------------------------------------------------
# Metrics


def roc_auc(scores: Sequence[float], labels: Sequence[int]) -> float:
    """Rank-based AUC (Mann-Whitney U) with correct handling of tied scores.

    Ties matter here: a degenerate classifier that emits one constant score must
    score 0.5, not 1.0, or the gate would read "no separation" as a failure.
    """
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        raise GateError("AUC needs both classes present")
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    index = 0
    while index < len(order):
        stop = index
        while stop + 1 < len(order) and scores[order[stop + 1]] == scores[order[index]]:
            stop += 1
        average = (index + stop) / 2.0 + 1.0
        for position in range(index, stop + 1):
            ranks[order[position]] = average
        index = stop + 1
    positive_rank_sum = sum(ranks[i] for i in range(len(labels)) if labels[i] == 1)
    return (positive_rank_sum - positives * (positives + 1) / 2.0) / (positives * negatives)


def average_precision(scores: Sequence[float], labels: Sequence[int]) -> float:
    """Area under the precision-recall curve, the interpolation-free variant."""
    positives = sum(labels)
    if positives == 0:
        raise GateError("average precision needs at least one positive")
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    true_positives = 0
    total = 0.0
    for seen, index in enumerate(order, start=1):
        if labels[index] == 1:
            true_positives += 1
            total += true_positives / seen
    return total / positives


def tpr_at_fpr(scores: Sequence[float], labels: Sequence[int], target_fpr: float) -> float:
    """Highest true-positive rate reachable without exceeding `target_fpr`.

    Declared in advance because a detector is deployed at a fixed budget for
    false alarms; aggregate AUC hides what happens at the operating point an
    observer would actually choose.
    """
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        raise GateError("TPR@FPR needs both classes present")
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    true_positives = 0
    false_positives = 0
    best = 0.0
    index = 0
    while index < len(order):
        stop = index
        while stop + 1 < len(order) and scores[order[stop + 1]] == scores[order[index]]:
            stop += 1
        # A threshold cannot separate equal scores, so the whole tie group moves
        # together; taking it partially would overstate achievable TPR.
        for position in range(index, stop + 1):
            if labels[order[position]] == 1:
                true_positives += 1
            else:
                false_positives += 1
        if false_positives / negatives <= target_fpr:
            best = max(best, true_positives / positives)
        index = stop + 1
    return best


# --------------------------------------------------------------------------
# Classifiers


def _standardise(rows: Sequence[Sequence[float]]) -> tuple[list[float], list[float]]:
    width = len(rows[0])
    means = [sum(r[j] for r in rows) / len(rows) for j in range(width)]
    deviations = []
    for j in range(width):
        variance = sum((r[j] - means[j]) ** 2 for r in rows) / max(1, len(rows) - 1)
        deviations.append(math.sqrt(variance) if variance > 0 else 1.0)
    return means, deviations


def _apply(row: Sequence[float], means: Sequence[float], deviations: Sequence[float]):
    return [(row[j] - means[j]) / deviations[j] for j in range(len(row))]


def logistic_regression(train: Sequence[Session], test: Sequence[Session],
                        seed: int) -> list[float]:
    """L2-regularised logistic regression by full-batch gradient descent."""
    rows = [s.features for s in train]
    means, deviations = _standardise(rows)
    design = [_apply(r, means, deviations) for r in rows]
    targets = [float(s.label) for s in train]
    width = len(design[0])
    weights = [0.0] * width
    bias = 0.0
    rate = 0.5
    penalty = 1e-3
    for _ in range(300):
        gradient = [0.0] * width
        gradient_bias = 0.0
        for row, target in zip(design, targets):
            z = bias + sum(weights[j] * row[j] for j in range(width))
            # Clamped to keep exp() finite on strongly separable inputs.
            prediction = 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, z))))
            error = prediction - target
            for j in range(width):
                gradient[j] += error * row[j]
            gradient_bias += error
        scale = rate / len(design)
        for j in range(width):
            weights[j] -= scale * gradient[j] + rate * penalty * weights[j]
        bias -= scale * gradient_bias
    del seed  # deterministic; no stochastic component
    return [bias + sum(weights[j] * v[j] for j in range(width))
            for v in (_apply(s.features, means, deviations) for s in test)]


def gaussian_naive_bayes(train: Sequence[Session], test: Sequence[Session],
                         seed: int) -> list[float]:
    """Closed-form contrast to the linear model; different inductive bias."""
    del seed
    width = len(train[0].features)
    summary = {}
    for label in (0, 1):
        rows = [s.features for s in train if s.label == label]
        if not rows:
            raise GateError("naive Bayes needs both classes in every training fold")
        means = [sum(r[j] for r in rows) / len(rows) for j in range(width)]
        variances = []
        for j in range(width):
            variance = sum((r[j] - means[j]) ** 2 for r in rows) / max(1, len(rows) - 1)
            # Floor keeps a constant feature from producing an infinite
            # log-likelihood and a spurious perfect separation.
            variances.append(max(variance, 1e-9))
        summary[label] = (means, variances, math.log(len(rows) / len(train)))
    scores = []
    for session in test:
        log_odds = 0.0
        for label, sign in ((1, 1.0), (0, -1.0)):
            means, variances, prior = summary[label]
            total = prior
            for j in range(width):
                total -= 0.5 * (math.log(2 * math.pi * variances[j]) +
                                (session.features[j] - means[j]) ** 2 / variances[j])
            log_odds += sign * total
        scores.append(log_odds)
    return scores


CLASSIFIERS = {
    "logistic_regression": logistic_regression,
    "gaussian_naive_bayes": gaussian_naive_bayes,
}


# --------------------------------------------------------------------------
# Evaluation


def leave_one_group_out(dataset: Dataset, classifier: str, seed: int
                        ) -> tuple[list[float], list[int], list[str]]:
    """Out-of-fold scores, holding out one whole group at a time.

    Holding out groups rather than random sessions is the point of the gate: a
    random split lets the classifier memorise a capture day or host and report
    an advantage that no real observer has.
    """
    fit = CLASSIFIERS[classifier]
    scores: list[float] = []
    labels: list[int] = []
    groups: list[str] = []
    for held_out in dataset.groups():
        train = [s for s in dataset.sessions if s.group != held_out]
        test = [s for s in dataset.sessions if s.group == held_out]
        if not test:
            continue
        if len({s.label for s in train}) < 2:
            raise GateError(
                f"holding out {held_out} leaves one class in training; "
                "arms must be spread across groups")
        scores.extend(fit(train, test, seed))
        labels.extend(s.label for s in test)
        groups.extend(s.group for s in test)
    return scores, labels, groups


def bootstrap_interval(scores: Sequence[float], labels: Sequence[int],
                       groups: Sequence[str], statistic, resamples: int,
                       confidence: float, seed: int) -> tuple[float, float]:
    """Percentile interval resampling whole groups, not individual sessions.

    Sessions inside a group are correlated, so resampling them independently
    would shrink the interval and overstate confidence in a pass.
    """
    by_group: dict[str, list[int]] = {}
    for index, group in enumerate(groups):
        by_group.setdefault(group, []).append(index)
    names = list(by_group)
    rng = random.Random(seed)
    samples = []
    for _ in range(resamples):
        picked: list[int] = []
        for _ in names:
            picked.extend(by_group[names[rng.randrange(len(names))]])
        drawn_labels = [labels[i] for i in picked]
        if len(set(drawn_labels)) < 2:
            continue
        samples.append(statistic([scores[i] for i in picked], drawn_labels))
    if not samples:
        raise GateError("bootstrap produced no usable resample")
    samples.sort()
    tail = (1.0 - confidence) / 2.0
    low = samples[max(0, int(math.floor(tail * len(samples))))]
    high = samples[min(len(samples) - 1, int(math.ceil((1.0 - tail) * len(samples))) - 1)]
    return low, high


def check_preconditions(dataset: Dataset, protocol: dict) -> list[str]:
    """Reasons the dataset cannot support a verdict at all."""
    rules = protocol["preconditions"]
    failures = []
    groups = dataset.groups()
    if len(groups) < rules["min_groups"]:
        failures.append(f"{len(groups)} groups < required {rules['min_groups']}")
    for label, name in ((1, "yume"), (0, "cover")):
        count = sum(1 for s in dataset.sessions if s.label == label)
        if count < rules["min_sessions_per_class"]:
            failures.append(
                f"{name} arm has {count} sessions < required "
                f"{rules['min_sessions_per_class']}")
        spread = len({s.group for s in dataset.sessions if s.label == label})
        if spread < rules["min_groups_per_class"]:
            failures.append(
                f"{name} arm spans {spread} groups < required "
                f"{rules['min_groups_per_class']}")
    return failures


def evaluate(dataset: Dataset, protocol: dict, protocol_digest: str) -> dict:
    decision = protocol["decision"]
    seed = int(protocol["seed"])
    result = {
        "schema": "yume.classifier-gate-result/1",
        "protocol_id": protocol["id"],
        "protocol_sha256": protocol_digest,
        "groups": len(dataset.groups()),
        "sessions": len(dataset.sessions),
        "features": list(dataset.feature_names),
        "classifiers": {},
        "does_not_prove": protocol["does_not_prove"],
    }

    blocking = check_preconditions(dataset, protocol)
    if blocking:
        result["verdict"] = "INSUFFICIENT"
        result["reasons"] = blocking
        return result

    reasons: list[str] = []
    worst_auc_upper = 0.0
    for name in protocol["classifiers"]:
        if name not in CLASSIFIERS:
            raise GateError(f"protocol names an unknown classifier: {name}")
        scores, labels, groups = leave_one_group_out(dataset, name, seed)
        auc = roc_auc(scores, labels)
        auc_low, auc_high = bootstrap_interval(
            scores, labels, groups, roc_auc,
            int(decision["bootstrap_resamples"]), float(decision["confidence"]), seed)
        entry = {
            "roc_auc": round(auc, 6),
            "roc_auc_ci": [round(auc_low, 6), round(auc_high, 6)],
            "average_precision": round(average_precision(scores, labels), 6),
            "tpr_at_fpr": {},
        }
        if auc_high > float(decision["roc_auc_upper_ci_max"]):
            reasons.append(
                f"{name}: ROC-AUC upper CI {auc_high:.4f} exceeds "
                f"{decision['roc_auc_upper_ci_max']}")
        worst_auc_upper = max(worst_auc_upper, auc_high)
        for target, ceiling in decision["tpr_at_fpr_max"].items():
            observed = tpr_at_fpr(scores, labels, float(target))
            entry["tpr_at_fpr"][target] = round(observed, 6)
            if observed > float(ceiling):
                reasons.append(
                    f"{name}: TPR {observed:.4f} at FPR {target} exceeds {ceiling}")
        result["classifiers"][name] = entry

    # The adversary picks the best classifier, so the gate is judged on the
    # strongest one, never on an average across them.
    result["worst_roc_auc_upper_ci"] = round(worst_auc_upper, 6)
    result["verdict"] = "FAIL" if reasons else "PASS"
    result["reasons"] = reasons
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("features", type=Path,
                        help="feature document from the extraction stage")
    parser.add_argument("--protocol", type=Path, default=DEFAULT_PROTOCOL)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    protocol = _load_json(args.protocol)
    digest = _digest(args.protocol)
    dataset = load_dataset(args.features, protocol["split"]["group_keys"])
    result = evaluate(dataset, protocol, digest)

    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    # PASS 0, FAIL 1, INSUFFICIENT 2 -- an unusable dataset must never be
    # scripted as if it were a pass.
    return {"PASS": 0, "FAIL": 1, "INSUFFICIENT": 2}[result["verdict"]]


if __name__ == "__main__":
    try:
        sys.exit(main())
    except GateError as error:
        print(f"classifier gate error: {error}", file=sys.stderr)
        sys.exit(3)
