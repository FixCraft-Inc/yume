#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Runs a YUME workload under an explicit resource tier and reports what it used.

`docs/OPERATIONS.md` names two future qualification targets, a 1-vCPU/1-GiB host
and a 2-vCPU/2-GiB host, and states the rule that makes them meaningful:
resource pressure must never silently downgrade cryptography or change cover
identity. A tier passes with post-quantum establishment, ratcheting,
verification and fail-closed behaviour fully on, or it does not pass.

Limits are applied with a transient systemd user scope, so no privilege is
required where the cpu, memory and pids controllers are delegated to the user
slice. Accounting is read from the scope's own cgroup rather than sampled from
outside: `memory.peak` and `pids.peak` are exact high-water marks, where a
sampler only sees whatever it happened to catch between polls.

Swap is pinned to zero. A tier that silently swaps is not the tier it claims.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Sequence

sys.dont_write_bytecode = True

KIB = 1024
MIB = 1024 * KIB


class TierError(RuntimeError):
    """The tier cannot be applied or the run cannot be trusted."""


@dataclass(frozen=True)
class Tier:
    name: str
    cpus: float
    memory_bytes: int
    tasks_max: int

    @property
    def cpu_quota_percent(self) -> int:
        return int(round(self.cpus * 100))


TIERS = {
    "1v1g": Tier("1v1g", 1.0, 1024 * MIB, 512),
    "2v2g": Tier("2v2g", 2.0, 2048 * MIB, 1024),
}


@dataclass
class Usage:
    memory_peak_bytes: int | None = None
    memory_events: dict | None = None
    pids_peak: int | None = None
    cpu_usage_usec: int | None = None
    cpu_throttled_usec: int | None = None
    cpu_nr_throttled: int | None = None
    fd_peak: int | None = None


def _steady_drift(samples: Sequence[int]) -> int | None:
    """Peak in the second half minus peak in the first half.

    Positive drift across a repeated workload means resources are not being
    returned between iterations. Needs at least four samples to mean anything.
    """
    if len(samples) < 4:
        return None
    half = len(samples) // 2
    return max(samples[half:]) - max(samples[:half])


def percentiles(values: Sequence[float]) -> dict:
    """p50/p95/p99 by nearest-rank on the sorted sample.

    Nearest-rank rather than interpolation: with the small sample counts a tier
    run produces, an interpolated p99 reports a number that was never observed.
    """
    if not values:
        return {}
    ordered = sorted(values)
    out = {"n": len(ordered), "min": ordered[0], "max": ordered[-1]}
    for label, q in (("p50", 0.50), ("p95", 0.95), ("p99", 0.99)):
        rank = max(1, math.ceil(q * len(ordered)))
        out[label] = ordered[rank - 1]
    out["mean"] = sum(ordered) / len(ordered)
    return {k: (round(v, 4) if isinstance(v, float) else v) for k, v in out.items()}


def extract_metric(document: object, dotted: str) -> float | None:
    """Reads one numeric value by dotted path, with [i] for list indices."""
    node = document
    for part in dotted.split("."):
        if part.endswith("]") and "[" in part:
            name, _, index = part.partition("[")
            if name:
                if not isinstance(node, dict) or name not in node:
                    return None
                node = node[name]
            try:
                node = node[int(index.rstrip("]"))]
            except (IndexError, TypeError, ValueError):
                return None
        else:
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
    if isinstance(node, bool) or not isinstance(node, (int, float)):
        return None
    return float(node)


def _read_int(path: Path) -> int | None:
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def _read_keyed(path: Path) -> dict:
    values: dict[str, int] = {}
    try:
        for line in path.read_text().splitlines():
            parts = line.split()
            if len(parts) == 2:
                try:
                    values[parts[0]] = int(parts[1])
                except ValueError:
                    continue
    except OSError:
        pass
    return values


def collect_usage(cgroup_dir: Path) -> Usage:
    """Reads the high-water marks the kernel kept for this scope."""
    cpu = _read_keyed(cgroup_dir / "cpu.stat")
    return Usage(
        memory_peak_bytes=_read_int(cgroup_dir / "memory.peak"),
        memory_events=_read_keyed(cgroup_dir / "memory.events") or None,
        pids_peak=_read_int(cgroup_dir / "pids.peak"),
        cpu_usage_usec=cpu.get("usage_usec"),
        cpu_throttled_usec=cpu.get("throttled_usec"),
        cpu_nr_throttled=cpu.get("nr_throttled"),
    )


def count_open_fds(cgroup_dir: Path) -> int | None:
    """Open descriptors across every process in the scope.

    `pids.peak` counts tasks; a descriptor leak shows up here and nowhere else,
    and a small host runs out of fds long before it runs out of memory.
    """
    procs = cgroup_dir / "cgroup.procs"
    try:
        pids = [int(line) for line in procs.read_text().split()]
    except (OSError, ValueError):
        return None
    total = 0
    for pid in pids:
        try:
            total += len(list(Path(f"/proc/{pid}/fd").iterdir()))
        except OSError:
            continue  # the process exited between listing and counting
    return total


def user_delegation_available() -> tuple[bool, str]:
    """True when cpu, memory and pids are delegated to this user's slice."""
    if shutil.which("systemd-run") is None:
        return False, "systemd-run is not installed"
    base = Path("/sys/fs/cgroup")
    if not (base / "cgroup.controllers").exists():
        return False, "cgroup v2 is not mounted at /sys/fs/cgroup"
    for candidate in base.glob("user.slice/user-*.slice/user@*.service/cgroup.controllers"):
        available = set(candidate.read_text().split())
        missing = {"cpu", "memory", "pids"} - available
        if not missing:
            return True, "cpu, memory and pids delegated"
        return False, f"controllers not delegated to the user slice: {sorted(missing)}"
    return False, "no delegated user slice found"


# The run must prove the full stack stayed on. A workload that prints nothing
# about its cryptography proves nothing, so absence is treated as a downgrade.
# Which text carries that proof depends on the workload -- the local benchmark
# names the suite in the daemon and client logs it leaves behind, not on stdout
# -- so callers can point at those with --evidence and adjust the patterns.
REQUIRED_MARKERS = (
    re.compile(r"\bml[-_ ]?kem", re.IGNORECASE),
    re.compile(r"\bratchet", re.IGNORECASE),
)
FORBIDDEN_MARKERS = (
    re.compile(r"\bno[-_ ]?inner\b", re.IGNORECASE),
    re.compile(r"falling back to", re.IGNORECASE),
    re.compile(r"\bdowngrad", re.IGNORECASE),
)
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024


def collect_evidence(globs: Sequence[str], not_before: float) -> tuple[str, list[str]]:
    """Reads log evidence produced by this run.

    Restricted to paths modified at or after the run started: a stale directory
    from an earlier run must never be able to satisfy the downgrade check for
    this one.
    """
    text: list[str] = []
    used: list[str] = []
    for pattern in globs:
        for path in sorted(Path("/").glob(pattern.lstrip("/"))):
            candidates = []
            if path.is_dir():
                candidates = sorted(path.rglob("*.log"))
            elif path.is_file():
                candidates = [path]
            for candidate in candidates:
                try:
                    if candidate.stat().st_mtime < not_before:
                        continue
                    if candidate.stat().st_size > MAX_EVIDENCE_BYTES:
                        continue
                    text.append(candidate.read_text(errors="replace"))
                    used.append(str(candidate))
                except OSError:
                    continue
    return "\n".join(text), used


def check_no_downgrade(output: str,
                       required: Sequence[re.Pattern] = REQUIRED_MARKERS,
                       forbidden: Sequence[re.Pattern] = FORBIDDEN_MARKERS
                       ) -> list[str]:
    problems = []
    for pattern in required:
        if not pattern.search(output):
            problems.append(f"expected evidence of {pattern.pattern} in workload output")
    for pattern in forbidden:
        match = pattern.search(output)
        if match:
            problems.append(f"workload output contains {match.group(0)!r}")
    return problems


def _find_scope_cgroup(unit: str) -> Path | None:
    base = Path("/sys/fs/cgroup/user.slice")
    for candidate in base.glob(f"user-*.slice/user@*.service/*/{unit}"):
        return candidate
    for candidate in base.glob(f"user-*.slice/user@*.service/{unit}"):
        return candidate
    return None


def _poll_usage(unit: str, stop: threading.Event, out: list[Usage]) -> None:
    """Samples the scope's accounting from outside, until it disappears.

    Reading from inside the scope is not enough: when the tier limit is what
    kills the workload, systemd tears the whole scope down and any in-scope
    copy step dies with it, which is exactly the case the accounting is needed
    for. `memory.peak` is monotonic and `memory.events` only counts up, so the
    last successful sample is still the high-water mark.
    """
    cgroup: Path | None = None
    while not stop.is_set():
        if cgroup is None or not cgroup.exists():
            cgroup = _find_scope_cgroup(unit)
        if cgroup is not None and cgroup.exists():
            usage = collect_usage(cgroup)
            if usage.memory_peak_bytes is not None:
                usage.fd_peak = count_open_fds(cgroup)
                if out and out[-1].fd_peak is not None:
                    usage.fd_peak = max(usage.fd_peak or 0, out[-1].fd_peak)
                out.append(usage)
        stop.wait(0.05)


def run_in_tier(tier: Tier, command: Sequence[str], timeout_sec: int,
                repeat: int = 1
                ) -> tuple[subprocess.CompletedProcess, Usage, list[float]]:
    """Runs `command` inside a transient scope and returns its cgroup usage.

    With `repeat` above one the iterations share a single scope, so the limits
    apply to the whole series and the accounting is a high-water mark across it.
    That is the point: a descriptor or task leak only shows up once the same
    session work has run many times under one budget.
    """
    unit = f"yume-tier-{os.getpid()}-{int(time.time())}.scope"
    with tempfile.TemporaryDirectory(prefix="yume-tier-") as tmp:
        usage_dir = Path(tmp) / "usage"
        usage_dir.mkdir()
        # Exact snapshot when the workload exits normally; the poller below
        # covers the case where the scope is torn down instead.
        inner = (
            'rc=0; '
            f'for i in $(seq 1 {int(repeat)}); do '
            '  YUME_TIER_ITERATION=$i "$@" || { rc=$?; break; }; '
            'done; '
            'cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); '
            f'for f in memory.peak memory.events pids.peak cpu.stat; do '
            f'  cp "$cg/$f" "{usage_dir}/$f" 2>/dev/null || true; '
            'done; exit $rc'
        )
        scope = [
            "systemd-run", "--user", "--scope", "--quiet", f"--unit={unit}",
            "--property", f"CPUQuota={tier.cpu_quota_percent}%",
            "--property", f"MemoryMax={tier.memory_bytes}",
            "--property", "MemorySwapMax=0",
            "--property", f"TasksMax={tier.tasks_max}",
            "--", "bash", "-c", inner, "yume-tier", *command,
        ]
        sampled: list[Usage] = []
        stop = threading.Event()
        poller = threading.Thread(target=_poll_usage, args=(unit, stop, sampled),
                                  daemon=True)
        poller.start()
        started = time.monotonic()
        try:
            completed = subprocess.run(
                scope, capture_output=True, text=True, timeout=timeout_sec,
                check=False)
        finally:
            stop.set()
            poller.join(timeout=2.0)
        completed.elapsed_sec = round(time.monotonic() - started, 3)  # type: ignore[attr-defined]

        fd_samples = [u.fd_peak for u in sampled if u.fd_peak is not None]
        exact = collect_usage(usage_dir)
        if exact.memory_peak_bytes is not None:
            exact.fd_peak = max(fd_samples, default=None)
            return completed, exact, fd_samples
        if sampled:
            sampled[-1].fd_peak = max(fd_samples, default=None)
            return completed, sampled[-1], fd_samples
        return completed, exact, fd_samples


def evaluate(tier: Tier, completed: subprocess.CompletedProcess, usage: Usage,
             evidence: str = "") -> tuple[str, list[str]]:
    reasons: list[str] = []
    if completed.returncode != 0:
        reasons.append(f"workload exited {completed.returncode}")

    events = usage.memory_events or {}
    # `oom_kill` means the tier could not hold the workload at all; `max` means
    # it only survived by reclaiming under pressure, which is worth reporting
    # even when the run succeeded.
    if events.get("oom_kill"):
        reasons.append(f"workload was OOM-killed ({events['oom_kill']} times)")
    if usage.memory_peak_bytes is None:
        reasons.append("no memory accounting was recorded; tier not proven")
    elif usage.memory_peak_bytes > tier.memory_bytes:
        reasons.append("peak memory exceeded the tier limit")

    downgrades = check_no_downgrade(
        completed.stdout + completed.stderr + evidence)
    reasons.extend(downgrades)

    verdict = "PASS" if not reasons else "FAIL"
    return verdict, reasons


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tier", choices=sorted(TIERS), required=True)
    parser.add_argument("--timeout-sec", type=int, default=1800)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--repeat", type=int, default=1, metavar="N",
        help="run the workload N times in one scope; required for handshake "
             "and rekey percentiles, and for leak detection")
    parser.add_argument(
        "--collect", action="append", default=[], metavar="NAME=GLOB:PATH",
        help="after each iteration read the newest file matching GLOB and "
             "extract the numeric JSON value at dotted PATH, reporting "
             "p50/p95/p99 across iterations (repeatable)")
    parser.add_argument(
        "--evidence", action="append", default=[], metavar="GLOB",
        help="file or directory glob holding proof the crypto stack stayed on; "
             "directories are scanned for *.log. Only paths modified during "
             "this run are read, so a stale tree cannot satisfy the check.")
    parser.add_argument("command", nargs=argparse.REMAINDER,
                        help="workload command, after --")
    args = parser.parse_args(argv)

    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a workload command is required after --")

    available, detail = user_delegation_available()
    if not available:
        raise TierError(
            f"cannot apply a resource tier: {detail}. "
            "Delegation is required so the run is bounded by the kernel rather "
            "than by hope; a tier claim without it would be unfounded.")

    if args.repeat < 1:
        parser.error("--repeat must be at least 1")
    collectors = []
    for spec in args.collect:
        name, _, rest = spec.partition("=")
        glob_part, _, dotted = rest.partition(":")
        if not name or not glob_part or not dotted:
            parser.error(f"--collect expects NAME=GLOB:PATH, got {spec!r}")
        collectors.append((name, glob_part, dotted))

    tier = TIERS[args.tier]
    run_started = time.time()
    completed, usage, fd_samples = run_in_tier(
        tier, command, args.timeout_sec, args.repeat)
    evidence_text, evidence_files = collect_evidence(args.evidence, run_started)
    verdict, reasons = evaluate(tier, completed, usage, evidence_text)

    metrics: dict[str, dict] = {}
    for name, glob_part, dotted in collectors:
        values: list[float] = []
        for path in sorted(Path("/").glob(glob_part.lstrip("/"))):
            try:
                if path.stat().st_mtime < run_started or not path.is_file():
                    continue
                value = extract_metric(json.loads(path.read_text()), dotted)
            except (OSError, ValueError):
                continue
            if value is not None:
                values.append(value)
        if values:
            metrics[name] = percentiles(values)
        else:
            reasons.append(f"--collect {name}: no samples matched {glob_part}:{dotted}")
            verdict = "FAIL" if verdict == "PASS" else verdict

    report = {
        "schema": "yume.constrained-host/1",
        "tier": asdict(tier),
        "delegation": detail,
        "command": command,
        "exit_code": completed.returncode,
        "elapsed_sec": getattr(completed, "elapsed_sec", None),
        "usage": asdict(usage),
        "headroom": {
            # Second half against first half, not last against first: every
            # run ramps from zero to its working set, so a first-to-last delta
            # reports startup as if it were a leak. Steady-state drift is the
            # signal, and it needs enough iterations to have a steady state.
            "fd_steady_drift": _steady_drift(fd_samples),
            "memory_peak_fraction": (
                round(usage.memory_peak_bytes / tier.memory_bytes, 4)
                if usage.memory_peak_bytes else None),
            "cpu_throttled": bool(usage.cpu_nr_throttled),
        },
        "repeat": args.repeat,
        "metrics": metrics,
        "evidence_files": evidence_files,
        "verdict": verdict,
        "reasons": reasons,
        "does_not_prove": [
            "That a real host of this size behaves identically; this bounds "
            "resources, it does not emulate slower cores, storage or NICs.",
            "Anything about workloads, durations or failure modes not exercised "
            "by the command that was run.",
        ],
    }
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    if verdict != "PASS":
        print("\n--- workload stderr (tail) ---", file=sys.stderr)
        print("\n".join((completed.stderr or "").splitlines()[-20:]), file=sys.stderr)
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TierError as error:
        print(f"constrained-host error: {error}", file=sys.stderr)
        sys.exit(3)
