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
The peaks include the Python worker that runs each iteration and records its
metrics, as well as the workload and its descendants.

Swap is pinned to zero. A tier that silently swaps is not the tier it claims.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import signal
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


def _metric_files(pattern: str) -> dict[Path, tuple[int, int, int, int]]:
    """Snapshot file identities so an unchanged result cannot count twice."""
    files = {}
    for path in Path("/").glob(pattern.lstrip("/")):
        try:
            if path.is_file():
                info = path.stat()
                files[path] = (info.st_mtime_ns, info.st_ctime_ns,
                               info.st_ino, info.st_size)
        except OSError:
            continue
    return files


def _run_workload(configuration: Path) -> int:
    """Internal scope worker; the supervising process owns its deadline.

    Read each result before another iteration can overwrite it. Per-iteration
    snapshots let the supervisor require every sample even after an early exit.
    """
    settings = json.loads(configuration.read_text(encoding="utf-8"))
    usage_dir = Path(settings["usage_dir"])
    collectors = settings["collectors"]
    try:
        for iteration in range(1, settings["repeat"] + 1):
            before = {name: _metric_files(pattern)
                      for name, pattern, _ in collectors}
            environment = dict(os.environ, YUME_TIER_ITERATION=str(iteration))
            # The outer scope deadline covers every iteration and its children.
            result = subprocess.run(settings["command"], env=environment, check=False)
            values = {}
            for name, pattern, dotted in collectors:
                candidates = _metric_files(pattern)
                changed = [path for path, identity in candidates.items()
                           if before[name].get(path) != identity]
                if not changed:
                    continue
                newest = max(changed, key=lambda path: (candidates[path][0], str(path)))
                try:
                    if newest.stat().st_size > MAX_EVIDENCE_BYTES:
                        continue
                    value = extract_metric(json.loads(newest.read_text(encoding="utf-8")), dotted)
                except (OSError, ValueError, OverflowError):
                    continue
                if value is not None and math.isfinite(value):
                    values[name] = value
            (usage_dir / f"iteration-{iteration}.json").write_text(
                json.dumps(values), encoding="utf-8")
            if result.returncode:
                return result.returncode
        return 0
    finally:
        # Exact normal-exit accounting; the external poller covers OOM/timeout.
        try:
            relative = Path("/proc/self/cgroup").read_text().strip().split(":", 2)[2]
            cgroup = Path("/sys/fs/cgroup") / relative.lstrip("/")
            for name in ("memory.peak", "memory.events", "pids.peak", "cpu.stat"):
                try:
                    shutil.copyfile(cgroup / name, usage_dir / name)
                except OSError:
                    pass  # evaluate refuses absent accounting unless sampled
        except (OSError, IndexError):
            pass


def _collected_metrics(usage_dir: Path, collectors: Sequence[tuple[str, str, str]],
                       repeat: int) -> tuple[dict[str, dict], list[str]]:
    samples: dict[str, list[float]] = {name: [] for name, _, _ in collectors}
    for iteration in range(1, repeat + 1):
        try:
            values = json.loads((usage_dir / f"iteration-{iteration}.json").read_text(
                encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for name in samples:
            value = values.get(name) if isinstance(values, dict) else None
            if (not isinstance(value, bool) and isinstance(value, (int, float))
                    and math.isfinite(value)):
                samples[name].append(value)
    problems = [f"--collect {name}: expected {repeat} iteration samples, got {len(values)}"
                for name, values in samples.items() if len(values) != repeat]
    return {name: percentiles(values) for name, values in samples.items()}, problems


def _stop_scope(unit: str, process: subprocess.Popen) -> None:
    """Stop all scope members and reap the launcher, with bounded cleanup."""
    problems = []
    try:
        subprocess.run(["systemctl", "--user", "stop", unit], check=True,
                       capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as error:
        problems.append(f"scope stop failed ({type(error).__name__})")
    # Covers a launcher that failed before creating its scope. Its process group
    # is ours because Popen used start_new_session, never the caller's group.
    if process.returncode is None:
        # An unreaped child still owns its PID. Never signal a reused group ID
        # after communicate already reaped the launcher during interruption.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as error:
            problems.append(f"launcher group kill failed ({type(error).__name__})")
    try:
        process.wait(timeout=5)
    except (OSError, subprocess.SubprocessError) as error:
        problems.append(f"launcher reap failed ({type(error).__name__})")
    if problems:
        raise TierError(f"cannot clean up {unit}: " + "; ".join(problems))


def run_in_tier(tier: Tier, command: Sequence[str], timeout_sec: int,
                repeat: int = 1,
                collectors: Sequence[tuple[str, str, str]] = ()
                ) -> tuple[subprocess.CompletedProcess, Usage, list[int],
                           dict[str, dict], list[str]]:
    """Runs `command` inside a transient scope and returns its cgroup usage.

    With `repeat` above one the iterations share a single scope, so the limits
    apply to the whole series and the accounting is a high-water mark across it.
    That is the point: a descriptor or task leak only shows up once the same
    session work has run many times under one budget.
    """
    with tempfile.TemporaryDirectory(prefix="yume-tier-") as tmp:
        unit = f"{Path(tmp).name}.scope"
        usage_dir = Path(tmp) / "usage"
        usage_dir.mkdir()
        configuration = Path(tmp) / "workload.json"
        configuration.write_text(json.dumps({
            "command": list(command), "repeat": repeat,
            "collectors": list(collectors), "usage_dir": str(usage_dir),
        }), encoding="utf-8")
        scope = [
            "systemd-run", "--user", "--scope", "--quiet", f"--unit={unit}",
            "--property", f"CPUQuota={tier.cpu_quota_percent}%",
            "--property", f"MemoryMax={tier.memory_bytes}",
            "--property", "MemorySwapMax=0",
            "--property", f"TasksMax={tier.tasks_max}",
            "--property", "TimeoutStopSec=5s",
            "--property", "KillMode=control-group",
            "--property", "SendSIGKILL=yes",
            "--", sys.executable, str(Path(__file__).resolve()),
            "--_workload", str(configuration),
        ]
        sampled: list[Usage] = []
        stop = threading.Event()
        poller = threading.Thread(target=_poll_usage, args=(unit, stop, sampled),
                                  daemon=True)
        poller.start()
        started = time.monotonic()
        try:
            process = subprocess.Popen(scope, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True,
                                       start_new_session=True)
            try:
                stdout, stderr = process.communicate(timeout=timeout_sec)
                completed = subprocess.CompletedProcess(
                    scope, process.returncode, stdout, stderr)
            except BaseException:
                # The scope also owns descendants that started new sessions.
                # Killing only systemd-run can leave them alive with our pipes.
                _stop_scope(unit, process)
                raise
            finally:
                process.stdout.close()
                process.stderr.close()
        except subprocess.TimeoutExpired:
            raise TierError(f"workload exceeded its {timeout_sec}-second deadline") from None
        finally:
            stop.set()
            poller.join(timeout=2.0)
        completed.elapsed_sec = round(time.monotonic() - started, 3)  # type: ignore[attr-defined]
        metrics, problems = _collected_metrics(usage_dir, collectors, repeat)

        fd_samples = [u.fd_peak for u in sampled if u.fd_peak is not None]
        exact = collect_usage(usage_dir)
        if exact.memory_peak_bytes is not None:
            exact.fd_peak = max(fd_samples, default=None)
            return completed, exact, fd_samples, metrics, problems
        if sampled:
            sampled[-1].fd_peak = max(fd_samples, default=None)
            return completed, sampled[-1], fd_samples, metrics, problems
        return completed, exact, fd_samples, metrics, problems


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
             "p50/p95/p99 across iterations; each iteration must change a "
             "matching file and supply one finite sample (repeatable)")
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
    if args.timeout_sec < 1:
        parser.error("--timeout-sec must be at least 1")
    collectors = []
    for spec in args.collect:
        name, _, rest = spec.partition("=")
        glob_part, _, dotted = rest.partition(":")
        if not name or not glob_part or not dotted:
            parser.error(f"--collect expects NAME=GLOB:PATH, got {spec!r}")
        if any(existing[0] == name for existing in collectors):
            parser.error(f"--collect name {name!r} is repeated")
        collectors.append((name, glob_part, dotted))

    tier = TIERS[args.tier]
    run_started = time.time()
    completed, usage, fd_samples, metrics, collection_problems = run_in_tier(
        tier, command, args.timeout_sec, args.repeat, collectors)
    evidence_text, evidence_files = collect_evidence(args.evidence, run_started)
    verdict, reasons = evaluate(tier, completed, usage, evidence_text)

    reasons.extend(collection_problems)
    if collection_problems:
        verdict = "FAIL"

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
        if len(sys.argv) == 3 and sys.argv[1] == "--_workload":
            sys.exit(_run_workload(Path(sys.argv[2])))
        sys.exit(main())
    except TierError as error:
        print(f"constrained-host error: {error}", file=sys.stderr)
        sys.exit(3)
