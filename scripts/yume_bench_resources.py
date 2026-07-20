#!/usr/bin/env python3
"""Low-overhead Linux process and host resource sampling for benchmarks."""

from __future__ import annotations

import json
import os
import platform
import statistics
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path


MIB = 1024 * 1024
MAX_RETAINED_SAMPLES = 10_000


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _read_khz(path: Path) -> float | None:
    raw = _read_text(path)
    if raw is None:
        return None
    try:
        return float(raw.strip()) / 1000.0
    except ValueError:
        return None


def _round(value: float, digits: int = 3) -> float:
    return round(value, digits)


def host_resource_info() -> dict[str, object]:
    """Return portable-capacity context for interpreting process percentages."""
    available_cpus = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else []
    logical_cpus = os.cpu_count() or 1
    if not available_cpus:
        available_cpus = list(range(logical_cpus))

    cpuinfo = _read_text(Path("/proc/cpuinfo")) or ""
    model = "unknown"
    physical_pairs: set[tuple[str, str]] = set()
    current_entry: dict[str, str] = {}
    cpu_mhz: list[float] = []
    for line in [*cpuinfo.splitlines(), ""]:
        if not line.strip():
            if "physical id" in current_entry and "core id" in current_entry:
                physical_pairs.add((current_entry["physical id"], current_entry["core id"]))
            current_entry = {}
            continue
        if ":" not in line:
            continue
        key, value = (item.strip() for item in line.split(":", 1))
        current_entry[key] = value
        if key == "model name" and model == "unknown":
            model = value
        elif key == "cpu MHz":
            try:
                cpu_mhz.append(float(value))
            except ValueError:
                pass

    frequency_min: list[float] = []
    frequency_max: list[float] = []
    frequency_current: list[float] = []
    for cpu in available_cpus:
        cpufreq = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq")
        minimum = _read_khz(cpufreq / "cpuinfo_min_freq")
        maximum = _read_khz(cpufreq / "cpuinfo_max_freq")
        current = _read_khz(cpufreq / "scaling_cur_freq")
        if minimum is not None:
            frequency_min.append(minimum)
        if maximum is not None:
            frequency_max.append(maximum)
        if current is not None:
            frequency_current.append(current)
    if not frequency_current:
        frequency_current = cpu_mhz

    meminfo = _read_text(Path("/proc/meminfo")) or ""
    memory_total_bytes: int | None = None
    for line in meminfo.splitlines():
        if line.startswith("MemTotal:"):
            try:
                memory_total_bytes = int(line.split()[1]) * 1024
            except (IndexError, ValueError):
                pass
            break

    def range_summary(values: list[float]) -> dict[str, float] | None:
        if not values:
            return None
        return {
            "min": _round(min(values), 1),
            "median": _round(statistics.median(values), 1),
            "max": _round(max(values), 1),
        }

    return {
        "hostname": platform.node(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "cpu_model": model,
        "physical_cores": len(physical_pairs) or None,
        "logical_cpus": logical_cpus,
        "available_logical_cpus": len(available_cpus),
        "cpu_affinity": available_cpus,
        "frequency_mhz": {
            "hardware_min": _round(min(frequency_min), 1) if frequency_min else None,
            "hardware_max": _round(max(frequency_max), 1) if frequency_max else None,
            "current_snapshot": range_summary(frequency_current),
        },
        "memory_total_bytes": memory_total_bytes,
        "memory_total_gib": (
            _round(memory_total_bytes / (1024**3), 2)
            if memory_total_bytes is not None
            else None
        ),
    }


def _parse_proc_stat(raw: str) -> dict[str, int] | None:
    closing = raw.rfind(")")
    if closing < 0:
        return None
    prefix = raw[:closing]
    tail = raw[closing + 2 :].split()
    try:
        return {
            "pid": int(prefix.split("(", 1)[0].strip()),
            "pgrp": int(tail[2]),
            "user_ticks": int(tail[11]),
            "system_ticks": int(tail[12]),
            "threads": int(tail[17]),
            "start_ticks": int(tail[19]),
            "rss_pages": int(tail[21]),
        }
    except (IndexError, ValueError):
        return None


class ProcessResourceSampler:
    """Sample one new-session process group without instrumenting its binaries."""

    def __init__(self, process_group_id: int, interval_ms: int = 250) -> None:
        self.process_group_id = process_group_id
        self.interval_ms = interval_ms
        self._clock_ticks = os.sysconf("SC_CLK_TCK")
        self._page_size = os.sysconf("SC_PAGE_SIZE")
        self._available_cpus = (
            len(os.sched_getaffinity(0))
            if hasattr(os, "sched_getaffinity")
            else (os.cpu_count() or 1)
        )
        self._started = time.monotonic()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._capture_lock = threading.Lock()
        self._samples: deque[dict[str, float | int | str]] = deque(
            maxlen=MAX_RETAINED_SAMPLES
        )
        self._sample_count = 0
        self._known_processes = {process_group_id}
        self._cpu_by_process: dict[tuple[int, int], tuple[int, int]] = {}

    def start(self) -> None:
        self._capture()
        self._thread = threading.Thread(
            target=self._run,
            name=f"yume-resource-sampler-{self.process_group_id}",
            daemon=True,
        )
        self._thread.start()

    def _run(self) -> None:
        interval = self.interval_ms / 1000.0
        while not self._stop_event.wait(interval):
            self._capture()

    def _group_snapshot(self) -> tuple[int, int, int, int, int]:
        user_ticks = 0
        system_ticks = 0
        rss_bytes = 0
        threads = 0
        process_count = 0
        pending = list(self._known_processes)
        candidates: set[int] = set()
        while pending:
            pid = pending.pop()
            if pid in candidates:
                continue
            candidates.add(pid)
            children = _read_text(Path(f"/proc/{pid}/task/{pid}/children"))
            if children:
                for value in children.split():
                    try:
                        child = int(value)
                    except ValueError:
                        continue
                    if child not in candidates:
                        pending.append(child)

        live_processes: set[int] = set()
        for pid in candidates:
            raw = _read_text(Path(f"/proc/{pid}/stat"))
            if raw is None:
                continue
            stat = _parse_proc_stat(raw)
            if stat is None or stat["pgrp"] != self.process_group_id:
                continue
            live_processes.add(pid)
            identity = (stat["pid"], stat["start_ticks"])
            previous = self._cpu_by_process.get(identity, (0, 0))
            self._cpu_by_process[identity] = (
                max(previous[0], stat["user_ticks"]),
                max(previous[1], stat["system_ticks"]),
            )
            rss_bytes += max(0, stat["rss_pages"]) * self._page_size
            threads += max(0, stat["threads"])
            process_count += 1
        self._known_processes.update(live_processes)
        for process_user, process_system in self._cpu_by_process.values():
            user_ticks += process_user
            system_ticks += process_system
        return user_ticks, system_ticks, rss_bytes, threads, process_count

    def _capture(self) -> None:
        # The runner takes an explicit final sample while the background sampler
        # may still be awake. Serialize both paths so child accounting and the
        # retained sample deque remain consistent.
        with self._capture_lock:
            user_ticks, system_ticks, rss_bytes, threads, process_count = (
                self._group_snapshot()
            )
            sample = {
                "utc": datetime.now(timezone.utc).isoformat(),
                "elapsed_seconds": time.monotonic() - self._started,
                "cpu_user_seconds": user_ticks / self._clock_ticks,
                "cpu_system_seconds": system_ticks / self._clock_ticks,
                "rss_bytes": rss_bytes,
                "threads": threads,
                "processes": process_count,
            }
            with self._lock:
                self._samples.append(sample)
                self._sample_count += 1

    def capture(self) -> None:
        self._capture()

    def stop(self) -> None:
        if self._stop_event.is_set():
            return
        self._capture()
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.interval_ms / 500.0))

    def samples(self) -> list[dict[str, float | int | str]]:
        with self._lock:
            return [dict(sample) for sample in self._samples]

    def summary(self) -> dict[str, object]:
        samples = self.samples()
        if not samples:
            return {
                "available": False,
                "source": "linux-procfs-process-group",
                "reason": "no samples",
            }
        wall_seconds = max(float(samples[-1]["elapsed_seconds"]), 1e-9)
        cpu_user = max(float(sample["cpu_user_seconds"]) for sample in samples)
        cpu_system = max(float(sample["cpu_system_seconds"]) for sample in samples)
        cpu_total = cpu_user + cpu_system
        average_cores = cpu_total / wall_seconds

        peak_cores = 0.0
        active_seconds = 0.0
        active_cpu_seconds = 0.0
        active_rss: list[int] = []
        for previous, current in zip(samples, samples[1:]):
            delta_wall = (
                float(current["elapsed_seconds"])
                - float(previous["elapsed_seconds"])
            )
            delta_cpu = (
                float(current["cpu_user_seconds"])
                + float(current["cpu_system_seconds"])
                - float(previous["cpu_user_seconds"])
                - float(previous["cpu_system_seconds"])
            )
            if delta_wall <= 0:
                continue
            peak_cores = max(peak_cores, max(0.0, delta_cpu) / delta_wall)
            if delta_cpu > 0:
                active_seconds += delta_wall
                active_cpu_seconds += delta_cpu
                active_rss.append(int(current["rss_bytes"]))

        rss_samples = [
            int(sample["rss_bytes"])
            for sample in samples
            if int(sample["processes"]) > 0
        ] or [0]
        average_rss = sum(rss_samples) / len(rss_samples)
        active_average_cores = (
            active_cpu_seconds / active_seconds if active_seconds > 0 else 0.0
        )

        return {
            "available": True,
            "source": "linux-procfs-process-group",
            "scope": "process-group",
            "sample_interval_ms": self.interval_ms,
            "sample_count": self._sample_count,
            "retained_sample_count": len(samples),
            "samples_dropped": max(0, self._sample_count - len(samples)),
            "wall_seconds": _round(wall_seconds),
            "cpu": {
                "user_seconds": _round(cpu_user),
                "system_seconds": _round(cpu_system),
                "total_seconds": _round(cpu_total),
                "total_core_hours": _round(cpu_total / 3600.0, 6),
                "average_cores": _round(average_cores),
                "peak_interval_cores": _round(peak_cores),
                "average_single_core_percent": _round(average_cores * 100.0, 2),
                "average_machine_percent": _round(
                    average_cores * 100.0 / self._available_cpus, 3
                ),
                "available_logical_cpus": self._available_cpus,
            },
            "memory": {
                "average_rss_bytes": round(average_rss),
                "average_rss_mib": _round(average_rss / MIB),
                "peak_rss_bytes": max(rss_samples),
                "peak_rss_mib": _round(max(rss_samples) / MIB),
            },
            "concurrency": {
                "peak_threads": max(int(sample["threads"]) for sample in samples),
                "peak_processes": max(int(sample["processes"]) for sample in samples),
            },
            "active_cpu_intervals": {
                "wall_seconds": _round(active_seconds),
                "cpu_seconds": _round(active_cpu_seconds),
                "average_cores": _round(active_average_cores),
                "average_machine_percent": _round(
                    active_average_cores * 100.0 / self._available_cpus, 3
                ),
                "average_rss_mib": (
                    _round(statistics.fmean(active_rss) / MIB)
                    if active_rss
                    else 0.0
                ),
                "peak_rss_mib": (
                    _round(max(active_rss) / MIB) if active_rss else 0.0
                ),
            },
        }


def aggregate_resource_summaries(
    summaries: list[dict[str, object] | None],
    wall_seconds: float,
) -> dict[str, object]:
    available = [summary for summary in summaries if summary and summary.get("available")]
    if not available:
        return {"available": False, "reason": "no process summaries"}
    cpu_sections = [summary["cpu"] for summary in available]
    memory_sections = [summary["memory"] for summary in available]
    if not all(isinstance(section, dict) for section in cpu_sections + memory_sections):
        return {"available": False, "reason": "malformed process summaries"}
    cpu_user = sum(float(section["user_seconds"]) for section in cpu_sections)
    cpu_system = sum(float(section["system_seconds"]) for section in cpu_sections)
    cpu_total = cpu_user + cpu_system
    available_cpus = int(cpu_sections[0]["available_logical_cpus"])
    average_cores = cpu_total / max(wall_seconds, 1e-9)
    peak_rss_upper_bound = sum(
        float(section["peak_rss_mib"]) for section in memory_sections
    )
    return {
        "available": True,
        "source": "sum-of-client-process-groups",
        "process_groups": len(available),
        "wall_seconds": _round(wall_seconds),
        "cpu": {
            "user_seconds": _round(cpu_user),
            "system_seconds": _round(cpu_system),
            "total_seconds": _round(cpu_total),
            "total_core_hours": _round(cpu_total / 3600.0, 6),
            "average_cores": _round(average_cores),
            "average_single_core_percent": _round(average_cores * 100.0, 2),
            "average_machine_percent": _round(
                average_cores * 100.0 / available_cpus, 3
            ),
            "available_logical_cpus": available_cpus,
        },
        "memory": {
            "peak_rss_mib_upper_bound": _round(peak_rss_upper_bound),
            "note": (
                "sum of per-client peaks; conservative because peaks may not "
                "coincide and RSS can count shared pages in each process"
            ),
        },
    }


def print_host_resources(prefix: str, host: dict[str, object]) -> None:
    frequency = host["frequency_mhz"]
    maximum = frequency["hardware_max"] if isinstance(frequency, dict) else None
    max_text = (
        f", max {float(maximum) / 1000.0:.2f} GHz"
        if isinstance(maximum, (int, float))
        else ""
    )
    physical = host["physical_cores"] or "unknown"
    memory = host["memory_total_gib"]
    memory_text = f"{memory} GiB" if memory is not None else "unknown"
    print(
        f"{prefix} host: {host['cpu_model']}; {physical} physical / "
        f"{host['logical_cpus']} logical CPUs ({host['available_logical_cpus']} available)"
        f"{max_text}; RAM {memory_text}"
    )


def print_process_resources(prefix: str, summary: dict[str, object] | None) -> None:
    if not summary or not summary.get("available"):
        print(f"{prefix} resources: unavailable")
        return
    cpu = summary["cpu"]
    memory = summary["memory"]
    concurrency = summary.get("concurrency")
    assert isinstance(cpu, dict) and isinstance(memory, dict)
    print(
        f"{prefix} CPU: {cpu['total_seconds']:.3f} core-s "
        f"(user {cpu['user_seconds']:.3f}, sys {cpu['system_seconds']:.3f}), "
        f"avg {cpu['average_cores']:.3f} cores / "
        f"{cpu['average_machine_percent']:.3f}% machine"
    )
    memory_text = (
        f"avg RSS {memory['average_rss_mib']:.2f} MiB, "
        f"peak RSS {memory['peak_rss_mib']:.2f} MiB"
        if "average_rss_mib" in memory
        else f"peak RSS <= {memory['peak_rss_mib_upper_bound']:.2f} MiB"
    )
    suffix = ""
    if isinstance(concurrency, dict):
        suffix = (
            f", peak {concurrency['peak_threads']} threads / "
            f"{concurrency['peak_processes']} processes"
        )
    print(f"{prefix} RAM: {memory_text}{suffix}")
    active = summary.get("active_cpu_intervals")
    if isinstance(active, dict) and active.get("wall_seconds", 0) > 0:
        print(
            f"{prefix} active CPU intervals: {active['wall_seconds']:.3f} s, "
            f"avg {active['average_cores']:.3f} cores / "
            f"{active['average_machine_percent']:.3f}% machine"
        )


def write_resource_samples(path: Path, sampler: ProcessResourceSampler | None) -> None:
    if sampler is None:
        return
    with path.open("w", encoding="utf-8") as output:
        for sample in sampler.samples():
            output.write(json.dumps(sample, separators=(",", ":")) + "\n")
