#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Measure circuits with the client on this host and the nodes on another.

For each condition this starts scripts/yume_circuit_wan.py with
`--serve-at ADDRESS` on the node host over SSH. That run builds the four
nodes, the destination and the router namespaces there, applies the
condition to every hop and serves the entry node and the destination on
one port of ADDRESS, which `--serve-port` can pick to suit the node host's
firewall. This script fetches the clients' kits, points them at ADDRESS,
starts one yume per path here and measures what yume_circuit_wan.py
measures locally: the destination without YUME, the direct session and
circuits of two and three hops, with timed downloads, small requests and
optional parallel downloads. It then stops the run and keeps its report
and logs next to its own.

The node host's relay ends TCP. The emulated first hop's TCP runs from the
relay to the entry, so this host's kernel carries only the real link, and
the rates show this host's yume and the link rather than its TCP over the
emulated path.

It needs key-based SSH to HOST, the node host's checkout at REMOTE_ROOT
with its yumed, yume and OpenSSL, and this host's yume and OpenSSL. The
kits are test credentials of a cluster that exists only for the run. They
stay in a private temporary directory here and in the run's own on the
node host, and both are removed when it ends.
"""

from __future__ import annotations

import argparse
import datetime
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yume_circuit_wan as circuit  # noqa: E402
import yume_native_session as session  # noqa: E402
import yume_wan_emulation as wan  # noqa: E402

SSH = ("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10")
SERVE_WAIT_SECONDS = 240
REPORT_WAIT_SECONDS = 120
DOES_NOT_PROVE = [
    "TCP over the emulated first hop from this host: the node host's relay ends TCP, so this "
    "host's kernel sees only the real link.",
    "Nodes on separate machines: every node and the router share the node host.",
    *circuit.DOES_NOT_PROVE[:2],
]


class Remote:
    """The node host, reached with key-based SSH and a login shell."""

    def __init__(self, host: str, root: str) -> None:
        self.host, self.root = host, root

    def run(self, command: str, timeout: float = 60) -> subprocess.CompletedProcess:
        return subprocess.run([*SSH, self.host, f"cd {shlex.quote(self.root)} && {command}"],
                              capture_output=True, timeout=timeout, check=False)

    def check(self, command: str, timeout: float = 60) -> bytes:
        result = self.run(command, timeout)
        if result.returncode != 0:
            raise session.SessionFailure(f"{self.host}: {command!r} exited with {result.returncode}: "
                                         f"{result.stderr.decode(errors='replace').strip()[-400:]}")
        return result.stdout

    def unpack(self, directory: str, destination: Path) -> None:
        """Copies a directory from the node host with tar over SSH."""
        data = self.check(f"tar -C {shlex.quote(directory)} -cf - .", timeout=120)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            archive.extractall(destination, filter="data")


def serve_command(arguments: argparse.Namespace, output: str, condition: str) -> str:
    """The detached serve run, which records its exit code next to its output.

    The job starts inside a subshell that exits at once. A background list
    of the calling shell would keep SSH's output open for the whole run
    under bash, which does not exec the list's last command.
    """
    argv = ["python3", "scripts/yume_circuit_wan.py", "--yumed", arguments.remote_yumed,
            "--yume", arguments.remote_yume, "--openssl", arguments.remote_openssl, "--output", output,
            "--serve-at", arguments.serve_at, "--condition", condition,
            "--serve-port", str(arguments.serve_port), "--serve-seconds", str(arguments.serve_seconds)]
    if arguments.preset:
        argv += ["--preset", arguments.preset]
    if arguments.idle_epoch_rotation:
        argv.append("--idle-epoch-rotation")
    if arguments.tcp_buffer_mib:
        argv += ["--tcp-buffer-mib", str(arguments.tcp_buffer_mib)]
    run = f"TMPDIR=/tmp {shlex.join(argv)} > {shlex.quote(output + '.log')} 2>&1 < /dev/null\n" \
          f"echo $? > {shlex.quote(output + '.status')}\n"
    return f"(setsid sh -c {shlex.quote(run)} > /dev/null 2>&1 < /dev/null &)"


def wait_for_file(remote: Remote, path: str, seconds: float, ended: str | None = None) -> bytes:
    """Polls the node host for PATH, failing early once ENDED exists."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        found = remote.run(f"cat {shlex.quote(path)}")
        if found.returncode == 0:
            return found.stdout
        if ended and remote.run(f"test -e {shlex.quote(ended)}").returncode == 0:
            log = remote.run(f"tail -c 2000 {shlex.quote(ended.removesuffix('.status') + '.log')}")
            raise session.SessionFailure(f"the serve run ended before {Path(path).name}: "
                                         f"{log.stdout.decode(errors='replace').strip()}")
        time.sleep(1)
    raise session.SessionFailure(f"{path} did not appear within {seconds:.0f} s")


def point_kits(kits: Path, served: dict, sockets: Path) -> tuple[dict[str, Path], dict[str, int]]:
    """Sends each kit's session to the served entry and gives it local ports."""
    configs: dict[str, Path] = {}
    socks: dict[str, int] = {}
    for path in ("direct", *circuit.CIRCUIT_HOPS):
        socks[path] = session.free_port()

        def local(config: dict, path: str = path) -> None:
            config["endpoint"]["connect_address"] = served["address"]
            config["endpoint"]["port"] = served["ports"]["entry"]
            for adapter in config["adapters"]:
                if adapter["kind"] == "socks5":
                    adapter["listen_port"] = socks[path]
            if "control" in config:
                config["control"] = {"socket": str(sockets / f"{path}.sock")}

        configs[path] = kits / path / "yume.json"
        circuit.edit(configs[path], local)
    return configs, socks


def routes(control: Path, served: dict, hops: int) -> list[list[str]]:
    """The routes a client uses, which must have the configured length."""
    state = circuit.query(control).get("circuits") or {}
    found = [route["nodes"] for route in state.get("routes", [])]
    if state.get("current_hops") != hops or not found or \
            any(len(route) != hops or route[0] != served["entry"] or route[-1] not in served["exits"]
                for route in found):
        raise session.SessionFailure(f"the client is not using {hops}-hop circuits: {state}")
    return found


def measure(arguments: argparse.Namespace, environment: dict[str, str], served: dict, index: int,
            temporary: Path) -> dict[str, object]:
    kits, sockets = temporary / "kits", temporary / "sockets"
    sockets.mkdir(mode=0o700)
    configs, socks = point_kits(kits, served, sockets)
    target = tuple(served["target"])
    targets = {"untunnelled": (None, served["address"], served["ports"]["destination"]),
               **{path: (port, *target) for path, port in socks.items()}}
    result: dict[str, object] = {"condition": served["condition"], "netem": served["netem"]}
    clients: dict[str, subprocess.Popen] = {}
    logs = {path: (arguments.output / f"yume-{path}-{index}.log").open("wb") for path in configs}
    try:
        ready: dict[str, float] = {}
        for path, config in configs.items():
            clients[path], ready[path] = circuit.start_client(arguments.yume, config, environment, socks[path],
                                                              target, logs[path])
        result["session_ready_ms"] = ready
        result["routes"] = {path: routes(sockets / f"{path}.sock", served, hops)
                            for path, hops in circuit.CIRCUIT_HOPS.items()}
        downloads: dict[str, list[dict[str, float]]] = {path: [] for path in circuit.PATHS}
        requests: dict[str, list[float]] = {path: [] for path in circuit.PATHS}
        for _ in range(arguments.repeats):
            for path in circuit.PATHS:
                downloads[path].append(circuit.timed_download(*targets[path], arguments.seconds))
        for _ in range(arguments.requests):
            for path in circuit.PATHS:
                requests[path].append(circuit.small_request(*targets[path]))
        if arguments.streams > 1:
            result["parallel"] = {path: circuit.parallel_downloads(*targets[path], arguments.seconds,
                                                                   arguments.streams)
                                  for path in circuit.PATHS}
        for path, client in clients.items():
            session.stop_process(client, f"yume {path}")
    finally:
        for client in clients.values():
            if client.poll() is None:
                client.kill()
                client.wait(timeout=5)
        for handle in logs.values():
            handle.close()
    for path in configs:
        session.reject_secret_output(
            "yume", (arguments.output / f"yume-{path}-{index}.log").read_text(encoding="utf-8", errors="replace"))
    result["downloads"] = downloads
    result["requests_ms"] = requests
    result.update(circuit.summarize(downloads, requests))
    return result


def run_condition(arguments: argparse.Namespace, remote: Remote, environment: dict[str, str], text: str,
                  index: int) -> dict[str, object]:
    output = f"{arguments.remote_output}/condition-{index}"
    result: dict[str, object] = {"condition": text}
    try:
        remote.check(serve_command(arguments, output, text), timeout=30)
        served = json.loads(wait_for_file(remote, f"{output}/serve.json", SERVE_WAIT_SECONDS,
                                          ended=f"{output}.status"))
        with tempfile.TemporaryDirectory(prefix="yume-circuit-cable-", dir="/tmp") as temporary:
            remote.unpack(served["kits"], Path(temporary) / "kits")
            result = measure(arguments, environment, served, index, Path(temporary))
    except (session.SessionFailure, OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
        result["error"] = str(error)
    finally:
        remote.run(f"test -d {shlex.quote(output)} && touch {shlex.quote(output + '/stop')}")
    try:
        status = wait_for_file(remote, f"{output}.status", REPORT_WAIT_SECONDS).decode().strip()
        pulled = arguments.output / f"remote-{index}"
        pulled.mkdir()
        remote.unpack(output, pulled)
        (arguments.output / f"serve-{index}.log").write_bytes(remote.check(f"cat {shlex.quote(output + '.log')}"))
        report = json.loads((pulled / "report.json").read_text(encoding="utf-8"))
        result["remote"] = {"exit": int(status), "binaries": report.get("binaries"), "host": report.get("host"),
                            "tcp": report.get("tcp"), "limits": report.get("limits"),
                            "serve": report.get("serve"), "error": report.get("error")}
        if int(status) != 0:
            result.setdefault("error", f"the serve run exited with {status}")
    except (session.SessionFailure, OSError, subprocess.SubprocessError, ValueError) as error:
        result.setdefault("error", f"the serve run's report: {error}")
    return result


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True, help="SSH destination of the node host")
    parser.add_argument("--remote-root", required=True, help="the node host's YUME checkout")
    parser.add_argument("--remote-output", required=True,
                        help="new directory for the serve runs, relative to the remote checkout")
    parser.add_argument("--remote-yumed", required=True, help="yumed on the node host")
    parser.add_argument("--remote-yume", required=True, help="yume on the node host, recorded by its run")
    parser.add_argument("--remote-openssl", required=True, help="OpenSSL 3.5 or newer on the node host")
    parser.add_argument("--serve-at", required=True, metavar="ADDRESS",
                        help="the node host's address on the link to this host")
    parser.add_argument("--yume", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True, help="OpenSSL 3.5 or newer for this host's yume")
    parser.add_argument("--output", type=Path, required=True, help="new directory for results")
    parser.add_argument("--condition", action="append",
                        help="rtt=MS[,loss=PERCENT][,rate=MBIT] for every hop, repeatable, "
                             "default rtt=0, rtt=40 and rtt=100")
    parser.add_argument("--seconds", type=float, default=12.0, help="download window, 2..60")
    parser.add_argument("--repeats", type=int, default=3, help="downloads per path and condition, 1..20")
    parser.add_argument("--requests", type=int, default=20, help="small requests per path and condition, 1..200")
    parser.add_argument("--streams", type=int, default=1,
                        help="parallel downloads per path after the single-stream samples, 1..64")
    parser.add_argument("--serve-port", type=int, default=0,
                        help="the one port the node host serves on, one its firewall passes, "
                             "default any free port")
    parser.add_argument("--serve-seconds", type=float, default=1800.0,
                        help="the longest each serve run waits for its stop file, 60..7200")
    parser.add_argument("--tcp-buffer-mib", type=int, default=0,
                        help="raise the node host's namespace TCP buffer ceilings to this many MiB, 1..256")
    parser.add_argument("--preset", choices=wan.preset_names(),
                        help="give every node and client this tuning preset's limits")
    parser.add_argument("--idle-epoch-rotation", action="store_true",
                        help="set limits.idle_epoch_rotation on every node and client")
    arguments = parser.parse_args()
    arguments.condition = arguments.condition or list(circuit.DEFAULT_CONDITIONS)
    try:
        for text in arguments.condition:
            wan.parse_condition(text)
    except ValueError as error:
        parser.error(str(error))
    if not 2 <= arguments.seconds <= 60 or not 1 <= arguments.repeats <= 20 or \
            not 1 <= arguments.requests <= 200 or not 1 <= arguments.streams <= 64 or \
            not 60 <= arguments.serve_seconds <= 7200 or not 0 <= arguments.tcp_buffer_mib <= 256 or \
            not 0 <= arguments.serve_port <= 65535:
        parser.error("seconds must be 2..60, repeats 1..20, requests 1..200, streams 1..64, "
                     "serve seconds 60..7200, TCP buffers 0..256 MiB and a port 0..65535")
    if Path(arguments.remote_output).is_absolute() or ".." in Path(arguments.remote_output).parts:
        parser.error("--remote-output must be a relative path inside the remote checkout")
    arguments.yume = arguments.yume.resolve(strict=True)
    arguments.output = arguments.output.resolve()
    arguments.output.mkdir(parents=True, exist_ok=False)
    environment = session.openssl_environment(arguments.openssl)
    remote = Remote(arguments.host, arguments.remote_root)
    remote.check(f"mkdir {shlex.quote(arguments.remote_output)}")
    report: dict[str, object] = {
        "schema": "yume.circuit-cable/1",
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": {"name": os.uname().nodename, "kernel": os.uname().release, "cpus": os.cpu_count()},
        "tcp": {name: Path(f"/proc/sys/net/ipv4/{name}").read_text().strip()
                for name in ("tcp_congestion_control", "tcp_rmem", "tcp_wmem")},
        "yume": session.file_digest(arguments.yume), "node_host": arguments.host,
        "serve_at": arguments.serve_at, "window_seconds": arguments.seconds, "repeats": arguments.repeats,
        "requests": arguments.requests, "streams": arguments.streams, "preset": arguments.preset,
        "idle_epoch_rotation": arguments.idle_epoch_rotation, "conditions": [],
    }
    code = 0
    for index, text in enumerate(arguments.condition):
        result = run_condition(arguments, remote, environment, text, index)
        code |= 1 if "error" in result else 0
        report["conditions"].append(result)
        print(json.dumps({key: result.get(key) for key in
                          ("condition", "session_ready_ms", "median_tail_mbit_s", "to_direct",
                           "median_first_byte_ms", "median_request_ms", "error")}), flush=True)
    report["does_not_prove"] = DOES_NOT_PROVE
    report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (arguments.output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
