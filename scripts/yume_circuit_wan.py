#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Measure circuits across emulated wide-area links, without root.

The script re-executes itself under `unshare -rn`. Four clustered yumed
nodes, a destination and a router each get a network namespace, and the
client side, which runs yume and the measurements, keeps this process's.
Every namespace joins the router over its own veth pair, and the router
applies the condition's netem settings on each of its exits, so every hop
crosses the emulated link once: the client to the entry, each node to the
next and the exit to the destination. A condition's rtt is therefore the
round trip of one hop. node-a is the entry, node-b a middle, node-c and
node-d exits, each on its own /16 so the routes view gives them distinct
network tags.

For every condition it starts one yume per path and records how long each
takes to carry its first stream: the direct session through node-a, and
circuits of two and three hops that yume chooses itself. It then
alternates timed downloads over those paths and the destination reached
without YUME, reporting first-byte times and rates over a fixed window
with the second half separately as steady state, and small request round
trips. Every byte is checked against the served pattern. The workload
speaks a one-byte binary request rather than HTTP, so the circuits keep
their default plain-HTTP refusal.

A YTP/1 epoch carries records for at most 500 ms, so without
`--idle-epoch-rotation` a record after a quiet spell waits one round trip
for a new key on every hop it crosses. The option sets
`limits.idle_epoch_rotation` on every node and client, as the fast and max
presets do, which rotates the key during quiet at the cost of a rekey
exchange that captures show.

`--soak SECONDS` then keeps parallel downloads running through three-hop
circuits under `--soak-condition` while it samples the resident memory and
open descriptors of yume and every node. Circuits rotate every ten minutes,
so a soak of half an hour crosses several rotations. The run fails unless
the last quarter's peaks stay near the second quarter's.

Emulating each packet in software caps throughput well below a real
network card, and a circuit crosses the router more often than the direct
session, so compare paths from the same run only. Results describe this
emulation on this host and are no benchmark without matched repeats on an
idle, pinned host.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yume_native_session as session  # noqa: E402
import yume_wan_emulation as wan  # noqa: E402

INSIDE = "YUME_CIRCUIT_WAN_INSIDE"
NODES = ("node-a", "node-b", "node-c", "node-d")
EXITS = ("node-c", "node-d")
ENTRY = "node-a"
# The client first, then the nodes and the destination. Each side's address
# is on its own /16, and the router's end of its link is the next address.
SIDES = ("client", *NODES, "destination")
MTU = 1500
NODE_PORT = 443
SMALL_BYTES = 1024
STREAM_REQUEST, SMALL_REQUEST = b"\x01", b"\x02"
PATHS = ("untunnelled", "direct", "two_hops", "three_hops")
CIRCUIT_HOPS = {"two_hops": 2, "three_hops": 3}
DEFAULT_CONDITIONS = ["rtt=0", "rtt=40", "rtt=100"]
# A soak samples every program this often and records the client's circuits
# every STATUS_SAMPLES samples.
SOAK_SAMPLE_SECONDS = 5.0
STATUS_SAMPLES = 12
DOES_NOT_PROVE = [
    "Behavior on real wide-area paths, whose loss, reordering and queues differ from netem.",
    "Anonymity or unlinkability: every node runs on one host and one operator's cluster.",
    "Throughput on another host, with other kernel TCP settings or with nodes on separate machines.",
]

PAYLOAD_SERVER = r'''
import socket, sys, threading
pattern = bytes(range(256)) * 4096
small = int(sys.argv[1])
listener = socket.create_server(("0.0.0.0", int(sys.argv[2])), backlog=512)
def serve(connection):
    with connection:
        try:
            request = connection.recv(1)
            if request == b"\x02":
                connection.sendall(pattern[:small])
            elif request == b"\x01":
                while True:
                    connection.sendall(pattern)
        except OSError:
            pass
print("ready", flush=True)
while True:
    connection, _ = listener.accept()
    threading.Thread(target=serve, args=(connection,), daemon=True).start()
'''


def address(side: str) -> str:
    return f"10.{20 + SIDES.index(side)}.0.1"


def router_address(side: str) -> str:
    return f"10.{20 + SIDES.index(side)}.0.2"


class Mesh:
    """Every side joined to one router namespace by its own veth pair.

    The client side is this process's namespace. The others are namespaces
    held open by `sleep` children and entered with nsenter.
    """

    def __init__(self) -> None:
        self.ip = shutil.which("ip") or "/sbin/ip"
        self.tc = shutil.which("tc") or "/sbin/tc"
        self.nsenter = shutil.which("nsenter") or "/usr/bin/nsenter"
        unshare = shutil.which("unshare") or "/usr/bin/unshare"
        self.holders: dict[str, subprocess.Popen] = {}
        try:
            for side in ("router", *SIDES[1:]):
                self.holders[side] = subprocess.Popen([unshare, "-n", "sleep", "infinity"])
            deadline = time.monotonic() + 10
            own = os.readlink("/proc/self/ns/net")
            for side, holder in self.holders.items():
                while os.readlink(f"/proc/{holder.pid}/ns/net") == own:
                    if time.monotonic() > deadline or holder.poll() is not None:
                        raise session.SessionFailure(f"the {side} namespace did not start")
                    time.sleep(0.05)
            for index, side in enumerate(SIDES):
                near, far = f"ycw{index}", f"ycw{index}r"
                wan.run([self.ip, "link", "add", near, "type", "veth", "peer", "name", far])
                wan.run([self.ip, "link", "set", far, "netns", str(self.holders["router"].pid)])
                if side != "client":
                    wan.run([self.ip, "link", "set", near, "netns", str(self.holders[side].pid)])
                for owner, name, value in ((side, near, address(side)),
                                           ("router", far, router_address(side))):
                    wan.run(self.command(owner, [self.ip, "addr", "add", f"{value}/30", "dev", name]))
                    wan.run(self.command(owner, [self.ip, "link", "set", name, "mtu", str(MTU),
                                                 "gso_max_segs", "1", "up"]))
                wan.run(self.command(side, [self.ip, "link", "set", "lo", "up"]))
                wan.run(self.command(side, [self.ip, "route", "add", "default", "via",
                                            router_address(side)]))
            wan.run(self.command("router", [self.ip, "link", "set", "lo", "up"]))
            wan.run(self.command("router", ["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"]))
        except BaseException:
            self.close()
            raise

    def command(self, side: str, argv: list[str]) -> list[str]:
        if side == "client":
            return argv
        return [self.nsenter, "-t", str(self.holders[side].pid), "-n", *argv]

    def tune_tcp_buffers(self, maximum: int) -> None:
        for side in ("router", *SIDES):
            for name, default in (("tcp_rmem", 131072), ("tcp_wmem", 16384)):
                wan.run(self.command(side, ["sh", "-c",
                                            f"echo '4096 {default} {maximum}' > /proc/sys/net/ipv4/{name}"]))

    def shape(self, condition: dict[str, float]) -> list[str]:
        """The same netem settings on every router exit, so each hop gets the condition."""
        qdisc = wan.netem_arguments(condition)
        for index in range(len(SIDES)):
            wan.run(self.command("router", [self.tc, "qdisc", "replace", "dev", f"ycw{index}r",
                                            "root", *qdisc]))
        return qdisc

    def close(self) -> None:
        for holder in self.holders.values():
            if holder.poll() is None:
                holder.kill()
                holder.wait(timeout=5)


def timed_download(socks_port: int | None, host: str, port: int, seconds: float) -> dict[str, float]:
    """Reads the stream for a fixed time, as the WAN emulation's download does."""
    started = time.monotonic()
    with wan.open_connection(socks_port, host, port, timeout=30) as connection:
        connection.settimeout(30)
        connection.sendall(STREAM_REQUEST)
        check = wan.PatternCheck()
        chunk = connection.recv(1 << 20)
        if not chunk:
            raise session.SessionFailure("the stream ended before its first byte")
        first_byte = time.monotonic()
        check.feed(chunk)
        half, stop = first_byte + seconds / 2, first_byte + seconds
        at_half = None
        while (now := time.monotonic()) < stop:
            if at_half is None and now >= half:
                at_half = (now, check.offset)
            chunk = connection.recv(1 << 20)
            if not chunk:
                raise session.SessionFailure("the stream ended before the measurement window")
            check.feed(chunk)
        finished = time.monotonic()
    elapsed = finished - first_byte
    half_time, half_bytes = at_half or (first_byte, 0)
    tail = finished - half_time
    return {"first_byte_ms": round((first_byte - started) * 1000, 2), "bytes": check.offset,
            "seconds": round(elapsed, 3), "mbit_s": round(check.offset * 8 / 1e6 / elapsed, 2),
            "tail_mbit_s": round((check.offset - half_bytes) * 8 / 1e6 / tail, 2) if tail > 0 else 0.0}


def small_request(socks_port: int | None, host: str, port: int) -> float:
    """Milliseconds from connecting to the last byte of a small response."""
    started = time.monotonic()
    with wan.open_connection(socks_port, host, port, timeout=30) as connection:
        connection.settimeout(30)
        connection.sendall(SMALL_REQUEST)
        body = bytearray()
        while chunk := connection.recv(65536):
            body += chunk
    if bytes(body) != session.PATTERN * (SMALL_BYTES // len(session.PATTERN)):
        raise session.SessionFailure("the small response differs from the served pattern")
    return round((time.monotonic() - started) * 1000, 2)


def parallel_downloads(socks_port: int | None, host: str, port: int, seconds: float,
                       streams: int) -> dict[str, object]:
    results: list[dict[str, float] | None] = [None] * streams
    errors: list[str] = []

    def worker(index: int) -> None:
        try:
            results[index] = timed_download(socks_port, host, port, seconds)
        except (session.SessionFailure, OSError) as error:
            errors.append(f"stream {index}: {error}")

    threads = [threading.Thread(target=worker, args=(index,), daemon=True) for index in range(streams)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=seconds + 90)
    if errors or any(thread.is_alive() for thread in threads) or any(result is None for result in results):
        raise session.SessionFailure("parallel downloads failed: " + (", ".join(errors) or "a download did not finish"))
    finished = [result for result in results if result is not None]
    tails = [result["tail_mbit_s"] for result in finished]
    return {"streams": finished, "aggregate_tail_mbit_s": round(sum(tails), 2),
            "fairness": round(wan.fairness_index(tails), 3)}


def summarize(downloads: dict[str, list[dict[str, float]]],
              requests: dict[str, list[float]]) -> dict[str, object]:
    """Medians per path and each path's steady rate against the direct session's."""
    tail = {name: statistics.median(sample["tail_mbit_s"] for sample in samples)
            for name, samples in downloads.items()}
    direct = tail.get("direct")
    return {
        "median_tail_mbit_s": tail,
        "median_first_byte_ms": {name: statistics.median(sample["first_byte_ms"] for sample in samples)
                                 for name, samples in downloads.items()},
        "median_request_ms": {name: statistics.median(samples) for name, samples in requests.items()},
        "to_direct": {name: round(rate / direct, 3) if direct else None
                      for name, rate in tail.items() if name != "direct"},
    }


def query(control: Path, request: str = "status") -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(control))
        connection.sendall(json.dumps({"control": 1, "request": request}).encode() + b"\n")
        reply = bytearray()
        while block := connection.recv(65536):
            reply.extend(block)
    return json.loads(reply)


def setup(environment: dict[str, str], *arguments: str) -> None:
    result = subprocess.run([sys.executable, str(session.SETUP_TOOL), *arguments], env=environment,
                            capture_output=True, text=True, timeout=120, check=False)
    if result.returncode:
        raise session.SessionFailure(f"yume-setup {arguments[0]} failed: {result.stderr.strip()}")


def edit(path: Path, change) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    change(document)
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")


class Cluster:
    """The nodes' kits, the operator's signed list and the clients' kits."""

    def __init__(self, root: Path, environment: dict[str, str], target_port: int,
                 limits: dict[str, object]) -> None:
        self.root = root
        self.sockets = root / "sockets"
        self.sockets.mkdir(mode=0o700)
        operator = root / "operator"
        setup(environment, "cluster-init", "--output", str(operator))
        destination = f"{address('destination')}/32"
        for name in NODES:
            kit = root / name
            session.provision_kit(kit, address(name), NODE_PORT, environment)

            def serve(config: dict, name: str = name) -> None:
                config["limits"].update(limits)
                config["endpoint"]["listen_addresses"] = [address(name)]
                config["control"] = {"socket": str(self.control(name))}
                for adapter in config["adapters"]:
                    if adapter["kind"] in {"direct_tcp", "direct_udp"}:
                        adapter["destinations"] = {"public": False, "networks": [destination]}

            edit(kit / "server/yumed.json", serve)
            setup(environment, "cluster-add", "--cluster", str(operator), "--server", str(kit / "server"),
                  "--name", name, "--host", address(name), "--address", address(name),
                  *(["--exit"] if name in EXITS else []))
        setup(environment, "cluster-sign", "--cluster", str(operator), "--days", "2")
        self.socks = {path: session.free_port() for path in ("direct", *CIRCUIT_HOPS)}
        self.clients = {"direct": root / ENTRY / "client/yume.json"}

        def direct(config: dict) -> None:
            config["limits"].update(limits)
            config["endpoint"]["connect_address"] = address(ENTRY)
            for adapter in config["adapters"]:
                if adapter["kind"] == "socks5":
                    adapter["listen_port"] = self.socks["direct"]

        edit(self.clients["direct"], direct)
        for path, hops in CIRCUIT_HOPS.items():
            kit = root / path
            setup(environment, "add-client", "--server", str(root / ENTRY / "server"), "--host",
                  address(ENTRY), "--output", str(kit), "--client-name", path, "--circuits")

            def circuits(config: dict, path: str = path, hops: int = hops) -> None:
                config["limits"].update(limits)
                config["circuits"]["hops"] = hops
                config["circuits"]["min_hops"] = hops
                config["control"] = {"socket": str(self.control(path))}
                for adapter in config["adapters"]:
                    if adapter["kind"] == "socks5":
                        adapter["listen_port"] = self.socks[path]

            edit(kit / "yume.json", circuits)
            self.clients[path] = kit / "yume.json"
        self.target_port = target_port

    def control(self, name: str) -> Path:
        return self.sockets / f"{name}.sock"

    def server_config(self, name: str) -> Path:
        return self.root / name / "server/yumed.json"


def linked(cluster: Cluster) -> bool:
    for name in NODES:
        try:
            status = query(cluster.control(name))
        except (OSError, ValueError):
            return False
        links = {link["peer"]: link for link in (status.get("cluster") or {}).get("links", [])}
        for peer in NODES:
            link = links.get(peer)
            if peer != name and not (link and link["outbound"]["state"] == "connected" and
                                     link["inbound"]["sessions"] >= 1):
                return False
    return True


def start_client(yume: Path, config: Path, environment: dict[str, str], socks_port: int,
                 target: tuple[str, int], log: object) -> tuple[subprocess.Popen, float]:
    """Starts yume and waits for its first stream to the destination."""
    client = subprocess.Popen([str(yume), "--config", str(config)], env=environment, stdout=log,
                              stderr=subprocess.STDOUT)
    try:
        started = time.monotonic()
        session.wait_for_port("127.0.0.1", socks_port, client, started + 30)
        deadline, last = started + 120, None
        while True:
            try:
                small_request(socks_port, *target)
                break
            except (session.SessionFailure, OSError) as error:
                last = error
                if client.poll() is not None or time.monotonic() > deadline:
                    raise session.SessionFailure(f"no stream through {config.parent.name} succeeded: {last}") from None
                time.sleep(0.05)
        return client, round((time.monotonic() - started) * 1000, 1)
    except BaseException:
        client.kill()
        client.wait(timeout=5)
        raise


def circuit_routes(cluster: Cluster, path: str, hops: int) -> list[list[str]]:
    """The routes the client uses, which must have the configured length."""
    state = query(cluster.control(path)).get("circuits") or {}
    routes = [route["nodes"] for route in state.get("routes", [])]
    if state.get("current_hops") != hops or not routes or \
            any(len(route) != hops or route[0] != ENTRY or route[-1] not in EXITS for route in routes):
        raise session.SessionFailure(f"{path} is not using {hops}-hop circuits: {state}")
    return routes


def measure_condition(arguments: argparse.Namespace, mesh: Mesh, cluster: Cluster,
                      environment: dict[str, str], text: str, index: int) -> dict[str, object]:
    condition = wan.parse_condition(text)
    result: dict[str, object] = {"condition": text, **condition, "netem": mesh.shape(condition)}
    target = (address("destination"), cluster.target_port)
    clients: dict[str, subprocess.Popen] = {}
    logs = {path: (arguments.output / f"yume-{path}-{index}.log").open("wb") for path in cluster.clients}
    try:
        ready: dict[str, float] = {}
        for path, config in cluster.clients.items():
            clients[path], ready[path] = start_client(arguments.yume, config, environment,
                                                      cluster.socks[path], target, logs[path])
        result["session_ready_ms"] = ready
        result["routes"] = {path: circuit_routes(cluster, path, hops) for path, hops in CIRCUIT_HOPS.items()}
        ports = {"untunnelled": None, **cluster.socks}
        downloads: dict[str, list[dict[str, float]]] = {path: [] for path in PATHS}
        requests: dict[str, list[float]] = {path: [] for path in PATHS}
        for _ in range(arguments.repeats):
            for path in PATHS:
                downloads[path].append(timed_download(ports[path], *target, arguments.seconds))
        for _ in range(arguments.requests):
            for path in PATHS:
                requests[path].append(small_request(ports[path], *target))
        if arguments.streams > 1:
            result["parallel"] = {path: parallel_downloads(ports[path], *target, arguments.seconds,
                                                           arguments.streams) for path in PATHS}
        for path, client in clients.items():
            session.stop_process(client, f"yume {path}")
    finally:
        for client in clients.values():
            if client.poll() is None:
                client.kill()
                client.wait(timeout=5)
        for handle in logs.values():
            handle.close()
    for path in cluster.clients:
        session.reject_secret_output(
            "yume", (arguments.output / f"yume-{path}-{index}.log").read_text(encoding="utf-8", errors="replace"))
    result["downloads"] = downloads
    result["requests_ms"] = requests
    result.update(summarize(downloads, requests))
    return result


def run_soak(arguments: argparse.Namespace, mesh: Mesh, cluster: Cluster, environment: dict[str, str],
             nodes: dict[str, subprocess.Popen]) -> dict[str, object]:
    """Parallel downloads through three-hop circuits while every program is sampled."""
    condition = wan.parse_condition(arguments.soak_condition)
    result: dict[str, object] = {"condition": arguments.soak_condition, "seconds": arguments.soak,
                                 "streams": arguments.streams, "netem": mesh.shape(condition)}
    target = (address("destination"), cluster.target_port)
    samples: list[dict[str, object]] = []
    statuses: list[dict[str, object]] = []
    rounds: list[dict[str, object]] = []
    log_path = arguments.output / "yume-soak.log"
    with log_path.open("wb") as log:
        client, result["session_ready_ms"] = start_client(
            arguments.yume, cluster.clients["three_hops"], environment, cluster.socks["three_hops"],
            target, log)
        programs = {"yume": client, **nodes}
        stop = threading.Event()
        sampler_errors: list[str] = []
        started = time.monotonic()

        def sample() -> None:
            while not stop.wait(SOAK_SAMPLE_SECONDS):
                try:
                    seconds = round(time.monotonic() - started, 1)
                    samples.append({"seconds": seconds, **{name: wan.process_resources(process.pid)
                                                           for name, process in programs.items()}})
                    if len(samples) % STATUS_SAMPLES == 0:
                        state = query(cluster.control("three_hops")).get("circuits") or {}
                        statuses.append({"seconds": seconds, "current_hops": state.get("current_hops"),
                                         "routes": state.get("routes", [])})
                except (OSError, ValueError, session.SessionFailure) as error:
                    sampler_errors.append(str(error))
                    return

        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()
        failure = None
        try:
            while (remaining := started + arguments.soak - time.monotonic()) >= 2:
                round_start = round(time.monotonic() - started, 1)
                try:
                    outcome = parallel_downloads(cluster.socks["three_hops"], *target, min(30.0, remaining),
                                                 arguments.streams)
                except (session.SessionFailure, OSError) as error:
                    failure = f"round {len(rounds) + 1}, {round_start} s into the soak: {error}"
                    break
                rounds.append({"start_s": round_start, "aggregate_tail_mbit_s": outcome["aggregate_tail_mbit_s"],
                               "fairness": outcome["fairness"],
                               "bytes": sum(stream["bytes"] for stream in outcome["streams"])})
        finally:
            stop.set()
            sampler.join(timeout=SOAK_SAMPLE_SECONDS + 10)
            # A program that died during the soak is the finding, and the
            # rounds and samples before it are its evidence.
            died = {name: process.returncode for name, process in programs.items()
                    if process.poll() is not None}
            stop_error = None
            if "yume" not in died:
                try:
                    session.stop_process(client, "yume")
                except session.SessionFailure as error:
                    stop_error = str(error)
    session.reject_secret_output("yume", log_path.read_text(encoding="utf-8", errors="replace"))
    result["rounds"] = rounds
    result["samples"] = samples
    result["circuit_status"] = statuses
    problems = [failure] if failure else []
    problems += [f"{name} exited with {code} during the soak" for name, code in died.items()]
    if stop_error:
        problems.append(stop_error)
    if sampler_errors:
        problems.append(f"sampling failed: {sampler_errors[0]}")
    if died:
        result["died"] = died
    if problems:
        result["error"] = ", ".join(problems)
        result["flat"] = False
        return result
    # A rotated circuit may take a new exit, which moves its destination
    # sockets from one node to another, so the nodes' descriptors are judged
    # together. Each node's own count stays in the samples.
    result["plateau"] = {
        f"{program}_{metric}": wan.plateau([row[program][metric] for row in samples], *bounds)
        for program in programs for metric, bounds in wan.PLATEAU_BOUNDS.items()
        if program == "yume" or metric != "fds"}
    result["plateau"]["nodes_fds"] = wan.plateau(
        [sum(row[name]["fds"] for name in NODES) for row in samples], *wan.PLATEAU_BOUNDS["fds"])
    result["flat"] = all(check["flat"] for check in result["plateau"].values())
    return result


def run_inside(arguments: argparse.Namespace) -> int:
    arguments.output.mkdir(parents=True, exist_ok=False)
    environment = session.openssl_environment(arguments.openssl)
    report: dict[str, object] = {
        "schema": "yume.circuit-wan/1",
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": {"name": os.uname().nodename, "kernel": os.uname().release, "cpus": os.cpu_count()},
        "binaries": {"yumed": session.file_digest(arguments.yumed), "yume": session.file_digest(arguments.yume)},
        "window_seconds": arguments.seconds, "repeats": arguments.repeats, "requests": arguments.requests,
        "streams": arguments.streams, "idle_epoch_rotation": arguments.idle_epoch_rotation,
        "nodes": {name: address(name) for name in NODES}, "exits": list(EXITS),
        "conditions": [],
    }
    mesh = Mesh()
    processes: dict[str, subprocess.Popen] = {}
    logs: list[object] = []
    code = 0
    try:
        if arguments.tcp_buffer_mib:
            mesh.tune_tcp_buffers(arguments.tcp_buffer_mib << 20)
        report["tcp"] = {name: Path(f"/proc/sys/net/ipv4/{name}").read_text().strip()
                         for name in ("tcp_congestion_control", "tcp_rmem", "tcp_wmem")}
        with tempfile.TemporaryDirectory(prefix="yume-circuit-wan-", dir="/tmp") as temporary:
            limits = {"idle_epoch_rotation": True} if arguments.idle_epoch_rotation else {}
            cluster = Cluster(Path(temporary), environment, session.free_port(), limits)
            payload_log = arguments.output / "payload.log"
            logs.append(payload_log.open("wb"))
            processes["payload"] = subprocess.Popen(
                mesh.command("destination", [sys.executable, "-c", PAYLOAD_SERVER, str(SMALL_BYTES),
                                             str(cluster.target_port)]),
                stdout=logs[-1], stderr=subprocess.STDOUT)
            for name in NODES:
                logs.append((arguments.output / f"{name}.log").open("wb"))
                processes[name] = subprocess.Popen(
                    mesh.command(name, [str(arguments.yumed), "--config", str(cluster.server_config(name))]),
                    env=environment, stdout=logs[-1], stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 30
            wan.wait_for_text(payload_log, "ready", processes["payload"], deadline)
            linked_by = time.monotonic() + 90
            while not linked(cluster):
                for name in NODES:
                    if processes[name].poll() is not None:
                        raise session.SessionFailure(f"{name} exited with {processes[name].returncode}")
                if time.monotonic() > linked_by:
                    raise session.SessionFailure("the nodes did not all link to each other")
                time.sleep(0.25)
            for index, text in enumerate(arguments.condition):
                try:
                    result = measure_condition(arguments, mesh, cluster, environment, text, index)
                except (session.SessionFailure, OSError, subprocess.SubprocessError, ValueError) as error:
                    result = {"condition": text, "error": str(error)}
                    code = 1
                report["conditions"].append(result)
                print(json.dumps({key: result.get(key) for key in
                                  ("condition", "session_ready_ms", "median_tail_mbit_s", "to_direct",
                                   "median_first_byte_ms", "median_request_ms", "error")}), flush=True)
            if arguments.soak:
                nodes = {name: processes[name] for name in NODES}
                try:
                    report["soak"] = run_soak(arguments, mesh, cluster, environment, nodes)
                    if not report["soak"]["flat"]:
                        code = 1
                except (session.SessionFailure, OSError, subprocess.SubprocessError, ValueError) as error:
                    report["soak"] = {"error": str(error)}
                    code = 1
                print(json.dumps({"soak_flat": report["soak"].get("flat"),
                                  "error": report["soak"].get("error")}), flush=True)
            report["node_status"] = {name: (query(cluster.control(name)).get("cluster") or {}).get("circuits")
                                     for name in NODES}
            for name in NODES:
                session.stop_process(processes[name], f"yumed {name}")
    except (session.SessionFailure, OSError, subprocess.SubprocessError, ValueError) as error:
        report["error"] = str(error)
        code = 1
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.send_signal(signal.SIGKILL)
                process.wait(timeout=5)
        for handle in logs:
            handle.close()
        mesh.close()
    for name in NODES:
        log = arguments.output / f"{name}.log"
        if log.is_file():
            session.reject_secret_output(name, log.read_text(encoding="utf-8", errors="replace"))
    report["does_not_prove"] = DOES_NOT_PROVE
    report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (arguments.output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return code


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--yumed", type=Path, required=True)
    parser.add_argument("--yume", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True, help="OpenSSL 3.5 or newer for kit generation")
    parser.add_argument("--output", type=Path, required=True, help="new directory for results")
    parser.add_argument("--condition", action="append",
                        help="rtt=MS[,loss=PERCENT][,rate=MBIT] for every hop, repeatable, "
                             "default rtt=0, rtt=40 and rtt=100")
    parser.add_argument("--seconds", type=float, default=12.0, help="download window, 2..60")
    parser.add_argument("--repeats", type=int, default=3, help="downloads per path and condition, 1..20")
    parser.add_argument("--requests", type=int, default=20, help="small requests per path and condition, 1..200")
    parser.add_argument("--streams", type=int, default=1,
                        help="parallel downloads per path after the single-stream samples, 1..64. "
                             "A soak uses them too")
    parser.add_argument("--soak", type=float, default=0.0,
                        help="seconds, 60..86400, of parallel downloads through three-hop circuits after "
                             "the matrix while yume and every node are sampled")
    parser.add_argument("--soak-condition", default="rtt=40", help="network condition of every hop in the soak")
    parser.add_argument("--tcp-buffer-mib", type=int, default=0,
                        help="raise every namespace's TCP buffer ceilings to this many MiB, 1..256")
    parser.add_argument("--idle-epoch-rotation", action="store_true",
                        help="set limits.idle_epoch_rotation on every node and client")
    arguments = parser.parse_args()
    arguments.condition = arguments.condition or list(DEFAULT_CONDITIONS)
    try:
        for text in (*arguments.condition, arguments.soak_condition):
            wan.parse_condition(text)
    except ValueError as error:
        parser.error(str(error))
    if not 2 <= arguments.seconds <= 60 or not 1 <= arguments.repeats <= 20 or \
            not 1 <= arguments.requests <= 200 or not 1 <= arguments.streams <= 64 or \
            (arguments.soak and not 60 <= arguments.soak <= 86400) or \
            not 0 <= arguments.tcp_buffer_mib <= 256:
        parser.error("seconds must be 2..60, repeats 1..20, requests 1..200, streams 1..64, "
                     "a soak 60..86400 seconds and TCP buffers 0..256 MiB")
    for name in ("yumed", "yume", "openssl"):
        setattr(arguments, name, getattr(arguments, name).resolve(strict=True))
    arguments.output = arguments.output.resolve()
    if os.environ.get(INSIDE) != "1":
        unshare = shutil.which("unshare")
        if not unshare:
            parser.error("unshare is required")
        environment = dict(os.environ, **{INSIDE: "1"})
        return subprocess.run([unshare, "-rn", sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
                              env=environment, check=False).returncode
    return run_inside(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
