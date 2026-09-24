#!/usr/bin/env python3
"""Bounded native stream stress over a delayed, isolated loopback transport.

This is a repeatable integration workload, not a production soak or a WAN
performance measurement. Kernel netem delays only the native TLS connection;
the application sockets and destination sockets remain ordinary loopback I/O.
"""

from __future__ import annotations

import argparse
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
import yume_native_session as session  # noqa: E402

MIB = 1024 * 1024
TRANSPORT_PORT = 32123
SOCKS_PORT = 32124
TARGET_PORT = 32125
# This workload churns small buffers. Keep ASan's deliberately retained freed
# storage below the RSS growth guard while preserving poisoning and leak checks.
ASAN_RESOURCE_OPTIONS = (
    "quarantine_size_mb=16:thread_local_quarantine_size_kb=64:"
    "detect_leaks=1:halt_on_error=1"
)


def command(argv: list[str]) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True,
                          timeout=10, stdin=subprocess.DEVNULL).stdout


def wire_sockets() -> set[str]:
    """Identify both ends of the single established native TCP connection."""
    result: set[str] = set()
    for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
        fields = line.split()
        ports = [int(fields[index].split(":")[1], 16) for index in (1, 2)]
        if fields[3] == "01" and TRANSPORT_PORT in ports:
            result.add(fields[9])
    return result


class Progress:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.total = 0
        self.changed = time.monotonic()

    def record(self, count: int) -> None:
        with self.lock:
            self.total += count
            self.changed = time.monotonic()

    def snapshot(self) -> tuple[int, float]:
        with self.lock:
            return self.total, self.changed


class Observation:
    def __init__(self, processes: dict[str, subprocess.Popen]) -> None:
        self.processes = processes
        self.wire = wire_sockets()
        if len(self.wire) != 2:
            raise session.SessionFailure("expected one established native TCP connection")
        self.baseline = self.sample()
        self.peaks = {name: values.copy() for name, values in self.baseline.items()}

    def sample(self) -> dict[str, dict[str, int]]:
        if wire_sockets() != self.wire:
            raise session.SessionFailure("native transport reconnected or closed during stress")
        values = {}
        for name, process in self.processes.items():
            if process.poll() is not None:
                raise session.SessionFailure(f"{name} exited during stress")
            proc = Path("/proc") / str(process.pid)
            status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines())
            values[name] = {"rss_kib": int(status["VmRSS"].split()[0]),
                            "fds": len(list((proc / "fd").iterdir()))}
        return values

    def check(self) -> None:
        for name, values in self.sample().items():
            for key, value in values.items():
                self.peaks[name][key] = max(self.peaks[name][key], value)
            # Broad fixture guards, not an assertion that RSS precisely tracks
            # queue budgets or that one finite run proves absence of leaks.
            if values["rss_kib"] > self.baseline[name]["rss_kib"] + 256 * 1024:
                raise session.SessionFailure(
                    f"{name} RSS grew by more than 256 MiB: "
                    f"baseline={self.baseline[name]['rss_kib']} KiB, "
                    f"observed={values['rss_kib']} KiB, "
                    f"peak={self.peaks[name]['rss_kib']} KiB")
            if values["fds"] > self.baseline[name]["fds"] + 64:
                raise session.SessionFailure(
                    f"{name} retained more than 64 additional descriptors: "
                    f"baseline={self.baseline[name]['fds']}, observed={values['fds']}, "
                    f"peak={self.peaks[name]['fds']}")


def block(salt: int) -> bytes:
    return bytes((index + salt) % 256 for index in range(256)) * 256


def transmit(connection: socket.socket, size: int, salt: int,
             progress: Progress | None = None) -> None:
    payload = block(salt)
    remaining = size
    while remaining:
        count = connection.send(payload[:min(remaining, len(payload))])
        if not count:
            raise session.SessionFailure("stream sender stopped making progress")
        # The pattern repeats every 256 bytes. Partial sends need the next
        # block to begin at the corresponding offset, not at byte zero.
        sent = count
        while sent < min(remaining, len(payload)):
            count = connection.send(payload[sent:min(remaining, len(payload))])
            if not count:
                raise session.SessionFailure("stream sender stopped making progress")
            sent += count
        remaining -= sent
        if progress is not None:
            progress.record(sent)
    connection.shutdown(socket.SHUT_WR)


def receive(connection: socket.socket, size: int, salt: int) -> None:
    expected = hashlib.sha256()
    payload = block(salt)
    remaining = size
    while remaining:
        amount = min(remaining, len(payload))
        expected.update(payload[:amount])
        remaining -= amount
    actual = hashlib.sha256()
    remaining = size
    while remaining:
        payload = connection.recv(min(remaining, 65536))
        if not payload:
            raise session.SessionFailure("stream ended before its complete payload")
        actual.update(payload)
        remaining -= len(payload)
    if connection.recv(1) or actual.digest() != expected.digest():
        raise session.SessionFailure("stream payload differs, has trailing bytes, or lacks half-close")


def wait_work(futures: list[Future], observation: Observation, deadline: float) -> None:
    while True:
        observation.check()
        for future in futures:
            if future.done():
                future.result()
        if all(future.done() for future in futures):
            return
        if time.monotonic() >= deadline:
            raise session.SessionFailure("stress workload exceeded its deadline")
        time.sleep(0.1)


def open_pair(listener: socket.socket, sockets: list[socket.socket],
              deadline: float) -> tuple[socket.socket, socket.socket]:
    while time.monotonic() < deadline:
        code, app = session.socks_connect(SOCKS_PORT, "127.0.0.1", TARGET_PORT, timeout=10)
        if code == session.REPLY_SUCCEEDED:
            sockets.append(app)
            target, _ = listener.accept()
            sockets.append(target)
            for connection in (app, target):
                connection.settimeout(120)
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16384)
            return app, target
        app.close()
        time.sleep(0.1)
    raise session.SessionFailure("native session did not accept the stress route")


def duplex(pool: ThreadPoolExecutor, app: socket.socket, target: socket.socket,
           size: int, salt: int) -> list[Future]:
    return [pool.submit(transmit, app, size, salt),
            pool.submit(receive, target, size, salt),
            pool.submit(transmit, target, size, salt + 1),
            pool.submit(receive, app, size, salt + 1)]


def stress(args: argparse.Namespace, processes: dict[str, subprocess.Popen]) -> dict:
    sockets: list[socket.socket] = []
    pool = ThreadPoolExecutor(max_workers=args.streams * 4 + 4)
    deadline = time.monotonic() + 120
    try:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
            listener.bind(("127.0.0.1", TARGET_PORT))
            listener.listen(args.streams + 2)
            listener.settimeout(10)
            stalled_app, stalled_target = open_pair(listener, sockets, deadline)
            observation = Observation(processes)
            progress = Progress()
            stalled_size = 16 * MIB
            stalled_send = pool.submit(transmit, stalled_app, stalled_size, 1, progress)
            stall_deadline = min(deadline, time.monotonic() + 30)
            while True:
                observation.check()
                if stalled_send.done():
                    stalled_send.result()
                    raise session.SessionFailure("unread destination did not backpressure its sender")
                queued, changed = progress.snapshot()
                if queued and time.monotonic() - changed >= 2:
                    break
                if time.monotonic() >= stall_deadline:
                    raise session.SessionFailure("sender did not reach a stable backpressure point")
                time.sleep(0.1)

            started = time.monotonic()
            competing = []
            for index in range(args.streams):
                app, target = open_pair(listener, sockets, deadline)
                competing.extend(duplex(pool, app, target, args.mib * MIB, 10 + index * 2))
            wait_work(competing, observation, deadline)
            competing_seconds = time.monotonic() - started
            if stalled_send.done():
                stalled_send.result()
                raise session.SessionFailure("stalled stream unexpectedly drained without a reader")

            # Only after every competing transfer finishes do we drain the
            # held destination. The original sender must resume, preserving
            # byte order and half-close on the same authenticated connection.
            resumed = [stalled_send, pool.submit(receive, stalled_target, stalled_size, 1),
                       pool.submit(transmit, stalled_target, MIB, 2),
                       pool.submit(receive, stalled_app, MIB, 2)]
            wait_work(resumed, observation, deadline)
            app, target = open_pair(listener, sockets, deadline)
            wait_work(duplex(pool, app, target, 65536, 100), observation, deadline)
            return {"delay_each_direction_ms": args.delay_ms,
                    "competing_streams": args.streams, "bytes_per_direction_per_stream": args.mib * MIB,
                    "competing_seconds": round(competing_seconds, 3),
                    "blocked_upload_bytes": stalled_size, "sender_bytes_at_stall": queued,
                    "resumed_download_bytes": MIB, "transport_connection_unchanged": True,
                    "process_baseline": observation.baseline, "process_peaks": observation.peaks}
    finally:
        for connection in sockets:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        pool.shutdown(wait=True, cancel_futures=True)


def isolated(args: argparse.Namespace) -> None:
    if (os.stat("/proc/self/ns/net").st_ino == args.outer_netns or
            os.stat("/proc/self/ns/user").st_ino == args.outer_userns or os.geteuid() != 0):
        raise session.SessionFailure("stress requires a new unprivileged user/network namespace")
    if [row["ifname"] for row in json.loads(command(["ip", "-j", "link"]))] != ["lo"]:
        raise session.SessionFailure("isolated stress namespace has unexpected network links")
    command(["ip", "link", "set", "lo", "up"])
    environment = session.openssl_environment(args.openssl)
    if args.asan:
        inherited = environment.get("ASAN_OPTIONS", "")
        environment["ASAN_OPTIONS"] = ":".join(
            option for option in (inherited, ASAN_RESOURCE_OPTIONS) if option)
    with tempfile.TemporaryDirectory(prefix="yume-stress-") as temporary, ExitStack() as stack:
        root = Path(temporary)
        kit = root / "kit"
        session.provision_kit(kit, "localhost", TRANSPORT_PORT, environment)
        session.configure_kit(kit, listen_address="127.0.0.2", networks=["127.0.0.1/32"],
                              connect_address="127.0.0.2", socks_port=SOCKS_PORT)
        logs = {name: stack.enter_context((root / f"{name}.log").open("w+"))
                for name in ("yume", "yumed")}
        processes: dict[str, subprocess.Popen] = {}
        try:
            processes["yumed"] = subprocess.Popen(
                [str(args.yumed), "--config", str(kit / "server/yumed.json")], env=environment,
                stdin=subprocess.DEVNULL, stdout=logs["yumed"], stderr=subprocess.STDOUT)
            session.wait_for_port("127.0.0.2", TRANSPORT_PORT, processes["yumed"], time.monotonic() + 30)
            # All normal packets use band 1. Only packets to/from the native
            # transport port enter band 3 and its deterministic netem delay.
            command([str(args.tc), "qdisc", "add", "dev", "lo", "root", "handle", "1:",
                     "prio", "bands", "3", "priomap", *(["0"] * 16)])
            command([str(args.tc), "qdisc", "add", "dev", "lo", "parent", "1:3", "handle", "30:",
                     "netem", "delay", f"{args.delay_ms}ms", "limit", "4096"])
            for field in ("sport", "dport"):
                command([str(args.tc), "filter", "add", "dev", "lo", "protocol", "ip", "parent", "1:",
                         "prio", "1", "u32", "match", "ip", "protocol", "6", "0xff",
                         "match", "ip", field, str(TRANSPORT_PORT), "0xffff", "flowid", "1:3"])
            start = time.monotonic()
            with socket.create_connection(("127.0.0.2", TRANSPORT_PORT), timeout=10):
                observed_rtt = time.monotonic() - start
            if observed_rtt < args.delay_ms * 1.5 / 1000:
                raise session.SessionFailure("transport TCP handshake did not observe configured delay")
            processes["yume"] = subprocess.Popen(
                [str(args.yume), "--config", str(kit / "client/yume.json")], env=environment,
                stdin=subprocess.DEVNULL, stdout=logs["yume"], stderr=subprocess.STDOUT)
            session.wait_for_port("127.0.0.1", SOCKS_PORT, processes["yume"], time.monotonic() + 30)
            report = stress(args, processes)
            report["asan_resource_options"] = ASAN_RESOURCE_OPTIONS if args.asan else None
            report["observed_tcp_handshake_ms"] = round(observed_rtt * 1000, 3)
            report["qdisc"] = json.loads(command([str(args.tc), "-j", "-s", "qdisc", "show", "dev", "lo"]))
            for name in ("yume", "yumed"):
                session.stop_process(processes[name], name, timeout=15)
                logs[name].seek(0)
                session.reject_secret_output(name, logs[name].read())
            report["clean_shutdown"] = True
            print(json.dumps(report, sort_keys=True))
        except Exception:
            for name, log in logs.items():
                log.seek(0)
                text = log.read()
                session.reject_secret_output(name, text)
                print(f"{name}: {text[-3000:]}", file=sys.stderr)
            raise
        finally:
            for process in processes.values():
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("yume", "yumed", "openssl", "tc"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--mib", type=int, default=4, choices=range(2, 9))
    parser.add_argument("--streams", type=int, default=3, choices=range(2, 5))
    parser.add_argument("--delay-ms", type=int, default=100, choices=range(50, 201))
    parser.add_argument("--asan", action="store_true",
                        help="use a bounded ASan quarantine for this RSS-guarded workload")
    parser.add_argument("--outer-netns", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--outer-userns", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        for name in ("yume", "yumed", "openssl", "tc"):
            path = getattr(args, name).resolve(strict=True)
            if not path.is_file() or not os.access(path, os.X_OK):
                raise session.SessionFailure(f"{name} must be an executable regular file")
            setattr(args, name, path)
        if args.outer_netns is not None and args.outer_userns is not None:
            isolated(args)
        else:
            if args.outer_netns is not None or args.outer_userns is not None:
                raise session.SessionFailure("both namespace identities are required")
            for name in ("unshare", "ip"):
                if shutil.which(name) is None:
                    raise session.SessionFailure(f"required executable unavailable: {name}")
            argv = ["unshare", "--user", "--map-root-user", "--net", "--", sys.executable,
                    str(Path(__file__).resolve())]
            for name in ("yume", "yumed", "openssl", "tc", "mib", "streams", "delay_ms"):
                argv.extend(["--" + name.replace("_", "-"), str(getattr(args, name))])
            if args.asan:
                argv.append("--asan")
            argv.extend(["--outer-netns", str(os.stat("/proc/self/ns/net").st_ino),
                         "--outer-userns", str(os.stat("/proc/self/ns/user").st_ino)])
            process = subprocess.Popen(argv, start_new_session=True)
            try:
                if process.wait(timeout=300):
                    raise session.SessionFailure("isolated native stress failed")
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
    except (OSError, ValueError, session.SessionFailure, subprocess.SubprocessError) as error:
        print(f"native stress: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
