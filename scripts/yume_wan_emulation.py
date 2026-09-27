#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Measure a YTP/1 session across emulated wide-area links, without root.

The script re-executes itself under `unshare -rn` and builds three network
namespaces: the client side runs yume and the measurements, the server side
runs yumed and a payload server, and a router between them forwards packets
and applies netem delay, loss and rate limits on its two outgoing
interfaces. The direct path and the tunnel each cross the emulated link
once. The SOCKS hop to yume and the daemon's hop to its destination stay on
loopback without delay. The delay lives in the router because netem on a
sender's own interface holds that sender's packets, and TCP Small Queues
then throttles the socket far below the path's capacity. Every interface
sends one MTU-sized packet per buffer, so loss applies to packets as it
would on a real link.

For every condition the client starts a fresh session, so the report records
how long a session takes to carry its first request. It then alternates timed
downloads, direct and tunnelled, and small request round trips. Every byte of
every download is checked against the served pattern. Emulating each packet
in software caps throughput well below a real network card, so compare the
tunnel with the direct path measured in the same run. The report keeps each
sample, the medians, the netem settings and the binary hashes. Results
describe this emulation on this host: netem on veth is not a real path, and
the run is no benchmark without matched repeats on an idle, pinned host.
"""

from __future__ import annotations

import argparse
import datetime
import json
import math
import os
from pathlib import Path
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yume_native_session as session  # noqa: E402

INSIDE = "YUME_WAN_EMULATION_INSIDE"
CLIENT_ADDRESS, ROUTER_CLIENT_ADDRESS = "10.200.0.1", "10.200.0.2"
ROUTER_SERVER_ADDRESS, SERVER_ADDRESS = "10.200.1.1", "10.200.1.2"
CLIENT_LINK, ROUTER_CLIENT_LINK = "yume-wan-c", "yume-wan-rc"
ROUTER_SERVER_LINK, SERVER_LINK = "yume-wan-rs", "yume-wan-s"
MTU = 1500
STREAM_BYTES = 1 << 40
SMALL_BYTES = 1024
# Upper bound for netem's queue when a condition sets no rate.
UNSHAPED_QUEUE_PACKETS = 50_000
DEFAULT_CONDITIONS = [
    "rtt=2", "rtt=40", "rtt=100", "rtt=200",
    "rtt=100,loss=1", "rtt=200,loss=0.5,rate=50",
]
DOES_NOT_PROVE = [
    "Behavior on real wide-area paths, whose loss, reordering and queues differ from netem.",
    "A speed comparison with other transports, which needs matched runs of each on the same path.",
    "Throughput on another host or with other kernel TCP settings.",
]
PAYLOAD_SERVER = r'''
import http.server, sys
pattern = bytes(range(256)) * 4096
stream_bytes, small_bytes = int(sys.argv[1]), int(sys.argv[2])
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        size = small_bytes if self.path == "/small" else stream_bytes
        self.send_response(200)
        self.send_header("Content-Length", str(size))
        self.send_header("Connection", "close")
        self.end_headers()
        remaining = size
        try:
            while remaining:
                piece = pattern[:remaining]
                self.wfile.write(piece)
                remaining -= len(piece)
        except (BrokenPipeError, ConnectionResetError):
            pass
    def log_message(self, *args):
        pass
server = http.server.ThreadingHTTPServer(("0.0.0.0", int(sys.argv[3])), Handler)
server.daemon_threads = True
print("ready", flush=True)
server.serve_forever()
'''


def parse_condition(text: str) -> dict[str, float]:
    """`rtt=100,loss=1,rate=50`: round-trip ms, loss percent per direction, Mbit/s."""
    condition = {"rtt_ms": 0.0, "loss_percent": 0.0, "rate_mbit": 0.0}
    names = {"rtt": "rtt_ms", "loss": "loss_percent", "rate": "rate_mbit"}
    for field in text.split(","):
        key, separator, value = field.strip().partition("=")
        if not separator or key not in names:
            raise ValueError(f"condition field {field!r} is not rtt=, loss= or rate=")
        number = float(value)
        if not math.isfinite(number) or number < 0:
            raise ValueError(f"condition value {value!r} must be a finite non-negative number")
        condition[names[key]] = number
    if condition["rtt_ms"] > 2000 or condition["loss_percent"] > 20 or condition["rate_mbit"] > 100_000:
        raise ValueError(f"condition {text!r} is outside rtt 0..2000 ms, loss 0..20 %, rate 0..100000 Mbit/s")
    return condition


def netem_arguments(condition: dict[str, float]) -> list[str]:
    """netem settings for one direction. Each end delays half the round trip."""
    arguments = ["netem"]
    if condition["rtt_ms"]:
        arguments += ["delay", f"{condition['rtt_ms'] / 2:g}ms"]
    if condition["loss_percent"]:
        arguments += ["loss", f"{condition['loss_percent']:g}%"]
    if condition["rate_mbit"]:
        arguments += ["rate", f"{condition['rate_mbit']:g}mbit"]
        in_flight = condition["rate_mbit"] * 1e6 * max(condition["rtt_ms"], 1) / 1000 / 8 / MTU
        limit = max(1000, math.ceil(4 * in_flight))
    else:
        limit = UNSHAPED_QUEUE_PACKETS
    return arguments + ["limit", str(limit)]


class PatternCheck:
    """Checks a byte stream against the served 256-byte cycle as it arrives."""

    def __init__(self) -> None:
        self.offset = 0
        self._block = session.PATTERN * (1 + (1 << 20) // len(session.PATTERN) + 1)

    def feed(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            start = self.offset % len(session.PATTERN)
            size = min(len(view), len(self._block) - start)
            if view[:size] != self._block[start:start + size]:
                raise session.SessionFailure(f"payload differs from the served pattern near byte {self.offset}")
            self.offset += size
            view = view[size:]


def read_headers(connection: socket.socket) -> bytes:
    header = bytearray()
    while b"\r\n\r\n" not in header:
        chunk = connection.recv(4096)
        if not chunk:
            raise session.SessionFailure("response ended before its headers")
        header += chunk
        if len(header) > 64 * 1024:
            raise session.SessionFailure("response headers exceed 64 KiB")
    head, _, rest = bytes(header).partition(b"\r\n\r\n")
    if not head.startswith((b"HTTP/1.0 200", b"HTTP/1.1 200")):
        raise session.SessionFailure("destination did not answer 200")
    return rest


def open_connection(socks_port: int | None, host: str, port: int, timeout: float) -> socket.socket:
    if socks_port is None:
        return socket.create_connection((host, port), timeout=timeout)
    code, connection = session.socks_connect(socks_port, host, port, timeout=timeout)
    if code != session.REPLY_SUCCEEDED:
        connection.close()
        raise session.SessionFailure(f"SOCKS5 CONNECT failed with reply {code}")
    return connection


def timed_download(socks_port: int | None, host: str, port: int, seconds: float) -> dict[str, float]:
    """Reads the stream for a fixed time and reports first-byte time and rates.

    `mbit_s` covers the whole window, including TCP's ramp-up on a new
    connection. `tail_mbit_s` covers only the second half, so a connection
    that was already warm and one still in slow start compare at steady state.
    """
    started = time.monotonic()
    with open_connection(socks_port, host, port, timeout=30) as connection:
        connection.settimeout(30)
        connection.sendall(b"GET /stream HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
        check = PatternCheck()
        check.feed(read_headers(connection))
        first_byte = time.monotonic()
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
    with open_connection(socks_port, host, port, timeout=30) as connection:
        connection.settimeout(30)
        connection.sendall(b"GET /small HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
        body = bytearray(read_headers(connection))
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            body += chunk
    if bytes(body) != session.PATTERN * (SMALL_BYTES // len(session.PATTERN)):
        raise session.SessionFailure("the small response differs from the served pattern")
    return round((time.monotonic() - started) * 1000, 2)


def run(argv: list[str], **options: object) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=True, timeout=30, capture_output=True, text=True, **options)


class Link:
    """Client, router and server namespaces joined by two veth pairs.

    The client side is this process's namespace. The router and the server
    are namespaces held open by `sleep` children, entered with nsenter.
    """

    def __init__(self) -> None:
        self.ip = shutil.which("ip") or "/sbin/ip"
        self.tc = shutil.which("tc") or "/sbin/tc"
        self.nsenter = shutil.which("nsenter") or "/usr/bin/nsenter"
        unshare = shutil.which("unshare") or "/usr/bin/unshare"
        self.holders = {side: subprocess.Popen([unshare, "-n", "sleep", "infinity"])
                        for side in ("router", "server")}
        deadline = time.monotonic() + 10
        own = os.readlink("/proc/self/ns/net")
        for side, holder in self.holders.items():
            while os.readlink(f"/proc/{holder.pid}/ns/net") == own:
                if time.monotonic() > deadline or holder.poll() is not None:
                    raise session.SessionFailure(f"the {side} namespace did not start")
                time.sleep(0.05)
        pid = {side: str(holder.pid) for side, holder in self.holders.items()}
        run([self.ip, "link", "add", CLIENT_LINK, "type", "veth", "peer", "name", ROUTER_CLIENT_LINK])
        run([self.ip, "link", "set", ROUTER_CLIENT_LINK, "netns", pid["router"]])
        run(self.command("router", [self.ip, "link", "add", ROUTER_SERVER_LINK, "type", "veth",
                                    "peer", "name", SERVER_LINK]))
        run(self.command("router", [self.ip, "link", "set", SERVER_LINK, "netns", pid["server"]]))
        for side, name, address in (("client", CLIENT_LINK, CLIENT_ADDRESS),
                                    ("router", ROUTER_CLIENT_LINK, ROUTER_CLIENT_ADDRESS),
                                    ("router", ROUTER_SERVER_LINK, ROUTER_SERVER_ADDRESS),
                                    ("server", SERVER_LINK, SERVER_ADDRESS)):
            run(self.command(side, [self.ip, "addr", "add", f"{address}/30", "dev", name]))
            run(self.command(side, [self.ip, "link", "set", name, "mtu", str(MTU), "gso_max_segs", "1", "up"]))
        for side in ("client", "router", "server"):
            run(self.command(side, [self.ip, "link", "set", "lo", "up"]))
        run(self.command("client", [self.ip, "route", "add", "default", "via", ROUTER_CLIENT_ADDRESS]))
        run(self.command("server", [self.ip, "route", "add", "default", "via", ROUTER_SERVER_ADDRESS]))
        run(self.command("router", ["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"]))

    def command(self, side: str, argv: list[str]) -> list[str]:
        if side == "client":
            return argv
        return [self.nsenter, "-t", str(self.holders[side].pid), "-n", *argv]

    def shape(self, condition: dict[str, float]) -> list[str]:
        """The same netem settings on both router exits, one per direction."""
        qdisc = netem_arguments(condition)
        for name in (ROUTER_CLIENT_LINK, ROUTER_SERVER_LINK):
            run(self.command("router", [self.tc, "qdisc", "replace", "dev", name, "root", *qdisc]))
        return qdisc

    def close(self) -> None:
        for holder in self.holders.values():
            if holder.poll() is None:
                holder.kill()
                holder.wait(timeout=5)


def set_queued_bytes(kit: Path, value: int) -> None:
    """Sets limits.max_queued_bytes in both roles' configuration."""
    for relative in ("server/yumed.json", "client/yume.json"):
        path = kit / relative
        document = json.loads(path.read_text(encoding="utf-8"))
        document["limits"]["max_queued_bytes"] = value
        path.write_text(json.dumps(document, indent=2), encoding="utf-8")


def wait_for_text(path: Path, marker: str, process: subprocess.Popen, deadline: float) -> None:
    while time.monotonic() < deadline:
        if marker in path.read_text(encoding="utf-8", errors="replace"):
            return
        if process.poll() is not None:
            raise session.SessionFailure(f"{path.stem} exited with {process.returncode} before '{marker}'")
        time.sleep(0.1)
    raise session.SessionFailure(f"{path.stem} did not report '{marker}'")


def measure_condition(arguments: argparse.Namespace, link: Link, kit: Path, environment: dict[str, str],
                      socks_port: int, target_port: int, text: str, index: int) -> dict[str, object]:
    condition = parse_condition(text)
    result: dict[str, object] = {"condition": text, **condition, "netem": link.shape(condition)}
    log_path = arguments.output / f"yume-{index}.log"
    with log_path.open("wb") as log:
        client = subprocess.Popen([str(arguments.yume), "--config", str(kit / "client/yume.json")],
                                  env=environment, stdout=log, stderr=subprocess.STDOUT)
        try:
            started = time.monotonic()
            session.wait_for_port("127.0.0.1", socks_port, client, started + 30)
            deadline, last = started + 120, None
            while True:
                try:
                    small_request(socks_port, "127.0.0.1", target_port)
                    break
                except (session.SessionFailure, OSError) as error:
                    last = error
                    if client.poll() is not None or time.monotonic() > deadline:
                        raise session.SessionFailure(f"no tunnelled request succeeded: {last}") from None
                    time.sleep(0.05)
            result["session_ready_ms"] = round((time.monotonic() - started) * 1000, 1)
            paths = {"direct": (None, SERVER_ADDRESS), "tunnel": (socks_port, "127.0.0.1")}
            downloads: dict[str, list[dict[str, float]]] = {name: [] for name in paths}
            requests: dict[str, list[float]] = {name: [] for name in paths}
            for _ in range(arguments.repeats):
                for name, (port, host) in paths.items():
                    downloads[name].append(timed_download(port, host, target_port, arguments.seconds))
            for _ in range(arguments.requests):
                for name, (port, host) in paths.items():
                    requests[name].append(small_request(port, host, target_port))
            session.stop_process(client, "yume")
        finally:
            if client.poll() is None:
                client.kill()
                client.wait(timeout=5)
    session.reject_secret_output("yume", log_path.read_text(encoding="utf-8", errors="replace"))
    result["downloads"] = downloads
    result["requests_ms"] = requests
    result["median_mbit_s"] = {name: statistics.median(s["mbit_s"] for s in samples)
                               for name, samples in downloads.items()}
    result["median_tail_mbit_s"] = {name: statistics.median(s["tail_mbit_s"] for s in samples)
                                    for name, samples in downloads.items()}
    result["median_request_ms"] = {name: statistics.median(samples) for name, samples in requests.items()}
    direct = result["median_tail_mbit_s"]["direct"]
    result["tunnel_to_direct"] = round(result["median_tail_mbit_s"]["tunnel"] / direct, 3) if direct else None
    return result


def run_inside(arguments: argparse.Namespace) -> int:
    arguments.output.mkdir(parents=True, exist_ok=False)
    environment = session.openssl_environment(arguments.openssl)
    report: dict[str, object] = {
        "schema": "yume.wan-emulation/1",
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": {"name": os.uname().nodename, "kernel": os.uname().release, "cpus": os.cpu_count()},
        "binaries": {"yumed": session.file_digest(arguments.yumed), "yume": session.file_digest(arguments.yume)},
        "window_seconds": arguments.seconds, "repeats": arguments.repeats, "requests": arguments.requests,
        "conditions": [],
    }
    link = Link()
    processes: list[subprocess.Popen] = []
    code = 0
    try:
        report["tcp"] = {name: Path(f"/proc/sys/net/ipv4/{name}").read_text().strip()
                         for name in ("tcp_congestion_control", "tcp_rmem", "tcp_wmem")}
        with tempfile.TemporaryDirectory(prefix="yume-wan-kit-") as temporary:
            kit = Path(temporary) / "kit"
            session.provision_kit(kit, arguments.server_name, arguments.port, environment)
            socks_port, target_port = session.free_port(), session.free_port()
            session.configure_kit(kit, listen_address=SERVER_ADDRESS, networks=["127.0.0.1/32"],
                                  connect_address=SERVER_ADDRESS, socks_port=socks_port)
            if arguments.max_queued_bytes:
                set_queued_bytes(kit, arguments.max_queued_bytes)
            report["max_queued_bytes"] = json.loads(
                (kit / "client/yume.json").read_text(encoding="utf-8"))["limits"]["max_queued_bytes"]
            logs = {name: (arguments.output / f"{name}.log").open("wb") for name in ("payload", "yumed")}
            processes.append(subprocess.Popen(
                link.command("server", [sys.executable, "-c", PAYLOAD_SERVER, str(STREAM_BYTES),
                                    str(SMALL_BYTES), str(target_port)]),
                stdout=logs["payload"], stderr=subprocess.STDOUT))
            processes.append(subprocess.Popen(
                link.command("server", [str(arguments.yumed), "--config", str(kit / "server/yumed.json")]),
                env=environment, stdout=logs["yumed"], stderr=subprocess.STDOUT))
            deadline = time.monotonic() + 30
            wait_for_text(arguments.output / "payload.log", "ready", processes[0], deadline)
            wait_for_text(arguments.output / "yumed.log", "listening on", processes[1], deadline)
            for index, text in enumerate(arguments.condition):
                try:
                    result = measure_condition(arguments, link, kit, environment, socks_port,
                                               target_port, text, index)
                except (session.SessionFailure, OSError, subprocess.SubprocessError) as error:
                    result = {"condition": text, "error": str(error)}
                    code = 1
                report["conditions"].append(result)
                print(json.dumps({key: result.get(key) for key in
                                  ("condition", "session_ready_ms", "median_tail_mbit_s", "tunnel_to_direct",
                                   "median_request_ms", "error")}), flush=True)
            session.stop_process(processes[1], "yumed")
            for handle in logs.values():
                handle.close()
    except (session.SessionFailure, OSError, subprocess.SubprocessError, ValueError) as error:
        report["error"] = str(error)
        code = 1
    finally:
        for process in processes:
            if process.poll() is None:
                process.send_signal(signal.SIGKILL)
                process.wait(timeout=5)
        link.close()
    yumed_log = arguments.output / "yumed.log"
    if yumed_log.is_file():
        session.reject_secret_output("yumed", yumed_log.read_text(encoding="utf-8", errors="replace"))
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
                        help="rtt=MS[,loss=PERCENT][,rate=MBIT], repeatable, default a six-step matrix")
    parser.add_argument("--seconds", type=float, default=12.0,
                        help="download window, 2..60. A new connection needs several seconds to leave slow start at high RTT")
    parser.add_argument("--repeats", type=int, default=3, help="downloads per path and condition, 1..20")
    parser.add_argument("--requests", type=int, default=20, help="small requests per path and condition, 1..200")
    parser.add_argument("--max-queued-bytes", type=int,
                        help="limits.max_queued_bytes for both roles, default the kit's value")
    parser.add_argument("--server-name", default="cdn.example.test")
    parser.add_argument("--port", type=int, default=443, help="daemon port inside the namespace")
    arguments = parser.parse_args()
    arguments.condition = arguments.condition or list(DEFAULT_CONDITIONS)
    try:
        for text in arguments.condition:
            parse_condition(text)
    except ValueError as error:
        parser.error(str(error))
    if not 2 <= arguments.seconds <= 60 or not 1 <= arguments.repeats <= 20 or \
            not 1 <= arguments.requests <= 200 or not 1 <= arguments.port <= 65535 or \
            (arguments.max_queued_bytes is not None and not 1 << 16 <= arguments.max_queued_bytes <= 64 << 20):
        parser.error("seconds must be 2..60, repeats 1..20, requests 1..200, port 1..65535 "
                     "and max queued bytes 64 KiB..64 MiB")
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
