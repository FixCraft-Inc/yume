#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Capture circuit traffic as a passive observer sees it, without root.

The script re-executes itself under `unshare -rn` and builds the namespaces
and cluster of scripts/yume_circuit_wan.py. For each session it starts a
fresh yume with three-hop circuits and runs the frozen cover-page workload
of scripts/yume_carrier_workload.py through it, as the matched capture runs
that workload through the direct session: the same bytes to an echo target
behind the exit, the stream's end, the idle interval and the close.
tcpdump in the router namespace records every side's link from before the
nodes start.

Afterwards the script rebuilds each TCP connection's byte stream from the
captures and keeps only its TLS record timeline: each record's arrival
time, content type and length, as the capture relay records it. The
client's sessions get the classifier gate's features, and --compare adds
the sessions of one label from an earlier campaign's feature document, such
as its browser arm, and describes both. Every link between two nodes gets
its record counts and lengths over the whole run. That is a baseline, not a
classifier verdict: one host, one campaign and no held-out groups.

The output directory keeps the pcaps, which hold encrypted payload, next to
the timelines. It belongs in private evidence, never in Git.
"""

from __future__ import annotations

import argparse
import collections
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterator

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yume_carrier_workload as workload  # noqa: E402
import yume_circuit_wan as circuit_wan  # noqa: E402
import yume_classifier_features as features  # noqa: E402
import yume_native_session as session  # noqa: E402
import yume_tls_wire as tls_wire  # noqa: E402
import yume_wan_emulation as wan  # noqa: E402

INSIDE = "YUME_CIRCUIT_CAPTURE_INSIDE"
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
LINKTYPE_ETHERNET = 1
ETHERTYPE_IPV4 = 0x0800
TCP_PROTOCOL = 6
SYN, FIN, RST = 0x02, 0x01, 0x04
ECHO_TIMEOUT_SECONDS = 180
ECHO_TARGET = r'''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import yume_carrier_workload as workload
workload.echo((sys.argv[2], int(sys.argv[3])), Path(sys.argv[4]), float(sys.argv[5]))
'''
# The client's and the nodes' links. The destination sees only the exits'
# plaintext connections.
CAPTURED = ("client", *circuit_wan.NODES)
DOES_NOT_PROVE = [
    "Classifier resistance: one host, one campaign and no held-out groups.",
    "Behavior on real networks, whose timing and segmentation differ from these namespaces.",
    "Anything about link traffic with many clients, since one client used the cluster.",
]


class CaptureError(RuntimeError):
    """A capture is missing, truncated or does not parse."""


def read_pcap(data: bytes) -> Iterator[tuple[float, bytes]]:
    """Each frame of a classic Ethernet pcap with its capture time in seconds."""
    if len(data) < 24 or data[:4] not in PCAP_MAGIC:
        raise CaptureError("not a classic pcap file")
    order, unit = PCAP_MAGIC[data[:4]]
    if struct.unpack(order + "I", data[20:24])[0] != LINKTYPE_ETHERNET:
        raise CaptureError("the capture is not Ethernet")
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise CaptureError("the capture ends inside a record header")
        seconds, fraction, included, original = struct.unpack(order + "IIII", data[offset:offset + 16])
        offset += 16
        if included != original or offset + included > len(data):
            raise CaptureError("a frame was truncated, so its payload cannot be rebuilt")
        yield seconds + fraction * unit, data[offset:offset + included]
        offset += included


def tcp_segments(frames: Iterator[tuple[float, bytes]]) -> Iterator[dict[str, Any]]:
    """IPv4 TCP segments with their flow, sequence number, flags and payload."""
    for when, frame in frames:
        if len(frame) < 14 or struct.unpack("!H", frame[12:14])[0] != ETHERTYPE_IPV4:
            continue
        packet = frame[14:]
        if len(packet) < 20 or packet[0] >> 4 != 4 or packet[9] != TCP_PROTOCOL:
            continue
        header = (packet[0] & 0x0F) * 4
        total = struct.unpack("!H", packet[2:4])[0]
        if header < 20 or total > len(packet) or total < header + 20:
            raise CaptureError("a malformed IPv4 packet")
        segment = packet[header:total]
        offset = (segment[12] >> 4) * 4
        if offset < 20 or offset > len(segment):
            raise CaptureError("a malformed TCP header")
        source, target = ".".join(map(str, packet[12:16])), ".".join(map(str, packet[16:20]))
        source_port, target_port, sequence = struct.unpack("!HHI", segment[:8])
        yield {"time": when, "flow": (source, source_port, target, target_port), "seq": sequence,
               "flags": segment[13], "payload": segment[offset:]}


class Direction:
    """One direction's bytes in sequence order, fed to a TLS record timeline."""

    def __init__(self, started: float) -> None:
        self.timeline = tls_wire.RecordTimeline(started)
        self.next: int | None = None
        self.pending: dict[int, bytes] = {}
        self.bytes = 0
        self.last = started

    def add(self, when: float, sequence: int, flags: int, payload: bytes) -> None:
        if flags & SYN:
            self.next = (sequence + 1) & 0xFFFFFFFF
            return
        if not payload:
            return  # an ACK, FIN or the RST that refuses an early dial
        if self.next is None:
            raise CaptureError("a connection's data arrived before its SYN")
        self.pending[sequence] = payload
        # Bytes that arrived ahead of a gap are usable, by the receiver and by
        # an observer rebuilding records, only once the gap fills, so they take
        # the time of the segment that filled it. Times never go back.
        self.last = max(self.last, when)
        self._drain(self.last)

    def _drain(self, now: float) -> None:
        while True:
            ready = None
            for sequence, payload in self.pending.items():
                # Signed distance, so a sequence number that wrapped still orders.
                ahead = ((sequence - self.next + (1 << 31)) & 0xFFFFFFFF) - (1 << 31)
                if ahead <= 0:
                    ready = (sequence, payload[-ahead:] if ahead else payload)
                    break
            if ready is None:
                return
            sequence, payload = ready
            del self.pending[sequence]
            if payload:
                self.timeline.feed(payload, now)
                self.bytes += len(payload)
                self.next = (self.next + len(payload)) & 0xFFFFFFFF


def connections(segments: Iterator[dict[str, Any]]) -> list[dict[str, Any]]:
    """TCP connections in SYN order, each with a TLS record timeline per direction."""
    found: dict[tuple, dict[str, Any]] = {}
    order: list[dict[str, Any]] = []
    for segment in segments:
        source, source_port, target, target_port = segment["flow"]
        key = (source, source_port, target, target_port)
        reverse = (target, target_port, source, source_port)
        if key not in found and reverse not in found:
            if not segment["flags"] & SYN or segment["flags"] & 0x10:
                continue  # mid-connection traffic from before the capture
            connection = {"client": (source, source_port), "server": (target, target_port),
                          "started": segment["time"],
                          "client_to_server": Direction(segment["time"]),
                          "server_to_client": Direction(segment["time"])}
            found[key] = connection
            order.append(connection)
        connection = found.get(key) or found[reverse]
        direction = "client_to_server" if (source, source_port) == connection["client"] else "server_to_client"
        connection[direction].add(segment["time"], segment["seq"], segment["flags"], segment["payload"])
    for connection in order:
        for name in features.DIRECTIONS:
            if connection[name].pending:
                raise CaptureError("a connection has bytes after a gap the capture never filled")
    return order


def record_timeline(connection: dict[str, Any]) -> dict[str, Any]:
    return {name: connection[name].timeline.report() for name in features.DIRECTIONS}


def link_summary(timeline: dict[str, Any]) -> dict[str, Any]:
    """Record counts and lengths per direction of one long-lived link."""
    result: dict[str, Any] = {}
    for name in features.DIRECTIONS:
        side = timeline[name]
        lengths = [length for _, kind, length in side["records"] if kind == features.APPLICATION_DATA]
        common = collections.Counter(lengths).most_common(8)
        result[name] = {
            "records": len(side["records"]), "application_records": len(lengths),
            "bytes": sum(length for _, _, length in side["records"]),
            "lengths": [min(lengths), sorted(lengths)[len(lengths) // 2], max(lengths)] if lengths else [],
            "common_lengths": [[length, count] for length, count in common],
            "truncated": side["truncated"], "malformed": side["malformed"],
        }
    return result


def side_of(address: str) -> str:
    for side in circuit_wan.SIDES:
        if circuit_wan.address(side) == address:
            return side
    raise CaptureError(f"an address no side owns: {address}")


def analyse(output: Path, compare: Path | None, compare_label: int, group: dict[str, str]) -> dict[str, Any]:
    """Timelines, the client's session features and the link summaries from the pcaps."""
    captured = {side: connections(tcp_segments(read_pcap((output / f"{side}.pcap").read_bytes())))
                for side in CAPTURED}
    client_address = circuit_wan.address("client")
    entry = (circuit_wan.address(circuit_wan.ENTRY), circuit_wan.NODE_PORT)
    sessions = [connection for connection in captured["client"]
                if connection["client"][0] == client_address and connection["server"] == entry]
    links = {}
    for side in circuit_wan.NODES:
        for connection in captured[side]:
            # Each link once, from the capture beside the node that dialled it.
            if connection["client"][0] != circuit_wan.address(side) or \
                    connection["server"][1] != circuit_wan.NODE_PORT:
                continue
            timeline = record_timeline(connection)
            if not any(timeline[name]["records"] for name in features.DIRECTIONS):
                continue  # a dial refused before the peer listened
            links.setdefault(f"{side}>{side_of(connection['server'][0])}", []).append(timeline)
    timelines = [record_timeline(connection) for connection in sessions]
    (output / "timelines.json").write_text(json.dumps({"sessions": timelines, "links": links}) + "\n",
                                           encoding="utf-8")
    document = features.feature_document([(1, [{"record_timeline": timeline} for timeline in timelines])], group)
    result: dict[str, Any] = {"sessions": len(timelines), "features": document,
                              "links": {name: [link_summary(timeline) for timeline in runs]
                                        for name, runs in sorted(links.items())}}
    if compare is not None:
        earlier = json.loads(compare.read_text(encoding="utf-8"))
        if earlier.get("feature_names") != list(features.FEATURE_NAMES):
            raise CaptureError("the compared document uses other features")
        chosen = [dict(item, label=0) for item in earlier["sessions"] if item["label"] == compare_label]
        if not chosen:
            raise CaptureError(f"the compared document has no sessions labelled {compare_label}")
        result["describe"] = features.describe(dict(document, sessions=chosen + document["sessions"]))
        result["describe"]["compared"] = {"document": str(compare), "label": compare_label}
    return result


def run_session(arguments: argparse.Namespace, mesh: circuit_wan.Mesh, cluster: circuit_wan.Cluster,
                environment: dict[str, str], index: int) -> dict[str, Any]:
    """One fresh yume through three-hop circuits running the frozen workload."""
    target = (circuit_wan.address("destination"), session.free_port())
    ready = arguments.output / f"echo-{index}.json"
    with (arguments.output / f"echo-{index}.log").open("wb") as echo_log:
        # The echo subcommand takes loopback addresses only, and the exit
        # reaches this target over the router, so call the function itself.
        echo = subprocess.Popen(mesh.command("destination", [
            sys.executable, "-c", ECHO_TARGET, str(Path(__file__).resolve().parent), target[0],
            str(target[1]), str(ready), str(ECHO_TIMEOUT_SECONDS)]),
            stdout=echo_log, stderr=subprocess.STDOUT)
    client = None
    try:
        deadline = time.monotonic() + 30
        while not ready.exists():
            if echo.poll() is not None or time.monotonic() > deadline:
                raise CaptureError("the echo target did not start")
            time.sleep(0.05)
        config = cluster.clients["three_hops"]
        log = arguments.output / f"yume-{index}.log"
        with log.open("wb") as handle:
            client = subprocess.Popen([str(arguments.yume), "--config", str(config)], env=environment,
                                      stdout=handle, stderr=subprocess.STDOUT)
        session.wait_for_port("127.0.0.1", cluster.socks["three_hops"], client, time.monotonic() + 30)
        # SOCKS5 opens before the session, and without a session the client
        # refuses connections.
        deadline = time.monotonic() + 60
        while True:
            try:
                if circuit_wan.query(cluster.control("three_hops")).get("state") == "connected":
                    break
            except (OSError, ValueError):
                pass
            if client.poll() is not None or time.monotonic() > deadline:
                raise CaptureError("yume never connected")
            time.sleep(0.1)
        measured = workload.drive(("127.0.0.1", cluster.socks["three_hops"]), target, 0)
        state = circuit_wan.query(cluster.control("three_hops")).get("circuits") or {}
        measured["routes"] = [route["nodes"] for route in state.get("routes", [])]
        if state.get("current_hops") != 3:
            raise CaptureError(f"the client was not using three-hop circuits: {state}")
        session.stop_process(client, "yume")
        if echo.wait(timeout=30) != 0:
            raise CaptureError(f"the echo target exited with {echo.returncode}")
        session.reject_secret_output("yume", log.read_text(encoding="utf-8", errors="replace"))
        return measured
    finally:
        for process in (client, echo):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)


def run_inside(arguments: argparse.Namespace) -> int:
    arguments.output.mkdir(parents=True, exist_ok=False)
    environment = session.openssl_environment(arguments.openssl)
    report: dict[str, Any] = {
        "schema": "yume.circuit-capture/1",
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": {"name": os.uname().nodename, "kernel": os.uname().release, "cpus": os.cpu_count()},
        "binaries": {"yumed": session.file_digest(arguments.yumed), "yume": session.file_digest(arguments.yume)},
        "tools": {name: session.file_digest(Path(__file__).resolve().parent / name)
                  for name in ("yume_circuit_capture.py", "yume_circuit_wan.py", "yume_carrier_workload.py",
                               "yume_classifier_features.py", "yume_tls_wire.py")},
        "condition": arguments.condition, "sessions": [],
    }
    mesh = circuit_wan.Mesh()
    captures: list[tuple[subprocess.Popen, Path]] = []
    processes: dict[str, subprocess.Popen] = {}
    logs: list[Any] = []
    code = 0
    try:
        report["netem"] = mesh.shape(wan.parse_condition(arguments.condition))
        tcpdump = shutil.which("tcpdump") or "/usr/bin/tcpdump"
        for side in CAPTURED:
            index = circuit_wan.SIDES.index(side)
            errors = arguments.output / f"{side}.tcpdump.log"
            handle = errors.open("wb")
            logs.append(handle)
            captures.append((subprocess.Popen(mesh.command("router", [
                tcpdump, "-Z", "root", "-i", f"ycw{index}r", "-n", "-s", "0", "-B", "16384",
                "-w", str(arguments.output / f"{side}.pcap")]), stdout=subprocess.DEVNULL, stderr=handle), errors))
        time.sleep(1.0)
        with tempfile.TemporaryDirectory(prefix="yume-circuit-capture-", dir="/tmp") as temporary:
            cluster = circuit_wan.Cluster(Path(temporary), environment, session.free_port(), {},
                                          session.setup_program(arguments.yume))
            for name in circuit_wan.NODES:
                logs.append((arguments.output / f"{name}.log").open("wb"))
                processes[name] = subprocess.Popen(
                    mesh.command(name, [str(arguments.yumed), "--config", str(cluster.server_config(name))]),
                    env=environment, stdout=logs[-1], stderr=subprocess.STDOUT)
            linked_by = time.monotonic() + 90
            while not circuit_wan.linked(cluster):
                for name, process in processes.items():
                    if process.poll() is not None:
                        raise CaptureError(f"{name} exited with {process.returncode}")
                if time.monotonic() > linked_by:
                    raise CaptureError("the nodes did not all link to each other")
                time.sleep(0.25)
            for index in range(arguments.sessions):
                measured = run_session(arguments, mesh, cluster, environment, index)
                report["sessions"].append(measured)
                print(json.dumps({"session": index, "routes": measured["routes"],
                                  "transfer_ms": measured["transfer_ms"]}), flush=True)
                time.sleep(arguments.gap)
            for name in circuit_wan.NODES:
                session.stop_process(processes[name], f"yumed {name}")
    except (CaptureError, session.SessionFailure, workload.WorkloadError, OSError,
            subprocess.SubprocessError, ValueError) as error:
        report["error"] = str(error)
        code = 1
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.send_signal(signal.SIGKILL)
                process.wait(timeout=5)
        for capture, _ in captures:
            if capture.poll() is None:
                capture.send_signal(signal.SIGINT)
                capture.wait(timeout=10)
        for handle in logs:
            handle.close()
        mesh.close()
    for capture, errors in captures:
        text = errors.read_text(encoding="utf-8", errors="replace")
        if capture.returncode not in (0, -signal.SIGINT) or \
                not re.search(r"^0 packets dropped by kernel$", text, re.MULTILINE):
            report.setdefault("capture_errors", []).append(text[-400:])
            code = 1
    for name in circuit_wan.NODES:
        log = arguments.output / f"{name}.log"
        if log.is_file():
            session.reject_secret_output(name, log.read_text(encoding="utf-8", errors="replace"))
    if code == 0:
        try:
            group = {"capture_day": datetime.date.today().isoformat(), "host": os.uname().nodename,
                     "network": "circuit-netns", "provider": "local"}
            report["analysis"] = analyse(arguments.output, arguments.compare, arguments.compare_label, group)
            described = report["analysis"].get("describe", {})
            print(json.dumps({"sessions": report["analysis"]["sessions"],
                              "non_overlapping": described.get("non_overlapping")}), flush=True)
        except (CaptureError, features.FeatureError, OSError, ValueError, KeyError) as error:
            report["error"] = f"analysis: {error}"
            code = 1
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
    parser.add_argument("--output", type=Path, required=True,
                        help="new private directory for captures and results. tcpdump writes the pcaps "
                             "there, and its AppArmor profile may refuse hidden directories")
    parser.add_argument("--sessions", type=int, default=5, help="client sessions, 1..40")
    parser.add_argument("--gap", type=float, default=2.0, help="seconds between sessions, 0..60")
    parser.add_argument("--condition", default="rtt=0", help="network condition of every hop")
    parser.add_argument("--compare", type=Path, help="an earlier campaign's feature document to describe against")
    parser.add_argument("--compare-label", type=int, choices=(0, 1), default=0,
                        help="which of its arms: 0 the browser, 1 the direct YUME session")
    arguments = parser.parse_args()
    try:
        wan.parse_condition(arguments.condition)
    except ValueError as error:
        parser.error(str(error))
    if not 1 <= arguments.sessions <= 40 or not 0 <= arguments.gap <= 60:
        parser.error("sessions must be 1..40 and the gap 0..60 seconds")
    for name in ("yumed", "yume", "openssl"):
        setattr(arguments, name, getattr(arguments, name).resolve(strict=True))
    if arguments.compare is not None:
        arguments.compare = arguments.compare.resolve(strict=True)
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
