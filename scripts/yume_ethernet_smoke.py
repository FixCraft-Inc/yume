#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Run a YTP/1 session from this machine to a remote host over a direct link.

The client (yume-ytp1) runs here and the daemon (yumed-ytp1) runs on the remote
host through SSH. Before anything starts, a preflight records the route,
interface state, negotiated speed and MTU, and requires SSH to answer on the
remote address. An unavailable link fails with exit status 3.

Each repetition fetches the same payload untunnelled and then through the
tunnel, so both paths see the same link conditions. The daemon reaches the
tunnel destination on the remote host itself. The untunnelled fetch crosses the
link to --baseline-port, which any firewall on the remote host must allow.

--capture-ssh names a root login on the remote host. The runner uses it only to
start and stop tcpdump on the link interface, which drops to the normal user
once the interface is open, and with --wire-frames to turn segmentation and
receive offloads off for the run and restore the recorded values afterwards.
Without --wire-frames the capture holds coalesced frames, not frames as they
crossed the wire. --remote-ndpi-reader runs nDPI on the capture as the normal
user. The capture, reader output and remote logs are pulled into the output
directory, and the remote run directory is removed after a complete pull.

The report keeps every sample, the medians, both link states and the binary
hashes. It is a smoke measurement, not a benchmark: it has no CPU pinning or
matched comparison target, and a run with a capture or changed offloads is not
throughput evidence.
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import socket
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yume_native_session as session  # noqa: E402
import yume_ndpi_report as ndpi  # noqa: E402

EXIT_LINK_UNAVAILABLE = 3
MAX_CAPTURED_PAYLOAD = 256 * 1024 * 1024
OFFLOADS = {"tso": "tcp-segmentation-offload", "gso": "generic-segmentation-offload",
            "gro": "generic-receive-offload"}
INTERFACE = re.compile(r"[A-Za-z0-9._-]{1,15}")
REMOTE_PAYLOAD_SERVER = r'''
import http.server, sys, threading
host, size, ports = sys.argv[1], int(sys.argv[2]), [int(port) for port in sys.argv[3:]]
pattern = bytes(range(256)) * 4096
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(size))
        self.send_header("Connection", "close")
        self.end_headers()
        remaining = size
        while remaining:
            piece = pattern[:remaining]
            self.wfile.write(piece)
            remaining -= len(piece)
    def log_message(self, *args):
        pass
servers = [http.server.ThreadingHTTPServer((host, port), Handler) for port in ports]
print("ready", flush=True)
for server in servers[1:]:
    threading.Thread(target=server.serve_forever, daemon=True).start()
servers[0].serve_forever()
'''


class LinkUnavailable(RuntimeError):
    pass


def read_sys(interface: str, name: str) -> str | None:
    try:
        return (Path("/sys/class/net") / interface / name).read_text().strip()
    except OSError:
        return None


def preflight(remote: str) -> dict[str, object]:
    route = subprocess.run(["ip", "-json", "route", "get", remote],
                           capture_output=True, text=True, timeout=5, check=False)
    if route.returncode:
        raise LinkUnavailable(f"no route to {remote}")
    entries = json.loads(route.stdout or "[]")
    interface = entries[0].get("dev") if entries else None
    if not interface:
        raise LinkUnavailable(f"no interface for {remote}")
    facts = {
        "remote": remote,
        "interface": interface,
        "gateway": entries[0].get("gateway"),
        "source": entries[0].get("prefsrc"),
        "operstate": read_sys(interface, "operstate"),
        "carrier": read_sys(interface, "carrier"),
        "speed_mbit": read_sys(interface, "speed"),
        "mtu": read_sys(interface, "mtu"),
    }
    if facts["operstate"] != "up" or facts["carrier"] != "1":
        raise LinkUnavailable(f"{interface} is {facts['operstate']} with carrier {facts['carrier']}")
    if facts["gateway"]:
        raise LinkUnavailable(f"{remote} is routed through {facts['gateway']}, not a direct link")
    try:
        with socket.create_connection((remote, 22), timeout=3):
            pass
    except OSError as error:
        raise LinkUnavailable(f"SSH on {remote} did not answer: {error}") from None
    return facts


def ssh(host: str, command: str, *, stdin: bytes | None = None, timeout: float = 60) -> str:
    result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", host, command],
                            input=stdin, capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        raise session.SessionFailure(f"remote command failed: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout.decode(errors="replace")


def root(arguments: argparse.Namespace, command: str) -> str:
    """The root login runs only tcpdump start and stop and ethtool offload changes."""
    return ssh(arguments.capture_ssh, command, timeout=60)


def remote_link(ssh_host: str, remote: str) -> dict[str, object]:
    """The remote interface that owns the link address, and its negotiated state."""
    entries = json.loads(ssh(ssh_host, f"ip -json addr show to {shlex.quote(remote)}/32") or "[]")
    interface = entries[0].get("ifname", "") if entries else ""
    if not INTERFACE.fullmatch(interface):
        raise session.SessionFailure(f"the remote host does not own {remote}")
    values = ssh(ssh_host, " ".join(f"cat /sys/class/net/{interface}/{name};"
                                    for name in ("operstate", "speed", "mtu"))).split()
    return {"interface": interface, **dict(zip(("operstate", "speed_mbit", "mtu"), values))}


def remote_home(ssh_host: str) -> str:
    home = ssh(ssh_host, 'printf %s "$HOME"').strip()
    if not re.fullmatch(r"/[A-Za-z0-9._/-]+", home):
        raise session.SessionFailure("the remote home directory has an unexpected path")
    return home


def wait_for_remote_log(ssh_host: str, path: str, marker: str, deadline: float) -> None:
    """Readiness from a remote process's own report, so no probe connection reaches it."""
    while time.monotonic() < deadline:
        count = ssh(ssh_host, f"grep -c {shlex.quote(marker)} {shlex.quote(path)} 2>/dev/null || true").strip()
        if count not in ("", "0"):
            return
        time.sleep(0.5)
    raise session.SessionFailure(f"{PurePosixPath(path).name} did not report '{marker}'")


def require_baseline_port(host: str, port: int) -> None:
    try:
        with socket.create_connection((host, port), timeout=3):
            return
    except OSError as error:
        raise session.SessionFailure(
            f"the untunnelled baseline cannot reach {host} port {port} ({error}). "
            "A firewall on the remote host may drop it, so pass a --baseline-port it allows") from None


def wait_for_link(remote: str, local_interface: str, deadline: float) -> None:
    """Some drivers reset the link when offloads change."""
    while time.monotonic() < deadline:
        if read_sys(local_interface, "carrier") == "1":
            try:
                with socket.create_connection((remote, 22), timeout=2):
                    return
            except OSError:
                pass
        time.sleep(0.5)
    raise session.SessionFailure("the direct link did not come back after an offload change")


def parse_offloads(text: str) -> dict[str, str]:
    """TSO, GSO and GRO states from `ethtool -k` output, without any [fixed] marker."""
    state = {}
    for line in text.splitlines():
        name, _, value = line.partition(":")
        for key, feature in OFFLOADS.items():
            if name.strip() == feature and value.split():
                state[key] = value.split()[0]
    return state


def offload_state(ssh_host: str, interface: str) -> dict[str, str]:
    state = parse_offloads(ssh(ssh_host, f"/usr/sbin/ethtool -k {interface}"))
    if set(state) != set(OFFLOADS) or not set(state.values()) <= {"on", "off"}:
        raise session.SessionFailure(f"cannot read the offloads of {interface}")
    return state


def tcpdump_counts(text: str) -> dict[str, int | None]:
    counts = {}
    for key, label in (("captured", "packets captured"), ("received_by_filter", "packets received by filter"),
                       ("dropped_by_kernel", "packets dropped by kernel")):
        match = re.search(rf"(\d+) {label}", text)
        counts[key] = int(match.group(1)) if match else None
    return counts


def start_capture(arguments: argparse.Namespace, report: dict[str, object], state: dict[str, object],
                  ssh_host: str, remote_dir: str) -> None:
    interface = str(report["remote_link"]["interface"])
    user = ssh(ssh_host, "id -un").strip()
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
        raise session.SessionFailure("the remote user name has unexpected characters")
    local_address = str(ipaddress.ip_address(str(report["link"]["source"])))
    capture: dict[str, object] = {"interface": interface, "user": user,
                                  "offloads_before": offload_state(ssh_host, interface)}
    report["capture"] = capture
    if arguments.wire_frames:
        state["restore"] = (interface, dict(capture["offloads_before"]))
        root(arguments, f"/usr/sbin/ethtool -K {interface} " + " ".join(f"{key} off" for key in OFFLOADS))
        wait_for_link(arguments.remote_host, str(report["link"]["interface"]), time.monotonic() + 30)
        capture["offloads_during"] = offload_state(ssh_host, interface)
        if set(capture["offloads_during"].values()) != {"off"}:
            raise session.SessionFailure(f"offloads on {interface} did not turn off")
    expression = f"host {local_address} and tcp port {arguments.port}"
    pcap, log = f"{remote_dir}/link.pcap", f"{remote_dir}/tcpdump.log"
    pid = root(arguments, f"nohup /usr/bin/tcpdump -i {interface} -Z {user} -U -n -B 65536 "
                          f"-w {shlex.quote(pcap)} {shlex.quote(expression)} "
                          f"< /dev/null > {shlex.quote(log)} 2>&1 & echo $!").strip()
    if not pid.isdigit():
        raise session.SessionFailure("tcpdump did not start")
    state["pid"] = pid
    capture["filter"] = expression
    wait_for_remote_log(ssh_host, log, "listening on", time.monotonic() + 15)
    capture["tcpdump_user"] = ssh(ssh_host, f"ps -o user= -p {pid}").strip()
    if capture["tcpdump_user"] != user:
        raise session.SessionFailure(f"tcpdump runs as {capture['tcpdump_user']}, not {user}")


def stop_tcpdump(arguments: argparse.Namespace, ssh_host: str, pid: str) -> None:
    for signal_as in (lambda command: ssh(ssh_host, command), lambda command: root(arguments, command)):
        signal_as(f"kill -INT {pid} 2>/dev/null || true")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if ssh(ssh_host, f"test -d /proc/{pid} && echo running || echo stopped").strip() == "stopped":
                return
            time.sleep(0.5)
    raise session.SessionFailure(f"tcpdump {pid} did not stop")


def finish_capture(arguments: argparse.Namespace, report: dict[str, object], state: dict[str, object],
                   ssh_host: str, remote_dir: str) -> None:
    capture = report.setdefault("capture", {})
    pid = state.get("pid")
    if pid:
        try:
            stop_tcpdump(arguments, ssh_host, str(pid))
            capture["tcpdump"] = tcpdump_counts(ssh(ssh_host, f"cat {shlex.quote(remote_dir + '/tcpdump.log')}"))
        except (session.SessionFailure, subprocess.SubprocessError) as error:
            capture["stop_error"] = str(error)
    if "restore" in state:
        interface, before = state["restore"]
        command = f"/usr/sbin/ethtool -K {interface} " + " ".join(f"{key} {before[key]}" for key in OFFLOADS)
        try:
            root(arguments, command)
            wait_for_link(arguments.remote_host, str(report["link"]["interface"]), time.monotonic() + 30)
            capture["offloads_restored"] = offload_state(ssh_host, interface)
            if capture["offloads_restored"] != before:
                raise session.SessionFailure("offloads differ from their recorded values")
        except (session.SessionFailure, subprocess.SubprocessError, OSError) as error:
            capture["restore_error"] = f"{error}. Restore as root: {command}"
            print(f"OFFLOADS NOT RESTORED: {capture['restore_error']}", file=sys.stderr)
    if pid and arguments.remote_ndpi_reader:
        readers: dict[str, dict[str, object]] = {}
        capture["readers"] = readers
        pcap = shlex.quote(f"{remote_dir}/link.pcap")
        for index, reader in enumerate(arguments.remote_ndpi_reader):
            name = PurePosixPath(reader).parent.parent.name
            if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", name) or name in readers:
                name = f"reader-{index}"
            try:
                readers[name] = {"path": reader,
                                 "sha256": ssh(ssh_host, f"sha256sum {shlex.quote(reader)}").split()[0]}
                for mode, flag in (("default", ""), ("dpi-only", " -d")):
                    stem = f"{remote_dir}/ndpi-{name}-{mode}"
                    ssh(ssh_host, f"{shlex.quote(reader)}{flag} -i {pcap} -C {shlex.quote(stem + '.csv')} "
                                  f"> {shlex.quote(stem + '.txt')} 2>&1 || true", timeout=600)
            except (session.SessionFailure, subprocess.SubprocessError) as error:
                readers.setdefault(name, {})["error"] = str(error)


def pull_remote_directory(ssh_host: str, remote_dir: str, destination: Path) -> None:
    """Copies the run directory, then removes it remotely. The kit is already gone."""
    result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", ssh_host,
                             f"tar -C {shlex.quote(remote_dir)} -c --exclude=./server ."],
                            capture_output=True, timeout=900, check=False)
    if result.returncode:
        raise session.SessionFailure(f"pulling the remote run failed: {result.stderr.decode(errors='replace').strip()}")
    destination.mkdir()
    with tempfile.TemporaryFile() as archive:
        archive.write(result.stdout)
        archive.seek(0)
        with tarfile.open(fileobj=archive) as bundle:
            members = bundle.getmembers()
            if any(member.name.startswith("/") or ".." in PurePosixPath(member.name).parts or
                   not (member.isfile() or member.isdir()) for member in members):
                raise session.SessionFailure("the remote run archive has unexpected entries")
            # The data filter, where this Python has it, also refuses links and device files.
            if hasattr(tarfile, "data_filter"):
                bundle.extractall(destination, members=members, filter="data")
            else:
                bundle.extractall(destination, members=members)
    for path in destination.rglob("*"):
        if path.is_file() and path.suffix in {".log", ".txt", ".csv"}:
            session.reject_secret_output(path.name, path.read_text(encoding="utf-8", errors="replace"))
    ssh(ssh_host, f"rm -rf {shlex.quote(remote_dir)} && (rmdir {shlex.quote(str(PurePosixPath(remote_dir).parent))} "
                  "2>/dev/null || true)")


def summarize_capture(arguments: argparse.Namespace, report: dict[str, object]) -> list[str]:
    capture = report.get("capture")
    if not isinstance(capture, dict):
        return []
    failures = [str(capture[key]) for key in ("stop_error", "restore_error") if capture.get(key)]
    counts = capture.get("tcpdump") or {}
    if counts.get("dropped_by_kernel"):
        failures.append(f"tcpdump dropped {counts['dropped_by_kernel']} packets")
    pulled = arguments.output / "remote"
    for name, reader in (capture.get("readers") or {}).items():
        if reader.get("error"):
            failures.append(f"{name}: {reader['error']}")
            continue
        for mode in ("default", "dpi-only"):
            stem = pulled / f"ndpi-{name}-{mode}"
            result = ndpi.reader_report(Path(f"{stem}.txt"), arguments.port)
            result["csv_flows"] = ndpi.flows_on_port(Path(f"{stem}.csv"), arguments.port)
            reader[mode] = result
            failures += ndpi.capture_failures(f"{name} {mode}", result, arguments.port)
    capture["failures"] = failures
    return failures


def untunnelled_get(host: str, port: int) -> tuple[int, str, float]:
    with socket.create_connection((host, port), timeout=20) as connection:
        started = time.monotonic()
        connection.sendall(b"GET /payload HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
        length, digest = session.read_http_body(connection)
        return length, digest, time.monotonic() - started


def rate(length: int, seconds: float) -> float:
    return round(length * 8 / 1_000_000 / seconds, 2) if seconds > 0 else 0.0


def measure(arguments: argparse.Namespace, remote: str, socks_port: int,
            report: dict[str, object]) -> None:
    expected = session.payload_digest(arguments.payload_bytes)
    fetches = {
        "untunnelled": lambda: untunnelled_get(remote, arguments.baseline_port),
        "tunnelled": lambda: session.get_through_socks(socks_port, remote, arguments.target_port,
                                                       time.monotonic() + 60),
    }
    samples: list[dict[str, object]] = []
    report["samples"] = samples
    for _ in range(arguments.repeats):
        sample = {}
        for name, fetch in fetches.items():
            length, digest, seconds = fetch()
            if length != arguments.payload_bytes or digest != expected:
                raise session.SessionFailure(f"{name} payload differs from the served payload")
            sample[name] = {"seconds": round(seconds, 3), "mbit_s": rate(length, seconds)}
        samples.append(sample)
    report["median_mbit_s"] = {name: statistics.median(sample[name]["mbit_s"] for sample in samples)
                               for name in fetches}


def run(arguments: argparse.Namespace, report: dict[str, object]) -> None:
    remote, ssh_host = arguments.remote_host, arguments.ssh_host or arguments.remote_host
    environment = session.openssl_environment(arguments.openssl)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    remote_dir = f"{remote_home(ssh_host)}/yume-ethernet-runs/{stamp}"
    quoted = shlex.quote(remote_dir)
    report["local_host"] = {"name": platform.node(), "cpus": os.cpu_count()}
    report["remote_link"] = remote_link(ssh_host, remote)
    report["binaries"] = {
        "yume-ytp1": session.file_digest(arguments.yume),
        "yumed-ytp1": ssh(ssh_host, f"sha256sum {shlex.quote(arguments.remote_yumed)}").split()[0],
    }
    report["payload_bytes"] = arguments.payload_bytes
    report["ports"] = {"yumed": arguments.port, "tunnel_destination": arguments.target_port,
                       "baseline": arguments.baseline_port}
    with tempfile.TemporaryDirectory(prefix="yume-ethernet-") as temporary:
        kit = Path(temporary) / "kit"
        session.provision_kit(kit, arguments.server_name, arguments.port, environment)
        socks_port = session.free_port()
        session.configure_kit(kit, listen_address=remote, networks=[f"{remote}/32"],
                              connect_address=remote, socks_port=socks_port)
        archive = Path(temporary) / "server.tar"
        with tarfile.open(archive, "w") as bundle:
            bundle.add(kit / "server", arcname="server")

        remote_pids: list[str] = []
        capture_state: dict[str, object] = {}
        client = None
        log_path = arguments.output / "yume.log"
        try:
            ssh(ssh_host, f"umask 077 && mkdir -p {quoted} && tar -x -C {quoted}", stdin=archive.read_bytes())
            ssh(ssh_host, f"umask 077 && cat > {quoted}/payload_server.py", stdin=REMOTE_PAYLOAD_SERVER.encode())
            if arguments.capture_ssh:
                start_capture(arguments, report, capture_state, ssh_host, remote_dir)
            ports = " ".join(str(port) for port in dict.fromkeys((arguments.target_port, arguments.baseline_port)))
            remote_pids.append(ssh(ssh_host, f"nohup python3 {quoted}/payload_server.py {shlex.quote(remote)} "
                                             f"{arguments.payload_bytes} {ports} "
                                             f"< /dev/null > {quoted}/payload.log 2>&1 & echo $!").strip())
            remote_pids.append(ssh(ssh_host, f"nohup {shlex.quote(arguments.remote_yumed)} "
                                             f"--config {quoted}/server/yumed.json "
                                             f"< /dev/null > {quoted}/yumed.log 2>&1 & echo $!").strip())
            report["remote"] = {"directory": remote_dir, "pids": remote_pids}
            deadline = time.monotonic() + 30
            wait_for_remote_log(ssh_host, f"{remote_dir}/yumed.log", "listening on", deadline)
            wait_for_remote_log(ssh_host, f"{remote_dir}/payload.log", "ready", deadline)
            require_baseline_port(remote, arguments.baseline_port)
            with log_path.open("wb") as log:
                client = subprocess.Popen([str(arguments.yume), "--config", str(kit / "client/yume.json")],
                                          env=environment, stdout=log, stderr=subprocess.STDOUT)
                session.wait_for_port("127.0.0.1", socks_port, client, time.monotonic() + 30)
                measure(arguments, remote, socks_port, report)
                session.stop_process(client, "yume-ytp1")
                client = None
        finally:
            if client is not None and client.poll() is None:
                client.kill()
                client.wait(timeout=5)
            pids = " ".join(pid for pid in remote_pids if pid.isdigit())
            stop = f"kill {pids} 2>/dev/null; sleep 1; " if pids else ""
            # The kit's throwaway credentials leave the remote host before anything is pulled.
            try:
                report["remote_log_tail"] = ssh(
                    ssh_host, f"{stop}rm -rf {quoted}/server; tail -20 {quoted}/yumed.log 2>/dev/null || true",
                    timeout=30)
            except (session.SessionFailure, subprocess.SubprocessError) as error:
                report["cleanup_error"] = str(error)
            if arguments.capture_ssh:
                finish_capture(arguments, report, capture_state, ssh_host, remote_dir)
            try:
                pull_remote_directory(ssh_host, remote_dir, arguments.output / "remote")
            except (session.SessionFailure, subprocess.SubprocessError, OSError, tarfile.TarError) as error:
                report["pull_error"] = f"{error}. The remote run stays in {remote_dir}"
    if log_path.is_file():
        session.reject_secret_output("yume-ytp1", log_path.read_text(encoding="utf-8", errors="replace"))


def printable(report: dict[str, object]) -> dict[str, object]:
    shown = {key: report.get(key) for key in ("link", "remote_link", "median_mbit_s", "samples", "error",
                                              "pull_error")}
    capture = report.get("capture")
    if isinstance(capture, dict):
        summary = {key: capture.get(key) for key in ("interface", "tcpdump_user", "offloads_before",
                                                     "offloads_during", "offloads_restored", "tcpdump",
                                                     "restore_error", "failures")}
        for name, reader in (capture.get("readers") or {}).items():
            for mode in ("default", "dpi-only"):
                result = reader.get(mode) or {}
                summary[f"{name} {mode}"] = {
                    "max_packet_bytes": result.get("max_packet_bytes"),
                    "discarded_bytes": result.get("discarded_bytes"),
                    "flows": [ndpi.flow_summary(line) for line in result.get("flows", [])]}
        shown["capture"] = summary
    return shown


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--remote-host", default="10.77.77.1", help="remote address on the direct link")
    parser.add_argument("--ssh-host", help="SSH destination, default the remote address")
    parser.add_argument("--remote-yumed", help="yumed-ytp1 path on the remote host")
    parser.add_argument("--yume", type=Path, help="local yume-ytp1")
    parser.add_argument("--openssl", type=Path, help="openssl for kit generation")
    parser.add_argument("--output", type=Path, required=True, help="new directory for the report")
    parser.add_argument("--server-name", default="link.example.test")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--target-port", type=int, default=18080,
                        help="tunnel destination port, reached on the remote host itself")
    parser.add_argument("--baseline-port", type=int,
                        help="untunnelled payload port reached across the link, default the target port")
    parser.add_argument("--payload-bytes", type=int, default=256 * 1024 * 1024)
    parser.add_argument("--repeats", type=int, default=3, help="untunnelled and tunnelled pairs, 1..20")
    parser.add_argument("--capture-ssh", help="root SSH login on the remote host for tcpdump and offloads")
    parser.add_argument("--wire-frames", action="store_true",
                        help="turn TSO, GSO and GRO off on the remote link interface during the capture")
    parser.add_argument("--remote-ndpi-reader", action="append", default=[],
                        help="ndpiReader path on the remote host to run on the capture, repeatable")
    parser.add_argument("--preflight-only", action="store_true")
    arguments = parser.parse_args()
    if not arguments.preflight_only and not (arguments.remote_yumed and arguments.yume and arguments.openssl):
        parser.error("--remote-yumed, --yume and --openssl are required unless --preflight-only")
    if not 1 <= arguments.repeats <= 20 or not 1 << 20 <= arguments.payload_bytes <= 4 << 30:
        parser.error("repeats must be 1..20 and payload bytes 1 MiB..4 GiB")
    arguments.baseline_port = arguments.baseline_port or arguments.target_port
    ports = (arguments.port, arguments.target_port, arguments.baseline_port)
    if not all(1024 <= port <= 65535 for port in ports) or arguments.port in ports[1:]:
        parser.error("ports must be 1024..65535 and differ from the daemon port")
    if (arguments.wire_frames or arguments.remote_ndpi_reader) and not arguments.capture_ssh:
        parser.error("--wire-frames and --remote-ndpi-reader need --capture-ssh")
    if arguments.capture_ssh and arguments.payload_bytes * arguments.repeats > MAX_CAPTURED_PAYLOAD:
        parser.error("a capture run carries at most 256 MiB through the tunnel")
    arguments.output = arguments.output.resolve()
    arguments.output.mkdir(parents=True, exist_ok=False)
    report: dict[str, object] = {"schema": "yume.ethernet-smoke/3",
                                 "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    code = 0
    try:
        report["link"] = preflight(arguments.remote_host)
        if not arguments.preflight_only:
            run(arguments, report)
    except LinkUnavailable as error:
        report["error"] = f"link unavailable: {error}"
        code = EXIT_LINK_UNAVAILABLE
    except (session.SessionFailure, OSError, subprocess.SubprocessError, ValueError) as error:
        report["error"] = str(error)
        code = 1
    if summarize_capture(arguments, report) or report.get("pull_error"):
        code = code or 1
    if "PRIVATE KEY" in str(report.get("remote_log_tail", "")):
        report["remote_log_tail"] = "withheld: the remote log contained key material"
        code = code or 1
    report["does_not_prove"] = [
        "Throughput or latency beyond these transfers, this link and these hosts.",
        "Stealth, classifier or DPI behavior beyond the recorded reader output.",
    ]
    if "capture" in report:
        report["does_not_prove"].append("Throughput, from a run with a capture or changed offloads.")
    (arguments.output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(printable(report), indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
