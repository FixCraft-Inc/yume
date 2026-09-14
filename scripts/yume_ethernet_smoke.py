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
link to --baseline-port, which any firewall on the remote host must allow. The report keeps every
sample, the medians, both link states and both binary hashes. It is a smoke
measurement, not a benchmark: it has no CPU pinning, capture or matched
comparison target.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
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

EXIT_LINK_UNAVAILABLE = 3
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


def remote_link(ssh_host: str, remote: str) -> dict[str, object]:
    """The remote interface that owns the link address, and its negotiated state."""
    entries = json.loads(ssh(ssh_host, f"ip -json addr show to {shlex.quote(remote)}/32") or "[]")
    interface = entries[0].get("ifname", "") if entries else ""
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,15}", interface):
        raise session.SessionFailure(f"the remote host does not own {remote}")
    values = ssh(ssh_host, " ".join(f"cat /sys/class/net/{interface}/{name};"
                                    for name in ("operstate", "speed", "mtu"))).split()
    return {"interface": interface, **dict(zip(("operstate", "speed_mbit", "mtu"), values))}


def wait_for_remote_log(ssh_host: str, path: str, marker: str, deadline: float) -> None:
    """Readiness from a remote process's own report, so no probe connection reaches it."""
    while time.monotonic() < deadline:
        count = ssh(ssh_host, f"grep -c {shlex.quote(marker)} {shlex.quote(path)} 2>/dev/null || true").strip()
        if count not in ("", "0"):
            return
        time.sleep(0.5)
    raise session.SessionFailure(f"{Path(path).name} did not report '{marker}'")


def require_baseline_port(host: str, port: int) -> None:
    try:
        with socket.create_connection((host, port), timeout=3):
            return
    except OSError as error:
        raise session.SessionFailure(
            f"the untunnelled baseline cannot reach {host} port {port} ({error}). "
            "A firewall on the remote host may drop it, so pass a --baseline-port it allows") from None


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
    remote_dir = f"yume-ethernet-runs/{stamp}"
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
        ssh(ssh_host, f"umask 077 && mkdir -p {quoted} && tar -x -C {quoted}", stdin=archive.read_bytes())
        remote_payload = shlex.quote(f"{remote_dir}/payload_server.py")
        ssh(ssh_host, f"umask 077 && cat > {remote_payload}", stdin=REMOTE_PAYLOAD_SERVER.encode())

        remote_pids: list[str] = []
        client = None
        log_path = arguments.output / "yume.log"
        try:
            ports = " ".join(str(port) for port in dict.fromkeys((arguments.target_port, arguments.baseline_port)))
            remote_pids.append(ssh(ssh_host, f"nohup python3 {remote_payload} {shlex.quote(remote)} "
                                             f"{arguments.payload_bytes} {ports} "
                                             f"< /dev/null > {quoted}/payload.log 2>&1 & echo $!").strip())
            remote_pids.append(ssh(ssh_host, f"nohup {shlex.quote(arguments.remote_yumed)} "
                                             f"--config {quoted}/server/yumed.json "
                                             f"< /dev/null > {quoted}/yumed.log 2>&1 & echo $!").strip())
            report["remote"] = {"directory": f"~/{remote_dir}", "pids": remote_pids}
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
            # The kit's throwaway credentials are removed with the server directory. Logs stay.
            try:
                report["remote_log_tail"] = ssh(
                    ssh_host, f"{stop}rm -rf {quoted}/server; tail -20 {quoted}/yumed.log 2>/dev/null || true",
                    timeout=30)
            except (session.SessionFailure, subprocess.SubprocessError) as error:
                report["cleanup_error"] = str(error)
    session.reject_secret_output("yume-ytp1", log_path.read_text(encoding="utf-8", errors="replace"))


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
    arguments.output = arguments.output.resolve()
    arguments.output.mkdir(parents=True, exist_ok=False)
    report: dict[str, object] = {"schema": "yume.ethernet-smoke/2",
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
    if "PRIVATE KEY" in str(report.get("remote_log_tail", "")):
        report["remote_log_tail"] = "withheld: the remote log contained key material"
        code = code or 1
    report["does_not_prove"] = [
        "Throughput or latency beyond these transfers, this link and these hosts.",
        "Stealth, classifier or DPI behavior.",
    ]
    (arguments.output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report.get(key) for key in
                      ("link", "remote_link", "median_mbit_s", "samples", "error")}, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
