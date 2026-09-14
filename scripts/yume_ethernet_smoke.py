#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Run a YTP/1 session from this machine to a remote host over a direct link.

The client (yume-ytp1) runs here and the daemon (yumed-ytp1) runs on the remote
host through SSH. Before anything starts, a preflight records the route,
interface state, negotiated speed and MTU, and requires SSH to answer on the
remote address. An unavailable link fails with exit status 3.

The report compares an untunnelled HTTP transfer with the same transfer
through the tunnel. One run is a smoke measurement, not a benchmark: it has no
repetitions, CPU pinning or capture.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
import shlex
import socket
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
import http.server, sys
size = int(sys.argv[3])
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
http.server.ThreadingHTTPServer((sys.argv[1], int(sys.argv[2])), Handler).serve_forever()
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


def untunnelled_get(host: str, port: int) -> tuple[int, str, float]:
    with socket.create_connection((host, port), timeout=20) as connection:
        started = time.monotonic()
        connection.sendall(b"GET /payload HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
        length, digest = session.read_http_body(connection)
        return length, digest, time.monotonic() - started


def rate(length: int, seconds: float) -> float:
    return round(length * 8 / 1_000_000 / seconds, 2) if seconds > 0 else 0.0


def run(arguments: argparse.Namespace, report: dict[str, object]) -> None:
    remote, ssh_host = arguments.remote_host, arguments.ssh_host or arguments.remote_host
    environment = session.openssl_environment(arguments.openssl)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    remote_dir = f"yume-ethernet-runs/{stamp}"
    with tempfile.TemporaryDirectory(prefix="yume-ethernet-") as temporary:
        kit = Path(temporary) / "kit"
        session.provision_kit(kit, arguments.server_name, arguments.port, environment)
        socks_port = session.free_port()
        target_port = arguments.target_port
        session.configure_kit(kit, listen_address=remote, networks=[f"{remote}/32"],
                              connect_address=remote, socks_port=socks_port)
        archive = Path(temporary) / "server.tar"
        with tarfile.open(archive, "w") as bundle:
            bundle.add(kit / "server", arcname="server")
        quoted = shlex.quote(remote_dir)
        ssh(ssh_host, f"umask 077 && mkdir -p {quoted} && tar -x -C {quoted}", stdin=archive.read_bytes())

        remote_payload = shlex.quote(f"{remote_dir}/payload_server.py")
        ssh(ssh_host, f"umask 077 && cat > {remote_payload}", stdin=REMOTE_PAYLOAD_SERVER.encode())
        target_pid = ssh(ssh_host, f"nohup python3 {remote_payload} {shlex.quote(remote)} {target_port} "
                                   f"{arguments.payload_bytes} > {quoted}/payload.log 2>&1 & echo $!").strip()
        yumed_pid = ssh(ssh_host, f"nohup {shlex.quote(arguments.remote_yumed)} --config {quoted}/server/yumed.json "
                                  f"> {quoted}/yumed.log 2>&1 & echo $!").strip()
        report["remote"] = {"directory": f"~/{remote_dir}", "yumed_pid": yumed_pid, "payload_pid": target_pid}

        client = None
        log_path = Path(arguments.output) / "yume.log"
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                try:
                    with socket.create_connection((remote, arguments.port), timeout=1):
                        break
                except OSError:
                    time.sleep(0.2)
            expected = session.payload_digest(arguments.payload_bytes)
            length, digest, seconds = untunnelled_get(remote, target_port)
            if length != arguments.payload_bytes or digest != expected:
                raise session.SessionFailure("untunnelled payload differs")
            report["untunnelled"] = {"bytes": length, "seconds": round(seconds, 3), "mbit_s": rate(length, seconds)}

            with log_path.open("wb") as log:
                client = subprocess.Popen([str(arguments.yume), "--config", str(kit / "client/yume.json")],
                                          env=environment, stdout=log, stderr=subprocess.STDOUT)
                session.wait_for_port("127.0.0.1", socks_port, client, time.monotonic() + 30)
                length, digest, seconds = session.get_through_socks(
                    socks_port, remote, target_port, time.monotonic() + 60)
                if length != arguments.payload_bytes or digest != expected:
                    raise session.SessionFailure("tunnelled payload differs")
                report["tunnelled"] = {"bytes": length, "seconds": round(seconds, 3), "mbit_s": rate(length, seconds)}
                session.stop_process(client, "yume-ytp1")
                client = None
        finally:
            if client is not None and client.poll() is None:
                client.kill()
                client.wait(timeout=5)
            ssh(ssh_host, f"kill {shlex.quote(yumed_pid)} {shlex.quote(target_pid)} 2>/dev/null; sleep 1; "
                          f"tail -20 {quoted}/yumed.log", timeout=30)
            report["remote_log_tail"] = ssh(ssh_host, f"tail -20 {quoted}/yumed.log", timeout=30)
            session.reject_secret_output("yumed-ytp1", str(report["remote_log_tail"]))


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
    parser.add_argument("--target-port", type=int, default=18080)
    parser.add_argument("--payload-bytes", type=int, default=256 * 1024 * 1024)
    parser.add_argument("--preflight-only", action="store_true")
    arguments = parser.parse_args()
    if not arguments.preflight_only and not (arguments.remote_yumed and arguments.yume and arguments.openssl):
        parser.error("--remote-yumed, --yume and --openssl are required unless --preflight-only")
    arguments.output.mkdir(parents=True, exist_ok=False)
    report: dict[str, object] = {"schema": "yume.ethernet-smoke/1",
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
    report["does_not_prove"] = [
        "Throughput or latency beyond this single transfer and link state.",
        "Stealth, classifier or DPI behavior.",
    ]
    (arguments.output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report.get(key) for key in ("link", "untunnelled", "tunnelled", "error")}, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
