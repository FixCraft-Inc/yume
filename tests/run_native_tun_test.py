#!/usr/bin/env python3
"""Exercise native TUN traffic and cleanup inside unprivileged network namespaces."""
from __future__ import annotations

import argparse
import errno
import ipaddress
from contextlib import ExitStack
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
import yume_native_session as session  # noqa: E402
import native_resolved_fixture as resolved_fixture  # noqa: E402


def command(argv: list[str], timeout: float = 15) -> subprocess.CompletedProcess:
    return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                          timeout=timeout, check=True)


def send(process: subprocess.Popen, text: str) -> None:
    assert process.stdin is not None
    process.stdin.write(text + "\n")
    process.stdin.flush()


def receive(process: subprocess.Popen, timeout: float = 20) -> str:
    assert process.stdout is not None
    with selectors.DefaultSelector() as poll:
        poll.register(process.stdout, selectors.EVENT_READ)
        if not poll.select(timeout):
            raise RuntimeError("namespace worker did not respond")
    line = process.stdout.readline()
    if not line:
        raise RuntimeError(f"namespace worker exited with {process.poll()}")
    return line.strip()


def worker(role: str, kit: Path, binary: Path, resolved: Path | None) -> None:
    print("ready", flush=True)
    if sys.stdin.readline().strip() != "start":
        raise RuntimeError("invalid worker start")
    wire = "wire-server" if role == "server" else "wire-client"
    address = "192.0.2.1/30" if role == "server" else "192.0.2.2/30"
    command(["ip", "link", "set", "lo", "up"])
    command(["ip", "addr", "add", address, "dev", wire])
    command(["ip", "link", "set", wire, "up"])
    config = kit / role / ("yumed.json" if role == "server" else "yume.json")
    with ExitStack() as worker_stack, (kit / f"{role}.log").open("w+", encoding="utf-8") as log:
        if resolved is not None:
            artifacts = kit / "resolved"
            artifacts.mkdir()
            worker_stack.enter_context(resolved_fixture.isolated_resolved(resolved, artifacts))
        process = None
        action = "start"
        try:
            while True:
                if action == "start" and (process is None or process.poll() is not None):
                    attempt_start = log.tell()
                    process = subprocess.Popen([str(binary), "--config", str(config)],
                                               stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
                    print("started", flush=True)
                elif action == "stop" and process is not None:
                    session.stop_process(process, f"TUN {role}")
                    if resolved is not None:
                        resolved_fixture.check_clean()
                    print("stopped", flush=True)
                elif action.startswith("dns ") and resolved is not None:
                    resolved_fixture.check_link_and_query(action.split(" ", 1)[1])
                    print("resolved", flush=True)
                elif action == "expect-failure" and process is not None:
                    if process.wait(timeout=15) != 2:
                        raise RuntimeError("route conflict did not produce the expected startup refusal")
                    log.seek(attempt_start)
                    diagnostic = log.read()
                    log.seek(0, os.SEEK_END)
                    session.reject_secret_output(role, diagnostic)
                    if "configure TUN networking" not in diagnostic or os.strerror(errno.EEXIST) not in diagnostic:
                        raise RuntimeError("startup refusal was not caused by the conflicting route")
                    print("failed", flush=True)
                elif action == "exit" and process is not None and process.poll() is not None:
                    return
                else:
                    raise RuntimeError("invalid worker lifecycle command")
                action = sys.stdin.readline().strip()
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)


def in_namespace(worker_process: subprocess.Popen, argv: list[str], timeout: float = 15) -> subprocess.CompletedProcess:
    return command(["nsenter", "--target", str(worker_process.pid), "--net", "--", *argv], timeout)


def wait_interface(worker_process: subprocess.Popen, name: str) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        result = subprocess.run(["nsenter", "--target", str(worker_process.pid), "--net", "--",
                                 "ip", "-j", "link", "show", "dev", name],
                                capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            rows = json.loads(result.stdout)
            if len(rows) == 1 and "UP" in rows[0]["flags"] and rows[0]["mtu"] == 1420:
                return
        if worker_process.poll() is not None:
            raise RuntimeError("worker stopped before interface creation")
        time.sleep(0.05)
    raise RuntimeError(f"managed TUN {name} was not brought up with its MTU")


def echo() -> None:
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("10.71.0.1", 32123))
        listener.listen(1)
        listener.settimeout(15)
        print("ready", flush=True)
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(10)
            total = 0
            while data := connection.recv(65536):
                total += len(data)
                if total > 2 * 1024 * 1024:
                    raise RuntimeError("echo input exceeds fixture bound")
                connection.sendall(data)
            if total != 2 * 1024 * 1024:
                raise RuntimeError("echo input was incomplete")


def transfer() -> None:
    payload = bytes(range(256)) * 256
    with socket.create_connection(("10.71.0.1", 32123), timeout=15) as connection:
        for _ in range(32):
            connection.sendall(payload)
            received = bytearray()
            while len(received) < len(payload):
                chunk = connection.recv(len(payload) - len(received))
                if not chunk:
                    raise RuntimeError("TUN TCP response ended early")
                received.extend(chunk)
            if received != payload:
                raise RuntimeError("TUN TCP bytes changed")
        connection.shutdown(socket.SHUT_WR)
        if connection.recv(1):
            raise RuntimeError("TUN TCP response has trailing bytes")


def configure(kit: Path, resolved: bool = False) -> None:
    for role, local, peer in (("server", 1, 2), ("client", 2, 1)):
        path = kit / role / ("yumed.json" if role == "server" else "yume.json")
        config = json.loads(path.read_text())
        config["services"] = [{"name": "ip", "kind": "packet", "max_concurrent_streams": 1}]
        config["adapters"] = [{"kind": "packet", "service": "ip", "interface_name": f"ytp-{role}", "mtu": 1420,
            "network": {"addresses": [f"10.71.0.{local}/32", f"fd71::{local}/128"],
                        "routes": [f"10.71.0.{peer}/32", f"fd71::{peer}/128"],
                        "local_networks": [f"10.71.0.{local}/32", f"fd71::{local}/128"],
                        "peer_networks": [f"10.71.0.{peer}/32", f"fd71::{peer}/128"],
                        "dns": {"servers": [], "domains": []}}}]
        if role == "client":
            config["endpoint"]["connect_address"] = "192.0.2.1"
            config["adapters"][0]["network"]["routes"] = ["0.0.0.0/0", "::/0"]
            if resolved:
                config["adapters"][0]["network"]["dns"] = {
                    "servers": ["10.71.0.1"], "domains": ["yume.test"]}
        else:
            config["endpoint"]["listen_addresses"] = ["192.0.2.1"]
        path.write_text(json.dumps(config))
    auth_path = kit / "server/credentials/authorized-keys.json"
    auth = json.loads(auth_path.read_text())
    for key in auth["keys"]:
        key["capabilities"] = [{"service": "ip", "kind": "packet"}]
    auth_path.write_text(json.dumps(auth))


def isolated(yume: Path, yumed: Path, openssl: Path, resolved: Path | None) -> None:
    # The outer user/network namespace must have no host link. No command can
    # target the host namespace; child namespaces share this user namespace.
    if os.geteuid() != 0 or json.loads(command(["ip", "-j", "link"]).stdout)[0]["ifname"] != "lo":
        raise RuntimeError("test must run in its isolated user/network namespace")
    links = json.loads(command(["ip", "-j", "link"]).stdout)
    if [row["ifname"] for row in links] != ["lo"]:
        raise RuntimeError("unexpected links in test namespace")
    with tempfile.TemporaryDirectory(prefix="yume-tun-") as temporary, ExitStack() as stack:
        kit = Path(temporary) / "kit"
        environment = session.openssl_environment(openssl)
        os.environ.update(environment)
        session.provision_kit(kit, "localhost", 24443, environment)
        configure(kit, resolved is not None)
        processes: list[subprocess.Popen] = []
        echo_process = None
        dns_process = None
        try:
            for role, binary in (("server", yumed), ("client", yume)):
                error_log = stack.enter_context((kit / f"{role}-worker.log").open("w+"))
                dns_args = ["--resolved", str(resolved)] if role == "client" and resolved else []
                process = subprocess.Popen(["unshare", "--net", "--mount", "--", sys.executable, str(Path(__file__).resolve()),
                                            "--worker", role, "--kit", str(kit), "--binary", str(binary), *dns_args],
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error_log,
                                           text=True, bufsize=1, start_new_session=True)
                processes.append(process)
                if receive(process) != "ready":
                    raise RuntimeError("worker readiness failed")
            server, client = processes
            command(["ip", "link", "add", "wire-server", "type", "veth", "peer", "name", "wire-client"])
            command(["ip", "link", "set", "wire-server", "netns", str(server.pid)])
            command(["ip", "link", "set", "wire-client", "netns", str(client.pid)])
            for process in processes:
                send(process, "start")
                if receive(process) != "started":
                    raise RuntimeError("worker startup failed")
            wait_interface(server, "ytp-server")
            wait_interface(client, "ytp-client")
            routes = json.loads(in_namespace(client, ["ip", "-j", "route", "show", "table", "all"]).stdout)
            managed = [row for row in routes if row.get("dev") == "ytp-client" and row.get("type", "unicast") == "unicast"]
            transport = ipaddress.ip_address("192.0.2.1")
            if not managed or any(transport in ipaddress.ip_network(row["dst"]) for row in managed):
                raise RuntimeError("managed default routes did not exclude the transport address")
            transport_route = json.loads(in_namespace(client, ["ip", "-j", "route", "get", str(transport)]).stdout)
            if len(transport_route) != 1 or transport_route[0].get("dev") != "wire-client":
                raise RuntimeError("managed routing changed the transport's physical route")
            # Poll for authentication with an actual packet, not log wording.
            deadline = time.monotonic() + 15
            while True:
                try:
                    in_namespace(client, ["ping", "-n", "-c", "1", "-W", "1", "10.71.0.1"], 3)
                    break
                except subprocess.CalledProcessError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("native TUN failed to carry IPv4 traffic") from None
            if resolved is not None:
                dns_log = stack.enter_context((kit / "dns-server.log").open("w+"))
                dns_process = subprocess.Popen(["nsenter", "--target", str(server.pid), "--net", "--",
                    sys.executable, str(Path(__file__).resolve()), "--dns-echo"],
                    stdout=subprocess.PIPE, stderr=dns_log, text=True)
                if receive(dns_process) != "ready":
                    raise RuntimeError("TUN DNS target did not start")
                send(client, "dns first.yume.test")
                if receive(client) != "resolved":
                    raise RuntimeError("resolved did not query through YTP")
            # The client owns its TUN across session loss. A server restart
            # must reconnect after old OS callbacks drain without replacing it.
            client_link = json.loads(in_namespace(client, ["ip", "-j", "link", "show", "dev", "ytp-client"]).stdout)[0]
            send(server, "stop")
            if receive(server) != "stopped":
                raise RuntimeError("server restart did not stop cleanly")
            retained = json.loads(in_namespace(client, ["ip", "-j", "link", "show", "dev", "ytp-client"]).stdout)[0]
            if retained["ifindex"] != client_link["ifindex"]:
                raise RuntimeError("session loss replaced the client TUN")
            for address in ("10.71.0.1", "fd71::1"):
                routes = json.loads(in_namespace(client, ["ip", "-j", "route", "get", address]).stdout)
                if len(routes) != 1 or routes[0].get("dev") != "ytp-client":
                    raise RuntimeError("session loss removed the client's managed route")
            send(server, "start")
            if receive(server) != "started":
                raise RuntimeError("server restart failed")
            wait_interface(server, "ytp-server")
            deadline = time.monotonic() + 20
            while True:
                try:
                    in_namespace(client, ["ping", "-n", "-c", "1", "-W", "1", "10.71.0.1"], 3)
                    break
                except subprocess.CalledProcessError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("native TUN did not reconnect after server restart") from None
            retained = json.loads(in_namespace(client, ["ip", "-j", "link", "show", "dev", "ytp-client"]).stdout)[0]
            if retained["ifindex"] != client_link["ifindex"]:
                raise RuntimeError("reconnect replaced the client TUN")
            if resolved is not None:
                for name in ("reconnected.yume.test", "repeated.yume.test"):
                    send(client, "dns " + name)
                    if receive(client) != "resolved":
                        raise RuntimeError("resolved did not survive reconnect")
                if dns_process.wait(timeout=5) != 0:
                    raise RuntimeError("TUN DNS target failed")
            for address in ("10.71.0.1", "fd71::1"):
                in_namespace(client, ["ping", "-n", "-c", "3", "-W", "2", "-s", "1200", address], 10)
            oversize = subprocess.run(["nsenter", "--target", str(client.pid), "--net", "--",
                                      "ping", "-n", "-M", "do", "-c", "1", "-W", "1", "-s", "1393", "10.71.0.1"],
                                     capture_output=True, text=True, timeout=5)
            if oversize.returncode == 0:
                raise RuntimeError("TUN ignored configured MTU")
            echo_process = subprocess.Popen(["nsenter", "--target", str(server.pid), "--net", "--",
                sys.executable, str(Path(__file__).resolve()), "--echo"], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True)
            if receive(echo_process) != "ready":
                raise RuntimeError("TUN TCP target did not start")
            in_namespace(client, [sys.executable, str(Path(__file__).resolve()), "--transfer"], 45)
            if echo_process.wait(timeout=10) != 0:
                raise RuntimeError("TUN TCP echo failed")
            for process, role in ((client, "client"), (server, "server")):
                send(process, "stop")
                if receive(process) != "stopped":
                    raise RuntimeError("native TUN shutdown failed")
                links = json.loads(in_namespace(process, ["ip", "-j", "link"]).stdout)
                if any(row["ifname"].startswith("ytp-") for row in links):
                    raise RuntimeError("native shutdown left a TUN interface")
                for family in ("-4", "-6"):
                    routes = json.loads(in_namespace(process, ["ip", family, "-j", "route", "show", "table", "all"]).stdout)
                    if any(str(row.get("dev", "")).startswith("ytp-") for row in routes):
                        raise RuntimeError("native shutdown left a TUN route")
                if role == "server":
                    # A route owned by another caller makes the exclusive add
                    # fail after interface/address setup. Rollback must remove
                    # only YUME's new link and preserve that caller's route.
                    conflict = ["10.71.0.2/32", "dev", "wire-server"]
                    in_namespace(process, ["ip", "route", "add", *conflict])
                    send(process, "start")
                    if receive(process) != "started":
                        raise RuntimeError("rollback fixture failed to start")
                    send(process, "expect-failure")
                    if receive(process) != "failed":
                        raise RuntimeError("route conflict did not fail closed")
                    links = json.loads(in_namespace(process, ["ip", "-j", "link"]).stdout)
                    if any(row["ifname"].startswith("ytp-") for row in links):
                        raise RuntimeError("startup rollback left a TUN interface")
                    routes = json.loads(in_namespace(process, ["ip", "-j", "route", "show", "exact", "10.71.0.2/32"]).stdout)
                    if len(routes) != 1 or routes[0].get("dev") != "wire-server":
                        raise RuntimeError("startup rollback changed another caller's route")
                    in_namespace(process, ["ip", "route", "del", *conflict])
                session.reject_secret_output(role, (kit / f"{role}.log").read_text())
            # Keep both namespace owners alive until rollback checks finish;
            # dropping either namespace destroys both ends of the veth pair.
            for process in processes:
                send(process, "exit")
                if process.wait(timeout=5) != 0:
                    raise RuntimeError("namespace worker failed")
            print("native TUN: IPv4/IPv6, MTU, default-route exclusion, reconnect, 2 MiB TCP echo, startup rollback and shutdown cleanup passed")
            if resolved is not None:
                print("real resolved: per-link DNS/domain/default policy, tunneled queries, reconnect and DNS cleanup passed")
        except Exception:
            # Native logs contain no credential material; apply the existing
            # secret-output guard before bounded diagnostics leave this fixture.
            for role in ("server", "client"):
                path = kit / f"{role}.log"
                if path.exists():
                    text = path.read_text()
                    session.reject_secret_output(role, text)
                    print(f"{role}: {text[-3000:]}", file=sys.stderr)
                worker_log = kit / f"{role}-worker.log"
                if worker_log.exists():
                    print(worker_log.read_text()[-3000:], file=sys.stderr)
            raise
        finally:
            if dns_process is not None and dns_process.poll() is None:
                dns_process.kill()
                dns_process.wait(timeout=5)
            if echo_process is not None and echo_process.poll() is None:
                echo_process.kill()
                echo_process.wait(timeout=5)
            for process in processes:
                if process.poll() is None:
                    if process.stdin:
                        process.stdin.close()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yume", type=Path)
    parser.add_argument("--yumed", type=Path)
    parser.add_argument("--openssl", type=Path)
    parser.add_argument("--resolved", type=Path)
    parser.add_argument("--isolated", action="store_true")
    parser.add_argument("--worker", choices=("client", "server"))
    parser.add_argument("--kit", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--echo", action="store_true")
    parser.add_argument("--transfer", action="store_true")
    parser.add_argument("--dns-echo", action="store_true")
    args = parser.parse_args()
    try:
        if args.worker:
            worker(args.worker, args.kit, args.binary, args.resolved)
        elif args.dns_echo:
            resolved_fixture.serve_dns()
        elif args.echo:
            echo()
        elif args.transfer:
            transfer()
        elif args.isolated:
            isolated(args.yume, args.yumed, args.openssl, args.resolved)
        else:
            binaries = [path.resolve(strict=True) for path in (args.yume, args.yumed, args.openssl)]
            dns_args = ["--resolved", str(args.resolved.resolve(strict=True))] if args.resolved else []
            command(["unshare", "--user", "--map-root-user", "--net", "--pid", "--fork",
                     "--mount-proc", "--kill-child", "--", sys.executable,
                     str(Path(__file__).resolve()), "--isolated", "--yume", str(binaries[0]),
                     "--yumed", str(binaries[1]), "--openssl", str(binaries[2]), *dns_args], 180)
            print("native TUN and real resolved namespace integration passed" if args.resolved
                  else "native TUN namespace integration passed")
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"native TUN test: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print((error.stdout or "")[-4000:] + (error.stderr or "")[-4000:], file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
