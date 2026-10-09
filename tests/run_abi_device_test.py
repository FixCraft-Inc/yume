#!/usr/bin/env python3
"""Carry a TUN device's traffic through the public C ABI's device bridge.

Two unprivileged network namespaces stand for a phone and a server. The phone
side runs a probe that owns a TUN device, as an Android VpnService would, and
hands it to a client endpoint of libyume. Every route of that namespace leads
into the device except the one to the server's listener. The server side runs
a real yumed with the kit's ordinary tcp and udp services, and the
destinations. Ordinary sockets in the phone's namespace then reach those
destinations, and the test follows what happens to them when the session is
lost, replaced and stopped.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
import yume_native_session as session  # noqa: E402

SERVER_WIRE = "192.0.2.1"
PHONE_WIRE = "192.0.2.2"
TARGET4 = "203.0.113.9"
TARGET6 = "fd00:113::9"
# Outside what the server's direct adapters permit.
REFUSED4 = "198.51.100.7"
DEVICE4 = "10.71.0.1"
DEVICE6 = "fd71::1"
ECHO_PORT = 7001
UDP_PORT = 7002
SOURCE_PORT = 7003
DNS_PORT = 53
SERVER_PORT = 24443
MTU = 9000
# The session states of yume_endpoint_status.
ACTIVE, CONNECTING, WAITING = 1, 3, 4


def command(argv: list[str], timeout: float = 15) -> subprocess.CompletedProcess:
    return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                          timeout=timeout, check=True)


def send(process: subprocess.Popen, text: str) -> None:
    assert process.stdin is not None
    process.stdin.write(text + "\n")
    process.stdin.flush()


def receive(process: subprocess.Popen, timeout: float = 30) -> str:
    assert process.stdout is not None
    with selectors.DefaultSelector() as poll:
        poll.register(process.stdout, selectors.EVENT_READ)
        if not poll.select(timeout):
            raise RuntimeError("a fixture process did not respond")
    line = process.stdout.readline()
    if not line:
        raise RuntimeError(f"a fixture process exited with {process.poll()}")
    return line.strip()


def ask(process: subprocess.Popen, text: str, timeout: float = 30) -> str:
    send(process, text)
    return receive(process, timeout)


# What the test was doing, for the report of a failure.
STEPS: list[str] = []


def step(text: str) -> None:
    STEPS.append(text)


# --- destinations, in the server's namespace ---------------------------------

class Echo(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(60)
        while data := self.request.recv(65536):
            self.request.sendall(data)


class Source(socketserver.StreamRequestHandler):
    """Sends as many bytes as the request line asks for."""

    def handle(self) -> None:
        self.request.settimeout(60)
        remaining = int(self.rfile.readline(32).strip())
        if not 0 < remaining <= 256 * 1024 * 1024:
            raise ValueError("source size outside the fixture bound")
        block = bytes(range(256)) * 256
        while remaining:
            part = block[:min(len(block), remaining)]
            self.request.sendall(part)
            remaining -= len(part)


class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        payload, connection = self.request
        connection.sendto(payload, self.client_address)


class Tcp4(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Tcp6(Tcp4):
    address_family = socket.AF_INET6


class Udp6(socketserver.UDPServer):
    address_family = socket.AF_INET6


def serve_destinations(ipv6: bool) -> None:
    # The echo on the resolver's port answers each query with its own bytes,
    # identifier included, as a resolver's reply carries its query's.
    servers: list[socketserver.BaseServer] = [
        Tcp4((TARGET4, ECHO_PORT), Echo), Tcp4((TARGET4, SOURCE_PORT), Source),
        socketserver.UDPServer((TARGET4, UDP_PORT), UdpEcho),
        socketserver.UDPServer((TARGET4, DNS_PORT), UdpEcho)]
    if ipv6:
        servers += [Tcp6((TARGET6, ECHO_PORT), Echo), Udp6((TARGET6, UDP_PORT), UdpEcho)]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()


def server_worker(kit: Path, yumed: Path, ipv6: bool) -> None:
    print("ready", flush=True)
    if sys.stdin.readline().strip() != "setup":
        raise RuntimeError("invalid server worker start")
    command(["ip", "link", "set", "lo", "up"])
    command(["ip", "addr", "add", f"{SERVER_WIRE}/30", "dev", "wire-server"])
    command(["ip", "link", "set", "wire-server", "up"])
    command(["ip", "addr", "add", f"{TARGET4}/32", "dev", "lo"])
    # Answers to the phone's tunnelled traffic never leave this namespace: the
    # daemon connects to the destinations itself.
    if ipv6:
        command(["ip", "-6", "addr", "add", f"{TARGET6}/128", "dev", "lo", "nodad"])
    serve_destinations(ipv6)
    print("set", flush=True)
    process = None
    with (kit / "server.log").open("w+", encoding="utf-8") as log:
        try:
            while True:
                action = sys.stdin.readline().strip()
                if action == "start" and (process is None or process.poll() is not None):
                    process = subprocess.Popen(
                        [str(yumed), "--config", str(kit / "server/yumed.json")],
                        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
                    deadline = time.monotonic() + 15
                    session.wait_for_port(SERVER_WIRE, SERVER_PORT, process, deadline)
                    print("started", flush=True)
                elif action == "stop" and process is not None:
                    session.stop_process(process, "device test yumed")
                    print("stopped", flush=True)
                elif action == "exit":
                    return
                else:
                    raise RuntimeError("invalid server worker command")
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)


# --- the phone's namespace ---------------------------------------------------

def phone_worker(kit: Path, probe: Path, ipv6: bool) -> None:
    """Owns the namespace and relays the probe's command lines."""
    print("ready", flush=True)
    if sys.stdin.readline().strip() != "setup":
        raise RuntimeError("invalid phone worker start")
    command(["ip", "link", "set", "lo", "up"])
    command(["ip", "addr", "add", f"{PHONE_WIRE}/30", "dev", "wire-phone"])
    command(["ip", "link", "set", "wire-phone", "up"])
    with (kit / "probe.log").open("w+", encoding="utf-8") as log:
        process = subprocess.Popen(
            [str(probe), str(kit / "client"), str(kit / "server"), "dual" if ipv6 else "ipv4"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True, bufsize=1)
        try:
            if receive(process) != "device ydev0":
                raise RuntimeError("the probe did not create its device")
            # What an Android VpnService builder does: an address, the MTU and
            # every route. The second address of each prefix is the bridge's.
            command(["ip", "addr", "add", f"{DEVICE4}/30", "dev", "ydev0"])
            if ipv6:
                command(["ip", "-6", "addr", "add", f"{DEVICE6}/126", "dev", "ydev0", "nodad"])
            command(["ip", "link", "set", "ydev0", "mtu", str(MTU), "up"])
            command(["ip", "route", "add", "default", "dev", "ydev0"])
            if ipv6:
                command(["ip", "-6", "route", "add", "default", "dev", "ydev0"])
            if ask(process, "configured", 60) != "running":
                raise RuntimeError("the probe did not start its endpoint")
            print("running", flush=True)
            while True:
                action = sys.stdin.readline().strip()
                if not action or action == "exit":
                    send(process, "quit")
                    if process.wait(timeout=20) != 0:
                        raise RuntimeError("the probe failed at exit")
                    return
                # Every command has one answer line.
                print(ask(process, action, 60), flush=True)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


def tcp_echo(host: str, port: int, size: int) -> None:
    block = bytes(range(256)) * 256
    with socket.create_connection((host, port), timeout=20) as connection:
        connection.settimeout(30)
        sent = 0
        while sent < size:
            part = block[:min(len(block), size - sent)]
            connection.sendall(part)
            received = bytearray()
            while len(received) < len(part):
                chunk = connection.recv(len(part) - len(received))
                if not chunk:
                    raise RuntimeError("the echo ended early")
                received.extend(chunk)
            if received != part:
                raise RuntimeError("echoed bytes changed")
            sent += len(part)
        connection.shutdown(socket.SHUT_WR)
        if connection.recv(1):
            raise RuntimeError("the echo has trailing bytes")


def tcp_many(host: str, port: int, count: int) -> None:
    failures: list[str] = []

    def one() -> None:
        try:
            tcp_echo(host, port, 4096)
        except (OSError, RuntimeError) as error:
            failures.append(str(error))

    threads = [threading.Thread(target=one) for _ in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    if failures or any(thread.is_alive() for thread in threads):
        raise RuntimeError(f"{len(failures)} of {count} connections failed: {failures[:3]}")


def tcp_hold(host: str, port: int) -> None:
    """Keeps one connection busy and reports when it ends."""
    with socket.create_connection((host, port), timeout=20) as connection:
        connection.settimeout(20)
        connection.sendall(b"h")
        if connection.recv(1) != b"h":
            raise RuntimeError("the held connection did not echo")
        print("held", flush=True)
        started = time.monotonic()
        try:
            while True:
                connection.sendall(b"k")
                if not connection.recv(1):
                    break
                time.sleep(0.2)
        except OSError:
            pass
        print(f"ended {time.monotonic() - started:.1f}", flush=True)


def tcp_closed(host: str, port: int, limit: float) -> None:
    """A connection the bridge accepts locally and then ends, soon."""
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=limit) as connection:
            connection.settimeout(limit)
            connection.sendall(b"x")
            if connection.recv(1):
                raise RuntimeError("a connection that should have ended carried data")
    except (ConnectionError, TimeoutError) as error:
        if isinstance(error, TimeoutError):
            raise RuntimeError("the connection waited instead of ending") from None
    waited = time.monotonic() - started
    if waited >= limit:
        raise RuntimeError(f"the connection ended only after {waited:.1f} s")


def udp_echo(host: str, port: int, count: int, size: int) -> None:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as connection:
        connection.settimeout(5)
        connection.connect((host, port))
        for index in range(count):
            payload = bytes([index % 251]) * size
            # The first datagram waits for its stream to open.
            for attempt in range(5):
                connection.send(payload)
                try:
                    if connection.recv(65536) == payload:
                        break
                except TimeoutError:
                    if attempt == 4:
                        raise RuntimeError("no UDP reply through the bridge") from None
            else:
                raise RuntimeError("the UDP reply changed")


def lookups(host: str, count: int) -> None:
    """Queries from many local ports at once, each answered to its own port."""
    sockets = []
    try:
        for index in range(count):
            connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            connection.settimeout(5)
            connection.connect((host, DNS_PORT))
            # Every query carries the same identifier, as two applications
            # may, and its own question bytes.
            query = bytes([0x12, 0x34]) + bytes([index % 256]) * 30
            sockets.append((connection, query))
        for attempt in range(5):
            waiting = []
            for connection, query in sockets:
                connection.send(query)
            for connection, query in sockets:
                try:
                    if connection.recv(4096) != query:
                        raise RuntimeError("a lookup got another query's answer")
                except TimeoutError:
                    waiting.append((connection, query))
            if not waiting:
                return
            if attempt == 4:
                raise RuntimeError(f"{len(waiting)} of {count} lookups got no answer")
            sockets = waiting
    finally:
        for connection, _ in sockets:
            connection.close()


def source(host: str, port: int, size: int) -> None:
    started = time.monotonic()
    received = 0
    with socket.create_connection((host, port), timeout=20) as connection:
        connection.settimeout(30)
        connection.sendall(f"{size}\n".encode())
        while chunk := connection.recv(1 << 20):
            received += len(chunk)
    if received != size:
        raise RuntimeError(f"received {received} of {size} bytes")
    elapsed = time.monotonic() - started
    print(f"download {size * 8 / elapsed / 1e6:.0f} Mbit/s", flush=True)


def listener_refuses_local_process() -> None:
    """Another process that dials the bridge's listener gets nothing."""
    rows = command(["ss", "-Hltn"]).stdout.splitlines()
    ports = [int(row.split()[3].rsplit(":", 1)[1]) for row in rows
             if row.split()[3].startswith(DEVICE4 + ":")]
    if len(ports) != 1:
        raise RuntimeError(f"expected one listener on the device address, found {ports}")
    tcp_closed(DEVICE4, ports[0], 5)


def client(arguments: list[str]) -> None:
    mode = arguments[0]
    if mode == "echo":
        tcp_echo(arguments[1], int(arguments[2]), int(arguments[3]))
    elif mode == "many":
        tcp_many(arguments[1], int(arguments[2]), int(arguments[3]))
    elif mode == "hold":
        tcp_hold(arguments[1], int(arguments[2]))
    elif mode == "closed":
        tcp_closed(arguments[1], int(arguments[2]), float(arguments[3]))
    elif mode == "udp":
        udp_echo(arguments[1], int(arguments[2]), int(arguments[3]), int(arguments[4]))
    elif mode == "source":
        source(arguments[1], int(arguments[2]), int(arguments[3]))
    elif mode == "lookups":
        lookups(arguments[1], int(arguments[2]))
    elif mode == "listener":
        listener_refuses_local_process()
    else:
        raise RuntimeError("unknown client mode")


# --- the test ----------------------------------------------------------------

def status(phone: subprocess.Popen) -> dict[str, int]:
    line = ask(phone, "status")
    if not line.startswith("status "):
        raise RuntimeError(f"unexpected status line: {line}")
    return {key: int(value) for key, value in
            (field.split("=", 1) for field in line.split()[1:])}


def wait_status(phone: subprocess.Popen, wanted, what: str, timeout: float = 20) -> dict[str, int]:
    deadline = time.monotonic() + timeout
    while True:
        current = status(phone)
        if wanted(current):
            return current
        if time.monotonic() >= deadline:
            raise RuntimeError(f"{what}: last status {current}")
        time.sleep(0.1)


def messages(phone: subprocess.Popen) -> list[str]:
    fields = ask(phone, "messages").split("\t")
    if fields[0] != "messages":
        raise RuntimeError(f"unexpected message feed: {fields}")
    return fields[1:]


def isolated(probe: Path, yumed: Path, openssl: Path) -> None:
    links = json.loads(command(["ip", "-j", "link"]).stdout)
    if os.geteuid() != 0 or [row["ifname"] for row in links] != ["lo"]:
        raise RuntimeError("test must run in its isolated user/network namespace")
    ipv6 = Path("/proc/net/if_inet6").exists()
    script = str(Path(__file__).resolve())
    with tempfile.TemporaryDirectory(prefix="yume-device-") as temporary, ExitStack() as stack:
        kit = Path(temporary) / "kit"
        environment = session.openssl_environment(openssl)
        os.environ.update(environment)
        session.provision_kit(kit, "localhost", SERVER_PORT, environment,
                              session.setup_program(yumed))
        networks = [f"{TARGET4}/32"] + ([f"{TARGET6}/128"] if ipv6 else [])
        session.configure_kit(kit, listen_address=SERVER_WIRE, networks=networks,
                              connect_address=SERVER_WIRE, socks_port=1080)
        client_path = kit / "client/yume.json"
        config = json.loads(client_path.read_text(encoding="utf-8"))
        # The kit's services and limits stay as setup wrote them, so the
        # client offers what a yume client of this kit offers. Only the SOCKS5
        # adapter goes: the device bridge takes its place.
        config["adapters"] = []
        client_path.write_text(json.dumps(config), encoding="utf-8")

        family = "dual" if ipv6 else "ipv4"
        processes: list[subprocess.Popen] = []
        holders: list[subprocess.Popen] = []

        def worker(role: str, binary: Path) -> subprocess.Popen:
            error_log = stack.enter_context((kit / f"{role}-worker.log").open("w+"))
            process = subprocess.Popen(
                ["unshare", "--net", "--mount", "--", sys.executable, script, "--worker", role,
                 "--kit", str(kit), "--binary", str(binary), "--family", family],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error_log, text=True,
                bufsize=1, start_new_session=True)
            processes.append(process)
            if receive(process) != "ready":
                raise RuntimeError("worker readiness failed")
            return process

        def in_phone(arguments: list[str], timeout: float = 60) -> str:
            return command(["nsenter", "--target", str(phone.pid), "--net", "--",
                            sys.executable, script, "--client", *arguments], timeout).stdout

        def in_server(arguments: list[str]) -> None:
            command(["nsenter", "--target", str(server.pid), "--net", "--", *arguments])

        def hold() -> subprocess.Popen:
            process = subprocess.Popen(
                ["nsenter", "--target", str(phone.pid), "--net", "--", sys.executable, script,
                 "--client", "hold", TARGET4, str(ECHO_PORT)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1)
            holders.append(process)
            if receive(process) != "held":
                raise RuntimeError("a held connection did not open")
            return process

        try:
            server = worker("server", yumed)
            phone = worker("phone", probe)
            command(["ip", "link", "add", "wire-server", "type", "veth", "peer", "name", "wire-phone"])
            command(["ip", "link", "set", "wire-server", "netns", str(server.pid)])
            command(["ip", "link", "set", "wire-phone", "netns", str(phone.pid)])
            if ask(server, "setup") != "set" or ask(server, "start") != "started":
                raise RuntimeError("the server side did not start")
            if ask(phone, "setup", 90) != "running":
                raise RuntimeError("the phone side did not start")

            step("status after start")
            first = status(phone)
            if (first["state"], first["session"], first["sessions"], first["tcp"]) != (3, ACTIVE, 1, 0):
                raise RuntimeError(f"unexpected status after start: {first}")

            # TCP and UDP of each family, small and across many packets.
            step("traffic of both kinds")
            in_phone(["echo", TARGET4, str(ECHO_PORT), str(2 * 1024 * 1024)])
            # More connections at once than the session admits OPENs (64) or
            # holds streams (256): the surplus waits its turn and none fails.
            in_phone(["many", TARGET4, str(ECHO_PORT), "300"])
            in_phone(["udp", TARGET4, str(UDP_PORT), "8", "1200"])
            in_phone(["udp", TARGET4, str(UDP_PORT), "2", "8000"])
            if ipv6:
                in_phone(["echo", TARGET6, str(ECHO_PORT), str(512 * 1024)])
                in_phone(["udp", TARGET6, str(UDP_PORT), "4", "1200"])
            speed = in_phone(["source", TARGET4, str(SOURCE_PORT), str(64 * 1024 * 1024)], 120)

            # Name lookups from 40 local ports share one stream to their
            # resolver, where 40 separate destinations would be refused.
            before = status(phone)["udp"]
            in_phone(["lookups", TARGET4, "40"])
            if status(phone)["udp"] != before + 1:
                raise RuntimeError("lookups did not share one stream to their resolver")

            carried = status(phone)
            if carried["udp"] < 1 or carried["sent"] < 2 * 1024 * 1024 or carried["received"] < 66 * 1024 * 1024:
                raise RuntimeError(f"the traffic was not counted: {carried}")
            wait_status(phone, lambda now: now["tcp"] == 0, "closed connections stayed counted")

            step("refused destinations")
            # A destination the server's policy refuses: accepted locally,
            # then ended, without a wait. Likewise a local process that dials
            # the bridge's own listener.
            in_phone(["closed", REFUSED4, "80", "8"])
            in_phone(["listener"])
            wait_status(phone, lambda now: now["tcp"] == 0, "a refused connection stayed counted")

            # A connection in use is counted, and ends when its session does.
            step("session loss")
            held = hold()
            wait_status(phone, lambda now: now["tcp"] == 1, "a held connection was not counted")
            if ask(server, "stop") != "stopped":
                raise RuntimeError("the server did not stop")
            if not receive(held, 15).startswith("ended"):
                raise RuntimeError("a held connection outlived its session")
            lost = wait_status(phone, lambda now: now["session"] in (CONNECTING, WAITING),
                               "the endpoint did not notice the lost session")
            if lost["state"] != 3 or lost["failure"] == 0:
                raise RuntimeError(f"unexpected status without a session: {lost}")
            # While the session is away, a new connection fails at once.
            step("connection without a session")
            in_phone(["closed", TARGET4, str(ECHO_PORT), "3"])

            # The server stays away until the endpoint's wait between
            # attempts has grown to eight seconds. It then returns, and a
            # retry must reconnect well inside that wait.
            step("reconnect")
            wait_status(phone, lambda now: now["session"] == WAITING and now["retry"] >= 8000,
                        "the wait between attempts did not grow", 30)
            if ask(server, "start") != "started":
                raise RuntimeError("the server did not return")
            deadline = time.monotonic() + 4
            while status(phone)["session"] != ACTIVE:
                if ask(phone, "retry") != "retry 0":
                    raise RuntimeError("a retry was refused")
                if time.monotonic() >= deadline:
                    raise RuntimeError("a retry did not shorten the wait")
                time.sleep(0.25)
            step("traffic after the reconnect")
            again = status(phone)
            if again["sessions"] != 2 or again["failed"] != 0:
                raise RuntimeError(f"unexpected status after the reconnect: {again}")
            in_phone(["echo", TARGET4, str(ECHO_PORT), str(256 * 1024)])
            in_phone(["udp", TARGET4, str(UDP_PORT), "2", "1200"])

            said = messages(phone)
            if (sum(line == "session authenticated" for line in said) != 2 or
                    not any(line.startswith("session ended") for line in said)):
                raise RuntimeError(f"unexpected message feed: {said}")

            # The path stops answering without closing anything, as when a
            # server loses power or a network drops every packet. A send
            # after a pause rotates the key epoch, and YTP/1 gives a rotation
            # 30 s for its acknowledgement, so the session ends then and not
            # after the kernel's own retries, which take about a quarter of an
            # hour. The endpoint then reconnects once the path returns.
            step("silent path")
            quiet = hold()
            in_server(["ip", "route", "add", "blackhole", f"{PHONE_WIRE}/32"])
            silent_since = time.monotonic()
            # A new connection sends an OPEN, which is what goes unanswered.
            in_phone(["closed", TARGET4, str(ECHO_PORT), "45"], 75)
            wait_status(phone, lambda now: now["session"] in (CONNECTING, WAITING),
                        "a silent path did not end the session", 30)
            if time.monotonic() - silent_since > 60:
                raise RuntimeError("a silent path held the session too long")
            if not receive(quiet, 15).startswith("ended"):
                raise RuntimeError("a held connection outlived a silent path")
            in_server(["ip", "route", "del", "blackhole", f"{PHONE_WIRE}/32"])
            deadline = time.monotonic() + 30
            while status(phone)["session"] != ACTIVE:
                if ask(phone, "retry") != "retry 0":
                    raise RuntimeError("a retry was refused")
                if time.monotonic() >= deadline:
                    raise RuntimeError("the session did not return after a silent path")
                time.sleep(0.5)
            if status(phone)["sessions"] != 3:
                raise RuntimeError("the session after a silent path was not counted")
            in_phone(["echo", TARGET4, str(ECHO_PORT), str(256 * 1024)])

            step("restart with a connection open")
            # A stop and start keep the device. A connection from before it is
            # reset by the new bridge instead of being left to time out.
            stale = hold()
            if ask(phone, "restart", 60) != "restarted":
                raise RuntimeError("the endpoint did not restart with its device")
            if not receive(stale, 15).startswith("ended"):
                raise RuntimeError("a connection from before the restart was left waiting")
            in_phone(["echo", TARGET4, str(ECHO_PORT), str(256 * 1024)])
            final = status(phone)
            if final["received"] <= again["received"]:
                raise RuntimeError("the handle's totals did not continue across the restart")

            step("stop")
            if ask(phone, "stop") != "stopped":
                raise RuntimeError("the endpoint did not stop")
            for process in (phone, server):
                send(process, "exit")
                if process.wait(timeout=30) != 0:
                    raise RuntimeError("a namespace worker failed")
            session.reject_secret_output("server", (kit / "server.log").read_text())
            legs = "IPv4 and IPv6" if ipv6 else "IPv4 only, the host kernel has no IPv6"
            print(f"device bridge: {legs}; TCP echo, 300 parallel connections, UDP, "
                  f"shared lookups, loopback {speed.strip()}, refusals, session loss, "
                  "retry, reconnect, a silent path, restart and stop passed")
        except Exception:
            print("failed during: " + (STEPS[-1] if STEPS else "setup"), file=sys.stderr)
            for name in ("server.log", "probe.log", "server-worker.log", "phone-worker.log"):
                path = kit / name
                if path.exists():
                    text = path.read_text()
                    session.reject_secret_output(name, text)
                    print(f"{name}: {text[-3000:]}", file=sys.stderr)
            raise
        finally:
            for process in holders:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
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
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--yumed", type=Path)
    parser.add_argument("--openssl", type=Path)
    parser.add_argument("--isolated", action="store_true")
    parser.add_argument("--worker", choices=("server", "phone"))
    parser.add_argument("--kit", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--family", choices=("ipv4", "dual"))
    parser.add_argument("--client", nargs="+")
    args = parser.parse_args()
    try:
        if args.client:
            client(args.client)
        elif args.worker == "server":
            server_worker(args.kit, args.binary, args.family == "dual")
        elif args.worker == "phone":
            phone_worker(args.kit, args.binary, args.family == "dual")
        elif args.isolated:
            isolated(args.probe, args.yumed, args.openssl)
        else:
            binaries = [path.resolve(strict=True) for path in (args.probe, args.yumed, args.openssl)]
            result = command(
                ["unshare", "--user", "--map-root-user", "--net", "--pid", "--fork",
                 "--mount-proc", "--kill-child", "--", sys.executable,
                 str(Path(__file__).resolve()), "--isolated", "--probe", str(binaries[0]),
                 "--yumed", str(binaries[1]), "--openssl", str(binaries[2])], 280)
            print(result.stdout.strip())
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"device bridge test: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print((error.stdout or "")[-4000:] + (error.stderr or "")[-6000:], file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
