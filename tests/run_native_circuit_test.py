#!/usr/bin/env python3
"""Run four clustered yumed nodes and drive circuits through them.

A test client (yume_circuit_probe) holds a kit that node-a grants
yume.circuit. It fetches the routes view from node-a, builds circuits
through named hops and echoes bytes through an exit to a local target.
node-c and node-d are exits that may reach 127.0.0.1 only.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
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
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yume_native_session as session  # noqa: E402
import run_native_cluster_test as cluster  # noqa: E402

NAMES = ("node-a", "node-b", "node-c", "node-d")
EXITS = ("node-c", "node-d")
# Each node on its own /16 inside 127/8, so the routes view gives them
# different network tags and a client can choose routes among them.
ADDRESSES = {"node-a": "127.0.0.1", "node-b": "127.1.0.1", "node-c": "127.2.0.1",
             "node-d": "127.3.0.1"}


class EchoServer:
    """Echoes every connection's bytes until it ends, then closes it."""

    def __init__(self) -> None:
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self) -> None:
        while True:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self.echo, args=(connection,), daemon=True).start()

    @staticmethod
    def echo(connection: socket.socket) -> None:
        with connection:
            while block := connection.recv(65536):
                connection.sendall(block)

    def close(self) -> None:
        self.listener.close()


class Probe:
    def __init__(self, program: Path, environment: dict[str, str], operator: Path,
                 root: Path) -> None:
        self.program = program
        self.environment = environment
        self.operator_key = operator / "operator-composite.pub.pem"
        self.root = root

    def arguments(self, client: str, hops: str, target: str, *extra: str) -> list[str]:
        return [str(self.program), "--config", str(self.root / client / "yume.json"),
                "--connect", "127.0.0.1", "--operator-key", str(self.operator_key),
                "--hops", hops, "--target", target, *extra]

    def run(self, client: str, hops: str, target: str, *extra: str) -> dict:
        result = subprocess.run(self.arguments(client, hops, target, *extra),
                                env=self.environment, capture_output=True, text=True,
                                timeout=180, check=False)
        return self.parse(result.stdout, result.stderr, result.returncode)

    def start(self, client: str, hops: str, target: str, *extra: str) -> subprocess.Popen:
        return subprocess.Popen(self.arguments(client, hops, target, *extra),
                                env=self.environment, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)

    @staticmethod
    def parse(stdout: str, stderr: str, code: int) -> dict:
        lines = [line for line in stdout.splitlines() if line.startswith("{")]
        if len(lines) != 1:
            raise session.SessionFailure(f"the probe printed no report: {stdout} {stderr}")
        report = json.loads(lines[0])
        # 0 after a run, 2 after a reported error. Anything else, such as a
        # sanitizer's exit, fails the test.
        if code != (2 if "error" in report else 0):
            raise session.SessionFailure(f"the probe exited with {code}: {stderr[-4000:]}")
        return report


def expect(condition: bool, description: str, report: object) -> None:
    if not condition:
        raise session.SessionFailure(f"{description}: {report}")


def first(report: dict) -> dict:
    expect("error" not in report and bool(report.get("circuits")), "the probe failed", report)
    return report["circuits"][0]


def circuits(node: cluster.Node) -> dict:
    status = node.status() or {}
    return (status.get("cluster") or {}).get("circuits", {})


def wait_for_file(path: Path, process: subprocess.Popen, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise session.SessionFailure(f"the probe ended early: {process.communicate()}")
        time.sleep(0.1)
    raise session.SessionFailure("the probe never started its load")


class Client:
    """The real yume with a circuits kit, its SOCKS5 port and control socket."""

    def __init__(self, yume: Path, kit: Path, environment: dict[str, str], sockets: Path,
                 min_hops: int | None = None) -> None:
        self.yume = yume
        self.kit = kit
        self.environment = environment
        self.control = sockets / f"{kit.name}.sock"
        self.socks_port = session.free_port()
        config = json.loads((kit / "yume.json").read_text(encoding="utf-8"))
        if min_hops is not None:
            config["circuits"]["min_hops"] = min_hops
        for adapter in config["adapters"]:
            if adapter["kind"] == "socks5":
                adapter["listen_port"] = self.socks_port
                # A UDP service beside circuits: ASSOCIATE must still be
                # refused, since circuits carry TCP only.
                adapter["udp_service"] = "udp"
        config["control"] = {"socket": str(self.control)}
        (kit / "yume.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
        self.log = kit / "yume.log"
        self.process: subprocess.Popen | None = None

    def start(self) -> None:
        with self.log.open("wb") as log:
            self.process = subprocess.Popen(
                [str(self.yume), "--config", str(self.kit / "yume.json")],
                env=self.environment, stdout=log, stderr=subprocess.STDOUT)
        session.wait_for_port("127.0.0.1", self.socks_port, self.process,
                              time.monotonic() + 60.0)
        # SOCKS5 opens before the session, and without a session the client
        # refuses connections as not allowed, so wait for it.
        deadline = time.monotonic() + 60.0
        while not self.connected():
            if self.process.poll() is not None or time.monotonic() > deadline:
                raise session.SessionFailure(
                    f"yume never connected: {self.log.read_text(errors='replace')}")
            time.sleep(0.1)

    def connected(self) -> bool:
        try:
            return self.status().get("state") == "connected"
        except (OSError, ValueError):
            return False

    def status(self) -> dict:
        return cluster.query(self.control)

    def validate(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(self.yume), "--config", str(self.kit / "yume.json"),
                               "--validate"], env=self.environment, capture_output=True,
                              text=True, timeout=60, check=False)

    def circuits(self) -> dict:
        return self.status().get("circuits") or {}

    def accept(self, route: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(self.yume), "--config", str(self.kit / "yume.json"),
                               "--accept-route", route], env=self.environment,
                              capture_output=True, text=True, timeout=30, check=False)

    def associate(self) -> int:
        with socket.create_connection(("127.0.0.1", self.socks_port), timeout=20) as connection:
            connection.sendall(b"\x05\x01\x00")
            if session.recv_exact(connection, 2) != b"\x05\x00":
                raise session.SessionFailure("SOCKS5 method selection failed")
            connection.sendall(b"\x05\x03\x00\x01" + bytes(6))
            return session.recv_exact(connection, 2)[1]

    def echo(self, port: int, payload: bytes) -> bytes:
        code, connection = session.socks_connect(self.socks_port, "127.0.0.1", port)
        with connection:
            if code != 0:
                raise session.SessionFailure(f"SOCKS5 CONNECT was refused with {code}")
            connection.sendall(payload)
            connection.shutdown(socket.SHUT_WR)
            received = bytearray()
            while block := connection.recv(65536):
                received += block
            return bytes(received)

    def stop(self) -> None:
        if self.process is not None:
            session.stop_process(self.process, "yume")
            self.process = None

    def kill(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)
        self.process = None


def run(yumed: Path, program: Path, yume: Path, openssl: Path) -> None:
    environment = session.openssl_environment(openssl)
    with tempfile.TemporaryDirectory(prefix="yume-circuit-", dir="/tmp") as temporary:
        root = Path(temporary)
        sockets = root / "sockets"
        sockets.mkdir(mode=0o700)
        operator = root / "operator"
        cluster.setup(environment, "cluster-init", "--output", str(operator))
        nodes: dict[str, cluster.Node] = {}
        for name in NAMES:
            kit = root / name
            session.provision_kit(kit, "127.0.0.1", session.free_port(), environment)
            server = kit / "server"
            config = json.loads((server / "yumed.json").read_text(encoding="utf-8"))
            config["endpoint"]["listen_addresses"] = [ADDRESSES[name]]
            config["control"] = {"socket": str(sockets / f"{name}.sock")}
            # The exits, and the entry for an accepted one-hop route.
            if name in (*EXITS, "node-a"):
                for adapter in config["adapters"]:
                    if adapter["kind"] == "direct_tcp":
                        adapter["destinations"] = {"public": False, "networks": ["127.0.0.1/32"]}
            (server / "yumed.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
            cluster.setup(environment, "cluster-add", "--cluster", str(operator), "--server",
                          str(server), "--name", name, "--host", "127.0.0.1", "--address",
                          ADDRESSES[name], *(["--exit"] if name in EXITS else []))
            nodes[name] = cluster.Node(name, server, sockets / f"{name}.sock", yumed,
                                       environment, root)
        cluster.setup(environment, "cluster-sign", "--cluster", str(operator), "--days", "2")
        # Separate clients keep each phase within the entry's per-client
        # circuit rate, a burst of 4.
        for client in ("walker", "crowd", "hauler", "rider", "drifter"):
            cluster.setup(environment, "add-client", "--server", str(nodes["node-a"].server),
                          "--host", "127.0.0.1", "--output", str(root / client),
                          "--client-name", client, "--circuits")
        a, b = nodes["node-a"], nodes["node-b"]
        rider = Client(yume, root / "rider", environment, sockets)
        drifter = Client(yume, root / "drifter", environment, sockets, min_hops=1)
        echo = EchoServer()
        target = f"127.0.0.1:{echo.port}"
        probe = Probe(program, environment, operator, root)
        try:
            for node in nodes.values():
                node.start()
            cluster.wait_until("every node links to every other",
                               lambda: cluster.all_linked(list(nodes.values())), 60.0)
            status = circuits(a)
            expect(status.get("open") == 0 and status.get("exit") is False,
                   "node-a's circuit status is wrong before any circuit", status)
            expect(circuits(nodes["node-c"]).get("exit") is True,
                   "node-c is not reported as an exit", circuits(nodes["node-c"]))

            report = probe.run("walker", "node-a,node-b,node-c", target, "--bytes", "900000")
            built = first(report)
            expect(built["built"] and len(built["hop_ms"]) == 3 and report.get("stream") == "ok"
                   and report.get("echoed") == 900000 and report.get("routes_serial") == 1,
                   "a three-hop circuit did not carry 900000 bytes both ways", report)
            print("a three-hop circuit carried 900000 bytes both ways")

            report = probe.run("walker", "node-a,node-d", target, "--bytes", "70000")
            built = first(report)
            expect(built["built"] and len(built["hop_ms"]) == 2 and report.get("stream") == "ok",
                   "a two-hop circuit did not carry a stream", report)
            print("a two-hop circuit carried a stream")

            report = probe.run("walker", "node-a,node-b,node-d", f"127.0.0.2:{echo.port}")
            expect(first(report)["built"] and report.get("stream") == "permission-denied",
                   "the exit's policy did not refuse a destination outside it", report)
            report = probe.run("walker", "node-a,node-c,node-b", target)
            expect(first(report)["built"] and report.get("stream") == "permission-denied",
                   "a node that is not an exit carried a stream", report)
            print("the exit policy and a non-exit refused their streams")

            # A client without the grant cannot even fetch the routes view.
            report = probe.run("node-a/client", "node-a,node-b,node-c", target)
            expect("yume.routes refused" in report.get("error", ""),
                   "a client without yume.circuit fetched the routes view", report)

            report = probe.run("crowd", "node-a,node-c", target, "--circuits", "5")
            held = report.get("circuits", [])
            expect(len(held) == 5 and all(entry["built"] for entry in held[:4]) and
                   not held[4]["built"],
                   "the entry did not hold a client to four circuits", report)
            refused = circuits(a).get("refused", {})
            expect(refused.get("client_circuits", 0) >= 1, "node-a did not count the refusal",
                   refused)
            print("the entry held one client to four circuits")

            # A reload with unchanged inputs keeps links, so a loaded circuit
            # keeps running.
            ready = root / "reload-ready"
            loaded = probe.start("hauler", "node-a,node-b,node-c", target, "--load-ms", "6000",
                                 "--ready-file", str(ready))
            wait_for_file(ready, loaded)
            relay = circuits(b)
            links = {link["peer"]: link["circuits"] for link in b.links().values()}
            expect(relay.get("relayed") == 1 and links.get("node-a") == {"in": 1, "out": 0}
                   and links.get("node-c") == {"in": 0, "out": 1},
                   "node-b did not count the circuit per link", (relay, links))
            cluster.reload(list(nodes.values()))
            stdout, stderr = loaded.communicate(timeout=120)
            report = Probe.parse(stdout, stderr, loaded.returncode)
            expect(report.get("stream") == "ok" and report.get("echoed", 0) > 0 and
                   "failure" not in report,
                   "a reload with unchanged inputs broke a loaded circuit", report)
            print("a reload kept a loaded circuit running")

            # Stopping the middle under load ends the circuit, and the entry
            # says so without naming the hop that went away.
            ready = root / "stop-ready"
            loaded = probe.start("hauler", "node-a,node-b,node-c", target, "--load-ms", "60000",
                                 "--ready-file", str(ready))
            wait_for_file(ready, loaded)
            time.sleep(0.5)
            b.stop()
            stdout, stderr = loaded.communicate(timeout=120)
            report = Probe.parse(stdout, stderr, loaded.returncode)
            expect(report.get("stream") != "ok" and
                   report.get("failure") == {"hop": 1, "reason": "unreachable"},
                   "a stopped middle did not end the circuit at the entry", report)
            print("a stopped middle ended its circuit, reported by the entry")

            # The real client: SOCKS5 through three hops of its own choosing.
            rider.start()
            payload = os.urandom(300000)
            expect(rider.echo(echo.port, payload) == payload,
                   "yume did not carry a stream through its circuits", rider.circuits())
            state = rider.circuits()
            routes = state.get("routes", [])
            expect(state.get("current_hops") == 3 and routes and
                   len(routes[0]["nodes"]) == 3 and routes[0]["nodes"][0] == "node-a" and
                   routes[0]["nodes"][2] in EXITS and state.get("plain_http") == "refuse",
                   "yume's status does not show a three-hop route", state)
            print("yume chose a three-hop route and carried 300000 bytes both ways")

            # A circuit stream opens before the exit answers, so SOCKS5
            # succeeds and the exit's refusal then ends the connection.
            code, connection = session.socks_connect(rider.socks_port, "127.0.0.2", echo.port)
            with connection:
                connection.settimeout(20)
                try:
                    ended = connection.recv(1) == b""
                except ConnectionResetError:
                    ended = True
            expect(code == 0 and ended,
                   "a destination the exit refuses did not end its connection", code)
            print("a destination the exit refuses ended its connection after SOCKS5 success")

            # Plain HTTP stops at the client, by port and by request line.
            code, connection = session.socks_connect(rider.socks_port, "127.0.0.1", 80)
            connection.close()
            expect(code == 2, "a CONNECT to port 80 was not refused as not allowed", code)
            expect(rider.echo(echo.port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") == b"",
                   "a plain HTTP request left the client", rider.circuits())
            print("plain HTTP was refused before it left the client")
            expect(rider.associate() == 7, "UDP ASSOCIATE was not refused with circuits",
                   rider.circuits())
            print("UDP ASSOCIATE was refused, since circuits carry TCP only")

            # Without exits no route of three hops exists. The client does not
            # shorten on its own: it proposes a shorter route and waits. It
            # does not know the exits are down, so it may first propose two
            # hops through one it has not tried, and only a failed build of
            # that brings the direct session.
            for name in EXITS:
                nodes[name].stop()

            def await_proposal(seen: set[str]) -> dict:
                deadline = time.monotonic() + 60.0
                while time.monotonic() < deadline:
                    code, connection = session.socks_connect(rider.socks_port, "127.0.0.1",
                                                             echo.port)
                    connection.close()
                    expect(code != 0, "a stream left through a route the user did not accept",
                           rider.circuits())
                    proposal = rider.circuits().get("proposal")
                    if proposal is not None and proposal["id"] not in seen:
                        return proposal
                    time.sleep(0.5)
                raise session.SessionFailure(f"no new proposal appeared: {rider.circuits()}")

            seen: set[str] = set()
            proposal = await_proposal(seen)
            expect(proposal["hops"] in (1, 2) and proposal["nodes"][0] == "node-a",
                   "the first proposal is not a shorter route from the entry", proposal)
            wrong = rider.accept("ffffffffffffffff")
            expect(wrong.returncode == 2 and rider.circuits().get("current_hops") == 0,
                   "a wrong id accepted something", (wrong.returncode, wrong.stderr))
            while True:
                seen.add(proposal["id"])
                accepted = rider.accept(proposal["id"])
                expect(accepted.returncode == 0 and proposal["id"] in accepted.stdout,
                       "the proposal was not accepted", (accepted.returncode, accepted.stderr))
                if proposal["hops"] == 1:
                    break
                expect("neighbour" in proposal["gives_up"],
                       "a two-hop proposal did not say what it gives up", proposal)
                proposal = await_proposal(seen)
            expect(proposal["nodes"] == ["node-a"] and "entry server" in proposal["gives_up"],
                   "the last proposal is not the direct session", proposal)
            expect(rider.echo(echo.port, b"after consent") == b"after consent",
                   "the accepted route did not carry a stream", rider.circuits())
            state = rider.circuits()
            expect(state.get("current_hops") == 1 and state.get("accepted_hops") == 1,
                   "the status does not show the accepted route", state)
            print("the client proposed shorter routes and used one only after consent")
            rider.stop()

            # circuits.min_hops approves shorter routes in advance: this client
            # reaches the direct session on its own, and says what that costs.
            checked = drifter.validate()
            expect(checked.returncode == 0 and "/circuits/min_hops 1" in checked.stderr and
                   "sees both who you are" in checked.stderr,
                   "--validate did not warn about min_hops 1", checked.stderr)
            drifter.start()
            expect(drifter.echo(echo.port, b"pre-approved") == b"pre-approved",
                   "a pre-approved shorter route did not carry a stream", drifter.circuits())
            state = drifter.circuits()
            expect(state.get("current_hops") == 1 and state.get("accepted_hops") == 0 and
                   state.get("proposal") is None,
                   "the pre-approved route shows consent or a proposal", state)
            print("circuits.min_hops approved the direct session in advance")
            drifter.stop()
            for node in nodes.values():
                node.stop()
        except session.SessionFailure:
            rider.kill()
            drifter.kill()
            for node in nodes.values():
                node.kill()
            for client in (rider, drifter):
                if client.log.exists():
                    print(f"---- {client.kit.name} yume.log", file=sys.stderr)
                    print(client.log.read_text(encoding="utf-8", errors="replace")[-4000:],
                          file=sys.stderr)
            for log in sorted(root.glob("node-*.log")):
                print(f"---- {log.name}", file=sys.stderr)
                print(log.read_text(encoding="utf-8", errors="replace")[-4000:], file=sys.stderr)
            raise
        finally:
            echo.close()
            rider.kill()
            drifter.kill()
            for node in nodes.values():
                node.kill()
        for log in sorted(root.glob("node-*.log")):
            session.reject_secret_output(log.stem, log.read_text(encoding="utf-8",
                                                                 errors="replace"))


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--yumed", required=True, type=Path)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--yume", required=True, type=Path)
    parser.add_argument("--openssl", required=True, type=Path)
    arguments = parser.parse_args()
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    try:
        run(arguments.yumed, arguments.probe, arguments.yume, arguments.openssl)
    except session.SessionFailure as error:
        print(f"native circuit test: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
