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


def run(yumed: Path, program: Path, openssl: Path) -> None:
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
            config["endpoint"]["listen_addresses"] = ["127.0.0.1"]
            config["control"] = {"socket": str(sockets / f"{name}.sock")}
            if name in EXITS:
                for adapter in config["adapters"]:
                    if adapter["kind"] == "direct_tcp":
                        adapter["destinations"] = {"public": False, "networks": ["127.0.0.1/32"]}
            (server / "yumed.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
            cluster.setup(environment, "cluster-add", "--cluster", str(operator), "--server",
                          str(server), "--name", name, "--host", "127.0.0.1", "--address",
                          "127.0.0.1", *(["--exit"] if name in EXITS else []))
            nodes[name] = cluster.Node(name, server, sockets / f"{name}.sock", yumed,
                                       environment, root)
        cluster.setup(environment, "cluster-sign", "--cluster", str(operator), "--days", "2")
        # Separate clients keep each phase within the entry's per-client
        # circuit rate, a burst of 4.
        for client in ("walker", "crowd", "hauler"):
            cluster.setup(environment, "add-client", "--server", str(nodes["node-a"].server),
                          "--host", "127.0.0.1", "--output", str(root / client),
                          "--client-name", client, "--circuits")
        a, b = nodes["node-a"], nodes["node-b"]
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
            for node in nodes.values():
                node.stop()
        except session.SessionFailure:
            for node in nodes.values():
                node.kill()
            for log in sorted(root.glob("node-*.log")):
                print(f"---- {log.name}", file=sys.stderr)
                print(log.read_text(encoding="utf-8", errors="replace")[-4000:], file=sys.stderr)
            raise
        finally:
            echo.close()
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
    parser.add_argument("--openssl", required=True, type=Path)
    arguments = parser.parse_args()
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    try:
        run(arguments.yumed, arguments.probe, arguments.openssl)
    except session.SessionFailure as error:
        print(f"native circuit test: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
