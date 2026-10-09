#!/usr/bin/env python3
"""Run three clustered yumed nodes and check their links through status."""

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
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))

import yume_native_session as session  # noqa: E402

NAMES = ("node-a", "node-b", "node-c")


def setup(program: Path, environment: dict[str, str], *arguments: str) -> str:
    return session.run_setup(program, arguments, environment)


def query(path: Path) -> dict:
    """One control protocol 1 status request."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(path))
        connection.sendall(b'{"control":1,"request":"status"}\n')
        reply = bytearray()
        while block := connection.recv(65536):
            reply.extend(block)
    return json.loads(reply)


class Node:
    def __init__(self, name: str, server: Path, control: Path, yumed: Path,
                 environment: dict[str, str], logs: Path) -> None:
        self.name = name
        self.server = server
        self.control = control
        self.yumed = yumed
        self.environment = environment
        self.logs = logs
        self.process: subprocess.Popen | None = None
        self.runs = 0

    @property
    def config(self) -> Path:
        return self.server / "yumed.json"

    def start(self) -> None:
        self.runs += 1
        log = (self.logs / f"{self.name}-{self.runs}.log").open("wb")
        with log:
            self.process = subprocess.Popen([str(self.yumed), "--config", str(self.config)],
                                            env=self.environment, stdout=log,
                                            stderr=subprocess.STDOUT)

    def stop(self) -> None:
        if self.process is not None:
            session.stop_process(self.process, f"yumed {self.name}")
            self.process = None

    def kill(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)
        self.process = None

    def status(self) -> dict | None:
        if self.process is None or self.process.poll() is not None:
            raise session.SessionFailure(f"yumed {self.name} is not running")
        try:
            return query(self.control)
        except (OSError, ValueError):
            return None

    def links(self) -> dict[str, dict]:
        status = self.status()
        if status is None or status.get("cluster") is None:
            return {}
        return {link["peer"]: link for link in status["cluster"]["links"]}


def wait_until(description: str, condition, timeout: float = 45.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.25)
    raise session.SessionFailure(f"timed out waiting until {description}")


def linked(node: Node, peer: str) -> bool:
    link = node.links().get(peer)
    return bool(link and link["outbound"]["state"] == "connected" and
                link["inbound"]["sessions"] >= 1)


def all_linked(nodes: list[Node]) -> bool:
    return all(linked(node, other.name) for node in nodes for other in nodes if other is not node)


def kept(node: Node, peer: str, reloaded_at: float) -> bool:
    """The outbound link to peer has been up since before the reload."""
    outbound = node.links().get(peer, {}).get("outbound", {})
    up_for = outbound.get("connected_ms", 0) / 1000.0
    return outbound.get("state") == "connected" and up_for > time.monotonic() - reloaded_at + 0.2


def saved_serial(node: Node) -> int:
    state = json.loads((node.server / "cluster-state.json").read_text(encoding="utf-8"))
    return int(state["serial"])


def reload(nodes: list[Node]) -> float:
    reloaded_at = time.monotonic()
    for node in nodes:
        node.process.send_signal(signal.SIGHUP)
    return reloaded_at


def run(yumed: Path, openssl: Path) -> None:
    environment = session.openssl_environment(openssl)
    program = session.setup_program(yumed)
    with tempfile.TemporaryDirectory(prefix="yume-cluster-", dir="/tmp") as temporary:
        root = Path(temporary)
        sockets = root / "run"
        sockets.mkdir(mode=0o700)
        operator = root / "operator"
        setup(program, environment, "cluster-init", "--output", str(operator))
        nodes: list[Node] = []
        for name in NAMES:
            kit = root / name
            session.provision_kit(kit, "127.0.0.1", session.free_port(), environment, program)
            server = kit / "server"
            config = json.loads((server / "yumed.json").read_text(encoding="utf-8"))
            config["endpoint"]["listen_addresses"] = ["127.0.0.1"]
            config["control"] = {"socket": str(sockets / f"{name}.sock")}
            (server / "yumed.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
            setup(program, environment, "cluster-add", "--cluster", str(operator),
                  "--server", str(server), "--name", name, "--host", "127.0.0.1")
            nodes.append(Node(name, server, sockets / f"{name}.sock", yumed, environment, root))
        signed = setup(program, environment, "cluster-sign", "--cluster", str(operator),
                       "--days", "2")
        if "serial 1" not in signed:
            raise session.SessionFailure(f"the first signed list is not serial 1: {signed}")
        a, b, c = nodes
        peers = lambda node: node.server / "credentials/cluster/peers"  # noqa: E731
        pair_secrets = [
            (peers(a) / "node-b-outbound.psk").read_bytes(),
            (peers(a) / "node-b-inbound.psk").read_bytes(),
            (peers(b) / "node-c-outbound.psk").read_bytes(),
            (peers(b) / "node-c-inbound.psk").read_bytes(),
        ]
        if len(set(pair_secrets)) != len(pair_secrets) or \
                (peers(b) / "node-a-inbound.psk").read_bytes() != pair_secrets[0]:
            raise session.SessionFailure("the pairs do not hold distinct matching PSKs")
        for node in nodes:
            result = subprocess.run([str(yumed), "--config", str(node.config), "--validate"],
                                    env=environment, capture_output=True, text=True, timeout=30,
                                    check=False)
            if result.returncode:
                raise session.SessionFailure(f"{node.name} --validate: {result.stderr.strip()}")
        try:
            for node in nodes:
                node.start()
            wait_until("every node links to every other", lambda: all_linked(nodes))
            status = a.status() or {}
            cluster = status.get("cluster") or {}
            if cluster.get("serial") != 1 or cluster.get("self") != "node-a" or \
                    cluster.get("expired") is not False or status.get("client_sessions") != 0:
                raise session.SessionFailure(f"node-a status is wrong: {status}")
            printed = subprocess.run([str(yumed), "--config", str(a.config), "--status"],
                                     env=environment, capture_output=True, text=True, timeout=30,
                                     check=False)
            if printed.returncode or "link node-b: outbound connected" not in printed.stdout:
                raise session.SessionFailure(f"yumed --status printed: {printed.stdout}")
            print("three nodes linked in both directions")

            # A stopped node's peers wait and reconnect once it is back.
            c.stop()
            wait_until("the others wait for node-c", lambda: all(
                node.links()["node-c"]["outbound"]["state"] == "waiting" and
                node.links()["node-c"]["inbound"]["sessions"] == 0 for node in (a, b)))
            c.start()
            wait_until("node-c is linked again", lambda: all_linked(nodes))
            print("links waited for a stopped node and recovered")

            # node-b expects another PSK from node-a: node-a's link is
            # refused while node-b's link to node-a still authenticates.
            b.stop()
            expected = peers(b) / "node-a-inbound.psk"
            original = expected.read_bytes()
            expected.write_bytes(os.urandom(32))
            b.start()
            wait_until("node-a's link to node-b is refused", lambda: (
                a.links()["node-b"]["outbound"]["failed_attempts"] >= 1 and
                a.links()["node-b"]["outbound"]["state"] != "connected" and
                b.links()["node-a"]["inbound"]["sessions"] == 0 and
                b.links()["node-a"]["outbound"]["state"] == "connected"))
            # Restoring the PSK and reloading node-b lets node-a in again.
            expected.write_bytes(original)
            b.process.send_signal(signal.SIGHUP)
            wait_until("node-a links to node-b after the reload", lambda: all_linked(nodes), 60.0)
            print("a wrong link PSK was refused and a reload restored the link")

            # A newer list with the same nodes keeps every link running.
            if [saved_serial(node) for node in nodes] != [1, 1, 1]:
                raise session.SessionFailure("the nodes did not save serial 1")
            listed = a.server / "credentials/cluster"
            signed_files = ("cluster-list.json", "cluster-list.sig",
                            "cluster-routes.json", "cluster-routes.sig")
            first_list = [(listed / name).read_bytes() for name in signed_files]
            time.sleep(1.0)
            setup(program, environment, "cluster-sign", "--cluster", str(operator), "--days", "2")
            reloaded_at = reload(nodes)
            wait_until("every node loaded serial 2", lambda: all(
                (node.status() or {}).get("cluster", {}).get("serial") == 2 for node in nodes))
            if not all(kept(node, other.name, reloaded_at)
                       for node in nodes for other in nodes if other is not node):
                raise session.SessionFailure(
                    f"a reload restarted an unchanged link: {[node.links() for node in nodes]}")
            if [saved_serial(node) for node in nodes] != [2, 2, 2]:
                raise session.SessionFailure("the nodes did not save serial 2")
            print("a reload with a newer list kept every unchanged link")

            # Removing node-c closes only its links.
            setup(program, environment, "cluster-remove", "--cluster", str(operator),
                  "--name", "node-c")
            setup(program, environment, "cluster-sign", "--cluster", str(operator), "--days", "2")
            reloaded_at = reload([a, b])
            wait_until("node-a and node-b dropped node-c", lambda: all(
                set(node.links()) == {other} for node, other in ((a, "node-b"), (b, "node-a"))))
            if not (kept(a, "node-b", reloaded_at) and kept(b, "node-a", reloaded_at)):
                raise session.SessionFailure("removing node-c restarted the other link")
            if (c.server / "cluster-state.json").exists():
                raise session.SessionFailure("cluster-remove left node-c's saved serial")
            print("removing a node closed only its links")

            # node-a refuses the older list it saw before, even after a restart.
            current_list = [(listed / name).read_bytes() for name in signed_files]
            a.stop()
            for name, payload in zip(signed_files, first_list):
                (listed / name).write_bytes(payload)
            a.start()
            try:
                code = a.process.wait(timeout=30)
            except subprocess.TimeoutExpired as error:
                raise session.SessionFailure("node-a started with an older list") from error
            a.process = None
            if code == 0:
                raise session.SessionFailure("node-a exited cleanly with an older list")
            refusal = (root / f"node-a-{a.runs}.log").read_text(encoding="utf-8", errors="replace")
            if "older than one this node has loaded" not in refusal:
                raise session.SessionFailure(f"node-a did not say why it refused: {refusal}")
            for name, payload in zip(signed_files, current_list):
                (listed / name).write_bytes(payload)
            print("a restarted node refused a list older than the one it saved")
            for node in nodes:
                node.stop()
        except session.SessionFailure:
            # The daemons' own lines show why a link did not come up.
            for node in nodes:
                node.kill()
            for log in sorted(root.glob("node-*.log")):
                print(f"---- {log.name}", file=sys.stderr)
                print(log.read_text(encoding="utf-8", errors="replace")[-4000:], file=sys.stderr)
            raise
        finally:
            for node in nodes:
                node.kill()
        for log in sorted(root.glob("node-*.log")):
            text = log.read_text(encoding="utf-8", errors="replace")
            session.reject_secret_output(log.stem, text)
            if "credentials reloaded" not in text and log.name == "node-b-2.log":
                raise session.SessionFailure("node-b did not report its reload")


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yumed", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        run(arguments.yumed, arguments.openssl)
    except (session.SessionFailure, OSError, subprocess.SubprocessError) as error:
        print(f"native cluster test: {error}", file=sys.stderr)
        return 1
    print("clustered yumed nodes linked, recovered, kept links across reloads "
          "and refused a wrong PSK and an older list")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
