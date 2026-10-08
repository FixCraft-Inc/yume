#!/usr/bin/env python3
"""Run four clustered yumed nodes and drive circuits through them.

A test client (yume_circuit_probe) holds a kit that node-a grants
yume.circuit. It fetches the routes view from node-a, builds circuits
through named hops and echoes bytes through an exit to a local target.
node-c and node-d are exits that may reach 127.0.0.1 only.

Recovery runs on the same nodes: a stopped middle comes back and carries
circuits again, a client leaves while its circuit is being built, a link's
rekey fails under load, and reloads change the list, a link's PSK and the
membership.
"""

from __future__ import annotations

import argparse
from concurrent.futures import Future, ThreadPoolExecutor
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
import run_native_stress_test as stress  # noqa: E402

MIB = 1024 * 1024
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


def settle(nodes: dict[str, cluster.Node], names: tuple[str, ...] = NAMES,
           timeout: float = 30.0) -> None:
    """Waits until the named nodes hold no circuit, so none leaked."""
    cluster.wait_until(f"{', '.join(names)} hold no circuit", lambda: all(
        circuits(nodes[name]).get("open") == 0 for name in names), timeout)


def finish(process: subprocess.Popen, what: str, timeout: float = 120.0) -> dict:
    """The report of a probe started earlier, once it ends."""
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.communicate()
        raise session.SessionFailure(f"{what} did not end") from error
    return Probe.parse(stdout, stderr, process.returncode)


def loaded(probe: Probe, root: Path, client: str, hops: str, target: str,
           milliseconds: int) -> subprocess.Popen:
    """A probe echoing through its circuit for the given time, once it carries data."""
    ready = root / f"{client}-{time.monotonic_ns()}.ready"
    process = probe.start(client, hops, target, "--load-ms", str(milliseconds),
                          "--ready-file", str(ready))
    wait_for_file(ready, process)
    return process


class Frozen:
    """Stops a node's process for the block and continues it however the block ends."""

    def __init__(self, node: cluster.Node) -> None:
        self.node = node
        self.since = 0.0

    def __enter__(self) -> "Frozen":
        self.node.process.send_signal(signal.SIGSTOP)
        self.since = time.monotonic()
        return self

    def __exit__(self, *_: object) -> None:
        if self.node.process is not None and self.node.process.poll() is None:
            self.node.process.send_signal(signal.SIGCONT)


def log_text(root: Path, node: cluster.Node) -> str:
    return (root / f"{node.name}-{node.runs}.log").read_text(encoding="utf-8",
                                                             errors="replace")


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


def stream_pair(listener: socket.socket, client: Client,
                held: list[socket.socket]) -> tuple[socket.socket, socket.socket]:
    """A SOCKS5 stream through the client's circuit and the exit's connection to us."""
    code, app = session.socks_connect(client.socks_port, "127.0.0.1",
                                      listener.getsockname()[1])
    held.append(app)
    if code != 0:
        raise session.SessionFailure(f"SOCKS5 CONNECT was refused with {code}")
    try:
        target, _ = listener.accept()
    except TimeoutError as error:
        raise session.SessionFailure("the exit never connected the stream") from error
    held.append(target)
    for connection in (app, target):
        connection.settimeout(120)
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16384)
    return app, target


def await_backpressure(sender: Future, progress: stress.Progress, what: str) -> int:
    deadline = time.monotonic() + 30
    while True:
        if sender.done():
            sender.result()
            raise session.SessionFailure(f"{what} finished without a reader")
        sent, changed = progress.snapshot()
        if sent and time.monotonic() - changed >= 2:
            return sent
        if time.monotonic() >= deadline:
            raise session.SessionFailure(f"{what} never reached a stable backpressure point")
        time.sleep(0.1)


def await_all(futures: list[Future], what: str, seconds: float = 120) -> None:
    deadline = time.monotonic() + seconds
    while not all(future.done() for future in futures):
        for future in futures:
            if future.done():
                future.result()
        if time.monotonic() >= deadline:
            raise session.SessionFailure(f"{what} exceeded its deadline")
        time.sleep(0.1)
    for future in futures:
        future.result()


def stalled_streams(client: Client, nodes: dict[str, cluster.Node], probe: Probe,
                    echo_target: str, hold: float) -> dict:
    """A stream whose reader stops and one whose destination stops reading, beside healthy ones.

    Each end keeps a stream's data within the window it granted and goes on
    reading its circuit, so neither stall holds the circuit's other streams,
    another client's circuit over the same nodes, or a cell long enough for
    a node's stall timeout to end the circuit. Both stalled streams then
    resume with their bytes, order and half-close intact.
    """
    held: list[socket.socket] = []
    pool = ThreadPoolExecutor(max_workers=16)
    size = 32 * MIB
    try:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
            listener.bind(("127.0.0.1", 0))
            listener.listen(8)
            listener.settimeout(30)
            # The exit sends toward a client application that does not read.
            reader_app, reader_target = stream_pair(listener, client, held)
            download_progress = stress.Progress()
            download = pool.submit(stress.transmit, reader_target, size, 3, download_progress)
            download_held = await_backpressure(download, download_progress,
                                               "a download to an unread application")
            stalled_since = time.monotonic()
            # The client sends toward a destination that does not read.
            writer_app, writer_target = stream_pair(listener, client, held)
            upload_progress = stress.Progress()
            upload = pool.submit(stress.transmit, writer_app, size, 4, upload_progress)
            upload_held = await_backpressure(upload, upload_progress,
                                             "an upload to an unread destination")
            entry = nodes["node-a"]

            started = time.monotonic()
            healthy: list[Future] = []
            for index in range(2):
                app, target = stream_pair(listener, client, held)
                salt = 10 + index * 2
                healthy += [pool.submit(stress.transmit, app, 2 * MIB, salt),
                            pool.submit(stress.receive, target, 2 * MIB, salt),
                            pool.submit(stress.transmit, target, 2 * MIB, salt + 1),
                            pool.submit(stress.receive, app, 2 * MIB, salt + 1)]
            bystander = pool.submit(probe.run, "bystander", "node-a,node-b,node-c",
                                    echo_target, "--bytes", "900000")
            await_all(healthy, "healthy streams beside the stalled ones")
            report = bystander.result(timeout=120)
            expect(first(report)["built"] and report.get("stream") == "ok" and
                   report.get("echoed") == 900000,
                   "another client's circuit did not carry its stream beside the stall", report)
            healthy_seconds = time.monotonic() - started

            # The bystander's circuit ends when its probe exits, and the
            # entry may count that teardown as failed. Count from once the
            # entry's counts have settled.
            deadline = time.monotonic() + 30
            counts, since = None, time.monotonic()
            while time.monotonic() - since < 2:
                state = circuits(entry)
                if (state.get("open"), state.get("failed")) != counts:
                    counts, since = (state.get("open"), state.get("failed")), time.monotonic()
                if time.monotonic() >= deadline:
                    raise session.SessionFailure(f"the entry's circuits never settled: {state}")
                time.sleep(0.2)
            failed = {name: circuits(node).get("failed", 0) for name, node in nodes.items()}
            open_held = circuits(entry).get("open", 0)

            # Hold the stall, then show it ended nothing.
            time.sleep(max(0.0, hold - (time.monotonic() - stalled_since)))
            expect(not download.done() and not upload.done(),
                   "a stalled stream finished without its reader",
                   (download_progress.snapshot(), upload_progress.snapshot()))
            moved = (download_progress.snapshot()[0] - download_held,
                     upload_progress.snapshot()[0] - upload_held)
            after = {name: circuits(node).get("failed", 0) for name, node in nodes.items()}
            open_after = circuits(entry).get("open", 0)
            expect(after == failed and open_after >= open_held,
                   "a node ended a circuit while one of its streams stalled",
                   (failed, after, open_held, open_after))
            app, target = stream_pair(listener, client, held)
            await_all([pool.submit(stress.transmit, app, 65536, 20),
                       pool.submit(stress.receive, target, 65536, 20)],
                      "a new stream after the stall")

            # Readers return: every byte arrives, in order and with the
            # half-close, and each stream still carries the other way.
            await_all([download, pool.submit(stress.receive, reader_app, size, 3),
                       upload, pool.submit(stress.receive, writer_target, size, 4)],
                      "the stalled streams after their readers returned")
            await_all([pool.submit(stress.transmit, reader_app, MIB, 5),
                       pool.submit(stress.receive, reader_target, MIB, 5),
                       pool.submit(stress.transmit, writer_target, MIB, 6),
                       pool.submit(stress.receive, writer_app, MIB, 6)],
                      "the resumed streams in their other direction")
            return {"download_bytes_at_stall": download_held,
                    "upload_bytes_at_stall": upload_held,
                    "bytes_moved_while_held": moved,
                    "healthy_seconds": round(healthy_seconds, 2),
                    "held_seconds": round(time.monotonic() - stalled_since, 2),
                    "entry_open_circuits": open_held}
    finally:
        for connection in held:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        pool.shutdown(wait=True, cancel_futures=True)


def node_return(nodes: dict[str, cluster.Node], probe: Probe, target: str) -> None:
    """The stopped middle comes back: its links recover and circuits run through it again."""
    b = nodes["node-b"]
    started = time.monotonic()
    b.start()
    cluster.wait_until("node-b is linked again",
                       lambda: cluster.all_linked(list(nodes.values())), 60.0)
    relinked = time.monotonic() - started
    report = probe.run("returner", "node-a,node-b,node-c", target, "--bytes", "200000")
    built = first(report)
    expect(built["built"] and len(built["hop_ms"]) == 3 and report.get("stream") == "ok"
           and report.get("echoed") == 200000,
           "no circuit was built through the middle once it was back", report)
    settle(nodes)
    print(f"the stopped middle came back, linked again in {relinked:.1f} s "
          "and carried a new circuit")


def cancelled_build(nodes: dict[str, cluster.Node], probe: Probe, target: str) -> None:
    """A client goes away while its circuit waits at the entry for a frozen middle.

    The entry ends that circuit as soon as the client's session ends, well
    before its 10-second extension bound, and gives the client's circuit
    budget back, and the middle drops the half-built circuit once it runs.
    """
    a, b = nodes["node-a"], nodes["node-b"]
    started = time.monotonic()
    with Frozen(b):
        pending = probe.start("canceller", "node-a,node-b,node-c", target)
        cluster.wait_until("the entry extends a circuit to the frozen middle",
                           lambda: circuits(a).get("open") == 1, 20.0)
        pending.kill()
        pending.communicate(timeout=30)
        killed = time.monotonic()
        cluster.wait_until("the entry ended the circuit of a client that went away",
                           lambda: circuits(a).get("open") == 0, 5.0)
        ended = time.monotonic() - killed
    settle(nodes)
    cluster.wait_until("every node links to every other after the freeze",
                       lambda: cluster.all_linked(list(nodes.values())), 30.0)
    # The client's new-circuit rate allows a burst of 4, one a 5 seconds
    # after that, and the cancelled build took one.
    time.sleep(max(0.0, 6.0 - (time.monotonic() - started)))
    report = probe.run("canceller", "node-a,node-c", target, "--circuits", "4")
    held = report.get("circuits", [])
    expect(len(held) == 4 and all(entry["built"] for entry in held),
           "the cancelled build kept part of the client's circuit budget", report)
    settle(nodes)
    print(f"the entry ended a circuit {ended:.1f} s after its client left mid-build "
          "and gave its budget back")


def failed_rekey(nodes: dict[str, cluster.Node], probe: Probe, root: Path,
                 target: str) -> None:
    """A link's rekey fails under load.

    The middle freezes while a circuit through it carries data, and a new
    circuit's OPEN on the entry's link to it starts a key rotation that is
    never acknowledged. The entry ends that link at the 30-second
    acknowledgement deadline with that reason, the loaded circuit ends with
    a failure the entry reports, a loaded circuit that avoids the middle
    keeps running, and once the middle runs again its links and circuits
    through it recover.
    """
    a, b = nodes["node-a"], nodes["node-b"]

    def rekey_failed() -> bool:
        outbound = a.links().get("node-b", {}).get("outbound", {})
        failure = outbound.get("last_failure") or {}
        return "rekey acknowledgement deadline expired" in failure.get("message", "")

    expect(not rekey_failed(), "the entry's link to the middle failed a rekey before the freeze",
           a.links())
    through = loaded(probe, root, "freezer", "node-a,node-b,node-c", target, 120000)
    beside = loaded(probe, root, "sider", "node-a,node-d,node-c", target, 50000)
    with Frozen(b) as frozen:
        # The epoch is then past half its 500 ms send lifetime, so the
        # OPEN's record starts a rotation.
        time.sleep(1.0)
        poke = probe.start("poker", "node-a,node-b,node-c", target)
        cluster.wait_until("the entry's link to the frozen middle failed its rekey",
                           rekey_failed, 45.0)
        failed_after = time.monotonic() - frozen.since
        report = finish(through, "the circuit through the frozen middle")
        expect(report.get("stream") != "ok" and (report.get("failure") or {}).get("hop") == 1,
               "the loaded circuit did not end with a failure the entry reported", report)
        finish(poke, "the build toward the frozen middle")
    report = finish(beside, "the circuit beside the frozen middle")
    expect(report.get("stream") == "ok" and report.get("echoed", 0) > 0 and
           "failure" not in report,
           "a circuit that avoided the middle broke while the middle's links failed", report)
    cluster.wait_until("node-b is linked again after its failed rekeys",
                       lambda: cluster.all_linked(list(nodes.values())), 90.0)
    report = probe.run("freezer", "node-a,node-b,node-c", target, "--bytes", "200000")
    expect(first(report)["built"] and report.get("stream") == "ok" and
           report.get("echoed") == 200000,
           "no circuit was built through the middle after its failed rekeys", report)
    settle(nodes)
    print(f"a rekey the frozen middle never acknowledged ended the entry's link after "
          f"{failed_after:.1f} s, ended only the circuit through it, and the links recovered")


def refused_reload(nodes: dict[str, cluster.Node], probe: Probe, root: Path,
                   target: str) -> None:
    """A reload whose list fails its signature changes nothing a circuit uses."""
    a = nodes["node-a"]
    signature = a.server / "credentials/cluster/cluster-list.sig"
    original = signature.read_bytes()
    running = loaded(probe, root, "changer", "node-a,node-b,node-c", target, 4000)
    try:
        signature.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        reloaded_at = cluster.reload([a])
        cluster.wait_until("node-a refused the reload", lambda: log_text(root, a).count(
            "credential reload refused") == 1, 20.0)
    finally:
        signature.write_bytes(original)
    report = finish(running, "the circuit across a refused reload")
    expect(report.get("stream") == "ok" and report.get("echoed", 0) > 0 and
           "failure" not in report, "a refused reload broke a loaded circuit",
           (report, a.links()))
    status = (a.status() or {}).get("cluster") or {}
    expect(status.get("serial") == 1 and all(cluster.kept(a, peer, reloaded_at)
                                             for peer in ("node-b", "node-c", "node-d")),
           "a refused reload changed node-a's list or links", status)
    settle(nodes)
    print("a reload refused for a bad list signature kept the list, links and a loaded circuit")


def changed_link(nodes: dict[str, cluster.Node], probe: Probe, root: Path,
                 target: str) -> None:
    """A reload that changes one link's PSK replaces only that link.

    node-b's link to node-c gets a new pair PSK at both ends. The circuit
    over that link ends with the break reported by node-b, the hop before
    it, a circuit over other links keeps running, every other link is kept,
    and a new circuit uses the replaced link.
    """
    b, c = nodes["node-b"], nodes["node-c"]
    over = loaded(probe, root, "changer", "node-a,node-b,node-c", target, 60000)
    beside = loaded(probe, root, "sider", "node-a,node-d,node-c", target, 6000)
    secret = os.urandom(32)
    (b.server / "credentials/cluster/peers/node-c-outbound.psk").write_bytes(secret)
    (c.server / "credentials/cluster/peers/node-b-inbound.psk").write_bytes(secret)
    reloaded_at = cluster.reload([b, c])
    report = finish(over, "the circuit over the changed link")
    expect(report.get("stream") != "ok" and (report.get("failure") or {}).get("hop") == 2,
           "the circuit over the changed link did not end with node-b's report", report)
    report = finish(beside, "the circuit beside the changed link")
    expect(report.get("stream") == "ok" and report.get("echoed", 0) > 0 and
           "failure" not in report, "a circuit over unchanged links broke", report)
    cluster.wait_until("node-b's new link to node-c is up",
                       lambda: cluster.linked(b, "node-c"), 30.0)
    kept = {name: cluster.kept(node, peer, reloaded_at)
            for name, node, peer in (("b-c", b, "node-c"), ("b-a", b, "node-a"),
                                     ("b-d", b, "node-d"), ("c-a", c, "node-a"),
                                     ("c-b", c, "node-b"), ("c-d", c, "node-d"))}
    expect(kept == {"b-c": False, "b-a": True, "b-d": True, "c-a": True, "c-b": True,
                    "c-d": True}, "the reload did not replace exactly the changed link", kept)
    report = probe.run("changer", "node-a,node-b,node-c", target, "--bytes", "200000")
    expect(first(report)["built"] and report.get("stream") == "ok" and
           report.get("echoed") == 200000, "no circuit used the replaced link", report)
    settle(nodes)
    print("a changed link PSK replaced only that link, ended only the circuit over it, "
          "and new circuits used the new link")


def removed_node(nodes: dict[str, cluster.Node], probe: Probe, root: Path, target: str,
                 environment: dict[str, str], operator: Path) -> None:
    """Removing node-d ends the circuits through it and keeps the rest.

    The others reload a list without it: they end its sessions and links,
    the circuit through it ends, a circuit through the others keeps
    running, and new clients get the newer routes view.
    """
    a, b, c = nodes["node-a"], nodes["node-b"], nodes["node-c"]
    through = loaded(probe, root, "sider", "node-a,node-d,node-c", target, 60000)
    beside = loaded(probe, root, "changer", "node-a,node-b,node-c", target, 6000)
    cluster.setup(environment, "cluster-remove", "--cluster", str(operator), "--name", "node-d")
    cluster.setup(environment, "cluster-sign", "--cluster", str(operator), "--days", "2")
    reloaded_at = cluster.reload([a, b, c])
    cluster.wait_until("node-a, node-b and node-c dropped node-d", lambda: all(
        (node.status() or {}).get("cluster", {}).get("serial") == 2 and
        "node-d" not in node.links() for node in (a, b, c)), 30.0)
    report = finish(through, "the circuit through the removed node")
    expect(report.get("stream") != "ok" and "failure" in report,
           "the circuit through a removed node did not end", report)
    report = finish(beside, "the circuit beside the removed node")
    expect(report.get("stream") == "ok" and report.get("echoed", 0) > 0 and
           "failure" not in report, "removing a node broke a circuit that avoided it", report)
    kept = all(cluster.kept(node, peer.name, reloaded_at)
               for node in (a, b, c) for peer in (a, b, c) if peer is not node)
    expect(kept, "removing node-d restarted another link", [n.links() for n in (a, b, c)])
    # node-d still dials the others with its old list. A session of it left
    # over from before the reload would count as a client's.
    cluster.wait_until("node-d's sessions ended", lambda: all(
        (node.status() or {}).get("client_sessions") == 0 for node in (a, b, c)), 10.0)
    report = probe.run("returner", "node-a,node-b,node-c", target, "--bytes", "70000")
    expect(report.get("routes_serial") == 2 and first(report)["built"] and
           report.get("stream") == "ok", "a new client did not get the newer view", report)
    settle(nodes, ("node-a", "node-b", "node-c"))
    print("removing a node ended the circuit through it and kept every other link and circuit")


def run(yumed: Path, program: Path, yume: Path, openssl: Path, stall_seconds: float) -> None:
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
        for client in ("walker", "crowd", "hauler", "rider", "drifter", "lagger", "bystander",
                       "returner", "canceller", "freezer", "poker", "sider", "changer"):
            cluster.setup(environment, "add-client", "--server", str(nodes["node-a"].server),
                          "--host", "127.0.0.1", "--output", str(root / client),
                          "--client-name", client, "--circuits")
        a, b = nodes["node-a"], nodes["node-b"]
        rider = Client(yume, root / "rider", environment, sockets)
        drifter = Client(yume, root / "drifter", environment, sockets, min_hops=1)
        lagger = Client(yume, root / "lagger", environment, sockets)
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

            lagger.start()
            stall = stalled_streams(lagger, nodes, probe, target, stall_seconds)
            expect(lagger.circuits().get("current_hops") == 3,
                   "the stalled client left its three-hop route", lagger.circuits())
            lagger.stop()
            print("stalled streams held no other stream or circuit, then resumed intact: "
                  + json.dumps(stall, sort_keys=True))

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

            node_return(nodes, probe, target)
            cancelled_build(nodes, probe, target)
            failed_rekey(nodes, probe, root, target)
            refused_reload(nodes, probe, root, target)
            changed_link(nodes, probe, root, target)
            removed_node(nodes, probe, root, target, environment, operator)

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
            lagger.kill()
            for node in nodes.values():
                node.kill()
            for client in (rider, drifter, lagger):
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
            lagger.kill()
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
    # Seconds a stalled stream stays held beside healthy ones. Past a node's
    # 30-second stall timeout it also shows that only cells, not streams,
    # count toward it.
    parser.add_argument("--stall-seconds", type=float, default=3.0)
    arguments = parser.parse_args()
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    try:
        run(arguments.yumed, arguments.probe, arguments.yume, arguments.openssl,
            arguments.stall_seconds)
    except session.SessionFailure as error:
        print(f"native circuit test: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
