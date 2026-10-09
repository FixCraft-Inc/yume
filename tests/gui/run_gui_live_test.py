#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""yume-gui against a real yumed and yume.

A setup kit's client half is sealed with yume --seal-kit and imported
through the GUI with its code. The GUI then connects, stops, reconnects and
stops the kit, one headless action per process, and each leg's report is
inspected: the state and verified server identity the control socket gave,
the SOCKS5 listener, a payload fetched through the tunnel while it runs, the
socket and process gone after each stop. Between the legs the GUI process
has exited, and a window of it is killed, while the tunnel keeps carrying
traffic. A final cycle runs all four legs in one process. With --capture the
window's pages are saved against the running client for review.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import yume_native_session as session  # noqa: E402

PAYLOAD_BYTES = 4 * 1024 * 1024


def peer_pid(path: Path) -> int:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.connect(str(path))
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                            struct.calcsize("3i"))
        return struct.unpack("3i", credentials)[0]


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class Live:
    def __init__(self, gui: Path, yume: Path, yumed: Path, openssl: Path, root: Path) -> None:
        self.gui = gui
        self.yume = yume
        self.yumed = yumed
        self.root = root
        self.environment = session.openssl_environment(openssl)
        self.config = root / "config"
        self.runtime = root / "run"
        self.runtime.mkdir(mode=0o700)
        self.environment.update(XDG_CONFIG_HOME=str(self.config),
                                XDG_RUNTIME_DIR=str(self.runtime), QT_QPA_PLATFORM="offscreen")
        self.socket = self.runtime / "yume/live.sock"
        self.identity = ""

    def run_gui(self, *arguments: str, stdin: str = "", timeout: float = 120) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(self.gui), "--yume", str(self.yume), *arguments],
                              env=self.environment, input=stdin, capture_output=True, text=True,
                              timeout=timeout, check=False)

    def legs(self, result: subprocess.CompletedProcess[str], expected: int) -> list[dict[str, object]]:
        legs = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
        if len(legs) != expected:
            raise session.SessionFailure(f"expected {expected} reports, got {result!r}")
        for leg in legs:
            print("leg report: " + json.dumps(leg, sort_keys=True))
        return legs

    def import_kit(self, kit: Path) -> None:
        sealed = self.root / "live.kit"
        result = subprocess.run([str(self.yume), "--seal-kit", str(kit / "client"),
                                 "--output", str(sealed)],
                                env=self.environment, capture_output=True, text=True, timeout=120,
                                check=False)
        code = result.stdout.strip()
        if result.returncode or not re.fullmatch(r"[0-9A-Z]{5}(-[0-9A-Z]{5}){4}", code):
            raise session.SessionFailure(f"sealing failed: {result!r}")
        result = self.run_gui("--import-kit", str(sealed), "--name", "live", stdin=code + "\n")
        [leg] = self.legs(result, 1)
        if result.returncode or not leg["ok"] or leg["kit"] != "live":
            raise session.SessionFailure(f"the GUI's import failed: {result!r}")
        if not (self.config / "yume/kits/live/yume.json").is_file():
            raise session.SessionFailure("the imported kit has no yume.json")
        print("import verified: the GUI imported the sealed kit with its code")

    def connect(self, socks_port: int, target_port: int, sessions: int) -> int:
        result = self.run_gui("--kit", "live", "--headless", "connect")
        [leg] = self.legs(result, 1)
        identity = str(leg.get("server_identity", ""))
        if (result.returncode or not leg["ok"] or leg["phase"] != "running" or
                leg["state"] != "connected" or leg["sessions"] != sessions or
                leg["socks5"] != [f"127.0.0.1:{socks_port}"] or
                not re.fullmatch(r"[0-9a-f]{64}", identity) or
                leg["requests"] != ["status", "messages", "stop"] or
                leg["last_failure"] is not None):
            raise session.SessionFailure(f"the connect leg is wrong: {result!r}")
        if self.identity and identity != self.identity:
            raise session.SessionFailure("the reconnect verified another server identity")
        self.identity = identity
        # The GUI process has exited. The tunnel it started runs on, detached.
        pid = peer_pid(self.socket)
        if os.getsid(pid) == os.getsid(0):
            raise session.SessionFailure("yume runs in the GUI's session")
        self.fetch(socks_port, target_port)
        return pid

    def fetch(self, socks_port: int, target_port: int) -> None:
        length, digest, _ = session.get_through_socks(socks_port, "127.0.0.1", target_port,
                                                      time.monotonic() + 30)
        if length != PAYLOAD_BYTES or digest != session.payload_digest(PAYLOAD_BYTES):
            raise session.SessionFailure(f"tunnelled payload differs: {length} bytes")

    def stop(self, pid: int, socks_port: int) -> None:
        result = self.run_gui("--kit", "live", "--headless", "stop")
        [leg] = self.legs(result, 1)
        if (result.returncode or not leg["ok"] or leg["phase"] != "stopped" or
                not leg["socket_removed"] or not leg.get("process_ended")):
            raise session.SessionFailure(f"the stop leg is wrong: {result!r}")
        if alive(pid) or self.socket.exists():
            raise session.SessionFailure("yume outlived a reported stop")
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", socks_port)) == 0:
                raise session.SessionFailure("the SOCKS5 listener outlived a reported stop")

    def killed_window(self, socks_port: int, target_port: int, pid: int) -> None:
        window = subprocess.Popen([str(self.gui), "--yume", str(self.yume), "--kit", "live"],
                                  env=self.environment, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        time.sleep(3)
        if window.poll() is not None:
            raise session.SessionFailure(f"the window exited with {window.returncode}")
        window.send_signal(signal.SIGKILL)
        window.wait(timeout=10)
        if not alive(pid):
            raise session.SessionFailure("killing the window ended the tunnel")
        self.fetch(socks_port, target_port)
        print("crash verified: the tunnel carried traffic after its window was killed")

    def capture(self, directory: Path) -> None:
        for flags in ([], ["--theme", "dark"], ["--layout-direction", "rtl"]):
            result = self.run_gui("--kit", "live", "--size", "1280x800", *flags,
                                  "--capture", str(directory), timeout=180)
            if result.returncode:
                raise session.SessionFailure(f"the capture failed: {result!r}")
        print(f"pages captured against the live client in {directory}")


def run(arguments: argparse.Namespace) -> None:
    with tempfile.TemporaryDirectory(prefix="yume-gui-live-", dir="/tmp") as temporary:
        root = Path(temporary)
        live = Live(arguments.gui.resolve(strict=True), arguments.yume.resolve(strict=True),
                    arguments.yumed.resolve(strict=True), arguments.openssl, root)
        kit = root / "kit"
        server_port, socks_port, target_port = (session.free_port() for _ in range(3))
        session.provision_kit(kit, "localhost", server_port, live.environment,
                              arguments.setup.resolve(strict=True))
        session.configure_kit(kit, listen_address="127.0.0.1", networks=["127.0.0.1/32"],
                              connect_address="127.0.0.1", socks_port=socks_port)
        target = session.serve_payload("127.0.0.1", target_port, PAYLOAD_BYTES)
        log_path = root / "yumed.log"
        with log_path.open("wb") as log:
            server = subprocess.Popen([str(live.yumed), "--config", str(kit / "server/yumed.json")],
                                      env=live.environment, stdout=log, stderr=subprocess.STDOUT)
            try:
                session.wait_for_port("127.0.0.1", server_port, server, time.monotonic() + 30)
                live.import_kit(kit)
                pid = live.connect(socks_port, target_port, sessions=1)
                live.killed_window(socks_port, target_port, pid)
                if arguments.capture:
                    live.capture(arguments.capture)
                live.stop(pid, socks_port)
                print("leg 1 and 2 verified: connected with traffic, then stopped")
                pid = live.connect(socks_port, target_port, sessions=1)
                live.stop(pid, socks_port)
                print("leg 3 and 4 verified: reconnected with traffic, then stopped")

                result = live.run_gui("--kit", "live", "--headless", "cycle", timeout=240)
                legs = live.legs(result, 4)
                if (result.returncode or [leg["leg"] for leg in legs] != ["connect", "stop", "connect", "stop"]
                        or not all(leg["ok"] for leg in legs)
                        or any(leg.get("server_identity", live.identity) != live.identity for leg in legs)):
                    raise session.SessionFailure(f"the cycle failed: {result!r}")
                print("cycle verified: four legs in one GUI process")
                if server.poll() is not None:
                    raise session.SessionFailure("yumed exited during the GUI's lifecycle")
                session.stop_process(server, "yumed")
                server = None
            finally:
                if server is not None and server.poll() is None:
                    server.kill()
                    server.wait(timeout=5)
                target.shutdown()
                if live.socket.exists():
                    try:
                        os.kill(peer_pid(live.socket), signal.SIGTERM)
                    except OSError:
                        pass
        text = log_path.read_text(encoding="utf-8", errors="replace")
        session.reject_secret_output("yumed", text)
        for output in (live.runtime / "yume").glob("*.log"):
            session.reject_secret_output("yume", output.read_text(encoding="utf-8", errors="replace"))
        print("GUI live lifecycle passed against a real yumed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gui", required=True, type=Path)
    parser.add_argument("--yume", required=True, type=Path)
    parser.add_argument("--yumed", required=True, type=Path)
    parser.add_argument("--setup", required=True, type=Path)
    parser.add_argument("--openssl", required=True, type=Path)
    parser.add_argument("--capture", type=Path, help="save the pages against the live client here")
    arguments = parser.parse_args()
    try:
        run(arguments)
    except session.SessionFailure as failure:
        print(f"GUI live test: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
