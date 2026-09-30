#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""yume-gui without a display, against tests/gui/fake_yume.py.

The headless actions run the Tunnel the window uses, so these cases check
the lifecycle the window drives: a connect that leaves a detached tunnel
running after the GUI exits or is killed, a stop that waits for the process,
refusals reported in yume's words, a stop of a stopped kit reported as
nothing exercised, kit import through yume, the page capture and the
command line. run_gui_live_test.py repeats the lifecycle with a real yume.
"""

from __future__ import annotations

import argparse
import http.server
import json
import re
import threading
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

GUI = Path()
FAKE = Path()

PASSED, LEG_FAILED, NOTHING_EXERCISED = 0, 1, 2


def peer_pid(path: Path) -> int:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.connect(str(path))
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                            struct.calcsize("3i"))
        return struct.unpack("3i", credentials)[0]


def control(path: Path, request: dict[str, object]) -> dict[str, object]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(path))
        connection.sendall(json.dumps(request).encode() + b"\n")
        reply = b""
        while chunk := connection.recv(65536):
            reply += chunk
    return json.loads(reply)


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def png_size(path: Path) -> tuple[int, int]:
    header = path.read_bytes()[:24]
    if header[:8] != b"\x89PNG\r\n\x1a\n":
        raise AssertionError(f"{path} is not a PNG")
    return struct.unpack(">II", header[16:24])


class Gui(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="yume-gui-", dir="/tmp")
        self.root = Path(self.temporary.name)
        self.config = self.root / "config"
        self.runtime = self.root / "run"
        self.kits = self.config / "yume/kits"
        self.kits.mkdir(parents=True)
        self.runtime.mkdir(mode=0o700)
        self.environment = dict(os.environ, XDG_CONFIG_HOME=str(self.config),
                                XDG_RUNTIME_DIR=str(self.runtime), QT_QPA_PLATFORM="offscreen")
        self.started: list[str] = []

    def tearDown(self) -> None:
        for name in self.started:
            path = self.runtime / "yume" / f"{name}.sock"
            if path.exists():
                try:
                    pid = peer_pid(path)
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass
        self.temporary.cleanup()

    def kit(self, name: str, fake: dict[str, object] | None = None) -> Path:
        directory = self.kits / name
        directory.mkdir(mode=0o700)
        (directory / "yume.json").write_text(
            json.dumps({"endpoint": {"host": "origin.example.net", "port": 443}}), encoding="utf-8")
        if fake is not None:
            (directory / "fake.json").write_text(json.dumps(fake), encoding="utf-8")
        self.started.append(name)
        return directory

    def gui(self, *arguments: str, stdin: str = "", environment: dict[str, str] | None = None,
            timeout: float = 120) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(GUI), "--yume", str(FAKE), *arguments],
                              env=environment or self.environment, input=stdin,
                              capture_output=True, text=True, timeout=timeout, check=False)

    def legs(self, result: subprocess.CompletedProcess[str]) -> list[dict[str, object]]:
        return [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]

    def socket_of(self, name: str) -> Path:
        return self.runtime / "yume" / f"{name}.sock"

    # --- lifecycle -------------------------------------------------------

    def test_connect_leaves_a_detached_tunnel_that_stop_ends(self) -> None:
        self.kit("work", {"connect_after_ms": 300})
        result = self.gui("--kit", "work", "--headless", "connect")
        self.assertEqual(result.returncode, PASSED, result.stderr)
        [leg] = self.legs(result)
        self.assertEqual((leg["leg"], leg["ok"], leg["phase"], leg["state"]),
                         ("connect", True, "running", "connected"))
        self.assertEqual(leg["socks5"], ["127.0.0.1:1080"])
        self.assertIn("stop", leg["requests"])
        # The GUI has exited, and its tunnel runs on in a session of its own.
        pid = peer_pid(self.socket_of("work"))
        self.assertTrue(alive(pid))
        self.assertNotEqual(os.getsid(pid), os.getsid(0))
        self.assertEqual(control(self.socket_of("work"), {"control": 1, "request": "status"})["state"],
                         "connected")

        result = self.gui("--kit", "work", "--headless", "stop")
        self.assertEqual(result.returncode, PASSED, result.stderr)
        [leg] = self.legs(result)
        self.assertEqual((leg["leg"], leg["ok"], leg["phase"], leg["socket_removed"]),
                         ("stop", True, "stopped", True))
        self.assertFalse(alive(pid), "stop reported before the process ended")

    def test_cycle_reports_four_passing_legs(self) -> None:
        self.kit("work")
        result = self.gui("--kit", "work", "--headless", "cycle")
        self.assertEqual(result.returncode, PASSED, result.stderr)
        legs = self.legs(result)
        self.assertEqual([(leg["leg"], leg["ok"]) for leg in legs],
                         [("connect", True), ("stop", True), ("connect", True), ("stop", True)])
        self.assertEqual([leg["phase"] for leg in legs], ["running", "stopped", "running", "stopped"])
        self.assertFalse(self.socket_of("work").exists())

    def test_a_killed_gui_leaves_the_tunnel_running(self) -> None:
        self.kit("work", {"connect_after_ms": 5000})
        gui = subprocess.Popen([str(GUI), "--yume", str(FAKE), "--kit", "work", "--headless", "connect"],
                               env=self.environment, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 30
        while not self.socket_of("work").exists():
            self.assertLess(time.monotonic(), deadline, "the tunnel never opened its socket")
            time.sleep(0.05)
        gui.send_signal(signal.SIGKILL)
        gui.wait(timeout=10)
        time.sleep(0.5)
        status = control(self.socket_of("work"), {"control": 1, "request": "status"})
        self.assertIn(status["state"], ("connecting", "connected"))
        # A later GUI finds it by its socket and can stop it.
        result = self.gui("--kit", "work", "--headless", "stop")
        self.assertEqual(result.returncode, PASSED, result.stderr)

    def test_status_reports_a_stopped_kit(self) -> None:
        self.kit("work")
        result = self.gui("--kit", "work", "--headless", "status")
        self.assertEqual(result.returncode, PASSED, result.stderr)
        [leg] = self.legs(result)
        self.assertEqual((leg["leg"], leg["ok"], leg["phase"]), ("status", True, "stopped"))

    def test_a_refused_kit_fails_in_yumes_words(self) -> None:
        self.kit("bad", {"validate_error": "credentials are invalid: /credentials/access_psk"})
        result = self.gui("--kit", "bad", "--headless", "connect")
        self.assertEqual(result.returncode, LEG_FAILED, result.stderr)
        [leg] = self.legs(result)
        self.assertFalse(leg["ok"])
        self.assertEqual(leg["error"], "credentials are invalid: /credentials/access_psk")
        self.assertFalse(self.socket_of("bad").exists())

    def test_a_start_that_ends_early_says_why(self) -> None:
        self.kit("busy", {"start_error": "cannot start client adapters: address in use"})
        result = self.gui("--kit", "busy", "--headless", "connect")
        self.assertEqual(result.returncode, LEG_FAILED, result.stderr)
        [leg] = self.legs(result)
        self.assertEqual(leg["error"],
                         "yume stopped while starting: cannot start client adapters: address in use")

    def test_nothing_exercised_is_not_a_pass(self) -> None:
        self.kit("work")
        result = self.gui("--kit", "work", "--headless", "stop")
        self.assertEqual(result.returncode, NOTHING_EXERCISED, result.stderr)
        result = self.gui("--kit", "missing", "--headless", "connect")
        self.assertEqual(result.returncode, NOTHING_EXERCISED)
        self.assertIn("no kit named missing", result.stderr)
        without = dict(self.environment)
        del without["XDG_RUNTIME_DIR"]
        result = self.gui("--kit", "work", "--headless", "status", environment=without)
        self.assertEqual(result.returncode, NOTHING_EXERCISED)
        self.assertIn("XDG_RUNTIME_DIR", result.stderr)

    # --- import ----------------------------------------------------------

    def sealed(self, code: str) -> Path:
        path = self.root / "work.kit"
        path.write_text(json.dumps({"code": code, "files": {
            "yume.json": json.dumps({"endpoint": {"host": "edge.example.org", "port": 8443}})}}),
            encoding="utf-8")
        return path

    def test_import_hands_the_code_to_yume(self) -> None:
        sealed = self.sealed("ABCDE-FGH1J-KLMN0-PQRST-VWXYZ")
        result = self.gui("--import-kit", str(sealed), "--name", "work",
                          stdin="abcde fghij klmno pqrst vwxyz\n")
        self.assertEqual(result.returncode, PASSED, result.stderr)
        self.assertEqual(self.legs(result), [{"leg": "import", "ok": True, "kit": "work", "error": ""}])
        self.assertTrue((self.kits / "work/yume.json").is_file())
        # The code went to yume's standard input, not into any file.
        for path in self.config.rglob("*"):
            if path.is_file():
                self.assertNotIn("FGH1J", path.read_text(encoding="utf-8", errors="replace"))

        result = self.gui("--import-kit", str(sealed), "--name", "work",
                          stdin="ABCDE-FGH1J-KLMN0-PQRST-VWXYZ\n")
        self.assertEqual(result.returncode, LEG_FAILED)
        self.assertEqual(self.legs(result)[0]["error"], "a kit named work already exists")

    def test_import_reports_a_wrong_code(self) -> None:
        sealed = self.sealed("ABCDE-FGH1J-KLMN0-PQRST-VWXYZ")
        result = self.gui("--import-kit", str(sealed), "--name", "work",
                          stdin="ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ\n")
        self.assertEqual(result.returncode, LEG_FAILED)
        self.assertEqual(self.legs(result)[0]["error"],
                         "cannot open the kit: the code is wrong or the file is not a sealed kit")
        self.assertFalse((self.kits / "work").exists())
        for name in ("../escape", ".hidden", "-dash", "a" * 49, "sp ace"):
            result = self.gui("--import-kit", str(sealed), "--name", name, stdin="x\n")
            self.assertEqual(result.returncode, LEG_FAILED, name)
            self.assertIn("a kit name is", self.legs(result)[0]["error"])

    # --- pages -----------------------------------------------------------

    def test_capture_saves_every_page_without_qml_warnings(self) -> None:
        self.kit("work", {"circuits": True, "connect_after_ms": 100,
                          "lines": ["پیام آزمایشی: اتصال برقرار شد"]})
        result = self.gui("--kit", "work", "--headless", "connect")
        self.assertEqual(result.returncode, PASSED, result.stderr)
        shots = self.root / "shots"
        for flags in ([], ["--theme", "dark"], ["--layout-direction", "rtl"]):
            result = self.gui("--kit", "work", "--size", "1280x800", *flags, "--capture", str(shots),
                              timeout=180)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("QML", result.stderr)
        names = sorted(path.name for path in shots.iterdir())
        for page in ("overview", "connect", "logs", "posture", "route-review"):
            for suffix in ("light-ltr", "dark-ltr", "light-rtl"):
                self.assertIn(f"{page}-{suffix}.png", names)
        for kind in ("rest", "busy", "good", "bad"):
            self.assertEqual(png_size(shots / f"tray-{kind}.png"), (64, 64))
        for path in shots.iterdir():
            if path.name.startswith("tray-"):
                continue
            self.assertEqual(png_size(path), (1280, 800), path.name)
            self.assertGreater(path.stat().st_size, 20_000, path.name)
        # Capturing never answers a proposal.
        self.assertFalse((self.kits / "work/accepted.log").exists())

    def test_peer_text_is_plain_and_fetches_nothing(self) -> None:
        # A failure message and a printed line that hold markup, as a hostile
        # peer might send, stay text and make the GUI fetch nothing.
        fetched: list[str] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - http.server API
                fetched.append(self.path)
                self.send_response(404)
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            image = f'<img src="http://127.0.0.1:{server.server_address[1]}/%s.png">'
            self.kit("work", {"connect_after_ms": 100,
                              "last_failure": {"code": "closed",
                                               "message": "<b>" + image % "failure" + "</b>"},
                              "lines": ["<i>" + image % "line" + "</i>"]})
            result = self.gui("--kit", "work", "--headless", "connect")
            self.assertEqual(result.returncode, PASSED, result.stderr)
            result = self.gui("--kit", "work", "--capture", str(self.root / "shots"), timeout=180)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(fetched, [])

    def test_every_text_is_plain(self) -> None:
        # Pages show text from servers and peers, so no Text may guess rich
        # text from its content.
        missing = []
        for path in sorted((Path(__file__).resolve().parents[2] / "src/gui/qml").glob("*.qml")):
            source = path.read_text(encoding="utf-8")
            for match in re.finditer(r"(?m)^\s*(?:contentItem: )?Text \{", source):
                depth, end = 0, match.end() - 1
                while True:
                    depth += {"{": 1, "}": -1}.get(source[end], 0)
                    end += 1
                    if depth == 0:
                        break
                if "textFormat: Text.PlainText" not in source[match.start():end]:
                    missing.append(f"{path.name}:{source.count(chr(10), 0, match.start()) + 1}")
        self.assertEqual(missing, [])

    # --- command line ----------------------------------------------------

    def test_command_line(self) -> None:
        result = self.gui("--help")
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.startswith("Usage:\n  yume-gui "))
        result = self.gui("--version")
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.startswith("yume-gui 0.3.0-dev1\nQt "))
        for arguments, message in (
                (["--bogus"], "unknown argument: --bogus"),
                (["--page", "chat"], "--page takes overview, connect, logs, posture"),
                (["--theme", "blue"], "--theme takes light, dark or system"),
                (["--size", "wide"], "--size takes WIDTHxHEIGHT"),
                (["--headless", "connect"], "--headless takes --kit and --yume"),
                (["--kit", "a", "--headless", "restart"], "--headless takes status, connect, stop or cycle"),
                (["--kit", "a", "--headless", "status", "--page", "logs"], "--headless takes --kit and --yume"),
                (["--import-kit", "f"], "--import-kit takes --name and --yume"),
                (["--kit"], "--kit needs exactly one value")):
            with self.subTest(arguments=arguments):
                result = self.gui(*arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(f"yume-gui: {message}", result.stderr)
                self.assertIn("Usage:", result.stderr)


def main() -> int:
    global GUI, FAKE
    parser = argparse.ArgumentParser()
    parser.add_argument("--gui", required=True, type=Path)
    parser.add_argument("--fake-yume", required=True, type=Path)
    arguments, rest = parser.parse_known_args()
    GUI = arguments.gui.resolve(strict=True)
    FAKE = arguments.fake_yume.resolve(strict=True)
    runner = unittest.main(argv=[sys.argv[0], *rest], exit=False, verbosity=2)
    return 0 if runner.result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
