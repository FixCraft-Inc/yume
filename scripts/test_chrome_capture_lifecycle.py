#!/usr/bin/env python3
"""Bound capture readiness and direct-child teardown with real stalled peers."""

from __future__ import annotations

import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading
import time
import unittest

HELPER = Path(__file__).resolve().parents[1] / "tools/cover-node/capture_lifecycle.sh"


class CaptureLifecycleTest(unittest.TestCase):
    def bash(self, script: str, *arguments: str, timeout: float = 10) -> subprocess.CompletedProcess:
        process = subprocess.Popen(
            ["bash", "-c", 'source "$1"; shift\n' + script, "capture-test", str(HELPER), *arguments],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            out, error = process.communicate(timeout=timeout)
            return subprocess.CompletedProcess(process.args, process.returncode, out, error)
        finally:
            # Also cover a removed-fix control stuck in wait with live children.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)

    def test_child_exit_status_is_preserved(self) -> None:
        result = self.bash('(exit 7) &\nwait_capture_child "$!" 1')
        self.assertEqual(result.returncode, 7, result.stderr)

    def test_child_exit_wait_has_a_deadline(self) -> None:
        result = self.bash('''
sleep 60 &
pid=$!
wait_capture_child "$pid" 1
status=$?
kill -KILL "$pid"
wait "$pid" 2>/dev/null
exit "$status"
''', timeout=4)
        self.assertEqual(result.returncode, 124, result.stderr)

    def test_cleanup_kills_a_child_that_ignores_term(self) -> None:
        with tempfile.TemporaryDirectory(prefix="capture-stop-") as temporary:
            result = self.bash('''
python3 -c 'import pathlib, signal, sys, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); pathlib.Path(sys.argv[1]).touch(); time.sleep(60)' "$1" &
pid=$!
deadline=$((SECONDS + 2))
while [[ ! -e $1 ]] && (( SECONDS < deadline )); do sleep 0.01; done
[[ -e $1 ]] || exit 2
stop_capture_child "$pid" || exit 3
! kill -0 "$pid" 2>/dev/null
''', str(Path(temporary) / "ready"), timeout=9)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_cleanup_accepts_a_child_that_exited_124(self) -> None:
        result = self.bash('(exit 124) &\npid=$!\nsleep 0.1\nstop_capture_child "$pid"')
        self.assertEqual(result.returncode, 0, result.stderr)

    def check_devtools(self, responds: bool) -> None:
        stop = threading.Event()
        accepted = threading.Event()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(0.1)
            port = listener.getsockname()[1]

            def serve() -> None:
                while not stop.is_set():
                    try:
                        connection, _ = listener.accept()
                    except socket.timeout:
                        continue
                    with connection:
                        accepted.set()
                        if responds:
                            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                        else:
                            stop.wait(10)

            thread = threading.Thread(target=serve)
            thread.start()
            try:
                started = time.monotonic()
                result = self.bash('''
sleep 60 &
pid=$!
wait_capture_devtools "$pid" "$1" 3
status=$?
kill "$pid"
wait "$pid" 2>/dev/null
exit "$status"
''', str(port), timeout=6)
                self.assertTrue(accepted.is_set(), "the readiness request never reached the listener")
                self.assertEqual(result.returncode, 0 if responds else 1, result.stderr)
                self.assertLess(time.monotonic() - started, 5)
            finally:
                stop.set()
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())

    def test_ready_devtools_succeeds(self) -> None:
        self.check_devtools(True)

    def test_silent_devtools_is_bounded(self) -> None:
        self.check_devtools(False)


if __name__ == "__main__":
    unittest.main()
