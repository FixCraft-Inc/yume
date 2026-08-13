#!/usr/bin/env python3
"""Focused fail-closed tests for benchmark Chrome launches."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import yume_bench_common  # noqa: E402
from yume_bench_common import RuntimeIdentity, StreamedCommandResult  # noqa: E402
from yume_bench_lan import run_browser_cover as run_lan_browser_cover  # noqa: E402
from yume_bench_wan import run_browser_cover  # noqa: E402
from yume_carrier_diagnose import (  # noqa: E402
    browser_failures,
    chromium_base_args,
    diagnostic_exit_code,
    require_unprivileged_browser_driver,
)


class _FakeLab:
    client_ns = "client-test"

    @staticmethod
    def command(namespace: str, argv: list[str]) -> list[str]:
        return ["ip", "netns", "exec", namespace, *argv]


class BrowserSandboxTest(unittest.TestCase):
    @staticmethod
    def _write_executable(path: Path, body: str) -> None:
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)

    def test_exact_chrome_validates_launcher_binary_and_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            chrome_dir = Path(tmp)
            launcher = chrome_dir / "google-chrome"
            binary = chrome_dir / "chrome"
            launcher.write_text("launcher", encoding="utf-8")
            binary.write_text("binary", encoding="utf-8")
            launcher.chmod(0o755)
            binary.chmod(0o755)
            hashes = {
                launcher.resolve(): yume_bench_common.PINNED_CHROME_LAUNCHER_SHA256,
                binary.resolve(): yume_bench_common.PINNED_CHROME_BINARY_SHA256,
            }
            with (
                mock.patch.object(
                    yume_bench_common,
                    "sha256_file",
                    side_effect=lambda path: hashes[path.resolve()],
                ),
                mock.patch.object(
                    yume_bench_common,
                    "command_version",
                    return_value="Google Chrome 151.0.7922.71",
                ),
            ):
                identity = yume_bench_common.validate_pinned_chrome(launcher)

            self.assertEqual(identity["launcher"], str(launcher.resolve()))
            self.assertEqual(identity["binary"], str(binary.resolve()))

    def test_chrome_version_probe_uses_privilege_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            chrome_dir = Path(tmp)
            launcher = chrome_dir / "google-chrome"
            binary = chrome_dir / "chrome"
            launcher.write_text("launcher", encoding="utf-8")
            binary.write_text("binary", encoding="utf-8")
            launcher.chmod(0o755)
            binary.chmod(0o755)
            hashes = {
                launcher.resolve(): yume_bench_common.PINNED_CHROME_LAUNCHER_SHA256,
                binary.resolve(): yume_bench_common.PINNED_CHROME_BINARY_SHA256,
            }
            prefix = ["setpriv", "--reuid=1000", "--regid=1000", "--clear-groups", "--"]
            with (
                mock.patch.object(
                    yume_bench_common,
                    "sha256_file",
                    side_effect=lambda path: hashes[path.resolve()],
                ),
                mock.patch.object(
                    yume_bench_common,
                    "command_version",
                    return_value="Google Chrome 151.0.7922.71",
                ) as version_probe,
            ):
                yume_bench_common.validate_pinned_chrome(launcher, prefix)
            version_probe.assert_called_once_with([
                *prefix,
                str(launcher.resolve()),
                "--version",
            ])

    def test_chrome_hash_mismatch_fails_before_version_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            launcher = Path(tmp) / "google-chrome"
            launcher.write_text("wrong", encoding="utf-8")
            launcher.chmod(0o755)
            with mock.patch.object(
                yume_bench_common, "command_version"
            ) as version_probe:
                with self.assertRaisesRegex(RuntimeError, "launcher SHA-256"):
                    yume_bench_common.validate_pinned_chrome(launcher)
            version_probe.assert_not_called()

    def test_user_namespace_probe_runs_in_supplied_context(self) -> None:
        completed = subprocess.CompletedProcess([], 0, "", "")
        with (
            mock.patch.object(yume_bench_common.shutil, "which", return_value="/usr/bin/unshare"),
            mock.patch.object(
                yume_bench_common.subprocess, "run", return_value=completed
            ) as run,
        ):
            yume_bench_common.require_user_namespace_sandbox(
                ["ip", "netns", "exec", "client-test", "setpriv", "--"]
            )
        argv = run.call_args.args[0]
        self.assertEqual(argv[-4:], ["/usr/bin/unshare", "--user", "--map-root-user", "true"])
        self.assertEqual(argv[:4], ["ip", "netns", "exec", "client-test"])

    def test_wan_browser_command_drops_privilege_and_keeps_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            output = workdir / "browser.log"
            identity = RuntimeIdentity(1000, 1000, workdir)
            result = StreamedCommandResult(0, "ok")
            with (
                mock.patch(
                    "yume_bench_wan.require_user_namespace_sandbox"
                ) as sandbox_probe,
                mock.patch(
                    "yume_bench_wan.run_streamed_command", return_value=result
                ),
            ):
                code, argv = run_browser_cover(
                    _FakeLab(),
                    Path("/exact/google-chrome"),
                    workdir,
                    output,
                    identity,
                )
        self.assertEqual(code, 0)
        self.assertIn("--reuid=1000", argv)
        self.assertIn("--disable-setuid-sandbox", argv)
        self.assertNotIn("--no-sandbox", argv)
        sandbox_probe.assert_called_once_with([
            "ip", "netns", "exec", "client-test",
            "setpriv", "--reuid=1000", "--regid=1000", "--clear-groups", "--",
        ])

    def test_carrier_browser_command_keeps_user_namespace_sandbox(self) -> None:
        argv = chromium_base_args("/exact/google-chrome", Path("/fresh"), 12000)
        self.assertIn("--disable-setuid-sandbox", argv)
        self.assertNotIn("--no-sandbox", argv)

    def test_lan_browser_command_drops_privilege_and_keeps_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            identity = RuntimeIdentity(1000, 1000, workdir)
            result = StreamedCommandResult(0, "ok")
            with (
                mock.patch("yume_bench_lan.os.geteuid", return_value=0),
                mock.patch(
                    "yume_bench_lan.require_user_namespace_sandbox"
                ) as sandbox_probe,
                mock.patch(
                    "yume_bench_lan.run_streamed_command", return_value=result
                ),
            ):
                _result, argv = run_lan_browser_cover(
                    Path("/exact/google-chrome"),
                    identity,
                    workdir / "home",
                    workdir / "runtime",
                    workdir / "profile",
                    "192.0.2.10",
                    443,
                    "cover.test",
                )
        expected_prefix = [
            "setpriv", "--reuid=1000", "--regid=1000", "--clear-groups", "--",
        ]
        self.assertEqual(argv[:5], expected_prefix)
        self.assertIn("--disable-setuid-sandbox", argv)
        self.assertNotIn("--no-sandbox", argv)
        sandbox_probe.assert_called_once_with(expected_prefix)

    def test_normal_chrome_capture_script_enforces_sandbox_contract(self) -> None:
        script = (
            Path(__file__).resolve().parents[1]
            / "tools/cover-node/capture_chrome151_runs.sh"
        ).read_text(encoding="utf-8")
        self.assertNotIn("--no-sandbox", script)
        self.assertIn("--disable-setuid-sandbox", script)
        self.assertIn("normal Chrome capture must run as an unprivileged user", script)
        self.assertIn("EXPECTED_CHROME_LAUNCHER_SHA256", script)

    def test_normal_capture_rejects_hash_before_executing_browser(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("the capture script intentionally rejects a root caller first")
        capture_script = (
            Path(__file__).resolve().parents[1]
            / "tools/cover-node/capture_chrome151_runs.sh"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "chrome install"
            install.mkdir()
            marker = root / "browser-executed"
            launcher = install / "google-chrome"
            binary = install / "chrome"
            node = root / "node"
            self._write_executable(
                launcher,
                "#!/bin/sh\ntouch \"$EXECUTION_MARKER\"\nexit 0\n",
            )
            self._write_executable(binary, "#!/bin/sh\nexit 0\n")
            self._write_executable(node, "#!/bin/sh\nexit 0\n")
            environment = dict(os.environ)
            environment.update({
                "DISPLAY": ":99",
                "EXECUTION_MARKER": str(marker),
                "YUME_CHROME_LAUNCHER": str(launcher),
                "YUME_CHROME_BINARY": str(binary),
            })
            result = subprocess.run(
                [str(capture_script), str(root / "output"), str(node), "1", "0"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=environment,
                timeout=10,
            )
            browser_executed = marker.exists()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Chrome launcher SHA-256 mismatch", result.stderr)
        self.assertFalse(browser_executed)

    def test_normal_capture_rejects_unsuccessful_chrome_exit(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("the capture script intentionally rejects a root caller first")
        capture_script = (
            Path(__file__).resolve().parents[1]
            / "tools/cover-node/capture_chrome151_runs.sh"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "chrome install"
            fake_bin = root / "fake-bin"
            install.mkdir()
            fake_bin.mkdir()
            launcher = install / "google-chrome"
            binary = install / "chrome"
            node = root / "node"
            sanitizer_marker = root / "sanitizer-ran"
            self._write_executable(
                launcher,
                """#!/bin/sh
if [ "${1-}" = "--version" ]; then
    echo 'Google Chrome 151.0.7922.71'
    exit 0
fi
exit 7
""",
            )
            self._write_executable(binary, "#!/bin/sh\nexit 0\n")
            self._write_executable(
                node,
                """#!/bin/sh
if [ "${1-}" = "--version" ]; then
    echo 'v24.18.0'
    exit 0
fi
case "${1-}" in
    *server.mjs) exec /bin/sleep 60 ;;
    *capture_chrome.mjs) exit 0 ;;
    *sanitize_netlog.mjs) touch "$SANITIZER_MARKER"; exit 0 ;;
esac
exit 1
""",
            )
            self._write_executable(
                fake_bin / "sha256sum",
                """#!/bin/bash
target=${!#}
case "$target" in
    */google-chrome) hash=aea09d69ce7f24d5901f6bfb15dd44d0c856e793e0a498f8d8393ec7d2c308ec ;;
    */chrome) hash=4cf210c4a0aeee3e69a73639260918a7448626d6b99892ec61e20750bc7c7079 ;;
    */node) hash=41a74efb34cbde5c7632cdac0cf8bd1a14d0b8d73dc1e82755014d9a9ce70f5c ;;
    *) exec /usr/bin/sha256sum "$@" ;;
esac
printf '%s  %s\n' "$hash" "$target"
""",
            )
            self._write_executable(fake_bin / "unshare", "#!/bin/sh\nexit 0\n")
            self._write_executable(fake_bin / "curl", "#!/bin/sh\nexit 0\n")
            self._write_executable(fake_bin / "ss", "#!/bin/sh\nexit 0\n")
            environment = dict(os.environ)
            environment.update({
                "DISPLAY": ":99",
                "PATH": f"{fake_bin}:/usr/bin:/bin",
                "SANITIZER_MARKER": str(sanitizer_marker),
                "YUME_CHROME_LAUNCHER": str(launcher),
                "YUME_CHROME_BINARY": str(binary),
            })
            result = subprocess.run(
                [str(capture_script), str(root / "output"), str(node), "1", "0"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=environment,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Chrome exited unsuccessfully", result.stderr)
            self.assertFalse(sanitizer_marker.exists())

    def test_carrier_refuses_root_browser_driver(self) -> None:
        with mock.patch("yume_carrier_diagnose.os.geteuid", return_value=0):
            with self.assertRaisesRegex(RuntimeError, "refusing to launch Chrome as root"):
                require_unprivileged_browser_driver()

    def test_any_browser_failure_is_fatal(self) -> None:
        data = {
            "target_browser": [{"returncode": 0}],
            "baseline_browser": [{"returncode": 124}],
        }
        self.assertEqual(len(browser_failures(data)), 1)
        self.assertEqual(diagnostic_exit_code(data), 1)
        self.assertEqual(
            diagnostic_exit_code({"target_browser": [{"returncode": 0}]}),
            0,
        )


if __name__ == "__main__":
    unittest.main()
