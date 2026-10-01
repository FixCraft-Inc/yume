#!/usr/bin/env python3
"""Fail-closed tests for the pinned Chrome launch and the capture scripts."""

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

    def test_normal_chrome_capture_script_enforces_sandbox_contract(self) -> None:
        script = (
            Path(__file__).resolve().parents[1]
            / "tools/cover-node/capture_chrome151_runs.sh"
        ).read_text(encoding="utf-8")
        self.assertNotIn("--no-sandbox", script)
        self.assertIn("--disable-setuid-sandbox", script)
        self.assertIn("normal Chrome capture must run as an unprivileged user", script)
        self.assertIn("EXPECTED_CHROME_LAUNCHER_SHA256", script)
        self.assertIn('realpath -e -- "$(dirname -- "$output_dir_input")"', script)
        self.assertIn('readonly output_dir="$output_parent/$output_leaf"', script)
        self.assertIn("YUME_CAPTURE_TLS_CERT", script)
        self.assertIn("scripts/yume_capture_manifest.py", script)
        self.assertIn("capture source checkout changed during capture", script)
        self.assertIn("capture output must be outside every Git worktree", script)
        self.assertIn(
            '[[ -e $git_ancestor/.git || -L $git_ancestor/.git ]]', script
        )

    def test_chrome_capture_waits_for_navigated_fixture_document(self) -> None:
        driver = (
            Path(__file__).resolve().parents[1]
            / "tools/cover-node/capture_chrome.mjs"
        ).read_text(encoding="utf-8")
        navigation = "const navigation = await command('Page.navigate'"
        lifecycle = "await waitForLifecycleEvent({"
        readiness = "await waitForTargetDocument({ command, targetUrl, deadline, sleep });"
        fixture = "WebSocket fixture timeout"
        self.assertIn("export async function navigateToFixture", driver)
        self.assertIn("Page.setLifecycleEventsEnabled", driver)
        self.assertIn("event.loaderId === loaderId", driver)
        self.assertIn("diagnostic.state?.href === targetUrl", driver)
        self.assertIn("diagnostic.state?.fixtureReady === 'true'", driver)
        self.assertIn("if (navigation.errorText)", driver)
        self.assertIn("AbortSignal.timeout(timeoutMs)", driver)
        self.assertIn("DevTools HTTP request timed out", driver)
        self.assertIn(navigation, driver)
        self.assertIn(lifecycle, driver)
        self.assertIn(readiness, driver)
        self.assertIn(fixture, driver)
        self.assertLess(driver.index(navigation), driver.index(lifecycle))
        self.assertLess(driver.index(lifecycle), driver.index(readiness))
        self.assertLess(driver.index(readiness), driver.index(fixture))
        navigation_test = (
            Path(__file__).resolve().parents[1]
            / "tools/cover-node/test_capture_chrome_navigation.mjs"
        ).read_text(encoding="utf-8")
        self.assertIn("waits for the matching loader", navigation_test)
        self.assertIn("rejects a Page.navigate error", navigation_test)
        self.assertIn("times out without a matching frame", navigation_test)
        self.assertIn("bounds a stalled DevTools HTTP request", navigation_test)

    def test_normal_capture_passively_waits_for_node_before_relay(self) -> None:
        script = (
            Path(__file__).resolve().parents[1]
            / "tools/cover-node/capture_chrome151_runs.sh"
        ).read_text(encoding="utf-8")
        listener_wait = 'wait_for_loopback_listener "$node_port" "$node_pid"'
        relay = 'python3 "$runtime_root/scripts/yume_tls_wire.py" relay'
        self.assertIn("wait_for_loopback_listener()", script)
        self.assertIn('ss -H -ltn "src 127.0.0.1 and sport = :$port"', script)
        self.assertIn(listener_wait, script)
        self.assertIn(relay, script)
        self.assertLess(script.index(listener_wait), script.index(relay))

    def test_yume_capture_runner_enforces_provenance_and_cleanup_contract(self) -> None:
        script = (
            Path(__file__).resolve().parents[1]
            / "tools/cover-node/capture_yume151_runs.sh"
        ).read_text(encoding="utf-8")
        self.assertNotIn("--no-sandbox", script)
        self.assertIn("must run as an unprivileged user", script)
        self.assertIn("--user --map-root-user true", script)
        self.assertIn("capture source checkout is not clean", script)
        self.assertIn("capture output must be outside the source checkout", script)
        self.assertIn("capture output must be outside every Git worktree", script)
        self.assertIn(
            'for non_symlink_input in "$yume_input" "$yumed_input" "$release_bundle_input"',
            script,
        )
        self.assertIn("capture input must not be a symlink", script)
        self.assertIn(
            '[[ -e $git_ancestor/.git || -L $git_ancestor/.git ]]', script
        )
        self.assertIn('mkdir -m 0700 -- "$output_dir"', script)
        for identity in (
            "EXPECTED_CHROME_LAUNCHER_SHA256",
            "EXPECTED_CHROME_BINARY_SHA256",
            "EXPECTED_NODE_BINARY_SHA256",
        ):
            self.assertIn(identity, script)
        self.assertNotIn("EXPECTED_HELPER_SHA256", script)
        self.assertNotIn("yume-chrome-tls-helper", script)
        self.assertNotIn("--tls-helper", script)
        self.assertIn("--tls-backend openssl-chrome151", script)
        self.assertIn("yume_capture_binary_provenance.py", script)
        self.assertIn('--bundle "$release_bundle"', script)
        self.assertIn('--yume "$yume_bin" --yumed "$yumed_bin"', script)
        self.assertIn('--client-config-sha256 "$client_config_sha256"', script)
        self.assertIn('--server-config-sha256 "$server_config_sha256"', script)
        self.assertIn('openssl x509 -in "$certificate" -outform DER', script)
        self.assertIn('--tls-leaf-sha256 "$tls_leaf_sha256"', script)
        # Every pinned runtime and every input is hashed again after the runs.
        for runtime in ("chrome_launcher", "chrome_binary", "node_bin", "yume_bin",
                        "yumed_bin", "release_bundle", "client_config",
                        "server_config", "certificate"):
            self.assertIn(f'sha256sum -- "${runtime}"', script)
            self.assertRegex(script, rf'"\${runtime}:\${runtime.removesuffix("_bin")}')
        self.assertIn('for run_index in $(seq 1 "$run_count")', script)
        self.assertIn('sha256sum -- behavior.json tls-wire.json workload.json', script)
        self.assertIn("scripts/yume_capture_finalize.py", script)
        self.assertIn("trap cleanup_children EXIT", script)
        self.assertIn("trap 'exit 130' INT TERM", script)
        self.assertIn('ulimit -f "$LOG_BLOCKS"', script)
        self.assertIn("readonly LOG_BLOCKS=16384", script)
        self.assertIn('"${RUN_TIMEOUT_SECONDS}s"', script)
        self.assertNotRegex(script, r"install[^\n]*\$client_config")
        self.assertNotRegex(script, r"install[^\n]*(secret|private.key)")

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

    def test_yume_capture_rejects_hashes_before_executing_browser_or_node(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("the capture script intentionally rejects a root caller first")
        capture_script = (
            Path(__file__).resolve().parents[1]
            / "tools/cover-node/capture_yume151_runs.sh"
        )
        for forged_chrome_hashes in (False, True):
            with self.subTest(
                forged_chrome_hashes=forged_chrome_hashes
            ), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                install = root / "chrome install"
                yume_dir = root / "yume-bin"
                fake_bin = root / "fake-bin"
                install.mkdir()
                yume_dir.mkdir()
                fake_bin.mkdir()
                chrome_marker = root / "chrome-executed"
                node_marker = root / "node-executed"
                launcher = install / "google-chrome"
                binary = install / "chrome"
                node = root / "node"
                yume = yume_dir / "yume"
                yumed = yume_dir / "yumed"
                kit = root / "kit"
                self._write_executable(
                    launcher,
                    '#!/bin/sh\ntouch "$CHROME_MARKER"\nexit 0\n',
                )
                self._write_executable(binary, "#!/bin/sh\nexit 0\n")
                self._write_executable(
                    node,
                    '#!/bin/sh\ntouch "$NODE_MARKER"\nexit 0\n',
                )
                self._write_executable(yume, "#!/bin/sh\nexit 0\n")
                self._write_executable(yumed, "#!/bin/sh\nexit 0\n")
                for name in ("client/yume.json", "server/yumed.json",
                             "server/credentials/server-tls.pem"):
                    (kit / name).parent.mkdir(parents=True, exist_ok=True)
                    (kit / name).write_text("not executed\n", encoding="utf-8")
                # This case exercises the Chrome/Node hash gates, not host
                # package discovery. GitHub's minimal runner does not
                # necessarily provide ss or rg, so keep those later-stage
                # prerequisites hermetic and inert.
                for executable in ("ss", "rg"):
                    self._write_executable(
                        fake_bin / executable, "#!/bin/sh\nexit 0\n"
                    )
                (root / "bundle.tar.xz").write_text("not executed\n", encoding="utf-8")

                environment = dict(os.environ)
                environment.update({
                    "CHROME_MARKER": str(chrome_marker),
                    "NODE_MARKER": str(node_marker),
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                })
                expected_error = "Chrome launcher SHA-256 mismatch"
                if forged_chrome_hashes:
                    self._write_executable(
                        fake_bin / "sha256sum",
                        """#!/bin/sh
for target do :; done
case "$target" in
    */google-chrome) hash=aea09d69ce7f24d5901f6bfb15dd44d0c856e793e0a498f8d8393ec7d2c308ec ;;
    */chrome) hash=4cf210c4a0aeee3e69a73639260918a7448626d6b99892ec61e20750bc7c7079 ;;
    */node) hash=0000000000000000000000000000000000000000000000000000000000000000 ;;
    *) exec /usr/bin/sha256sum "$@" ;;
esac
printf '%s  %s\n' "$hash" "$target"
""",
                    )
                    expected_error = "Node binary SHA-256 mismatch"

                result = subprocess.run(
                    [
                        str(capture_script), str(root / "output"), str(yume),
                        str(yumed), str(root / "bundle.tar.xz"), str(kit),
                        "cover.lan", str(launcher), str(binary), str(node), "1",
                    ],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=environment,
                    timeout=10,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected_error, result.stderr)
                self.assertFalse(chrome_marker.exists())
                self.assertFalse(node_marker.exists())

    _ISOLATED_IP_STUB = """#!/bin/sh
case "$*" in
    *"route show default"*) exit 0 ;;
    *"link show"*) printf '1: lo: <LOOPBACK,UP> mtu 65536\\n' ;;
esac
exit 0
"""

    _CONNECTED_IP_STUB = """#!/bin/sh
case "$*" in
    *"route show default"*) printf 'default via 192.168.1.1 dev eth0\\n' ;;
    *"link show"*)
        printf '1: lo: <LOOPBACK,UP> mtu 65536\\n'
        printf '2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\\n'
        ;;
esac
exit 0
"""

    def _run_normal_capture(self, ip_stub: str) -> tuple[subprocess.CompletedProcess, bool]:
        """Drives the normal-Chrome capture runner far enough to reach the run
        loop, with every external command supplied by the fixture. `ip_stub`
        decides what the runner sees when it checks for network isolation."""
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
            # The real `ip` is not on this fixture's bounded PATH.
            self._write_executable(fake_bin / "ip", ip_stub)
            self._write_executable(
                fake_bin / "ss",
                "#!/bin/sh\ncase \" $* \" in *\"sport = :\"*) echo LISTEN ;; esac\n",
            )
            self._write_executable(
                fake_bin / "rg",
                "#!/bin/sh\nexec /usr/bin/grep \"$@\"\n",
            )
            self._write_executable(
                fake_bin / "openssl",
                """#!/bin/sh
[ "${1-}" = "req" ] || exit 64
shift
keyout=
certout=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -keyout)
            shift
            [ "$#" -gt 0 ] || exit 64
            keyout=$1
            ;;
        -out)
            shift
            [ "$#" -gt 0 ] || exit 64
            certout=$1
            ;;
    esac
    shift
done
[ -n "$keyout" ] && [ -n "$certout" ] || exit 64
printf 'test private key\n' >"$keyout"
printf 'test certificate\n' >"$certout"
""",
            )
            self._write_executable(
                fake_bin / "git",
                """#!/bin/sh
case " $* " in
    *" diff "*) exit 0 ;;
    *" ls-files "*) exit 0 ;;
    *"HEAD^{commit}"*) printf '%040d\n' 0 ;;
    *"HEAD^{tree}"*) printf '%040d\n' 1 ;;
    *) exit 1 ;;
esac
""",
            )
            self._write_executable(
                fake_bin / "python3",
                """#!/bin/sh
while [ "$#" -gt 0 ]; do
    if [ "$1" = "--output" ]; then
        printf '{}\n' >"$2"
        exit 0
    fi
    shift
done
exit 1
""",
            )
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
            return result, sanitizer_marker.exists()

    def test_normal_capture_rejects_unsuccessful_chrome_exit(self) -> None:
        result, sanitizer_ran = self._run_normal_capture(self._ISOLATED_IP_STUB)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Chrome exited unsuccessfully", result.stderr)
        self.assertFalse(sanitizer_ran)

    def test_normal_capture_requires_isolated_network(self) -> None:
        """A capture with egress stalls on Chrome's own startup service calls
        and records Chrome-to-Google connections the fixture never produced, so
        the runner refuses rather than emit a contaminated capture."""
        result, sanitizer_ran = self._run_normal_capture(self._CONNECTED_IP_STUB)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("loopback-only network namespace", result.stderr)
        self.assertNotIn("Chrome exited unsuccessfully", result.stderr)
        self.assertFalse(sanitizer_ran)

if __name__ == "__main__":
    unittest.main()
