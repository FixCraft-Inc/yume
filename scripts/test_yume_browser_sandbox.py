#!/usr/bin/env python3
"""Focused fail-closed tests for benchmark Chrome launches."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import yume_bench_common  # noqa: E402
import yume_bench_exec_guard  # noqa: E402
import yume_bench_isolation  # noqa: E402
import yume_bench_provenance  # noqa: E402
import yume_bench_wan  # noqa: E402
from yume_bench_common import RuntimeIdentity, StreamedCommandResult  # noqa: E402
from yume_bench_provenance import git_source_snapshot  # noqa: E402
from yume_bench_lan import run_browser_cover as run_lan_browser_cover  # noqa: E402
from yume_bench_wan import (  # noqa: E402
    capability_drop_prefix,
    enforce_private_artifact_modes,
    freeze_executable,
    frozen_executable_version,
    isolated_reexec_argv,
    node_sandbox_command,
    remove_private_tree,
    root_mount_is_private,
    run_browser_cover,
    runtime_security_state,
    single_id_mapping,
    validate_stopped_capture,
)
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

    def test_wan_isolated_wrapper_is_bounded_and_kills_children(self) -> None:
        outer = {
            "user": "user:[1]",
            "mount": "mnt:[2]",
            "pid": "pid:[3]",
            "network": "net:[4]",
        }
        with (
            mock.patch(
                "yume_bench_isolation.shutil.which", return_value="/usr/bin/unshare"
            ),
            mock.patch("yume_bench_isolation.namespace_inodes", return_value=outer),
        ):
            argv = isolated_reexec_argv(
                Path("/repo/scripts/yume_bench_wan.py"),
                ["--isolated-userns", "--no-browser", "--profile", "broadband"],
            )
        self.assertEqual(argv[0], "/usr/bin/unshare")
        self.assertIn("--map-root-user", argv)
        self.assertIn("--propagation", argv)
        self.assertIn("private", argv)
        self.assertIn("--pid", argv)
        self.assertIn("--kill-child=SIGKILL", argv)
        self.assertIn("--mount-proc", argv)
        self.assertIn("--net", argv)
        self.assertIn("--isolated-controller", argv)
        for name, value in outer.items():
            flag = "--outer-netns" if name == "network" else f"--outer-{name}ns"
            self.assertEqual(argv[argv.index(flag) + 1], value)

    def test_wan_isolated_workloads_drop_all_namespace_capabilities(self) -> None:
        prefix = capability_drop_prefix(True)
        self.assertEqual(prefix[0], "setpriv")
        self.assertIn("--bounding-set=-all", prefix)
        self.assertIn("--inh-caps=-all", prefix)
        self.assertIn("--ambient-caps=-all", prefix)
        self.assertIn("--nnp", prefix)
        self.assertEqual(capability_drop_prefix(False), [])

    def test_wan_isolated_controller_requires_exact_single_id_maps(self) -> None:
        self.assertEqual(single_id_mapping("0 1000 1\n"), (0, 1000))
        self.assertIsNone(single_id_mapping("0 0 4294967295\n"))
        self.assertIsNone(single_id_mapping("0 1000 2\n"))
        self.assertIsNone(single_id_mapping("0 1000 1\n1 1001 1\n"))
        self.assertIsNone(single_id_mapping("malformed\n"))

    def test_wan_direct_host_root_controller_fails_before_mount(self) -> None:
        reads = {
            "/proc/self/uid_map": "0 0 4294967295\n",
            "/proc/self/gid_map": "0 0 4294967295\n",
        }

        def read_text(path: Path, *args: object, **kwargs: object) -> str:
            del args, kwargs
            return reads[str(path)]

        with (
            mock.patch("yume_bench_isolation.os.geteuid", return_value=0),
            mock.patch.object(yume_bench_isolation.Path, "read_text", read_text),
            mock.patch("yume_bench_isolation.subprocess.run") as run,
        ):
            with self.assertRaisesRegex(RuntimeError, "exact one-ID"):
                yume_bench_wan.enter_isolated_controller({
                    "user": "user:[1]",
                    "mount": "mnt:[2]",
                    "pid": "pid:[3]",
                    "network": "net:[4]",
                })
        run.assert_not_called()

    def test_wan_controller_accepts_distinct_uid_gid_maps_after_structural_checks(self) -> None:
        reads = {
            "/proc/self/uid_map": "0 1000 1\n",
            "/proc/self/gid_map": "0 2000 1\n",
            "/proc/self/mountinfo": "10 9 0:1 / / rw - tmpfs tmpfs rw\n",
        }

        def read_text(path: Path, *args: object, **kwargs: object) -> str:
            del args, kwargs
            return reads[str(path)]

        current = {
            "user": "user:[11]",
            "mount": "mnt:[12]",
            "pid": "pid:[13]",
            "network": "net:[14]",
        }
        outer = {
            "user": "user:[1]",
            "mount": "mnt:[2]",
            "pid": "pid:[3]",
            "network": "net:[4]",
        }
        with (
            mock.patch("yume_bench_isolation.os.geteuid", return_value=0),
            mock.patch("yume_bench_isolation.os.getpid", return_value=1),
            mock.patch.object(yume_bench_isolation.Path, "read_text", read_text),
            mock.patch("yume_bench_isolation.namespace_inodes", return_value=current),
            mock.patch(
                "yume_bench_isolation.fresh_network_namespace_state",
                return_value={
                    "initial_interfaces": ["lo"],
                    "initial_routes": 0,
                    "initial_non_loopback_addresses": 0,
                },
            ),
            mock.patch("yume_bench_isolation.subprocess.run") as run,
            mock.patch.object(yume_bench_isolation.Path, "mkdir"),
        ):
            checks = yume_bench_wan.enter_isolated_controller(outer)
        self.assertEqual(checks["single_id_uid_map"], 1000)
        self.assertEqual(checks["single_id_gid_map"], 2000)
        self.assertEqual(run.call_count, 3)

    def test_wan_root_mount_must_not_be_shared_or_slave(self) -> None:
        self.assertTrue(root_mount_is_private(
            "10 9 0:1 / / rw,nosuid - tmpfs tmpfs rw\n"
        ))
        self.assertFalse(root_mount_is_private(
            "10 9 0:1 / / rw shared:1 - tmpfs tmpfs rw\n"
        ))
        self.assertFalse(root_mount_is_private(
            "10 9 0:1 / / rw master:2 - tmpfs tmpfs rw\n"
        ))

    def test_wan_controller_requires_pid_1_before_mounts_or_network_queries(self) -> None:
        reads = {
            "/proc/self/uid_map": "0 1000 1\n",
            "/proc/self/gid_map": "0 1000 1\n",
        }

        def read_text(path: Path, *args: object, **kwargs: object) -> str:
            del args, kwargs
            return reads[str(path)]

        with (
            mock.patch("yume_bench_isolation.os.geteuid", return_value=0),
            mock.patch("yume_bench_isolation.os.getpid", return_value=99),
            mock.patch.object(yume_bench_isolation.Path, "read_text", read_text),
            mock.patch("yume_bench_isolation.subprocess.run") as run,
        ):
            with self.assertRaisesRegex(RuntimeError, "must be PID 1"):
                yume_bench_wan.enter_isolated_controller({
                    "user": "user:[1]",
                    "mount": "mnt:[2]",
                    "pid": "pid:[3]",
                    "network": "net:[4]",
                })
        run.assert_not_called()

    def test_wan_fresh_network_namespace_rejects_preexisting_routes(self) -> None:
        links = SimpleNamespace(
            stdout='[{"ifname":"lo","addr_info":[]}]'
        )
        routes = SimpleNamespace(stdout='[{"dst":"default"}]')
        with mock.patch(
            "yume_bench_isolation.subprocess.run", side_effect=[links, routes]
        ):
            with self.assertRaisesRegex(RuntimeError, "prior network state"):
                yume_bench_isolation.fresh_network_namespace_state()

    def test_wan_artifacts_are_forced_private(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "evidence"
            nested = root / "nested"
            nested.mkdir(parents=True, mode=0o755)
            artifact = nested / "endpoint.pcap"
            artifact.write_bytes(b"private")
            artifact.chmod(0o644)
            enforce_private_artifact_modes(root)
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(nested.stat().st_mode & 0o777, 0o700)
            self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)

    def test_wan_private_text_applies_mode_and_owner_before_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "report.json"
            owner = os.getuid(), os.getgid()
            yume_bench_isolation.write_private_text(
                artifact, "{}\n", owner=owner
            )
            metadata = artifact.stat()
            self.assertEqual(metadata.st_mode & 0o777, 0o600)
            self.assertEqual((metadata.st_uid, metadata.st_gid), owner)

    def test_wan_output_owner_rejects_incomplete_sudo_identity(self) -> None:
        with mock.patch.dict(
            os.environ, {"SUDO_UID": "1000"}, clear=True
        ):
            with self.assertRaisesRegex(RuntimeError, "incomplete"):
                yume_bench_isolation.output_owner()

    def test_wan_runtime_sources_include_pinned_identity_manifest(self) -> None:
        self.assertIn(
            Path("tests/fixtures/chrome151-node24/manifest.json"),
            yume_bench_wan.RUNTIME_SOURCE_INPUTS,
        )

    def test_wan_artifact_mode_enforcement_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "evidence"
            root.mkdir()
            target = Path(tmp) / "outside"
            target.write_text("outside", encoding="utf-8")
            target.chmod(0o644)
            (root / "escape").symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, "refusing symlink"):
                enforce_private_artifact_modes(root)
            self.assertEqual(target.stat().st_mode & 0o777, 0o644)

    def test_wan_private_tree_cleanup_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            private = Path(tmp) / "private"
            private.mkdir()
            (private / "secret").write_text("secret", encoding="utf-8")
            remove_private_tree(private)
            self.assertFalse(private.exists())

    def test_wan_source_provenance_binds_commit_dirty_state_and_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repository = Path(tmp) / "repo"
            repository.mkdir()
            runtime_input = repository / "runtime.py"
            runtime_input.write_text("print('clean')\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "add", "runtime.py"], check=True
            )
            subprocess.run(
                [
                    "git", "-C", str(repository),
                    "-c", "user.name=YUME Test",
                    "-c", "user.email=yume-test.invalid@example.invalid",
                    "-c", "commit.gpgsign=false",
                    "commit", "-q", "-m", "fixture",
                ],
                check=True,
            )
            clean = git_source_snapshot(repository, (Path("runtime.py"),))
            self.assertFalse(clean["dirty"])
            self.assertEqual(clean["status"], [])
            self.assertEqual(len(clean["commit"]), 40)
            self.assertEqual(len(clean["tree"]), 40)
            clean_hash = clean["runtime_input_sha256"]["runtime.py"]

            runtime_input.write_text("print('dirty')\n", encoding="utf-8")
            dirty = git_source_snapshot(repository, (Path("runtime.py"),))
            self.assertTrue(dirty["dirty"])
            self.assertIn(" M runtime.py", dirty["status"])
            self.assertNotEqual(
                clean_hash, dirty["runtime_input_sha256"]["runtime.py"]
            )
            real_sha256 = yume_bench_provenance.sha256_file
            calls = 0

            def mutate_after_hash(path: Path) -> str:
                nonlocal calls
                result = real_sha256(path)
                calls += 1
                if calls == 1:
                    runtime_input.write_text("print('changed again')\n", encoding="utf-8")
                return result

            with mock.patch(
                "yume_bench_provenance.sha256_file",
                side_effect=mutate_after_hash,
            ):
                with self.assertRaisesRegex(RuntimeError, "changed while recording"):
                    git_source_snapshot(repository, (Path("runtime.py"),))

    def test_wan_source_provenance_rejects_parent_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repository = Path(tmp) / "repo"
            repository.mkdir()
            with self.assertRaisesRegex(RuntimeError, "repository-relative"):
                git_source_snapshot(repository, (Path("../outside"),))
            outside = Path(tmp) / "outside"
            outside.write_text("outside", encoding="utf-8")
            (repository / "escape").symlink_to(outside)
            with self.assertRaisesRegex(RuntimeError, "escapes repository"):
                git_source_snapshot(repository, (Path("escape"),))

    def test_wan_capture_requires_packets_and_zero_drops(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "endpoint.pcap"
            pcap.write_bytes(b"pcap" * 16)
            log = root / "tcpdump.log"
            log.write_text(
                "12 packets captured\n24 packets received by filter\n"
                "0 packets dropped by kernel\n",
                encoding="utf-8",
            )
            capture = SimpleNamespace(
                process=SimpleNamespace(returncode=0),
                log_path=log,
            )
            summary = validate_stopped_capture(capture, pcap)
            self.assertEqual(summary["packets_captured"], 12)
            log.write_text(
                "12 packets captured\n24 packets received by filter\n"
                "1 packet dropped by kernel\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "zero drops"):
                validate_stopped_capture(capture, pcap)

    def test_wan_capture_accepts_singular_tcpdump_grammar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "endpoint.pcap"
            pcap.write_bytes(b"pcap" * 16)
            log = root / "tcpdump.log"
            log.write_text(
                "1 packet captured\n1 packet received by filter\n"
                "0 packets dropped by kernel\n",
                encoding="utf-8",
            )
            capture = SimpleNamespace(
                process=SimpleNamespace(returncode=0),
                log_path=log,
            )
            summary = validate_stopped_capture(capture, pcap)
            self.assertEqual(summary["packets_captured"], 1)

    def test_wan_runtime_security_record_is_fail_closed(self) -> None:
        state = {
            "CapInh": "0000000000000000",
            "CapPrm": "0000000000000000",
            "CapEff": "0000000000000000",
            "CapBnd": "0000000000000000",
            "CapAmb": "0000000000000000",
            "NoNewPrivs": "1",
        }
        record = "YUME_BENCH_SECURITY_STATE=" + yume_bench_wan.json.dumps(state)
        self.assertEqual(runtime_security_state(record), state)
        state["CapEff"] = "0000000000000001"
        bad_record = "YUME_BENCH_SECURITY_STATE=" + yume_bench_wan.json.dumps(state)
        with self.assertRaisesRegex(RuntimeError, "not fail-closed"):
            runtime_security_state(bad_record)

    def test_wan_node_sandbox_hides_secret_and_artifact_trees(self) -> None:
        node = yume_bench_wan.FrozenExecutable(
            Path("/proc/self/fd/42"), "0" * 64, 42
        )
        argv = node_sandbox_command(node)
        self.assertIn("--die-with-parent", argv)
        self.assertIn("--unshare-user", argv)
        self.assertIn("--cap-drop", argv)
        self.assertNotIn("/home", argv)
        self.assertNotIn("/private/keys", argv)
        self.assertNotIn("/private/evidence", argv)
        self.assertIn("/opt/yume/exec_guard.py", argv)
        self.assertIn("/opt/yume/node", argv)
        self.assertEqual(argv[argv.index("--file") + 1], "42")
        self.assertNotIn("--ro-bind / /", " ".join(argv))
        self.assertNotIn("--share-net", argv)

    def test_wan_frozen_node_is_sealed_before_version_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            node = Path(tmp) / "node"
            self._write_executable(node, "#!/bin/sh\necho v24.18.0\n")
            frozen = freeze_executable(node)
            try:
                node.write_text("#!/bin/sh\necho changed\n", encoding="utf-8")
                self.assertEqual(
                    frozen_executable_version(frozen, allow_mismatch=False),
                    "v24.18.0",
                )
                with self.assertRaises(OSError):
                    os.write(frozen.descriptor, b"mutation")
            finally:
                frozen.close()

    def test_wan_exec_guard_validates_kernel_security_fields(self) -> None:
        status = "\n".join([
            "CapInh:\t0000000000000000",
            "CapPrm:\t0000000000000000",
            "CapEff:\t0000000000000000",
            "CapBnd:\t0000000000000000",
            "CapAmb:\t0000000000000000",
            "NoNewPrivs:\t1",
        ])
        state = yume_bench_exec_guard.security_state(status)
        yume_bench_exec_guard.validate_security_state(state)
        state["NoNewPrivs"] = "0"
        with self.assertRaisesRegex(RuntimeError, "no-new-privs"):
            yume_bench_exec_guard.validate_security_state(state)

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
            '[[ -e $git_ancestor/.git || -L $git_ancestor/.git ]]', script
        )
        self.assertIn('mkdir -m 0700 -- "$output_dir"', script)
        for identity in (
            "EXPECTED_CHROME_LAUNCHER_SHA256",
            "EXPECTED_CHROME_BINARY_SHA256",
            "EXPECTED_NODE_BINARY_SHA256",
            "EXPECTED_HELPER_SHA256",
        ):
            self.assertIn(identity, script)
        self.assertIn(
            '$(dirname -- "$yume_bin")/yume-chrome-tls-helper', script
        )
        self.assertIn('--tls-helper "$helper_bin"', script)
        self.assertIn("yume_capture_binary_provenance.py", script)
        self.assertIn('--bundle "$release_bundle"', script)
        self.assertIn('openssl x509 -in "$certificate" -outform DER', script)
        self.assertIn('--tls-pin "$tls_leaf_sha256"', script)
        self.assertIn('--tls-leaf-sha256 "$tls_leaf_sha256"', script)
        self.assertIn('for run_index in $(seq 1 "$run_count")', script)
        self.assertIn('sha256sum -- behavior.json tls-wire.json', script)
        self.assertIn("scripts/yume_capture_finalize.py", script)
        self.assertIn("trap cleanup_relay EXIT", script)
        self.assertIn("trap 'exit 130' INT TERM", script)
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
                helper = yume_dir / "yume-chrome-tls-helper"
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
                self._write_executable(helper, "#!/bin/sh\nexit 0\n")
                # This case exercises the Chrome/Node hash gates, not host
                # package discovery. GitHub's minimal runner does not
                # necessarily provide ss or rg, so keep those later-stage
                # prerequisites hermetic and inert.
                for executable in ("ss", "rg"):
                    self._write_executable(
                        fake_bin / executable, "#!/bin/sh\nexit 0\n"
                    )
                for name in ("bundle.tar.xz", "client.json", "server.crt"):
                    (root / name).write_text("not executed\n", encoding="utf-8")

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
                        str(root / "bundle.tar.xz"), str(root / "client.json"),
                        str(root / "server.crt"), "cover.test", "127.0.0.1:443",
                        str(launcher), str(binary), str(node), "1",
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
            self._write_executable(
                fake_bin / "ss",
                "#!/bin/sh\ncase \" $* \" in *\"sport = :\"*) echo LISTEN ;; esac\n",
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
