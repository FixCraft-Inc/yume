#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Check built native CLI output and rejection paths without opening a network.

Run with --yume /path/to/yume --yumed /path/to/yumed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))

import yume_cli  # noqa: E402

PROGRAMS: dict[str, Path] = {}


class NativeCli(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.expected_help = {}
        for layout in yume_cli.load_layouts():
            if layout.binary in PROGRAMS:
                ordered, _ = yume_cli.resolve(layout)
                cls.expected_help[layout.binary] = "\n".join(yume_cli.render_help(layout, ordered)) + "\n"

    def invoke(self, name: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(PROGRAMS[name]), *arguments], capture_output=True, text=True,
            timeout=5, check=False,
        )

    def assert_usage_failure(self, name: str, arguments: list[str], diagnostic: str) -> None:
        result = self.invoke(name, *arguments)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, f"{name}: {diagnostic}\n" + self.expected_help[name])

    def test_help_matches_the_canonical_manual(self) -> None:
        for name in PROGRAMS:
            for flag in ("--help", "-h"):
                with self.subTest(binary=name, flag=flag):
                    result = self.invoke(name, flag)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, "")
                    self.assertEqual(result.stdout, self.expected_help[name])

    def test_version_reports_the_native_composition(self) -> None:
        for name in PROGRAMS:
            with self.subTest(binary=name):
                result = self.invoke(name, "--version")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
                self.assertTrue(result.stdout.startswith(f"{name} "))
                self.assertIn("transport YTP/1, config schema 1, suite ytp1-tls13-h2\n", result.stdout)
                self.assertIn("session security ", result.stdout)
                self.assertIn(", crypto backend ", result.stdout)
                self.assertIn("evidence profile ", result.stdout)
                self.assertNotIn("unwired", result.stdout)

    def test_completion_prints_the_generated_script(self) -> None:
        for layout in yume_cli.load_layouts():
            if layout.binary not in PROGRAMS:
                continue
            _, completed = yume_cli.resolve(layout)
            expected = "\n".join(yume_cli.render_completion(layout, completed)) + "\n"
            with self.subTest(binary=layout.binary):
                result = self.invoke(layout.binary, "--completion", "bash")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
                self.assertEqual(result.stdout, expected)
                syntax = subprocess.run(["bash", "-n"], input=result.stdout, text=True,
                                        capture_output=True, timeout=5, check=False)
                self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_completion_completes_in_bash(self) -> None:
        # Bash loads the script and completes an option, then its value.
        script = self.invoke("yume", "--completion", "bash").stdout
        probe = (script + "\nCOMP_WORDS=(yume --comp)\nCOMP_CWORD=1\n_yume_complete\n"
                 "echo \"${COMPREPLY[*]}\"\nCOMP_WORDS=(yume --completion b)\n"
                 "COMP_CWORD=2\n_yume_complete\necho \"${COMPREPLY[*]}\"\n")
        result = subprocess.run(["bash", "--norc", "--noprofile"], input=probe, text=True,
                                capture_output=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "--completion\nbash\n")

    def test_completion_needs_bash(self) -> None:
        for name in PROGRAMS:
            for arguments in (["--completion"], ["--completion", "zsh"],
                              ["--completion", "bash", "--completion", "bash"]):
                with self.subTest(binary=name, arguments=arguments):
                    self.assert_usage_failure(name, arguments, "--completion needs bash")

    def test_status_is_an_action_on_its_own(self) -> None:
        self.assert_usage_failure("yumed", ["--config", "x.json", "--status", "--validate"],
                                  "--status takes only --config")
        for name in PROGRAMS:
            with self.subTest(binary=name):
                self.assert_usage_failure(name, ["--status"], "--config is required")
        for extra in (["--validate"], ["--connect", "192.0.2.7"],
                      ["--outer-carrier-evidence", "/tmp/evidence.json"]):
            with self.subTest(extra=extra):
                self.assert_usage_failure("yume", ["--config", "x.json", "--status", *extra],
                                          "--status takes only --config and --control-socket")
                self.assert_usage_failure(
                    "yume", ["--config", "x.json", "--accept-route", "ab", *extra],
                    "--accept-route takes only --config and --control-socket")

    def test_status_needs_a_control_socket_and_a_running_client(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yume-cli-") as temporary:
            path = Path(temporary) / "yume.json"
            config = json.loads((ROOT / "config/yume.json").read_text(encoding="utf-8"))
            path.write_text(json.dumps(config), encoding="utf-8")
            result = self.invoke("yume", "--config", str(path), "--status")
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stderr,
                             "yume: the configuration has no control socket (control.socket)\n")
            socket_path = Path(temporary) / "control.sock"
            config["control"] = {"socket": str(socket_path)}
            path.write_text(json.dumps(config), encoding="utf-8")
            result = self.invoke("yume", "--config", str(path), "--status")
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr,
                             f"yume: no yume is running on the control socket {socket_path}\n")
            # --control-socket finds a client whose configuration names none,
            # or another socket than the file names.
            other = Path(temporary) / "other.sock"
            for flags in (["--control-socket", str(other)],):
                result = self.invoke("yume", "--config", str(path), "--status", *flags)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stderr,
                                 f"yume: no yume is running on the control socket {other}\n")
            del config["control"]
            path.write_text(json.dumps(config), encoding="utf-8")
            result = self.invoke("yume", "--config", str(path), "--accept-route", "ab",
                                 "--control-socket", str(other))
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(result.stderr,
                             f"yume: no yume is running on the control socket {other}\n")

    def kit(self, root: Path, example: str = "config/yume.json") -> Path:
        kit = root / "kit"
        (kit / "credentials").mkdir(parents=True, mode=0o700)
        (kit / "yume.json").write_text((ROOT / example).read_text(encoding="utf-8"),
                                       encoding="utf-8")
        (kit / "credentials/client-access.psk").write_bytes(bytes(range(32)))
        start = kit / "start-client"
        start.write_text("#!/bin/sh\nexec yume --config yume.json\n", encoding="utf-8")
        start.chmod(0o700)
        return kit

    def import_kit(self, sealed: Path, into: Path, code: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(PROGRAMS["yume"]), "--import-kit", str(sealed), "--into",
                               str(into)], input=code, capture_output=True, text=True,
                              timeout=30, check=False)

    def test_a_sealed_kit_imports_with_its_code(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yume-kit-") as temporary:
            root = Path(temporary)
            kit = self.kit(root)
            sealed = root / "client.kit"
            result = self.invoke("yume", "--seal-kit", str(kit), "--output", str(sealed))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(result.stdout, r"^([0-9A-HJKMNP-TV-Z]{5}-){4}[0-9A-HJKMNP-TV-Z]{5}\n$")
            self.assertEqual(sealed.stat().st_mode & 0o777, 0o600)
            self.assertEqual((sealed.stat().st_size - 44) % 1024, 0)
            code = result.stdout.strip()
            result = self.import_kit(sealed, root / "wrong", code[:-1] + ("0" if code[-1] != "0" else "1"))
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("the code is wrong or the file is not a sealed kit", result.stderr)
            self.assertFalse((root / "wrong").exists())
            # Typed codes may be lower case and without separators.
            result = self.import_kit(sealed, root / "imported", code.lower().replace("-", "") + "\n")
            self.assertEqual(result.returncode, 0, result.stderr)
            imported = root / "imported"
            self.assertEqual(imported.stat().st_mode & 0o777, 0o700)
            for name in ("yume.json", "credentials/client-access.psk", "start-client"):
                self.assertEqual((imported / name).read_bytes(), (kit / name).read_bytes(), name)
            self.assertEqual((imported / "credentials/client-access.psk").stat().st_mode & 0o777, 0o600)
            self.assertEqual((imported / "start-client").stat().st_mode & 0o777, 0o700)
            result = self.import_kit(sealed, imported, code)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("the kit directory exists", result.stderr)
            result = self.import_kit(sealed, root / "empty", "")
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("no kit code on standard input", result.stderr)
            result = self.invoke("yume", "--seal-kit", str(kit), "--output", str(sealed))
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stderr, "yume: the output file exists\n")

    def test_only_a_client_kit_is_sealed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yume-kit-") as temporary:
            root = Path(temporary)
            kit = self.kit(root, "config/yumed.json")
            result = self.invoke("yume", "--seal-kit", str(kit), "--output", str(root / "k"))
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stderr, "yume: the kit's yume.json is a server configuration\n")
            self.assertFalse((root / "k").exists())

    def test_kit_actions_stand_alone(self) -> None:
        message = "use --seal-kit DIR --output FILE or --import-kit FILE --into DIR alone"
        for arguments in (["--seal-kit", "d"], ["--output", "f"], ["--import-kit", "f"],
                          ["--into", "d"], ["--seal-kit", "d", "--into", "e"],
                          ["--seal-kit", "d", "--output", "f", "--config", "c.json"],
                          ["--import-kit", "f", "--into", "d", "--status"],
                          ["--import-kit", "f", "--into", "d", "--control-socket", "/s"]):
            with self.subTest(arguments=arguments):
                self.assert_usage_failure("yume", arguments, message)
        self.assert_usage_failure("yume", ["--seal-kit"], "--seal-kit needs exactly one path")
        self.assert_usage_failure("yumed", ["--seal-kit", "d", "--output", "f"],
                                  "unknown argument: --seal-kit")

    def test_config_is_required_for_run_and_validation(self) -> None:
        for name in PROGRAMS:
            for arguments in ([], ["--validate"]):
                with self.subTest(binary=name, arguments=arguments):
                    self.assert_usage_failure(name, arguments, "--config is required")

    def test_config_requires_exactly_one_path(self) -> None:
        for name in PROGRAMS:
            for arguments in (["--config"], ["--config", "first", "--config", "second"]):
                with self.subTest(binary=name, arguments=arguments):
                    self.assert_usage_failure(name, arguments, "--config needs exactly one path")

    def test_reference_and_unimplemented_options_are_rejected(self) -> None:
        arguments = [
            ["--diagnostic-level", "debug"], ["setup"], ["doctor"],
            ["completion", "bash"], ["--credits"],
            ["--server", "localhost"], ["--listen", "443"], ["--socks", "1080"],
        ]
        for name in PROGRAMS:
            for values in arguments:
                with self.subTest(binary=name, arguments=values):
                    self.assert_usage_failure(name, values, f"unknown argument: {values[0]}")

    def test_only_the_client_takes_run_settings(self) -> None:
        for flag in ("--connect", "--socks-address", "--socks-port", "--control-socket"):
            with self.subTest(flag=flag):
                self.assert_usage_failure("yumed", [flag, "1"], f"unknown argument: {flag}")

    def test_run_settings_take_exactly_one_value(self) -> None:
        for flag, value in (("--connect", "IP address"), ("--socks-address", "IP address"),
                            ("--socks-port", "port"), ("--control-socket", "path")):
            for arguments in ([flag], ["--config", "client.json", flag, "1", flag, "2"]):
                with self.subTest(arguments=arguments):
                    self.assert_usage_failure("yume", arguments, f"{flag} needs exactly one {value}")

    def validate_example(self, *flags: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="yume-cli-") as temporary:
            path = Path(temporary) / "yume.json"
            path.write_text((ROOT / "config/yume.json").read_text(encoding="utf-8"), encoding="utf-8")
            return self.invoke("yume", "--config", str(path), "--validate", *flags)

    def test_a_run_setting_fails_at_its_key(self) -> None:
        cases = (
            (["--connect", "origin.example.com"], "/endpoint/connect_address", "IP literal"),
            (["--socks-address", "0.0.0.0"], "/adapters/0/listen_address", "127.0.0.1 or ::1"),
            (["--socks-port", "65536"], "/adapters/0/listen_port", ""),
            (["--control-socket", "relative.sock"], "/control/socket",
             "normalized absolute path"),
            (["--control-socket", "/run/" + "x" * 120], "/control/socket", ""),
        )
        for flags, pointer, detail in cases:
            with self.subTest(flags=flags):
                result = self.validate_example(*flags)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn(f'JSON pointer "{pointer}"', result.stderr)
                self.assertIn(f"{detail} (set on the command line)", result.stderr)

    def test_validation_reports_where_each_run_setting_came_from(self) -> None:
        # The example's credential files are absent, so validation fails after
        # the report, before any file is read as a credential.
        result = self.validate_example("--connect", "192.0.2.7", "--socks-port", "1081",
                                       "--control-socket", "/run/user/1000/yume/a.sock")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertTrue(result.stderr.startswith(
            "yume: /endpoint/connect_address 192.0.2.7 (from --connect)\n"
            "yume: /control/socket /run/user/1000/yume/a.sock (from --control-socket)\n"
            "yume: /adapters/0/listen_address 127.0.0.1 (from the configuration)\n"
            "yume: /adapters/0/listen_port 1081 (from --socks-port)\n"
            "yume: credentials are invalid: "), result.stderr)

    def test_metadata_flags_do_not_hide_unknown_arguments(self) -> None:
        for name in PROGRAMS:
            for flags in (["--help"], ["--version"], ["--completion", "bash"]):
                with self.subTest(binary=name, flags=flags):
                    self.assert_usage_failure(name, [*flags, "--unknown"],
                                              "unknown argument: --unknown")

    def test_metadata_does_not_read_the_configuration(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yume-cli-") as temporary:
            missing = str(Path(temporary) / "absent.json")
            for name in PROGRAMS:
                for flags in (["--help"], ["--version"], ["--completion", "bash"]):
                    with self.subTest(binary=name, flags=flags):
                        result = self.invoke(name, "--config", missing, *flags)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stderr, "")

    def test_validation_rejects_a_nonobject_configuration(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yume-cli-") as temporary:
            path = Path(temporary) / "invalid.json"
            path.write_text("[]\n", encoding="utf-8")
            for name in PROGRAMS:
                with self.subTest(binary=name):
                    result = self.invoke(name, "--config", str(path), "--validate")
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("configuration error at JSON pointer", result.stderr)
                    self.assertIn("must be an object", result.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yume", type=Path, required=True)
    parser.add_argument("--yumed", type=Path, required=True)
    args = parser.parse_args()
    for name in ("yume", "yumed"):
        path = getattr(args, name).resolve(strict=True)
        if not path.is_file():
            parser.error(f"{name} must name a regular executable file")
        PROGRAMS[name] = path
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeCli))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
