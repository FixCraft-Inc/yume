#!/usr/bin/env python3

import json
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "yume_setup.py"


class YumeSetupTests(unittest.TestCase):
    def run_tool(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(TOOL), *args], cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

    def test_init_generates_strict_secrets_and_complete_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kit = Path(tmp) / "kit"
            result = self.run_tool(
                "init", "--output", str(kit), "--host", "192.0.2.10",
                "--tls-name", "test-server", "--client-name", "phone",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("admission.hex", "inner-psk.hex"):
                secret = kit / "server" / name
                self.assertRegex(secret.read_text(), r"^[0-9a-f]{64}$")
                self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o600)
            config = json.loads((kit / "clients" / "phone" / "yume.json").read_text())
            self.assertEqual(config["obfs_secret_file"], "admission.hex")
            self.assertEqual(config["inner_psk_file"], "inner-psk.hex")
            self.assertEqual(config["tunnels"], 1)
            self.assertTrue(config["require_anonym"])
            self.assertEqual(
                (kit / "clients" / "phone" / "identity.pub").read_text().count(
                    "-----BEGIN PUBLIC KEY-----"),
                2,
            )
            self.assertTrue((kit / "server" / "start-yumed").stat().st_mode & stat.S_IXUSR)
            for launcher in ("start-socks", "export-yss"):
                path = kit / "clients" / "phone" / launcher
                self.assertTrue(path.stat().st_mode & stat.S_IXUSR)
                self.assertIn("$HOME/yume/build/bin/yume", path.read_text())
            self.assertIn(
                "$HOME/yume/build/bin/yumed",
                (kit / "server" / "start-yumed").read_text(),
            )
            for launcher in ("packet-up", "packet-down"):
                self.assertIn(
                    "$HOME/yume/tools/yume_packet_quick.py",
                    (kit / "server" / launcher).read_text(),
                )

    def test_bulk_and_admin_keys_use_separate_safe_stores(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kit = Path(tmp) / "kit"
            init = self.run_tool("init", "--output", str(kit),
                                 "--host", "192.0.2.10", "--tls-name", "test-server")
            self.assertEqual(init.returncode, 0, init.stderr)
            bulk = self.run_tool("issue-key", "--kit", str(kit), "--name", "shared",
                                 "--type", "bulk", "--max-sessions", "17")
            admin = self.run_tool("issue-key", "--kit", str(kit), "--name", "controller",
                                  "--type", "admin")
            self.assertEqual(bulk.returncode, 0, bulk.stderr)
            self.assertEqual(admin.returncode, 0, admin.stderr)
            regular = json.loads((kit / "server" / "authorized_keys.json").read_text())
            operator = json.loads((kit / "server" / "operator_keys.json").read_text())
            bulk_policy = next(value for value in regular.values() if value["alias"] == "shared")
            admin_policy = next(value for value in operator.values() if value["alias"] == "controller")
            self.assertEqual(bulk_policy["key_type"], "bulk")
            self.assertEqual(bulk_policy["max_sessions"], 17)
            self.assertFalse(bulk_policy["permissions"]["allow_bytes"])
            self.assertNotIn("permissions", admin_policy)
            admin_config = json.loads((kit / "clients" / "controller" / "yume.json").read_text())
            self.assertTrue(admin_config["allow_outbound_admin"])
            self.assertEqual(admin_config["admin_identity"], "admin-identity.key")
            self.assertTrue((kit / "clients" / "controller" / "admin-identity.key").is_file())
            self.assertEqual(
                (kit / "server" / "admin_keys").read_text().count(
                    "-----BEGIN PUBLIC KEY-----"),
                2,
            )

    def test_installed_layout_finds_cover_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp) / "prefix"
            (prefix / "bin").mkdir(parents=True)
            (prefix / "share" / "yume" / "cover-node").mkdir(parents=True)
            (prefix / "share" / "yume" / "cover-profile").mkdir(parents=True)
            installed_tool = prefix / "bin" / "yume-setup"
            shutil.copyfile(TOOL, installed_tool)
            installed_tool.chmod(0o755)
            shutil.copyfile(
                ROOT / "tools" / "cover-node" / "backend.mjs",
                prefix / "share" / "yume" / "cover-node" / "backend.mjs",
            )
            shutil.copyfile(
                ROOT / "tests" / "fixtures" / "chrome151-node24" / "manifest.json",
                prefix / "share" / "yume" / "cover-profile" / "manifest.json",
            )
            kit = Path(tmp) / "kit"
            result = subprocess.run(
                [str(installed_tool), "init", "--output", str(kit),
                 "--host", "192.0.2.10", "--tls-name", "installed-test"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((kit / "server" / "backend.mjs").is_file())


if __name__ == "__main__":
    unittest.main()
