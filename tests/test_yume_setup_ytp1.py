#!/usr/bin/env python3

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "yume_setup_ytp1.py"
PEM_BLOCK = re.compile(
    rb"-----BEGIN ([A-Z0-9][A-Z0-9 ]*)-----\s+.*?-----END \1-----",
    re.DOTALL,
)


class YumeSetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temporary.name)
        cls.kit = cls.base / "kit"
        result = cls.run_tool(
            "init",
            "--host",
            "setup.example.test",
            "--output",
            str(cls.kit),
            "--client-name",
            "phone",
        )
        if result.returncode != 0:
            raise RuntimeError(f"setup fixture failed: {result.stderr}")
        cls.setup_output = result.stdout + result.stderr

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @staticmethod
    def run_tool(
        *arguments: str, environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOL), *arguments],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
        )

    def public_algorithms(self, path: Path, private: bool) -> list[str]:
        payload = path.read_bytes()
        blocks = [match.group(0) + b"\n" for match in PEM_BLOCK.finditer(payload)]
        algorithms: list[str] = []
        for block in blocks:
            command = ["openssl", "pkey"]
            if private:
                command += ["-pubout", "-outform", "DER"]
            else:
                command += ["-pubin", "-pubout", "-outform", "DER"]
            public = subprocess.run(
                command,
                input=block,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            ).stdout
            details = subprocess.run(
                ["openssl", "pkey", "-pubin", "-inform", "DER", "-text", "-noout"],
                input=public,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            ).stdout
            algorithms.append(details.splitlines()[0].decode().removesuffix(" Public-Key:"))
        return algorithms

    def test_init_creates_exact_schema_one_server_and_client(self) -> None:
        server = json.loads((self.kit / "server/yumed.json").read_text())
        client = json.loads((self.kit / "client/yume.json").read_text())
        manifest = json.loads((self.kit / "manifest.json").read_text())
        self.assertEqual(
            manifest["runtime_status"], "unwired-development-foundation"
        )
        top_keys = {
            "schema",
            "role",
            "endpoint",
            "suite",
            "credentials",
            "cover",
            "services",
            "adapters",
            "limits",
        }
        self.assertEqual(set(server), top_keys)
        self.assertEqual(set(client), top_keys)
        self.assertEqual(server["schema"], 1)
        self.assertEqual(client["schema"], 1)
        self.assertEqual(server["role"], "server")
        self.assertEqual(client["role"], "client")
        self.assertEqual(
            set(server["credentials"]),
            {
                "composite_key",
                "authorized_keys",
                "admin_keys",
                "tls_certificate",
                "tls_key",
                "admission_key",
                "mlkem_key",
            },
        )
        self.assertEqual(
            set(client["credentials"]),
            {
                "composite_key",
                "access_psk",
                "admission_key",
                "server_trust",
                "server_identity",
                "server_mlkem",
            },
        )
        for config in (server, client):
            for reference in config["credentials"].values():
                self.assertEqual(set(reference), {"file"})
                self.assertFalse(Path(reference["file"]).is_absolute())
                self.assertNotIn("..", Path(reference["file"]).parts)
            self.assertEqual(config["suite"]["id"], "ytp1-tls13-h2")
            self.assertEqual(config["cover"]["profile"], "chrome151-node24-v1")
            self.assertEqual(
                {(item["name"], item["kind"]) for item in config["services"]},
                {("tcp", "stream"), ("udp", "packet"), ("packet", "packet")},
            )
            self.assertTrue(
                all(
                    item["max_concurrent_streams"] == 256
                    for item in config["services"]
                )
            )

    def test_cryptographic_material_uses_mandatory_algorithms(self) -> None:
        server_credentials = self.kit / "server/credentials"
        client_credentials = self.kit / "client/credentials"
        self.assertEqual(
            self.public_algorithms(server_credentials / "server-composite.pem", True),
            ["ED25519", "ML-DSA-87"],
        )
        self.assertEqual(
            self.public_algorithms(client_credentials / "client-composite.pem", True),
            ["ED25519", "ML-DSA-87"],
        )
        self.assertEqual(
            self.public_algorithms(
                client_credentials / "server-composite.pub.pem", False
            ),
            ["ED25519", "ML-DSA-87"],
        )
        self.assertEqual(
            (server_credentials / "server-composite.pub.pem").read_bytes(),
            (client_credentials / "server-composite.pub.pem").read_bytes(),
        )
        self.assertEqual(
            self.public_algorithms(server_credentials / "server-mlkem.key.pem", True),
            ["ML-KEM-1024"],
        )
        verify = subprocess.run(
            [
                "openssl",
                "verify",
                "-CAfile",
                str(server_credentials / "server-trust.pem"),
                str(server_credentials / "server-tls.pem"),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(verify.returncode, 0, verify.stderr.decode())

    def test_admin_store_is_separate_and_starts_empty(self) -> None:
        server_credentials = self.kit / "server/credentials"
        authorized_path = server_credentials / "authorized-keys.json"
        admin_path = server_credentials / "admin-keys.json"
        self.assertTrue(admin_path.is_file())
        self.assertNotEqual(authorized_path, admin_path)
        admin = json.loads(admin_path.read_text())
        self.assertEqual(set(admin), {"schema", "keys"})
        self.assertEqual(admin["schema"], 1)
        # A fresh deployment must have no administrator until an operator
        # deliberately adds one; admin is never implied by a traffic key.
        self.assertEqual(admin["keys"], [])
        authorized = json.loads(authorized_path.read_text())
        for entry in authorized["keys"]:
            self.assertNotIn("admin", entry)
            self.assertEqual(
                set(entry), {"name", "identity", "access_psk", "capabilities"}
            )

    def test_access_psk_is_per_identity_and_not_admission_key(self) -> None:
        authorized_path = self.kit / "server/credentials/authorized-keys.json"
        authorized = json.loads(authorized_path.read_text())
        self.assertEqual(set(authorized), {"schema", "keys"})
        self.assertEqual(len(authorized["keys"]), 1)
        entry = authorized["keys"][0]
        self.assertEqual(entry["name"], "phone")
        self.assertEqual(
            {capability["service"] for capability in entry["capabilities"]},
            {"tcp", "udp", "packet"},
        )
        server_psk = (
            authorized_path.parent / entry["access_psk"]["file"]
        ).read_bytes()
        client_psk = (self.kit / "client/credentials/client-access.psk").read_bytes()
        admission = (self.kit / "server/credentials/admission.key").read_bytes()
        client_admission = (
            self.kit / "client/credentials/admission.key"
        ).read_bytes()
        self.assertEqual(len(server_psk), 32)
        self.assertEqual(server_psk, client_psk)
        self.assertNotEqual(server_psk, admission)
        self.assertEqual(client_admission, admission)
        self.assertNotIn(server_psk.hex(), self.setup_output)
        self.assertNotIn(admission.hex(), self.setup_output)

        second = self.base / "second-kit"
        result = self.run_tool(
            "init",
            "--host",
            "setup.example.test",
            "--output",
            str(second),
            "--client-name",
            "phone",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        second_psk = (second / "client/credentials/client-access.psk").read_bytes()
        self.assertNotEqual(client_psk, second_psk)

    def test_permissions_launchers_cover_and_manifests_are_complete(self) -> None:
        for path in self.kit.rglob("*"):
            mode = stat.S_IMODE(path.lstat().st_mode)
            if path.is_dir():
                self.assertEqual(mode, 0o700, path)
            elif path.name in {"start-server", "start-client"}:
                self.assertEqual(mode, 0o700, path)
            else:
                self.assertEqual(mode, 0o600, path)

        for launcher in (
            self.kit / "server/start-server",
            self.kit / "client/start-client",
        ):
            text = launcher.read_text()
            self.assertEqual(re.findall(r"--[a-z-]+", text), ["--config"])
        self.assertEqual(
            {path.name for path in (self.kit / "server/services").glob("*.json")},
            {"tcp.json", "udp.json", "packet.json"},
        )
        self.assertTrue((self.kit / "client/adapters/socks5.json").is_file())
        cover = (self.kit / "server/cover-site/index.html").read_text().lower()
        self.assertIn("<!doctype html>", cover)
        self.assertIn("<body>", cover)
        self.assertNotIn("yume", cover)

    def test_cli_has_only_init_and_refuses_legacy_modes(self) -> None:
        help_result = self.run_tool("--help")
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        for removed in (
            "issue-key",
            "admin",
            "bulk",
            "anonym",
            "packet-policy",
            "inner-crypto",
        ):
            self.assertNotIn(removed, help_result.stdout)
        rejected = self.run_tool("issue-key", "--kit", str(self.kit))
        self.assertNotEqual(rejected.returncode, 0)

    def test_refuses_overwrite_and_removes_failed_staging(self) -> None:
        manifest = (self.kit / "manifest.json").read_bytes()
        overwrite = self.run_tool(
            "init",
            "--host",
            "setup.example.test",
            "--output",
            str(self.kit),
        )
        self.assertEqual(overwrite.returncode, 1)
        self.assertIn("refusing to overwrite", overwrite.stderr)
        self.assertEqual((self.kit / "manifest.json").read_bytes(), manifest)

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            environment = os.environ.copy()
            environment["PATH"] = "/directory-that-does-not-exist"
            failed = self.run_tool(
                "init",
                "--host",
                "setup.example.test",
                "--output",
                str(parent / "kit"),
                environment=environment,
            )
            self.assertEqual(failed.returncode, 1)
            self.assertIn("openssl", failed.stderr.lower())
            self.assertFalse((parent / "kit").exists())
            self.assertEqual(
                list(parent.glob(".yume-setup-staging-*")),
                [],
            )

    def test_rejects_invalid_host_client_name_and_output_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            for arguments in (
                (
                    "init",
                    "--host",
                    "999.1.1.1",
                    "--output",
                    str(parent / "bad-host"),
                ),
                (
                    "init",
                    "--host",
                    "example.test",
                    "--output",
                    str(parent / "bad-name"),
                    "--client-name",
                    "../device",
                ),
                (
                    "init",
                    "--host",
                    "example.test",
                    "--output",
                    str(parent / "missing" / "kit"),
                ),
            ):
                result = self.run_tool(*arguments)
                self.assertEqual(result.returncode, 1, result.stdout)
            self.assertFalse(any(parent.iterdir()))


if __name__ == "__main__":
    unittest.main()
