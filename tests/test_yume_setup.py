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
TOOL = ROOT / "tools" / "yume_setup.py"
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
            manifest["runtime_status"], "development-runtimes"
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
        direct = [
            adapter
            for adapter in server["adapters"]
            if adapter["kind"] in {"direct_tcp", "direct_udp"}
        ]
        self.assertEqual(len(direct), 2)
        for adapter in direct:
            self.assertEqual(
                adapter["destinations"], {"public": True, "networks": []}
            )
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
                {("tcp", "stream"), ("udp", "packet")},
            )
            self.assertTrue(
                all(
                    item["max_concurrent_streams"] == 256
                    for item in config["services"]
                )
            )
        # yume and yumed start from the kit as generated. No adapter
        # names a packet/TUN device they cannot serve, and SOCKS5 carries UDP.
        self.assertEqual(
            [adapter["kind"] for adapter in server["adapters"]],
            ["direct_tcp", "direct_udp"],
        )
        self.assertEqual(
            client["adapters"],
            [
                {
                    "kind": "socks5",
                    "service": "tcp",
                    "listen_address": "127.0.0.1",
                    "listen_port": 1080,
                    "udp_service": "udp",
                }
            ],
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

    def test_outer_tls_certificates_use_browser_compatible_p256(self) -> None:
        credentials = self.kit / "server/credentials"
        for name in ("server-tls.pem", "server-trust.pem"):
            certificate = credentials / name
            details = subprocess.run(
                ["openssl", "x509", "-in", str(certificate), "-text", "-noout"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=10,
            ).stdout
            self.assertIn(b"ASN1 OID: prime256v1", details)
            self.assertIn(b"Signature Algorithm: ecdsa-with-SHA256", details)
        key = subprocess.run(
            ["openssl", "pkey", "-in", str(credentials / "server-tls.key.pem"),
             "-pubout"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=10,
        ).stdout
        certificate_key = subprocess.run(
            ["openssl", "x509", "-in", str(credentials / "server-tls.pem"),
             "-pubkey", "-noout"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=10,
        ).stdout
        self.assertEqual(key, certificate_key)

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
            {"tcp", "udp"},
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
        self.assertIn(
            '"${YUMED_BIN:-yumed}"',
            (self.kit / "server/start-server").read_text(),
        )
        self.assertIn(
            '"${YUME_BIN:-yume}"',
            (self.kit / "client/start-client").read_text(),
        )
        self.assertEqual(
            {path.name for path in (self.kit / "server/services").glob("*.json")},
            {"tcp.json", "udp.json"},
        )
        self.assertEqual(
            {path.name for path in (self.kit / "client/adapters").glob("*.json")},
            {"socks5.json"},
        )
        socks5 = json.loads((self.kit / "client/adapters/socks5.json").read_text())
        self.assertEqual(socks5["adapter"]["udp_service"], "udp")
        for filename in ("index.html", "404.html"):
            with self.subTest(cover=filename):
                cover = (self.kit / "server/cover-site" / filename).read_text().lower()
                self.assertIn("<!doctype html>", cover)
                self.assertIn("<body>", cover)
                self.assertGreaterEqual(len(cover), 256)
                self.assertNotIn("yume", cover)
        not_found = (self.kit / "server/cover-site/404.html").read_text()
        self.assertIn("<h1>Page not found</h1>", not_found)
        self.assertIn('href="/"', not_found)

    def test_cover_serves_the_selected_profile_asset_sequence(self) -> None:
        registry = json.loads((ROOT / "config/transport_profiles.json").read_text())
        selected = next(
            profile for profile in registry["profiles"]
            if profile["id"] == registry["active_profile"]
        )
        profile = json.loads((
            ROOT / selected["fixture"] / selected["artifacts"]["http2_profile"]
        ).read_text())
        cover_root = self.kit / "server/cover-site"
        index = (cover_root / "index.html").read_text()
        paths = [asset["path"] for asset in profile["asset_sequence"]]
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(asset=path):
                asset = cover_root / path.removeprefix("/")
                self.assertTrue(asset.is_file())
                self.assertFalse(asset.is_symlink())
                self.assertGreater(asset.stat().st_size, 0)
                self.assertIn(f'"{path}"', index)
                self.assertNotIn("yume", asset.read_text().lower())

    def test_cli_refuses_legacy_modes(self) -> None:
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

    def copy_server(self, destination: Path) -> Path:
        """A private copy of the fixture's server tree for mutating tests."""
        import shutil

        server = destination / "server"
        shutil.copytree(self.kit / "server", server, symlinks=True)
        return server

    @staticmethod
    def tree_snapshot(root: Path) -> dict[str, bytes]:
        return {
            str(path.relative_to(root)): path.read_bytes()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    def test_add_client_issues_bundle_and_extends_store(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            server = self.copy_server(base)
            before = json.loads((server / "credentials/authorized-keys.json").read_text())
            result = self.run_tool(
                "add-client",
                "--server",
                str(server),
                "--host",
                "setup.example.test",
                "--output",
                str(base / "tablet"),
                "--client-name",
                "tablet",
                "--max-sessions",
                "2",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            bundle = base / "tablet"
            self.assertEqual(
                json.loads((bundle / "yume.json").read_text()),
                json.loads((self.kit / "client/yume.json").read_text()),
            )
            for name in (
                "admission.key",
                "server-trust.pem",
                "server-composite.pub.pem",
                "server-mlkem.pub.pem",
            ):
                self.assertEqual(
                    (bundle / "credentials" / name).read_bytes(),
                    (server / "credentials" / name).read_bytes(),
                )
            for name in ("client-composite.pem", "client-access.psk"):
                mode = stat.S_IMODE((bundle / "credentials" / name).stat().st_mode)
                self.assertEqual(mode, 0o600)
                self.assertNotEqual(
                    (bundle / "credentials" / name).read_bytes(),
                    (self.kit / "client/credentials" / name).read_bytes(),
                )
            store = json.loads((server / "credentials/authorized-keys.json").read_text())
            self.assertEqual(store["keys"][:-1], before["keys"])
            entry = store["keys"][-1]
            self.assertEqual(entry["name"], "tablet")
            self.assertEqual(entry["max_sessions"], 2)
            self.assertEqual(entry["capabilities"], before["keys"][0]["capabilities"])
            authorized = server / "credentials"
            self.assertEqual(
                (authorized / entry["identity"]["file"]).read_bytes(),
                (bundle / "credentials/client-composite.pub.pem").read_bytes(),
            )
            psk = (authorized / entry["access_psk"]["file"]).read_bytes()
            self.assertEqual(psk, (bundle / "credentials/client-access.psk").read_bytes())
            self.assertNotEqual(psk, (authorized / "admission.key").read_bytes())
            self.assertEqual(list(base.glob(".yume-setup-staging-*")), [])
            doctor = ROOT / "tools" / "yume_doctor.py"
            for config in (server / "yumed.json", bundle / "yume.json"):
                checked = subprocess.run(
                    [sys.executable, str(doctor), "--config", str(config)],
                    cwd=ROOT,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)

    def test_remove_client_reverses_add_client(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            server = self.copy_server(base)
            store_path = server / "credentials/authorized-keys.json"
            before = json.loads(store_path.read_text())
            last = self.run_tool("remove-client", "--server", str(server), "--client-name", "phone")
            self.assertEqual(last.returncode, 1)
            self.assertIn("at least one client", last.stderr)
            added = self.run_tool(
                "add-client", "--server", str(server), "--host", "setup.example.test",
                "--output", str(base / "tablet"), "--client-name", "tablet",
            )
            self.assertEqual(added.returncode, 0, added.stderr)
            entry = json.loads(store_path.read_text())["keys"][-1]
            files = [server / "credentials" / entry[field]["file"]
                     for field in ("identity", "access_psk")]
            self.assertTrue(all(path.is_file() for path in files))
            missing = self.run_tool("remove-client", "--server", str(server), "--client-name", "absent")
            self.assertEqual(missing.returncode, 1)
            removed = self.run_tool("remove-client", "--server", str(server), "--client-name", "tablet")
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertEqual(json.loads(store_path.read_text()), before)
            self.assertFalse(any(path.exists() for path in files))
            self.assertEqual(stat.S_IMODE(store_path.stat().st_mode), 0o600)

    def test_add_client_failures_change_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            server = self.copy_server(base)
            before = self.tree_snapshot(server)
            attempts = (
                (["--client-name", "phone"], None, "already authorized"),
                (["--client-name", "tablet", "--max-sessions", "0"], None, "max sessions"),
                (["--client-name=-bad"], None, "client name"),
                (["--client-name", "tablet"], "/directory-that-does-not-exist", "openssl"),
            )
            for extra, path, message in attempts:
                environment = None
                if path is not None:
                    environment = os.environ.copy()
                    environment["PATH"] = path
                result = self.run_tool(
                    "add-client",
                    "--server",
                    str(server),
                    "--host",
                    "setup.example.test",
                    "--output",
                    str(base / "bundle"),
                    *extra,
                    environment=environment,
                )
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(message, result.stderr.lower())
                self.assertFalse((base / "bundle").exists())
                self.assertEqual(list(base.glob(".yume-setup-staging-*")), [])
                self.assertEqual(self.tree_snapshot(server), before)

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
