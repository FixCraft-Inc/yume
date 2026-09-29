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


def runpy_tool() -> dict:
    import runpy
    return runpy.run_path(str(TOOL))


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

    def test_weight_and_egress_rate_reach_the_server(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            kit = base / "kit"
            created = self.run_tool(
                "init", "--host", "setup.example.test", "--output", str(kit),
                "--client-name", "phone", "--weight", "2.5", "--max-egress-mbps", "100",
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            server = kit / "server"
            config = json.loads((server / "yumed.json").read_text())
            self.assertEqual(config["limits"]["max_egress_mbps"], 100)
            client = json.loads((kit / "client/yume.json").read_text())
            self.assertNotIn("max_egress_mbps", client["limits"])
            store_path = server / "credentials/authorized-keys.json"
            self.assertEqual(json.loads(store_path.read_text())["keys"][0]["weight"], 2.5)
            added = self.run_tool(
                "add-client", "--server", str(server), "--host", "setup.example.test",
                "--output", str(base / "tablet"), "--client-name", "tablet", "--weight", "0.5",
            )
            self.assertEqual(added.returncode, 0, added.stderr)
            self.assertEqual(json.loads(store_path.read_text())["keys"][1]["weight"], 0.5)
            doctor = ROOT / "tools" / "yume_doctor.py"
            checked = subprocess.run(
                [sys.executable, str(doctor), "--config", str(server / "yumed.json")],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
            for extra, message in ((["--weight", "0"], "weight"),
                                   (["--weight", "nan"], "weight"),
                                   (["--max-egress-mbps", "0"], "max egress")):
                refused = self.run_tool(
                    "init", "--host", "setup.example.test", "--output", str(base / "refused"),
                    *extra,
                )
                self.assertEqual(refused.returncode, 1, refused.stdout)
                self.assertIn(message, refused.stderr.lower())
                self.assertFalse((base / "refused").exists())

    def test_tuning_presets_reach_both_sides_and_new_clients(self) -> None:
        tool = runpy_tool()
        default = tool["TUNING_PRESETS"][tool["DEFAULT_PRESET"]]
        for relative in ("server/yumed.json", "client/yume.json"):
            limits = json.loads((self.kit / relative).read_text())["limits"]
            self.assertEqual({key: limits[key] for key in default}, default)
        self.assertIn("Tuning preset: stealth", self.setup_output)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            kit = base / "kit"
            created = self.run_tool(
                "init", "--host", "setup.example.test", "--output", str(kit),
                "--client-name", "phone", "--preset", "fast",
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            fast = tool["TUNING_PRESETS"]["fast"]
            for relative in ("server/yumed.json", "client/yume.json"):
                limits = json.loads((kit / relative).read_text())["limits"]
                self.assertEqual({key: limits[key] for key in fast}, fast)
            added = self.run_tool(
                "add-client", "--server", str(kit / "server"), "--host", "setup.example.test",
                "--output", str(base / "tablet"), "--client-name", "tablet",
            )
            self.assertEqual(added.returncode, 0, added.stderr)
            limits = json.loads((base / "tablet/yume.json").read_text())["limits"]
            self.assertEqual({key: limits[key] for key in fast}, fast)
            refused = self.run_tool(
                "init", "--host", "setup.example.test", "--output", str(base / "refused"),
                "--preset", "unlimited",
            )
            self.assertEqual(refused.returncode, 2, refused.stdout)
            self.assertFalse((base / "refused").exists())

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
                (["--client-name", "tablet", "--weight", "101"], None, "weight"),
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



class ClusterSetupTests(unittest.TestCase):
    """cluster-init, cluster-add, cluster-sign and cluster-remove on three kits."""

    HOSTS = {"north": "north.example.test", "south": "south.example.test",
             "west": "west.example.test"}
    # Test hosts do not resolve, so each node names its address, and north
    # and west share one /16.
    ADDRESSES = {"north": "192.0.2.10", "south": "198.51.100.10", "west": "192.0.77.10"}

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.servers: dict[str, Path] = {}
        for name, host in self.HOSTS.items():
            kit = self.base / name
            self.tool("init", "--host", host, "--output", str(kit))
            self.servers[name] = kit / "server"
        self.operator = self.base / "operator"
        self.tool("cluster-init", "--output", str(self.operator))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def tool(self, *arguments: str, code: int = 0) -> subprocess.CompletedProcess[str]:
        result = YumeSetupTests.run_tool(*arguments)
        self.assertEqual(result.returncode, code, result.stderr)
        return result

    def add(self, name: str, code: int = 0, host: str | None = None,
            *extra: str) -> subprocess.CompletedProcess[str]:
        return self.tool("cluster-add", "--cluster", str(self.operator), "--server",
                         str(self.servers[name]), "--name", name, "--host",
                         host or self.HOSTS[name], "--address", self.ADDRESSES[name],
                         *extra, code=code)

    def verify(self, domain: bytes, document: bytes, signature: bytes) -> None:
        message = self.base / "message"
        message.write_bytes(domain + b"\0" + document)
        blocks = [match.group(0) + b"\n" for match in
                  PEM_BLOCK.finditer((self.operator / "operator-composite.pub.pem").read_bytes())]
        self.assertEqual(len(blocks), 2)
        for index, (block, part) in enumerate(((blocks[0], signature[:64]),
                                               (blocks[1], signature[64:]))):
            key = self.base / f"key-{index}.pem"
            key.write_bytes(block)
            sig = self.base / f"sig-{index}"
            sig.write_bytes(part)
            verified = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(key),
                 "-in", str(message), "-sigfile", str(sig)],
                capture_output=True, check=False)
            self.assertEqual(verified.returncode, 0, verified.stderr)

    def peers(self, name: str) -> Path:
        return self.servers[name] / "credentials/cluster/peers"

    def test_operator_directory_keeps_the_key_private(self) -> None:
        state = json.loads((self.operator / "cluster.json").read_text(encoding="utf-8"))
        self.assertEqual(set(state), {"schema", "cluster", "serial", "nodes"})
        self.assertEqual((state["serial"], state["nodes"]), (0, []))
        self.assertRegex(state["cluster"], r"\A[0-9a-f]{64}\Z")
        for path in (self.operator, self.operator / "operator-composite.pem",
                     self.operator / "routes-tag.key"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)
        self.assertEqual(len((self.operator / "routes-tag.key").read_bytes()), 32)
        self.assertEqual(len(PEM_BLOCK.findall(
            (self.operator / "operator-composite.pem").read_bytes())), 2)

    def test_add_writes_pairwise_secrets_and_the_cluster_section(self) -> None:
        for name in self.HOSTS:
            self.add(name)
        admission = {name: (server / "credentials/admission.key").read_bytes()
                     for name, server in self.servers.items()}
        secrets: list[bytes] = []
        for name in self.HOSTS:
            config = json.loads((self.servers[name] / "yumed.json").read_text(encoding="utf-8"))
            self.assertEqual(config["cluster"]["peers"],
                             {"file": "credentials/cluster/peers.json"})
            store = json.loads((self.servers[name] / "credentials/cluster/peers.json")
                               .read_text(encoding="utf-8"))
            self.assertEqual(len(store["keys"]), 2)
            for other in self.HOSTS:
                if other == name:
                    continue
                outbound = (self.peers(name) / f"{other}-outbound.psk").read_bytes()
                self.assertEqual(len(outbound), 32)
                self.assertEqual(outbound, (self.peers(other) / f"{name}-inbound.psk").read_bytes())
                self.assertEqual((self.peers(name) / f"{other}-admission.key").read_bytes(),
                                 admission[other])
                secrets.append(outbound)
        # Six directed links, six different PSKs, none an admission key.
        self.assertEqual(len(set(secrets)), 6)
        self.assertFalse(set(secrets) & set(admission.values()))

    def test_add_refuses_a_wrong_host_a_repeated_name_and_a_member(self) -> None:
        self.add("north")
        before = (self.operator / "cluster.json").read_bytes()
        self.add("south", code=1, host="other.example.test")
        self.assertFalse((self.servers["south"] / "credentials/cluster").exists())
        self.tool("cluster-add", "--cluster", str(self.operator), "--server",
                  str(self.servers["south"]), "--name", "north", "--host",
                  self.HOSTS["south"], code=1)
        self.tool("cluster-add", "--cluster", str(self.operator), "--server",
                  str(self.servers["north"]), "--name", "again", "--host",
                  self.HOSTS["north"], code=1)
        self.assertEqual((self.operator / "cluster.json").read_bytes(), before)

    def test_sign_produces_a_verifiable_composite_signature(self) -> None:
        self.tool("cluster-sign", "--cluster", str(self.operator), code=1)
        self.add("north")
        self.add("south")
        self.tool("cluster-sign", "--cluster", str(self.operator), "--days", "0", code=1)
        signed = self.tool("cluster-sign", "--cluster", str(self.operator), "--days", "7")
        self.assertIn("serial 1", signed.stdout)
        self.tool("cluster-sign", "--cluster", str(self.operator))
        listing = (self.operator / "cluster-list.json").read_bytes()
        signature = (self.operator / "cluster-list.sig").read_bytes()
        document = json.loads(listing)
        self.assertEqual(document["serial"], 2)
        self.assertEqual([node["name"] for node in document["nodes"]], ["north", "south"])
        self.assertEqual(len(signature), 64 + 4627)
        for name in ("north", "south"):
            cluster = self.servers[name] / "credentials/cluster"
            self.assertEqual((cluster / "cluster-list.json").read_bytes(), listing)
            self.assertEqual((cluster / "cluster-list.sig").read_bytes(), signature)
        self.verify(b"yume-cluster-list/1", listing, signature)

    def test_sign_writes_a_routes_view_without_addresses(self) -> None:
        self.add("north", 0, None, "--exit")
        self.add("south")
        self.add("west")
        config = json.loads((self.servers["north"] / "yumed.json").read_text(encoding="utf-8"))
        self.assertEqual(config["cluster"]["exit"], {"service": "tcp"})
        self.assertEqual(config["cluster"]["routes"],
                         {"file": "credentials/cluster/cluster-routes.json"})
        self.assertNotIn("exit", json.loads(
            (self.servers["south"] / "yumed.json").read_text(encoding="utf-8"))["cluster"])
        self.tool("cluster-sign", "--cluster", str(self.operator))
        listing = json.loads((self.operator / "cluster-list.json").read_bytes())
        view_bytes = (self.operator / "cluster-routes.json").read_bytes()
        view_signature = (self.operator / "cluster-routes.sig").read_bytes()
        view = json.loads(view_bytes)
        self.assertEqual({key: view[key] for key in ("schema", "cluster", "serial", "not_after")},
                         {key: listing[key] for key in ("schema", "cluster", "serial", "not_after")})
        self.assertEqual([node["name"] for node in view["nodes"]], ["north", "south", "west"])
        for node, listed in zip(view["nodes"], listing["nodes"]):
            self.assertEqual(set(node), {"name", "identity", "identity_key", "exit", "network"})
            self.assertEqual((node["identity"], node["identity_key"]),
                             (listed["identity"], listed["identity_key"]))
            self.assertRegex(node["network"], r"\A[0-9a-f]{16}\Z")
        self.assertEqual([node["exit"] for node in view["nodes"]], [True, False, False])
        tags = {node["name"]: node["network"] for node in view["nodes"]}
        self.assertEqual(tags["north"], tags["west"])
        self.assertNotEqual(tags["north"], tags["south"])
        self.assertNotIn(b"192.0.2.10", view_bytes)
        self.assertNotIn(b"example.test", view_bytes)
        for name in self.HOSTS:
            cluster = self.servers[name] / "credentials/cluster"
            self.assertEqual((cluster / "cluster-routes.json").read_bytes(), view_bytes)
            self.assertEqual((cluster / "cluster-routes.sig").read_bytes(), view_signature)
        self.verify(b"yume-cluster-routes/1", view_bytes, view_signature)
        # The same key gives the same tags at the next signing.
        self.tool("cluster-sign", "--cluster", str(self.operator))
        again = json.loads((self.operator / "cluster-routes.json").read_bytes())
        self.assertEqual({node["name"]: node["network"] for node in again["nodes"]}, tags)

    def test_exit_needs_one_direct_tcp_adapter(self) -> None:
        config_path = self.servers["south"] / "yumed.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["adapters"] = [adapter for adapter in config["adapters"]
                              if adapter.get("kind") != "direct_tcp"]
        config_path.write_text(json.dumps(config), encoding="utf-8")
        result = self.add("south", 1, None, "--exit")
        self.assertIn("direct_tcp", result.stderr)
        self.assertFalse((self.servers["south"] / "credentials/cluster").exists())

    def test_add_client_grants_circuits_only_in_a_cluster(self) -> None:
        output = self.base / "circuit-client"
        refused = self.tool("add-client", "--server", str(self.servers["north"]), "--host",
                            self.HOSTS["north"], "--output", str(output), "--client-name",
                            "walker", "--circuits", code=1)
        self.assertIn("cluster", refused.stderr)
        self.assertFalse(output.exists())
        self.add("north")
        # The bundle carries the node's routes view, so the cluster must be
        # signed first.
        unsigned = self.tool("add-client", "--server", str(self.servers["north"]), "--host",
                             self.HOSTS["north"], "--output", str(output), "--client-name",
                             "walker", "--circuits", code=1)
        self.assertIn("cluster-sign", unsigned.stderr)
        self.assertFalse(output.exists())
        self.tool("cluster-sign", "--cluster", str(self.operator))
        self.tool("add-client", "--server", str(self.servers["north"]), "--host",
                  self.HOSTS["north"], "--output", str(output), "--client-name", "walker",
                  "--circuits")
        store = json.loads((self.servers["north"] / "credentials/authorized-keys.json")
                           .read_text(encoding="utf-8"))
        entry = next(key for key in store["keys"] if key["name"] == "walker")
        self.assertIn({"service": "yume.circuit", "kind": "packet"}, entry["capabilities"])
        first = next(key for key in store["keys"] if key["name"] != "walker")
        self.assertNotIn({"service": "yume.circuit", "kind": "packet"}, first["capabilities"])
        config = json.loads((output / "yume.json").read_text(encoding="utf-8"))
        self.assertEqual(config["circuits"], {
            "hops": 3,
            "operator_key": {"file": "credentials/circuits/operator.pub.pem"},
            "routes": {"file": "credentials/circuits/cluster-routes.json"},
            "routes_signature": {"file": "credentials/circuits/cluster-routes.sig"},
            "state": {"file": "circuits-state.json"},
        })
        socks = [adapter for adapter in config["adapters"] if adapter["kind"] == "socks5"]
        self.assertEqual(len(socks), 1)
        self.assertNotIn("udp_service", socks[0])
        node = self.servers["north"] / "credentials/cluster"
        for name, source in (("operator.pub.pem", "operator.pub.pem"),
                             ("cluster-routes.json", "cluster-routes.json"),
                             ("cluster-routes.sig", "cluster-routes.sig")):
            copied = output / "credentials/circuits" / name
            self.assertEqual(copied.read_bytes(), (node / source).read_bytes())
            self.assertEqual(stat.S_IMODE(copied.stat().st_mode) & 0o077, 0)

    def test_remove_detaches_the_node_from_the_others(self) -> None:
        for name in self.HOSTS:
            self.add(name)
        self.tool("cluster-remove", "--cluster", str(self.operator), "--name", "south")
        self.tool("cluster-remove", "--cluster", str(self.operator), "--name", "south", code=1)
        state = json.loads((self.operator / "cluster.json").read_text(encoding="utf-8"))
        self.assertEqual([node["name"] for node in state["nodes"]], ["north", "west"])
        config = json.loads((self.servers["south"] / "yumed.json").read_text(encoding="utf-8"))
        self.assertNotIn("cluster", config)
        self.assertFalse((self.servers["south"] / "credentials/cluster").exists())
        for name in ("north", "west"):
            store = json.loads((self.servers[name] / "credentials/cluster/peers.json")
                               .read_text(encoding="utf-8"))
            self.assertEqual(len(store["keys"]), 1)
            self.assertEqual(sorted(path.name for path in self.peers(name).iterdir()),
                             sorted(f"{other}-{kind}" for other in ("north", "west") if other != name
                                    for kind in ("admission.key", "inbound.psk", "outbound.psk")))
        # The removed node can join again.
        self.add("south")


if __name__ == "__main__":
    unittest.main()
