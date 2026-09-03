#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SETUP = ROOT / "tools" / "yume_setup_ytp1.py"
DOCTOR = ROOT / "tools" / "yume_doctor_ytp1.py"


class YumeDoctorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.source_kit = cls.root / "source-kit"
        result = subprocess.run(
            [
                sys.executable,
                str(SETUP),
                "init",
                "--host",
                "doctor.example.test",
                "--output",
                str(cls.source_kit),
                "--client-name",
                "phone",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"doctor fixture failed: {result.stderr}")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def setUp(self) -> None:
        self.case = Path(tempfile.mkdtemp(dir=self.root)) / "kit"
        shutil.copytree(self.source_kit, self.case)

    def tearDown(self) -> None:
        shutil.rmtree(self.case.parent)

    def run_doctor(self, config: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(DOCTOR), "--config", str(config)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_generated_server_and_client_are_healthy(self) -> None:
        for config in (
            self.case / "server/yumed.json",
            self.case / "client/yume.json",
        ):
            result = self.run_doctor(config)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                result.stdout.strip(),
                "yume-doctor-ytp1: configuration and credentials valid; "
                "runtime provider not qualified",
            )
            self.assertEqual(result.stderr, "")

    def test_strict_schema_and_permissions_fail_with_pointer(self) -> None:
        config_path = self.case / "client/yume.json"
        config = json.loads(config_path.read_text())
        config["legacy_mode"] = True
        config_path.write_text(json.dumps(config))
        os.chmod(config_path, 0o600)
        unknown = self.run_doctor(config_path)
        self.assertEqual(unknown.returncode, 1)
        self.assertIn("/legacy_mode: unknown key", unknown.stderr)

        del config["legacy_mode"]
        config_path.write_text(json.dumps(config))
        os.chmod(config_path, 0o640)
        permissions = self.run_doctor(config_path)
        self.assertEqual(permissions.returncode, 1)
        self.assertIn("/config: group/world permissions are forbidden", permissions.stderr)

    def test_service_stream_bounds_are_required_and_strict(self) -> None:
        config_path = self.case / "client/yume.json"
        original = json.loads(config_path.read_text())

        missing = copy.deepcopy(original)
        del missing["services"][0]["max_concurrent_streams"]
        config_path.write_text(json.dumps(missing))
        os.chmod(config_path, 0o600)
        result = self.run_doctor(config_path)
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "/services/0/max_concurrent_streams: required key is missing",
            result.stderr,
        )

        out_of_range = copy.deepcopy(original)
        out_of_range["services"][0]["max_concurrent_streams"] = 0
        config_path.write_text(json.dumps(out_of_range))
        os.chmod(config_path, 0o600)
        result = self.run_doctor(config_path)
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "/services/0/max_concurrent_streams: must be in 1..65535",
            result.stderr,
        )

    def test_service_names_use_one_canonical_wire_grammar(self) -> None:
        config_path = self.case / "client/yume.json"
        original = json.loads(config_path.read_text())

        for invalid_name in (
            "Uppercase",
            "bad/name",
            ".leading",
            "trailing.",
            "bad.-segment",
            "bad_segment-",
            "écho",
            "a" * 129,
        ):
            document = copy.deepcopy(original)
            document["services"][0]["name"] = invalid_name
            config_path.write_text(json.dumps(document))
            os.chmod(config_path, 0o600)
            result = self.run_doctor(config_path)
            self.assertEqual(result.returncode, 1, invalid_name)
            self.assertIn("/services/0/name:", result.stderr)

        maximum = copy.deepcopy(original)
        maximum_name = "a" * 128
        maximum["services"][0]["name"] = maximum_name
        maximum["adapters"][0]["service"] = maximum_name
        config_path.write_text(json.dumps(maximum))
        os.chmod(config_path, 0o600)
        result = self.run_doctor(config_path)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dual_kind_services_and_distinct_adapter_instances_are_valid(self) -> None:
        client_path = self.case / "client/yume.json"
        client = json.loads(client_path.read_text())
        client["services"].append(
            {
                "name": "tcp",
                "kind": "packet",
                "max_concurrent_streams": 8,
            }
        )
        client["adapters"].append(
            {
                "kind": "socks5",
                "service": "tcp",
                "listen_address": "127.0.0.1",
                "listen_port": 1081,
            }
        )
        client_path.write_text(json.dumps(client))
        os.chmod(client_path, 0o600)
        result = self.run_doctor(client_path)
        self.assertEqual(result.returncode, 0, result.stderr)

        server_path = self.case / "server/yumed.json"
        server = json.loads(server_path.read_text())
        server["services"].append(
            {
                "name": "admin",
                "kind": "stream",
                "max_concurrent_streams": 8,
            }
        )
        server["services"].append(
            {
                "name": "tcp",
                "kind": "packet",
                "max_concurrent_streams": 8,
            }
        )
        server["adapters"].append(
            {"kind": "direct_tcp", "service": "admin"}
        )
        server_path.write_text(json.dumps(server))
        os.chmod(server_path, 0o600)
        authorized_path = (
            self.case / "server/credentials/authorized-keys.json"
        )
        authorized = json.loads(authorized_path.read_text())
        authorized["keys"][0]["capabilities"].append(
            {"service": "tcp", "kind": "packet"}
        )
        authorized_path.write_text(json.dumps(authorized))
        os.chmod(authorized_path, 0o600)
        result = self.run_doctor(server_path)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_adapter_instance_collisions_are_rejected(self) -> None:
        config_path = self.case / "client/yume.json"
        client = json.loads(config_path.read_text())
        client["adapters"].append(copy.deepcopy(client["adapters"][0]))
        config_path.write_text(json.dumps(client))
        os.chmod(config_path, 0o600)
        result = self.run_doctor(config_path)
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "/adapters/2/listen_port: duplicate SOCKS5 listen address and port",
            result.stderr,
        )

    def test_symlink_and_non_regular_credentials_are_rejected(self) -> None:
        credential = self.case / "client/credentials/client-access.psk"
        replacement = credential.with_name("replacement.psk")
        credential.rename(replacement)
        credential.symlink_to(replacement.name)
        symlink = self.run_doctor(self.case / "client/yume.json")
        self.assertEqual(symlink.returncode, 1)
        self.assertIn("/credentials/access_psk", symlink.stderr)
        self.assertIn("symlink", symlink.stderr.lower())

        credential.unlink()
        credential.mkdir(mode=0o700)
        non_regular = self.run_doctor(self.case / "client/yume.json")
        self.assertEqual(non_regular.returncode, 1)
        self.assertIn("must reference a regular file", non_regular.stderr)

    def test_tls_certificate_key_mismatch_is_rejected(self) -> None:
        tls_key = self.case / "server/credentials/server-tls.key.pem"
        generated = subprocess.run(
            ["openssl", "genpkey", "-algorithm", "Ed25519"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout
        tls_key.write_bytes(generated)
        os.chmod(tls_key, 0o600)
        result = self.run_doctor(self.case / "server/yumed.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("TLS certificate and private key do not match", result.stderr)

    def test_mlkem_public_private_mismatch_is_rejected(self) -> None:
        public_path = self.case / "server/credentials/server-mlkem.pub.pem"
        private = subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ML-KEM-1024"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout
        public = subprocess.run(
            ["openssl", "pkey", "-pubout"],
            input=private,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout
        public_path.write_bytes(public)
        os.chmod(public_path, 0o600)
        result = self.run_doctor(self.case / "server/yumed.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not match the ML-KEM private key", result.stderr)

    def test_client_server_identity_must_be_composite_public_key(self) -> None:
        identity = self.case / "client/credentials/server-composite.pub.pem"
        identity.write_bytes(
            (self.case / "client/credentials/server-mlkem.pub.pem").read_bytes()
        )
        os.chmod(identity, 0o600)
        result = self.run_doctor(self.case / "client/yume.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("/credentials/server_identity", result.stderr)
        self.assertIn("exactly 2 PEM objects", result.stderr)

    def test_admin_identity_may_not_also_be_a_traffic_key(self) -> None:
        # Admin means "an authorized traffic identity PLUS a different
        # identity from admin_keys". One identity in both stores would satisfy
        # both halves alone, so the doctor must reject the overlap.
        authorized_path = self.case / "server/credentials/authorized-keys.json"
        admin_path = self.case / "server/credentials/admin-keys.json"
        authorized = json.loads(authorized_path.read_text())
        traffic = authorized["keys"][0]
        admin = json.loads(admin_path.read_text())
        admin["keys"].append(
            {"name": "operator", "identity": copy.deepcopy(traffic["identity"])}
        )
        admin_path.write_text(json.dumps(admin))
        os.chmod(admin_path, 0o600)
        result = self.run_doctor(self.case / "server/yumed.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "admin identity must not also appear in authorized_keys",
            result.stderr,
        )

    def test_admin_store_rejects_policy_metadata(self) -> None:
        # The second-factor store proves an identity; it never carries
        # permissions. A policy field here would recreate the single-list
        # model the two-key split exists to prevent.
        admin_path = self.case / "server/credentials/admin-keys.json"
        admin = json.loads(admin_path.read_text())
        admin["keys"].append(
            {
                "name": "operator",
                "identity": {"file": "authorized/phone-composite.pub.pem",
                             "sha256": "0" * 64},
                "capabilities": [{"service": "tcp", "kind": "stream"}],
            }
        )
        admin_path.write_text(json.dumps(admin))
        os.chmod(admin_path, 0o600)
        result = self.run_doctor(self.case / "server/yumed.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("/credentials/admin_keys/keys/0/capabilities", result.stderr)

    def test_duplicate_access_psk_is_rejected(self) -> None:
        store_path = self.case / "server/credentials/authorized-keys.json"
        store = json.loads(store_path.read_text())
        duplicate = copy.deepcopy(store["keys"][0])
        duplicate["name"] = "tablet"
        store["keys"].append(duplicate)
        store_path.write_text(json.dumps(store))
        os.chmod(store_path, 0o600)
        result = self.run_doctor(self.case / "server/yumed.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("access PSK is reused by another authorized key", result.stderr)

    def test_client_admission_key_must_differ_from_access_psk(self) -> None:
        access_psk_path = self.case / "client/credentials/client-access.psk"
        admission = self.case / "client/credentials/admission.key"
        admission.write_bytes(access_psk_path.read_bytes())
        os.chmod(admission, 0o600)

        result = self.run_doctor(self.case / "client/yume.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "/credentials/admission_key: must differ from the per-identity access PSK",
            result.stderr,
        )

    def test_cover_index_and_profile_compatibility_are_checked(self) -> None:
        index = self.case / "server/cover-site/index.html"
        index.write_text("<html><body>placeholder</body></html>")
        os.chmod(index, 0o600)
        cover = self.run_doctor(self.case / "server/yumed.json")
        self.assertEqual(cover.returncode, 1)
        self.assertIn("/cover/root/index.html", cover.stderr)

        client_config_path = self.case / "client/yume.json"
        client_config = json.loads(client_config_path.read_text())
        client_config["cover"]["profile"] = "unqualified-profile"
        client_config_path.write_text(json.dumps(client_config))
        os.chmod(client_config_path, 0o600)
        profile = self.run_doctor(client_config_path)
        self.assertEqual(profile.returncode, 1)
        self.assertIn("/cover/profile: profile is not qualified", profile.stderr)

    def test_diagnostics_never_print_secret_contents(self) -> None:
        psk = self.case / "client/credentials/client-access.psk"
        secret = b"operator-visible-secret-material!"
        self.assertEqual(len(secret), 33)
        psk.write_bytes(secret)
        os.chmod(psk, 0o640)
        result = self.run_doctor(self.case / "client/yume.json")
        self.assertEqual(result.returncode, 1)
        output = result.stdout + result.stderr
        self.assertNotIn(secret.decode(), output)
        self.assertNotIn(secret.hex(), output)
        self.assertIn("/credentials/access_psk", output)

    def test_authorized_store_identity_and_capabilities_are_bound(self) -> None:
        store_path = self.case / "server/credentials/authorized-keys.json"
        store = json.loads(store_path.read_text())
        store["keys"][0]["identity"]["sha256"] = "0" * 64
        store_path.write_text(json.dumps(store))
        os.chmod(store_path, 0o600)
        identity = self.run_doctor(self.case / "server/yumed.json")
        self.assertEqual(identity.returncode, 1)
        self.assertIn("identity fingerprint does not match", identity.stderr)

        store = json.loads((self.source_kit / "server/credentials/authorized-keys.json").read_text())
        store["keys"][0]["capabilities"][0]["kind"] = "packet"
        store_path.write_text(json.dumps(store))
        os.chmod(store_path, 0o600)
        capabilities = self.run_doctor(self.case / "server/yumed.json")
        self.assertEqual(capabilities.returncode, 1)
        self.assertIn("capability does not match a configured service", capabilities.stderr)


if __name__ == "__main__":
    unittest.main()
