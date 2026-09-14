#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import shutil
import runpy
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
            {
                "kind": "direct_tcp",
                "service": "admin",
                "destinations": {"public": False, "networks": ["10.0.0.0/8"]},
            }
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

    def test_direct_adapter_destinations_are_validated(self) -> None:
        config_path = self.case / "server/yumed.json"
        original = json.loads(config_path.read_text())
        self.assertEqual(original["adapters"][0]["kind"], "direct_tcp")
        cases = (
            (lambda policy: policy.clear(), "/adapters/0/destinations/networks: required key is missing"),
            (lambda policy: policy.update(public="yes"), "/adapters/0/destinations/public: must be a boolean"),
            (lambda policy: policy.update(networks=["10.0.0.1/8"]), "/adapters/0/destinations/networks/0: must be a canonical"),
            (lambda policy: policy.update(networks=["224.0.0.0/4"]), "/adapters/0/destinations/networks/0: can never match"),
            (lambda policy: policy.update(networks=["10.0.0.0/8", "10.0.0.0/8"]), "/adapters/0/destinations/networks/1: duplicate"),
            (lambda policy: policy.update(public=False), "/adapters/0/destinations: must permit"),
            (lambda policy: policy.update(hosts=[]), "/adapters/0/destinations/hosts: unknown key"),
        )
        for mutate, expected in cases:
            document = copy.deepcopy(original)
            mutate(document["adapters"][0]["destinations"])
            config_path.write_text(json.dumps(document))
            os.chmod(config_path, 0o600)
            result = self.run_doctor(config_path)
            self.assertEqual(result.returncode, 1, expected)
            self.assertIn(expected, result.stderr)

        document = copy.deepcopy(original)
        del document["adapters"][0]["destinations"]
        config_path.write_text(json.dumps(document))
        os.chmod(config_path, 0o600)
        result = self.run_doctor(config_path)
        self.assertEqual(result.returncode, 1)
        self.assertIn("/adapters/0/destinations: required key is missing", result.stderr)

        document = copy.deepcopy(original)
        document["adapters"][0]["destinations"] = {
            "public": False,
            "networks": ["127.0.0.1/32", "fd00::/8", "0.0.0.0/7"],
        }
        config_path.write_text(json.dumps(document))
        os.chmod(config_path, 0o600)
        result = self.run_doctor(config_path)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_destination_network_vectors_match_native_parser(self) -> None:
        doctor = runpy.run_path(str(DOCTOR))
        check, error_type = doctor["_destination_network"], doctor["DoctorError"]
        vectors = ROOT / "src/common/testdata/ip_network_vectors.txt"
        seen = set()
        for line in vectors.read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            kind, text = line.split(" ", 1)
            seen.add(kind)
            with self.subTest(vector=line):
                if kind == "valid":
                    check(text, "/network")
                    continue
                with self.assertRaises(error_type) as raised:
                    check(text, "/network")
                detail = " ".join(map(str, raised.exception.args))
                self.assertIn("never" if kind == "never" else "canonical", detail)
        self.assertEqual(seen, {"valid", "never", "invalid"})

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
            ["openssl", "genpkey", "-algorithm", "EC",
             "-pkeyopt", "ec_paramgen_curve:prime256v1"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout
        tls_key.write_bytes(generated)
        os.chmod(tls_key, 0o600)
        result = self.run_doctor(self.case / "server/yumed.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("TLS certificate and private key do not match", result.stderr)

    def test_tls_key_check_is_separate_from_composite_identity(self) -> None:
        doctor = runpy.run_path(str(DOCTOR))
        cases = (
            (["EC", "-pkeyopt", "ec_paramgen_curve:prime256v1"], True),
            (["EC", "-pkeyopt", "ec_paramgen_curve:secp384r1"], True),
            (["EC", "-pkeyopt", "ec_paramgen_curve:secp521r1"], True),
            (["RSA", "-pkeyopt", "rsa_keygen_bits:2048"], True),
            (["RSA", "-pkeyopt", "rsa_keygen_bits:1024"], False),
            (["Ed25519"], False),
            (["EC", "-pkeyopt", "ec_paramgen_curve:secp256k1"], False),
        )
        for arguments, supported in cases:
            with self.subTest(algorithm=arguments):
                private = subprocess.run(
                    ["openssl", "genpkey", "-algorithm", *arguments],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=True, timeout=10,
                ).stdout
                public = subprocess.run(
                    ["openssl", "pkey", "-pubout", "-outform", "DER"],
                    input=private, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=True, timeout=10,
                ).stdout
                if supported:
                    doctor["_check_tls_public_key"]("openssl", public, "/tls")
                else:
                    with self.assertRaises(doctor["DoctorError"]):
                        doctor["_check_tls_public_key"]("openssl", public, "/tls")

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

    def test_duplicate_admin_identity_is_rejected_independently_of_names(self) -> None:
        doctor = runpy.run_path(str(DOCTOR))
        store_path = self.case / "server/credentials/authorized-keys.json"
        traffic = json.loads(store_path.read_text())["keys"][0]
        document = {
            "schema": 1,
            "keys": [
                {"name": name, "identity": copy.deepcopy(traffic["identity"])}
                for name in ("first-admin", "second-admin")
            ],
        }
        diagnostics = []
        with self.assertRaises(doctor["DoctorError"]) as rejected:
            doctor["_check_admin_keys"](
                "openssl", bytearray(json.dumps(document).encode()),
                store_path.parent / "admin-keys.json", set(), diagnostics,
            )
        self.assertEqual(diagnostics, [])
        self.assertEqual(
            rejected.exception.pointer,
            "/credentials/admin_keys/keys/1/identity/sha256",
        )
        self.assertIn("identity is reused by another admin key", str(rejected.exception))

    def test_authorized_identity_limit_matches_native_factory(self) -> None:
        doctor = runpy.run_path(str(DOCTOR))
        source = (ROOT / "src/providers/ytp1_security_provider.hpp").read_text()
        match = re.search(r"kMaxYtp1AuthorizedIdentities\s*=\s*(\d+)U", source)
        self.assertIsNotNone(match)
        maximum = int(match[1])
        self.assertEqual(doctor["MAX_AUTHORIZED_IDENTITIES"], maximum)
        store = {"schema": 1, "keys": [{}] * (maximum + 1)}
        with self.assertRaises(doctor["DoctorError"]) as rejected:
            doctor["_check_authorized_keys"](
                "unused", bytearray(json.dumps(store).encode()),
                self.case / "server/credentials/authorized-keys.json", {}, None, [],
            )
        self.assertEqual(rejected.exception.pointer, "/credentials/authorized_keys/keys")
        self.assertIn(f"1..{maximum} authorized keys", str(rejected.exception))

        # The separate admin store keeps its own bound. Parsing a store above
        # the traffic limit must reach the first entry, before any key work.
        self.assertGreater(doctor["MAX_ADMIN_IDENTITIES"], maximum)
        with self.assertRaises(doctor["DoctorError"]) as admin_entry:
            doctor["_check_admin_keys"](
                "unused", bytearray(json.dumps(store).encode()),
                self.case / "server/credentials/admin-keys.json", set(), [],
            )
        self.assertTrue(admin_entry.exception.pointer.startswith(
            "/credentials/admin_keys/keys/0/"
        ))

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

    def test_duplicate_authorized_identity_is_rejected(self) -> None:
        store_path = self.case / "server/credentials/authorized-keys.json"
        store = json.loads(store_path.read_text())
        duplicate = copy.deepcopy(store["keys"][0])
        duplicate["name"] = "tablet"
        duplicate_psk = store_path.parent / "authorized/tablet-access.psk"
        duplicate_psk.write_bytes(bytes(range(1, 33)))
        os.chmod(duplicate_psk, 0o600)
        duplicate["access_psk"]["file"] = "authorized/tablet-access.psk"
        store["keys"].append(duplicate)
        store_path.write_text(json.dumps(store))
        os.chmod(store_path, 0o600)

        result = self.run_doctor(self.case / "server/yumed.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "identity is reused by another authorized key", result.stderr
        )

    def test_all_zero_access_psk_is_rejected(self) -> None:
        access_psk = (
            self.case
            / "server/credentials/authorized/phone-access.psk"
        )
        access_psk.write_bytes(b"\0" * 32)
        os.chmod(access_psk, 0o600)

        result = self.run_doctor(self.case / "server/yumed.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("must not contain the all-zero secret", result.stderr)

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

    def test_cover_assets_match_the_selected_profile_and_are_required(self) -> None:
        doctor = runpy.run_path(str(DOCTOR))
        registry = json.loads((ROOT / "config/transport_profiles.json").read_text())
        selected = next(
            profile for profile in registry["profiles"]
            if profile["id"] == registry["active_profile"]
        )
        self.assertEqual(doctor["PROFILE"], selected["id"])
        profile = json.loads((
            ROOT / selected["fixture"] / selected["artifacts"]["http2_profile"]
        ).read_text())
        paths = tuple(asset["path"] for asset in profile["asset_sequence"])
        self.assertEqual(doctor["PROFILE_ASSETS"], paths)
        cover_root = self.case / "server/cover-site"
        for path in paths:
            asset = cover_root / path.removeprefix("/")
            contents = asset.read_bytes()
            try:
                asset.unlink()
                missing = self.run_doctor(self.case / "server/yumed.json")
                self.assertEqual(missing.returncode, 1)
                self.assertIn(f"/cover/root{path}", missing.stderr)
                asset.symlink_to(cover_root / "index.html")
                symlink = self.run_doctor(self.case / "server/yumed.json")
                self.assertEqual(symlink.returncode, 1)
                self.assertIn("symlink files are forbidden", symlink.stderr)
            finally:
                asset.unlink(missing_ok=True)
                asset.write_bytes(contents)
                os.chmod(asset, 0o600)

        assets = cover_root / Path(paths[0]).relative_to("/").parts[0]
        moved = cover_root / "moved-assets"
        assets.rename(moved)
        assets.symlink_to(moved, target_is_directory=True)
        result = self.run_doctor(self.case / "server/yumed.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("asset parents must be ordinary directories", result.stderr)

    def test_cover_requires_operator_not_found_page(self) -> None:
        page = self.case / "server/cover-site/404.html"
        page.unlink()
        missing = self.run_doctor(self.case / "server/yumed.json")
        self.assertEqual(missing.returncode, 1)
        self.assertIn("/cover/root/404.html", missing.stderr)
        page.write_text("<!doctype html><html><body>Missing</body></html>")
        os.chmod(page, 0o600)
        incomplete = self.run_doctor(self.case / "server/yumed.json")
        self.assertEqual(incomplete.returncode, 1)
        self.assertIn("complete static HTML cover page", incomplete.stderr)

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
