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
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SETUP = ROOT / "tools" / "yume_setup.py"
DOCTOR = ROOT / "tools" / "yume_doctor.py"


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
                "yume-doctor: configuration and credentials valid; "
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

    def test_socks5_udp_service_is_validated(self) -> None:
        client_path = self.case / "client/yume.json"
        original = json.loads(client_path.read_text())
        self.assertEqual(original["adapters"][0]["udp_service"], "udp")
        for value, expected in (
            ("tcp", "/adapters/0/udp_service: requires a packet service"),
            ("missing", "/adapters/0/udp_service: requires a packet service"),
            (
                "Udp",
                "/adapters/0/udp_service: must use lowercase ASCII namespace segments",
            ),
            (7, "/adapters/0/udp_service: must be a string"),
        ):
            document = copy.deepcopy(original)
            document["adapters"][0]["udp_service"] = value
            client_path.write_text(json.dumps(document))
            os.chmod(client_path, 0o600)
            result = self.run_doctor(client_path)
            self.assertEqual(result.returncode, 1, value)
            self.assertIn(expected, result.stderr)
        # Without udp_service the adapter refuses UDP ASSOCIATE and stays valid.
        document = copy.deepcopy(original)
        del document["adapters"][0]["udp_service"]
        client_path.write_text(json.dumps(document))
        os.chmod(client_path, 0o600)
        result = self.run_doctor(client_path)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_client_connect_address_is_validated(self) -> None:
        client_path = self.case / "client/yume.json"
        original = json.loads(client_path.read_text())
        for address, expected in (
            ("10.77.77.1", None),
            ("::1", None),
            ("server.example.test", "/endpoint/connect_address: must be an IP literal"),
            ("fe80::1%eth0", "/endpoint/connect_address: must be an IP literal"),
        ):
            document = copy.deepcopy(original)
            document["endpoint"]["connect_address"] = address
            client_path.write_text(json.dumps(document))
            os.chmod(client_path, 0o600)
            result = self.run_doctor(client_path)
            if expected is None:
                self.assertEqual(result.returncode, 0, result.stderr)
            else:
                self.assertEqual(result.returncode, 1, address)
                self.assertIn(expected, result.stderr)

        server_path = self.case / "server/yumed.json"
        server = json.loads(server_path.read_text())
        server["endpoint"]["connect_address"] = "10.77.77.1"
        server_path.write_text(json.dumps(server))
        os.chmod(server_path, 0o600)
        result = self.run_doctor(server_path)
        self.assertEqual(result.returncode, 1)
        self.assertIn("/endpoint/connect_address: unknown key", result.stderr)

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

    def test_egress_lists_match_the_native_parser(self) -> None:
        config_path = self.case / "server/yumed.json"
        original = json.loads(config_path.read_text())
        self.assertEqual(original["adapters"][0]["kind"], "direct_tcp")
        deny = {"action": "deny", "format": "vpdb", "file": "lists/vpn_db.bin"}
        item = "/adapters/0/destinations/lists/0"

        def with_item(**changes: Any) -> dict[str, Any]:
            entry = dict(deny, **changes)
            return {"lists": [{key: value for key, value in entry.items() if value is not None}]}

        cases = (
            ({"lists": True}, "/adapters/0/destinations/lists: must be an array"),
            ({"lists": ["lists/vpn_db.bin"]}, f"{item}: must be an object"),
            (with_item(action="block"), f"{item}/action: must be 'allow' or 'deny'"),
            (with_item(action="Deny"), f"{item}/action: must be 'allow' or 'deny'"),
            (with_item(format="tar.xz"), f"{item}/format: must be 'json' or 'vpdb'"),
            (with_item(format=None), f"{item}/format: required key is missing"),
            (with_item(path="x"), f"{item}/path: unknown key"),
            (with_item(file=7), f"{item}/file: must be a string"),
            (with_item(file="../vpn_db.bin"), f"{item}/file: file reference must not contain parent traversal"),
            ({"lists": [deny, deny]}, "/adapters/0/destinations/lists/1/file: duplicate list file"),
            (
                {"lists": [dict(deny, file=f"lists/{index}.bin") for index in range(17)]},
                "/adapters/0/destinations/lists: must contain at most 16 lists",
            ),
            (
                {"country_database": {"file": "GeoLite2-Country.mmdb"}},
                "/adapters/0/destinations/country_database: needs a list that names countries",
            ),
            (
                {"lists": [], "country_database": {"file": "GeoLite2-Country.mmdb"}},
                "/adapters/0/destinations/country_database: needs a list that names countries",
            ),
            (
                {"lists": [deny], "country_database": {"path": "x"}},
                "/adapters/0/destinations/country_database/path: unknown key",
            ),
        )
        for changes, expected in cases:
            with self.subTest(expected=expected):
                document = copy.deepcopy(original)
                document["adapters"][0]["destinations"].update(changes)
                config_path.write_text(json.dumps(document))
                os.chmod(config_path, 0o600)
                result = self.run_doctor(config_path)
                self.assertEqual(result.returncode, 1, expected)
                self.assertIn(expected, result.stderr)

        # The doctor checks the files the loader will open, not their contents.
        lists_dir = self.case / "server/lists"
        lists_dir.mkdir()
        (lists_dir / "vpn_db.bin").write_bytes(b"VPDB")
        (lists_dir / "allow.json").write_text('{"ips": ["8.8.8.8"]}')
        (lists_dir / "empty.json").write_text("")
        (lists_dir / "link.json").symlink_to(lists_dir / "allow.json")
        allow = {"action": "allow", "format": "json", "file": "lists/allow.json"}
        document = copy.deepcopy(original)
        document["adapters"][0]["destinations"]["lists"] = [deny, allow]
        config_path.write_text(json.dumps(document))
        os.chmod(config_path, 0o600)
        result = self.run_doctor(config_path)
        self.assertEqual(result.returncode, 0, result.stderr)

        file_cases = (
            (dict(allow, file="lists/missing.json"), "referenced file is missing or inaccessible"),
            (dict(allow, file="lists/link.json"), "symlink files are forbidden"),
            (dict(allow, file="lists/empty.json"), "file must not be empty"),
            (dict(allow, file="lists"), "must reference a regular file"),
        )
        for entry, expected in file_cases:
            with self.subTest(expected=expected):
                document = copy.deepcopy(original)
                document["adapters"][0]["destinations"]["lists"] = [deny, entry]
                config_path.write_text(json.dumps(document))
                os.chmod(config_path, 0o600)
                result = self.run_doctor(config_path)
                self.assertEqual(result.returncode, 1, expected)
                self.assertIn(f"/adapters/0/destinations/lists/1/file: {expected}", result.stderr)

        document = copy.deepcopy(original)
        document["adapters"][0]["destinations"]["lists"] = [deny]
        document["adapters"][0]["destinations"]["country_database"] = {"file": "GeoLite2-Country.mmdb"}
        config_path.write_text(json.dumps(document))
        os.chmod(config_path, 0o600)
        result = self.run_doctor(config_path)
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "/adapters/0/destinations/country_database/file: referenced file is missing or inaccessible",
            result.stderr,
        )

    def test_socks5_proxy_matches_the_native_parser(self) -> None:
        config_path = self.case / "client/yume.json"
        original = json.loads(config_path.read_text())
        pointer = "/endpoint/socks5_proxy"
        cases = (
            ("127.0.0.1:1080", f"{pointer}: must be an object"),
            ({"port": 1080}, f"{pointer}/address: required key is missing"),
            ({"address": "127.0.0.1"}, f"{pointer}/port: required key is missing"),
            ({"address": "proxy.example.test", "port": 1080}, f"{pointer}/address: must be an IP literal"),
            ({"address": "fe80::1%eth0", "port": 1080}, f"{pointer}/address: must be an IP literal"),
            ({"address": "127.0.0.1", "port": 0}, f"{pointer}/port:"),
            ({"address": "127.0.0.1", "port": 1080, "user": "x"}, f"{pointer}/user: unknown key"),
            (
                {"address": "127.0.0.1", "port": 1080, "credentials": "socks5-proxy"},
                f"{pointer}/credentials: must be an object",
            ),
            (
                {"address": "127.0.0.1", "port": 1080, "credentials": {"file": "../socks5-proxy"}},
                f"{pointer}/credentials/file: file reference must not contain parent traversal",
            ),
        )
        for proxy, expected in cases:
            with self.subTest(expected=expected):
                document = copy.deepcopy(original)
                document["endpoint"]["socks5_proxy"] = proxy
                config_path.write_text(json.dumps(document))
                os.chmod(config_path, 0o600)
                result = self.run_doctor(config_path)
                self.assertEqual(result.returncode, 1, expected)
                self.assertIn(expected, result.stderr)

        document = copy.deepcopy(original)
        document["endpoint"]["socks5_proxy"] = {"address": "::1", "port": 1080}
        config_path.write_text(json.dumps(document))
        os.chmod(config_path, 0o600)
        result = self.run_doctor(config_path)
        self.assertEqual(result.returncode, 0, result.stderr)

        # The credentials file is protected and holds exactly two lines.
        secret = self.case / "client/socks5-proxy"
        document["endpoint"]["socks5_proxy"]["credentials"] = {"file": "socks5-proxy"}
        config_path.write_text(json.dumps(document))
        os.chmod(config_path, 0o600)
        file_pointer = f"{pointer}/credentials/file"
        contents = (
            (b"user\nsecret\n", None),
            (b"user\nsecret", None),
            (b"user", "need a username line and a password line"),
            (b"user\n", "need 1 to 255 bytes each"),
            (b"\nsecret", "need 1 to 255 bytes each"),
            (b"user\r\nsecret", "must not contain a carriage return or NUL"),
            (b"user\nsecret\nextra", "hold only a username line and a password line"),
            (b"user\n" + b"p" * 256, "need 1 to 255 bytes each"),
        )
        for payload, expected in contents:
            with self.subTest(payload=payload):
                secret.write_bytes(payload)
                os.chmod(secret, 0o600)
                result = self.run_doctor(config_path)
                if expected is None:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertEqual(result.returncode, 1, expected)
                    self.assertIn(f"{file_pointer}: SOCKS5 proxy", result.stderr)
                    self.assertIn(expected, result.stderr)
                self.assertNotIn("secret", result.stderr)
        secret.write_bytes(b"user\nsecret\n")
        os.chmod(secret, 0o640)
        result = self.run_doctor(config_path)
        self.assertEqual(result.returncode, 1)
        self.assertIn(f"{file_pointer}: group/world permissions are forbidden", result.stderr)

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
        duplicate = len(client["adapters"])
        client["adapters"].append(copy.deepcopy(client["adapters"][0]))
        config_path.write_text(json.dumps(client))
        os.chmod(config_path, 0o600)
        result = self.run_doctor(config_path)
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            f"/adapters/{duplicate}/listen_port: duplicate local listen address and port",
            result.stderr,
        )

    def test_forward_adapters_match_the_native_parser(self) -> None:
        config_path = self.case / "client/yume.json"
        original = config_path.read_text()
        socks = json.loads(original)["adapters"][0]
        valid = (
            {"kind": "forward", "service": "tcp", "listen_address": "::1",
             "listen_port": 2222, "destination": {"host": "git.example.net", "port": 22}},
            {"kind": "forward", "service": "tcp",
             "listen_path": "/run/user/1000/yume/chat.sock"},
        )
        client = json.loads(original)
        client["adapters"].extend(valid)
        config_path.write_text(json.dumps(client))
        os.chmod(config_path, 0o600)
        result = self.run_doctor(config_path)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        base = {"kind": "forward", "service": "tcp"}
        invalid = (
            ({}, "listen_address", "required key is missing"),
            ({"listen_address": "0.0.0.0", "listen_port": 2222}, "listen_address", "loopback"),
            ({"listen_address": socks["listen_address"], "listen_port": socks["listen_port"]},
             "listen_port", "duplicate local listen address and port"),
            ({"listen_path": "/run/a.sock", "listen_port": 22}, "listen_port",
             "absent with listen_path"),
            ({"listen_path": "/run/../a.sock"}, "listen_path", "normalized absolute path"),
            ({"listen_path": "/" + "a" * 107}, "listen_path", ""),
            ({"listen_path": "/run/a.sock", "destination": {"host": "bad host", "port": 22}},
             "destination/host", "IP literal or DNS host name"),
            ({"listen_path": "/run/a.sock", "destination": {"host": "example.net"}},
             "destination/port", "required key is missing"),
        )
        for extra, key, message in invalid:
            client = json.loads(original)
            client["adapters"].append(dict(base, **extra))
            config_path.write_text(json.dumps(client))
            result = self.run_doctor(config_path)
            self.assertEqual(result.returncode, 1, extra)
            self.assertIn(f"/adapters/1/{key}", result.stderr)
            self.assertIn(message, result.stderr)
        config_path.write_text(original)
        server_path = self.case / "server/yumed.json"
        server = json.loads(server_path.read_text())
        server["adapters"].append(dict(base, listen_path="/run/a.sock"))
        server_path.write_text(json.dumps(server))
        result = self.run_doctor(server_path)
        self.assertEqual(result.returncode, 1)
        self.assertIn("client-only", result.stderr)

    def test_module_adapters_match_the_native_parser(self) -> None:
        server_path = self.case / "server/yumed.json"
        original = json.loads(server_path.read_text())
        original["services"].append(
            {"kind": "stream", "max_concurrent_streams": 16, "name": "echo"}
        )
        base = {"kind": "module", "service": "echo", "program": "/usr/lib/yume/echo"}
        server = copy.deepcopy(original)
        server["adapters"].append(dict(base, arguments=["--greeting", "hi"]))
        server_path.write_text(json.dumps(server))
        result = self.run_doctor(server_path)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        index = len(original["adapters"])
        invalid = (
            ({"program": "echo"}, "program", "must be a normalized absolute path"),
            ({"program": "/usr/lib/../echo"}, "program", "must be a normalized absolute path"),
            ({"arguments": "--greeting"}, "arguments", "must be an array of at most 32 strings"),
            ({"arguments": ["x"] * 33}, "arguments", "must be an array of at most 32 strings"),
            ({"arguments": ["x" * 1025]}, "arguments/0", "must be at most 1024 bytes"),
            ({"arguments": ["a\0b"]}, "arguments/0", "must not contain NUL"),
            ({"arguments": [1]}, "arguments/0", "must be a string"),
            ({"service": "tcp"}, "service", "stream service already has an adapter"),
            ({"service": "udp"}, "service", "requires a stream service"),
            ({"listen_path": "/run/a.sock"}, "listen_path", "unknown key"),
        )
        for extra, key, message in invalid:
            server = copy.deepcopy(original)
            server["adapters"].append(dict(base, **extra))
            server_path.write_text(json.dumps(server))
            result = self.run_doctor(server_path)
            self.assertEqual(result.returncode, 1, extra)
            self.assertIn(f"/adapters/{index}/{key}: {message}", result.stderr)

        # A direct_tcp adapter cannot take a stream service a module serves.
        server = copy.deepcopy(original)
        direct = next(item for item in server["adapters"] if item["kind"] == "direct_tcp")
        server["adapters"].remove(direct)
        server["adapters"].extend([dict(base, service="tcp"), direct])
        server_path.write_text(json.dumps(server))
        result = self.run_doctor(server_path)
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            f"/adapters/{index}/service: stream service already has an adapter",
            result.stderr,
        )

        client_path = self.case / "client/yume.json"
        client = json.loads(client_path.read_text())
        client["adapters"].append(dict(base, service="tcp"))
        client_path.write_text(json.dumps(client))
        result = self.run_doctor(client_path)
        self.assertEqual(result.returncode, 1)
        self.assertIn("module adapter is server-only", result.stderr)

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

    def test_max_sessions_matches_the_native_bound(self) -> None:
        # The optional per-identity bound is accepted from 1 through the
        # daemon's limit and refused outside it at its own pointer.
        source = (ROOT / "src/runtime/native_credentials.hpp").read_text()
        match = re.search(r"kMaxSessionsPerIdentity\s*=\s*(\d+)U", source)
        self.assertIsNotNone(match)
        doctor = runpy.run_path(str(DOCTOR))
        self.assertEqual(doctor["MAX_SESSIONS_PER_IDENTITY"], int(match[1]))
        store_path = self.case / "server/credentials/authorized-keys.json"
        original = store_path.read_text()
        for value, accepted in ((1, True), (int(match[1]), True), (0, False),
                                (int(match[1]) + 1, False), ("2", False), (2.0, False)):
            store = json.loads(original)
            store["keys"][0]["max_sessions"] = value
            store_path.write_text(json.dumps(store))
            os.chmod(store_path, 0o600)
            result = self.run_doctor(self.case / "server/yumed.json")
            if accepted:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            else:
                self.assertEqual(result.returncode, 1, value)
                self.assertIn("/credentials/authorized_keys/keys/0/max_sessions", result.stderr)
        store_path.write_text(original)
        os.chmod(store_path, 0o600)

    def test_egress_weight_matches_the_native_bounds(self) -> None:
        # The optional weight is a number within the limiter's bounds.
        source = (ROOT / "src/runtime/egress_limiter.hpp").read_text()
        minimum = re.search(r"kMinWeight\s*=\s*([0-9.]+);", source)
        maximum = re.search(r"kMaxWeight\s*=\s*([0-9.]+);", source)
        self.assertIsNotNone(minimum)
        self.assertIsNotNone(maximum)
        doctor = runpy.run_path(str(DOCTOR))
        self.assertEqual(doctor["MIN_WEIGHT"], float(minimum[1]))
        self.assertEqual(doctor["MAX_WEIGHT"], float(maximum[1]))
        store_path = self.case / "server/credentials/authorized-keys.json"
        original = store_path.read_text()
        for value, accepted in ((float(minimum[1]), True), (1, True), (2.5, True),
                                (float(maximum[1]), True), (0, False), (0.05, False),
                                (float(maximum[1]) + 0.5, False), ("2", False),
                                (True, False), (None, False)):
            store = json.loads(original)
            store["keys"][0]["weight"] = value
            store_path.write_text(json.dumps(store))
            os.chmod(store_path, 0o600)
            result = self.run_doctor(self.case / "server/yumed.json")
            if accepted:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            else:
                self.assertEqual(result.returncode, 1, value)
                self.assertIn("/credentials/authorized_keys/keys/0/weight", result.stderr)
        store_path.write_text(original)
        os.chmod(store_path, 0o600)

    def test_egress_rate_matches_the_native_bounds(self) -> None:
        # limits.max_egress_mbps is optional, bounded and server-only.
        source = (ROOT / "src/config/v1/config.cpp").read_text()
        match = re.search(r"kMaxEgressMbps\s*=\s*([0-9']+);", source)
        self.assertIsNotNone(match)
        maximum = int(match[1].replace("'", ""))
        doctor = runpy.run_path(str(DOCTOR))
        self.assertEqual(doctor["MAX_EGRESS_MBPS"], maximum)
        server_path = self.case / "server/yumed.json"
        original = server_path.read_text()
        for value, accepted in ((1, True), (maximum, True), (0, False),
                                (maximum + 1, False), (1.5, False), ("8", False)):
            config = json.loads(original)
            config["limits"]["max_egress_mbps"] = value
            server_path.write_text(json.dumps(config))
            result = self.run_doctor(server_path)
            if accepted:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            else:
                self.assertEqual(result.returncode, 1, value)
                self.assertIn("/limits/max_egress_mbps", result.stderr)
        server_path.write_text(original)
        client_path = self.case / "client/yume.json"
        config = json.loads(client_path.read_text())
        config["limits"]["max_egress_mbps"] = 8
        client_path.write_text(json.dumps(config))
        result = self.run_doctor(client_path)
        self.assertEqual(result.returncode, 1)
        self.assertIn("/limits/max_egress_mbps", result.stderr)
        self.assertIn("server-only", result.stderr)

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


class TunNetworkValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = runpy.run_path(str(DOCTOR))

    def validate(self, network: dict, mtu: int = 1420) -> None:
        self.module["_validate_tun_network"](network, "/network", mtu)

    def fixture(self) -> dict:
        return {"addresses": ["10.71.0.1/32"], "routes": ["10.71.0.2/32"],
                "local_networks": ["10.71.0.1/32"], "peer_networks": ["10.71.0.2/32"],
                "dns": {"servers": [], "domains": []}}

    def test_dns_requires_managed_path(self) -> None:
        network = self.fixture()
        network["dns"] = {"servers": ["10.71.0.2"], "domains": ["."]}
        self.validate(network)
        network["routes"] = []
        with self.assertRaises(self.module["DoctorError"]):
            self.validate(network)

    def test_address_policy_and_canonical_forms(self) -> None:
        for address in ("10.71.0.3/32", "127.0.0.1/32", "224.0.0.1/32", "0.0.0.0/32",
                        "10.071.0.1/32", "::ffff:a47:1/128", "10.71.0.1"):
            with self.subTest(address=address):
                network = self.fixture()
                network["addresses"] = [address]
                with self.assertRaises(self.module["DoctorError"]):
                    self.validate(network)

    def test_ipv6_mtu_and_disjoint_routes(self) -> None:
        network = self.fixture()
        network["addresses"] = ["fd71::1/64"]
        network["local_networks"] = ["fd71::/64"]
        self.validate(network)
        with self.assertRaises(self.module["DoctorError"]):
            self.validate(network, 1200)
        network = self.fixture()
        network["routes"] += ["10.71.0.0/24"]
        with self.assertRaises(self.module["DoctorError"]):
            self.validate(network)

    def test_required_fields_and_bounds(self) -> None:
        for field in self.fixture():
            network = self.fixture()
            del network[field]
            with self.subTest(field=field), self.assertRaises(self.module["DoctorError"]):
                self.validate(network)
        network = self.fixture()
        network["addresses"] *= 17
        with self.assertRaises(self.module["DoctorError"]):
            self.validate(network)


if __name__ == "__main__":
    unittest.main()
