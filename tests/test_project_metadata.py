#!/usr/bin/env python3
"""Negative tests for bounded dependency and transport-profile metadata."""

from __future__ import annotations

import copy
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_transport_profiles import (  # noqa: E402
    DEFAULT_REGISTRY,
    ProfileError,
    active_profile_metadata,
    carrier_sections,
    generate,
)
from check_source_archive_listing import rejected_paths  # noqa: E402
from yume_dependencies import (  # noqa: E402
    DEFAULT_MANIFEST,
    DependencyError,
    load_dependencies,
)


class MetadataTests(unittest.TestCase):
    def write_json(self, directory: pathlib.Path, name: str, value: object) -> pathlib.Path:
        path = directory / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_current_metadata_is_coherent(self) -> None:
        dependencies = load_dependencies()
        self.assertRegex(dependencies["basefwx"]["revision"], r"^[0-9a-f]{40}$")
        profile = active_profile_metadata()
        registry = json.loads(DEFAULT_REGISTRY.read_text(encoding="utf-8"))
        self.assertEqual(profile["id"], registry["active_profile"])
        self.assertTrue(profile["fixture"].is_dir())
        self.assertTrue(profile["http2_profile"].is_file())
        self.assertTrue(profile["tls_wire_profile"].is_file())
        self.assertGreaterEqual(len(profile["tls_wire_candidates"]), 1)

    def test_dependency_revision_must_be_immutable(self) -> None:
        document = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
        document["dependencies"]["basefwx"]["revision"] = "main"
        with tempfile.TemporaryDirectory() as temporary:
            path = self.write_json(pathlib.Path(temporary), "dependencies.json", document)
            with self.assertRaises(DependencyError):
                load_dependencies(path)

    def test_profile_fixture_cannot_escape_repository(self) -> None:
        document = json.loads(DEFAULT_REGISTRY.read_text(encoding="utf-8"))
        document["profiles"][0]["fixture"] = "../private-profile"
        with tempfile.TemporaryDirectory() as temporary:
            path = self.write_json(pathlib.Path(temporary), "profiles.json", document)
            with self.assertRaises(ProfileError):
                generate(path)

    def test_profile_ids_and_aliases_are_unique(self) -> None:
        document = json.loads(DEFAULT_REGISTRY.read_text(encoding="utf-8"))
        duplicate = copy.deepcopy(document["profiles"][0])
        duplicate["id"] = "second-profile-v1"
        document["profiles"].append(duplicate)
        with tempfile.TemporaryDirectory() as temporary:
            path = self.write_json(pathlib.Path(temporary), "profiles.json", document)
            with self.assertRaises(ProfileError):
                generate(path)

    def test_active_profile_must_be_registered(self) -> None:
        document = json.loads(DEFAULT_REGISTRY.read_text(encoding="utf-8"))
        document["active_profile"] = "missing-profile-v1"
        with tempfile.TemporaryDirectory() as temporary:
            path = self.write_json(pathlib.Path(temporary), "profiles.json", document)
            with self.assertRaises(ProfileError):
                generate(path)

    def test_active_profile_must_match_authenticated_profile(self) -> None:
        document = json.loads(DEFAULT_REGISTRY.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            path = self.write_json(pathlib.Path(temporary), "profiles.json", document)
            with self.assertRaises(ProfileError):
                generate(path, authenticated_profile_id="different-profile-v1")

    def test_helper_build_ids_must_be_unique(self) -> None:
        document = json.loads(DEFAULT_REGISTRY.read_text(encoding="utf-8"))
        duplicate = copy.deepcopy(document["profiles"][0])
        duplicate["id"] = "second-profile-v1"
        duplicate["client_alias"] = "second"
        document["profiles"].append(duplicate)
        with tempfile.TemporaryDirectory() as temporary:
            path = self.write_json(pathlib.Path(temporary), "profiles.json", document)
            with self.assertRaisesRegex(ProfileError, "duplicate helper build ID"):
                generate(path)

    def test_current_carrier_geometry_is_exact(self) -> None:
        document = json.loads(DEFAULT_REGISTRY.read_text(encoding="utf-8"))
        fixture = ROOT / document["profiles"][0]["fixture"]
        profile_path = fixture / document["profiles"][0]["artifacts"]["http2_profile"]
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        self.assertEqual(profile["priming_get"]["stream_id"], 1)
        self.assertEqual([asset["stream_id"] for asset in profile["asset_sequence"]],
                         [3, 5])
        self.assertEqual(profile["extended_connect"]["stream_id"], 7)

    def test_unsupported_carrier_geometry_is_rejected(self) -> None:
        document = json.loads(DEFAULT_REGISTRY.read_text(encoding="utf-8"))
        fixture = ROOT / document["profiles"][0]["fixture"]
        profile_path = fixture / document["profiles"][0]["artifacts"]["http2_profile"]
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        profile["asset_sequence"][1]["stream_id"] = 9
        with self.assertRaises(ProfileError):
            carrier_sections(profile, document["profiles"][0]["id"])

    def test_profile_artifact_cannot_escape_fixture(self) -> None:
        document = json.loads(DEFAULT_REGISTRY.read_text(encoding="utf-8"))
        document["profiles"][0]["artifacts"]["http2_profile"] = "../manifest.json"
        with tempfile.TemporaryDirectory() as temporary:
            path = self.write_json(pathlib.Path(temporary), "profiles.json", document)
            with self.assertRaises(ProfileError):
                generate(path)

    def test_tls_candidates_must_be_unique(self) -> None:
        document = json.loads(DEFAULT_REGISTRY.read_text(encoding="utf-8"))
        candidates = document["profiles"][0]["artifacts"]["tls_wire_candidates"]
        candidates.append(candidates[0])
        with tempfile.TemporaryDirectory() as temporary:
            path = self.write_json(pathlib.Path(temporary), "profiles.json", document)
            with self.assertRaises(ProfileError):
                generate(path)

    def test_source_archive_rejects_private_and_malformed_paths(self) -> None:
        prefix = "yume-2.0~dev6"
        rejected = rejected_paths([
            f"{prefix}/README.md",
            f"{prefix}/.private/handoff.md",
            f"{prefix}/.secrets/token",
            f"{prefix}/nested/.secrets/credential",
            f"{prefix}/../outside",
            "unexpected-root/file",
        ], prefix)
        self.assertEqual(rejected, [
            f"{prefix}/.private/handoff.md",
            f"{prefix}/.secrets/token",
            f"{prefix}/nested/.secrets/credential",
            f"{prefix}/../outside",
            "unexpected-root/file",
        ])

    def test_orig_archive_creation_excludes_secret_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "repo"
            (root / "scripts").mkdir(parents=True)
            (root / "src/core").mkdir(parents=True)
            (root / ".private").mkdir()
            (root / ".secrets").mkdir()
            shutil.copyfile(ROOT / "scripts/make_debian_orig.sh",
                            root / "scripts/make_debian_orig.sh")
            (root / "src/core/version.hpp").write_text(
                'constexpr const char kVersion[] = "2.0-dev6";\n',
                encoding="utf-8")
            (root / "README.md").write_text("public\n", encoding="utf-8")
            (root / ".private/handoff.md").write_text("private\n", encoding="utf-8")
            (root / ".secrets/token").write_text("secret\n", encoding="utf-8")
            environment = dict(os.environ)
            environment["SOURCE_DATE_EPOCH"] = "0"
            result = subprocess.run(
                ["bash", str(root / "scripts/make_debian_orig.sh")],
                check=True, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=environment)
            archive = pathlib.Path(result.stdout.strip())
            with tarfile.open(archive, "r:xz") as handle:
                names = handle.getnames()
            self.assertIn("yume-2.0~dev6/README.md", names)
            self.assertFalse(any(".private" in pathlib.PurePosixPath(name).parts
                                 for name in names))
            self.assertFalse(any(".secrets" in pathlib.PurePosixPath(name).parts
                                 for name in names))

    def test_dpkg_source_ignores_secret_roots(self) -> None:
        options = (ROOT / "debian/source/options").read_text(encoding="utf-8")
        self.assertIn(r"\.private|\.secrets|", options)


if __name__ == "__main__":
    unittest.main()
