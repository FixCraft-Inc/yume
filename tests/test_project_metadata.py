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

    def make_source_archive_fixture(self, root: pathlib.Path) -> None:
        (root / "scripts").mkdir(parents=True)
        (root / "src/core").mkdir(parents=True)
        (root / ".agents").mkdir()
        (root / ".private").mkdir()
        (root / ".secrets").mkdir()
        (root / ".pytest_cache").mkdir()
        (root / "docs/_site").mkdir(parents=True)
        (root / "nested/.secrets").mkdir(parents=True)
        (root / "website/_site").mkdir(parents=True)
        (root / "yume-bench-results").mkdir()
        shutil.copyfile(ROOT / "scripts/make_debian_orig.sh",
                        root / "scripts/make_debian_orig.sh")
        shutil.copyfile(ROOT / "scripts/check_source_archive_listing.py",
                        root / "scripts/check_source_archive_listing.py")
        (root / "src/core/version.hpp").write_text(
            'constexpr const char kVersion[] = "0.2.0-dev6";\n',
            encoding="utf-8")
        (root / "README.md").write_text("public\n", encoding="utf-8")
        (root / "CONTRIBUTING.md").write_text("public untracked\n",
                                               encoding="utf-8")
        (root / "docs/AGENTS.md").write_text(
            "component guidance\n", encoding="utf-8")
        (root / "docs/_site/manual.txt").write_text(
            "legitimate nested name\n", encoding="utf-8")
        (root / "AGENTS.md").write_text("machine local\n", encoding="utf-8")
        (root / "AI_NOTES.md").write_text("machine local\n", encoding="utf-8")
        (root / "opencode.json").write_text("{}\n", encoding="utf-8")
        (root / ".agents/example.txt").write_text("agent\n", encoding="utf-8")
        (root / ".private/handoff.md").write_text("private\n", encoding="utf-8")
        (root / ".secrets/token").write_text("secret\n", encoding="utf-8")
        (root / "nested/.secrets/credential").write_text(
            "nested secret\n", encoding="utf-8")
        (root / ".pytest_cache/CACHEDIR.TAG").write_text(
            "cache\n", encoding="utf-8")
        (root / "website/_site/index.html").write_text(
            "generated\n", encoding="utf-8")
        (root / "yume-bench-results/report.json").write_text(
            "{}\n", encoding="utf-8")
        (root / ".DS_Store").write_text("metadata\n", encoding="utf-8")

    def create_source_archive(
            self, root: pathlib.Path,
            environment_overrides: dict[str, str] | None = None) -> list[str]:
        environment = dict(os.environ)
        environment["SOURCE_DATE_EPOCH"] = "0"
        if environment_overrides:
            environment.update(environment_overrides)
        result = subprocess.run(
            ["bash", str(root / "scripts/make_debian_orig.sh")],
            check=True, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=environment)
        archive = pathlib.Path(result.stdout.strip())
        with tarfile.open(archive, "r:xz") as handle:
            return handle.getnames()

    def assert_source_archive_boundary(self, names: list[str]) -> None:
        prefix = "yume-0.2.0~dev6"
        self.assertIn(f"{prefix}/README.md", names)
        self.assertIn(f"{prefix}/docs/AGENTS.md", names)
        self.assertIn(f"{prefix}/docs/_site/manual.txt", names)
        for name in names:
            parts = pathlib.PurePosixPath(name).parts
            self.assertEqual(parts[0], prefix)
            relative = parts[1:]
            if not relative:
                continue
            self.assertNotIn(
                relative[0],
                {"AGENTS.md", "AI_NOTES.md", "opencode.json",
                 "yume-bench-results"})
            for forbidden in {
                    ".agents", ".cache", ".claude", ".codex", ".private",
                    ".pytest_cache", ".secrets", ".wrangler", ".DS_Store"}:
                self.assertNotIn(forbidden, relative)
            self.assertNotEqual(relative[:2], ("website", "_site"))

    def test_current_metadata_is_coherent(self) -> None:
        dependencies = load_dependencies()
        self.assertRegex(dependencies["basefwx"]["revision"], r"^[0-9a-f]{40}$")
        self.assertEqual(dependencies["openssl"]["minimum_version"], "3.5.0")
        self.assertEqual(
            dependencies["openssl"]["revision"],
            "8cf17aaeb4599f8af87fefd810b5b5fee90fe69e",
        )
        self.assertEqual(dependencies["openssl"]["patch_series"],
                         "patches/openssl/series")
        series = ROOT / dependencies["openssl"]["patch_series"]
        self.assertTrue(series.is_file())
        self.assertIn("0001-yume-chrome-clienthello.patch",
                      series.read_text(encoding="utf-8"))
        self.assertEqual(dependencies["liboqs"]["minimum_version"], "0.16.0")
        self.assertEqual(
            dependencies["liboqs"]["revision"],
            "5a1a854b0dc9f2141bdc771c555ee60c37950183",
        )
        profile = active_profile_metadata()
        registry = json.loads(DEFAULT_REGISTRY.read_text(encoding="utf-8"))
        self.assertEqual(profile["id"], registry["active_profile"])
        self.assertTrue(profile["fixture"].is_dir())
        self.assertTrue(profile["http2_profile"].is_file())
        self.assertTrue(profile["tls_wire_profile"].is_file())
        self.assertGreaterEqual(len(profile["tls_wire_candidates"]), 1)

    def test_product_and_transport_versions_are_coherent(self) -> None:
        version_header = (ROOT / "src/core/version.hpp").read_text(encoding="utf-8")
        self.assertIn('kVersion[] = "0.2.0-dev6"', version_header)
        self.assertIn("kTransportVersion = kVersion", version_header)
        vcpkg = json.loads((ROOT / "vcpkg.json").read_text(encoding="utf-8"))
        self.assertEqual(vcpkg["version-string"], "0.2.0-dev6")

    def test_debian_daemon_bootstrap_contract_is_complete(self) -> None:
        config = json.loads(
            (ROOT / "debian/yumed.json").read_text(encoding="utf-8"))
        self.assertEqual(config["obfs_secret_file"], "/etc/yume/obfs.hex")
        self.assertEqual(config["inner_psk_file"], "/etc/yume/inner.hex")
        self.assertRegex(
            config["real_backend"],
            r"^loopback://(?:127\.0\.0\.1|\[::1\]):[1-9][0-9]{0,4}$",
        )

        unit = (ROOT / "debian/yume-daemon.yumed.service").read_text(
            encoding="utf-8")
        for path in (config["obfs_secret_file"], config["inner_psk_file"]):
            self.assertIn(f"ConditionPathExists={path}", unit)

        readme = (ROOT / "debian/yume-daemon.README.Debian").read_text(
            encoding="utf-8")
        for required in (
                config["obfs_secret_file"], config["inner_psk_file"],
                config["real_backend"], "exactly 64 lowercase hexadecimal",
                "owned by yume, mode 0600"):
            self.assertIn(required, readme)

    def test_installed_documentation_keeps_authoritative_links(self) -> None:
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        for document in (
                "CONTRIBUTING.md", "docs/CONTROL_API.md",
                "docs/IMPLEMENTATION_STATUS.md"):
            self.assertIn(document, cmake)
        self.assertIn("install(DIRECTORY docs/", cmake)
        self.assertIn("install(DIRECTORY docs/protocol/", cmake)

        documentation_map = (ROOT / "docs/README.md").read_text(
            encoding="utf-8")
        self.assertIn("IMPLEMENTATION_STATUS.md", documentation_map)
        self.assertIn("docs/agents/", documentation_map)

    def test_website_documentation_uses_one_sync_path(self) -> None:
        sync_script = (ROOT / "scripts/sync_website_docs.sh").read_text(
            encoding="utf-8")
        for workflow_name in ("ci.yml", "pages.yml"):
            workflow = (ROOT / ".github/workflows" / workflow_name).read_text(
                encoding="utf-8")
            self.assertIn("bash scripts/sync_website_docs.sh", workflow)

        pages_workflow = (ROOT / ".github/workflows/pages.yml").read_text(
            encoding="utf-8")
        self.assertIn('"CONTRIBUTING.md"', pages_workflow)
        self.assertIn('"scripts/sync_website_docs.sh"', pages_workflow)

        self.assertIn('docs/protocol/*.md', sync_script)
        self.assertIn('CONTRIBUTING.md', sync_script)
        self.assertIn('github.com/FixCraft-Inc/yume/blob/main', sync_script)

        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("website/docs/**/*.md", gitignore)

    def test_audited_cli_help_and_man_options_are_synchronized(self) -> None:
        client_man = (ROOT / "docs/man/yume.1").read_text(encoding="utf-8")
        for option in (
                "--cluster ", "--packet-tun ", "--quick-bench",
                "--outer-carrier-evidence ", "--tls-name "):
            self.assertIn(option, client_man)

        server_help = (ROOT / "src/server/cli/help.cpp").read_text(
            encoding="utf-8")
        server_man = (ROOT / "docs/man/yumed.8").read_text(encoding="utf-8")
        self.assertIn("--admin-keys <path>", server_help)
        self.assertIn("--keys-admin", server_help)
        self.assertIn("--admin-keys ", server_man)
        self.assertIn("--keys-admin", server_man)

    def test_native_openssl_runtime_contract_is_fail_closed(self) -> None:
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertRegex(
            cmake,
            r'option\(YUME_STATIC_OPENSSL[\s\S]*?runtime libssl dependency"\s+ON\)',
        )
        self.assertIn("SSL_OP_YUME_CHROME_CLIENT_HELLO", cmake)
        self.assertIn("SSL_CTRL_YUME_CHROME_CLIENT_HELLO", cmake)
        self.assertIn("Stock libssl is not accepted for a normal build", cmake)

        package_script = (ROOT / "scripts/package_linux_release.py").read_text(
            encoding="utf-8")
        self.assertIn('"native_chrome_client_hello": True', package_script)
        self.assertIn('"patched_openssl_embedded": True', package_script)
        self.assertIn('"required_at_runtime": False', package_script)
        self.assertNotIn('"chrome_tls_helper": True,\n                "openssl_minimum"',
                         package_script)

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
        prefix = "yume-0.2.0~dev6"
        rejected = rejected_paths([
            f"{prefix}/README.md",
            f"{prefix}/docs/AGENTS.md",
            f"{prefix}/docs/_site/manual.txt",
            f"{prefix}/AGENTS.md",
            f"{prefix}/opencode.json",
            f"{prefix}/nested/.agents/task.md",
            f"{prefix}/.pytest_cache/CACHEDIR.TAG",
            f"{prefix}/yume-bench-results/run/report.json",
            f"{prefix}/.private/handoff.md",
            f"{prefix}/.secrets/token",
            f"{prefix}/nested/.secrets/credential",
            f"{prefix}/website/_site/index.html",
            f"{prefix}/docs/.DS_Store",
            f"{prefix}/../outside",
            "unexpected-root/file",
        ], prefix)
        self.assertEqual(rejected, [
            f"{prefix}/AGENTS.md",
            f"{prefix}/opencode.json",
            f"{prefix}/nested/.agents/task.md",
            f"{prefix}/.pytest_cache/CACHEDIR.TAG",
            f"{prefix}/yume-bench-results/run/report.json",
            f"{prefix}/.private/handoff.md",
            f"{prefix}/.secrets/token",
            f"{prefix}/nested/.secrets/credential",
            f"{prefix}/website/_site/index.html",
            f"{prefix}/docs/.DS_Store",
            f"{prefix}/../outside",
            "unexpected-root/file",
        ])

    def test_orig_archive_creation_excludes_secret_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "repo"
            self.make_source_archive_fixture(root)
            names = self.create_source_archive(root)
            self.assertIn("yume-0.2.0~dev6/CONTRIBUTING.md", names)
            self.assert_source_archive_boundary(names)

    def test_git_orig_archive_applies_explicit_public_path_filter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "repo"
            self.make_source_archive_fixture(root)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(
                ["git", "add", "README.md", "scripts", "src"],
                cwd=root, check=True)
            subprocess.run(
                ["git", "add", "-f", "AGENTS.md", "AI_NOTES.md",
                 "opencode.json", ".agents", ".pytest_cache",
                 "nested/.secrets", "website/_site", ".DS_Store"],
                cwd=root, check=True)
            developer_excludes = root / "developer-global-ignore"
            developer_excludes.write_text(
                "CONTRIBUTING.md\n", encoding="utf-8")
            subprocess.run(
                ["git", "config", "core.excludesFile",
                 str(developer_excludes)], cwd=root, check=True)
            names = self.create_source_archive(root)
            # Intentional non-ignored untracked public files remain part of
            # the live candidate, while even tracked local overlays do not.
            self.assertIn("yume-0.2.0~dev6/CONTRIBUTING.md", names)
            self.assert_source_archive_boundary(names)

    def test_orig_archive_creation_invokes_validator_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "repo"
            self.make_source_archive_fixture(root)
            (root / "scripts/check_source_archive_listing.py").write_text(
                "raise SystemExit(9)\n", encoding="utf-8")
            environment = dict(os.environ)
            environment["SOURCE_DATE_EPOCH"] = "0"
            result = subprocess.run(
                ["bash", str(root / "scripts/make_debian_orig.sh")],
                check=False, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(
                (root.parent / "yume_0.2.0~dev6.orig.tar.xz").exists())

    def test_orig_archive_tmpdir_inside_repo_is_not_enumerated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "repo"
            self.make_source_archive_fixture(root)
            # This validator runs while the maker's listing scratch file is
            # live. It fails the old implementation where TMPDIR caused that
            # file to exist inside the repository during validation.
            (root / "scripts/check_source_archive_listing.py").write_text(
                """import pathlib
root = pathlib.Path(__file__).resolve().parents[1]
raise SystemExit(97 if list(root.glob("tmp.*")) else 0)
""",
                encoding="utf-8")
            names = self.create_source_archive(
                root, {"TMPDIR": str(root)})
            prefix = "yume-0.2.0~dev6"
            self.assertFalse(any(
                pathlib.PurePosixPath(name).parts[0] == prefix and
                len(pathlib.PurePosixPath(name).parts) == 2 and
                pathlib.PurePosixPath(name).parts[1].startswith("tmp.")
                for name in names))
            self.assert_source_archive_boundary(names)

    def test_orig_archive_publication_refuses_directory_races(self) -> None:
        real_ln = shutil.which("ln")
        self.assertIsNotNone(real_ln)
        for mode in ("directory", "symlink"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                parent = pathlib.Path(temporary)
                root = parent / "repo"
                self.make_source_archive_fixture(root)
                tool_bin = parent / "tool-bin"
                tool_bin.mkdir()
                wrapper = tool_bin / "ln"
                wrapper.write_text(
                    """#!/usr/bin/env bash
set -euo pipefail
destination="${@: -1}"
if [[ "${YUME_TEST_LN_RACE:?}" == directory ]]; then
  mkdir -- "${destination}"
else
  mkdir -- "${destination}.target"
  "${REAL_LN:?}" -s -- "${destination}.target" "${destination}"
fi
exec "${REAL_LN}" "$@"
""",
                    encoding="utf-8")
                wrapper.chmod(0o755)
                environment = dict(os.environ)
                environment["PATH"] = (
                    str(tool_bin) + os.pathsep + environment["PATH"])
                environment["REAL_LN"] = str(real_ln)
                environment["SOURCE_DATE_EPOCH"] = "0"
                environment["YUME_TEST_LN_RACE"] = mode
                result = subprocess.run(
                    ["bash", str(root / "scripts/make_debian_orig.sh")],
                    check=False, text=True, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, env=environment)
                self.assertNotEqual(result.returncode, 0)
                archive = parent / "yume_0.2.0~dev6.orig.tar.xz"
                if mode == "directory":
                    self.assertTrue(archive.is_dir())
                else:
                    self.assertTrue(archive.is_symlink())
                self.assertEqual(list(archive.iterdir()), [])

    def test_dpkg_source_ignores_secret_roots(self) -> None:
        options = (ROOT / "debian/source/options").read_text(encoding="utf-8")
        self.assertIn(r"\.private", options)
        self.assertIn(r"\.secrets", options)
        self.assertIn(r"(^|/)\.DS_Store$", options)
        self.assertIn(r"^(AGENTS\.md|AI_NOTES\.md|opencode\.json)$", options)

        copyright_text = (ROOT / "debian/copyright").read_text(encoding="utf-8")
        self.assertIn("\n AGENTS.md\n", copyright_text)
        self.assertIn("\n opencode.json\n", copyright_text)
        self.assertIn("\n .pytest_cache\n", copyright_text)
        self.assertIn("\n .secrets\n", copyright_text)
        self.assertIn("\n .DS_Store\n", copyright_text)
        self.assertIn("\n website/_site\n", copyright_text)


if __name__ == "__main__":
    unittest.main()
