#!/usr/bin/env python3
"""Negative tests for bounded dependency and transport-profile metadata."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import re
import runpy
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
            'inline constexpr char kVersion[] = "0.3.0-dev1";\n',
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
        prefix = "yume-0.3.0~dev1"
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
        self.assertEqual(dependencies["openssl"]["source_version"], "3.5.7")
        self.assertEqual(
            dependencies["openssl"]["revision"],
            "8cf17aaeb4599f8af87fefd810b5b5fee90fe69e",
        )
        self.assertEqual(dependencies["openssl"]["patch_series"],
                         "patches/openssl/series")
        self.assertEqual(dependencies["openssl"]["patch_license"],
                         "AGPL-3.0-or-later")
        series = ROOT / dependencies["openssl"]["patch_series"]
        self.assertTrue(series.is_file())
        self.assertIn("0001-yume-chrome-clienthello.patch",
                      series.read_text(encoding="utf-8"))
        sbom = json.loads(
            (ROOT / "docs/release/SBOM.spdx.json").read_text(encoding="utf-8")
        )
        openssl_package = next(
            package for package in sbom["packages"]
            if package["name"] == "openssl"
        )
        self.assertEqual(openssl_package["versionInfo"], "3.5.7")
        self.assertEqual(openssl_package["licenseDeclared"], "Apache-2.0")
        self.assertEqual(
            openssl_package["licenseConcluded"],
            "Apache-2.0 AND AGPL-3.0-or-later",
        )
        self.assertIn("patches/openssl/series", openssl_package["comment"])
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

    def test_reader_facing_docs_state_the_product_version(self) -> None:
        """The website and vcpkg had drift checks; the human-facing docs did
        not, so all three front-door documents drifted into calling the
        transport-v2 wire version the product version and labelling the
        binaries with it. The product version is derived here rather than
        hardcoded so a version bump forces these documents forward."""
        version_header = (ROOT / "src/core/version.hpp").read_text(encoding="utf-8")
        product = re.search(
            r'kVersion\[\]\s*=\s*"([^"]+)";', version_header
        ).group(1)
        wire = re.search(
            r'kTransportVersion\s*=\s*"([^"]+)";', version_header
        ).group(1)

        for relative in ("README.md", "docs/README.md",
                         "docs/IMPLEMENTATION_STATUS.md"):
            text = (ROOT / relative).read_text(encoding="utf-8")
            # assertTrue, not assertIn: a failed assertIn would dump the
            # whole document into the report.
            self.assertTrue(
                product in text,
                f"{relative} must state the product version {product}")
            # The wire version may appear, but only where the prose says it is
            # the transport-v2 wire. Otherwise it reads as the product version.
            for paragraph in text.split("\n\n"):
                if wire not in paragraph:
                    continue
                self.assertRegex(
                    paragraph.replace("\n", " "),
                    r"transport-v2 wire|wire `?" + re.escape(wire),
                    f"{relative} mentions {wire} without saying it is the "
                    "transport-v2 wire version")

    def test_manual_pages_state_the_product_version(self) -> None:
        """The roff header names the product a page belongs to. It carried
        the transport-v2 wire version until the front-door documents were
        corrected, so pin it to the product version as well."""
        version_header = (ROOT / "src/core/version.hpp").read_text(encoding="utf-8")
        product = re.search(
            r'kVersion\[\]\s*=\s*"([^"]+)";', version_header
        ).group(1)
        wire = re.search(
            r'kTransportVersion\s*=\s*"([^"]+)";', version_header
        ).group(1)
        for relative in ("docs/man/yume.1", "docs/man/yumed.8",
                         "docs/man/yume-gui.1"):
            first_line = (ROOT / relative).read_text(
                encoding="utf-8").splitlines()[0]
            self.assertTrue(
                first_line.startswith(".TH "),
                f"{relative} must open with a .TH header")
            self.assertIn(
                f'"YUME {product}"', first_line,
                f"{relative} header must name product version {product}")
            self.assertNotIn(
                wire, first_line,
                f"{relative} header must not carry wire version {wire}")

    def test_product_and_transport_versions_are_coherent(self) -> None:
        version_header = (ROOT / "src/core/version.hpp").read_text(encoding="utf-8")
        self.assertIn('kVersion[] = "0.3.0-dev1"', version_header)
        self.assertIn('kRuntimeTransport = "transport-v2"', version_header)
        self.assertIn('kTransportVersion = "0.2.0-dev6"', version_header)
        self.assertIn("kTransportProfile = kEvidenceProfile", version_header)
        self.assertIn('kYtpVersion = "YTP/1"', version_header)
        self.assertIn("kYtpVersionNumber = 1", version_header)
        self.assertIn('kYtpMaturity = "experimental-unwired"', version_header)
        self.assertIn("kConfigSchema = 1", version_header)
        self.assertIn("kAbiVersion = 1", version_header)
        self.assertIn('kTransportSuite = "ytp1-tls13-h2"', version_header)
        vcpkg = json.loads((ROOT / "vcpkg.json").read_text(encoding="utf-8"))
        self.assertEqual(vcpkg["version-string"], "0.3.0-dev1")

        setup = runpy.run_path(str(ROOT / "tools/yume_setup_ytp1.py"))
        doctor = runpy.run_path(str(ROOT / "tools/yume_doctor_ytp1.py"))
        self.assertEqual(setup["PRODUCT_VERSION"], "0.3.0-dev1")
        for tool in (setup, doctor):
            self.assertEqual(tool["PROFILE"], "chrome151-node24-v1")
            self.assertEqual(tool["SUITE"]["id"], "ytp1-tls13-h2")
            self.assertEqual(tool["SUITE"]["secure_channel"], "tls13-native")
            self.assertEqual(tool["SUITE"]["front_door"], "h2-web")
            self.assertEqual(tool["SUITE"]["carrier"], "h2-duplex")
            self.assertEqual(tool["SUITE"]["session"], "ytp1-hybrid")
            self.assertEqual(
                tool["IDENTITY_DOMAIN"],
                b"yume/ytp/1/composite-identity/v1",
            )

    def test_runnable_transport_and_experimental_surfaces_are_separated(self) -> None:
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertRegex(
            cmake,
            r'option\(YUME_BUILD_TRANSPORT_V2[\s\S]*?\n\s*ON\)',
        )
        self.assertRegex(
            cmake,
            r'option\(YUME_BUILD_SHARED_ABI[\s\S]*?\n\s*OFF\)',
        )
        self.assertIn("tools/yume_setup_transport_v2.py", cmake)
        self.assertIn("tools/yume_setup_ytp1.py", cmake)
        self.assertIn("YUME_INSTALL_EXPERIMENTAL_YTP1_TOOLS", cmake)
        self.assertNotIn("YUME_BUILD_LEGACY_02", cmake)

        source_cmake = (ROOT / "src/CMakeLists.txt").read_text(
            encoding="utf-8")
        self.assertIn("if(YUME_BUILD_TRANSPORT_V2)", source_cmake)
        # The build-tree-only candidate deliberately has no numbered SONAME,
        # but it still needs the normal unversioned ELF SONAME so consumers do
        # not record a build-directory-relative DT_NEEDED entry.
        self.assertNotIn("NO_SONAME ON", source_cmake)
        self.assertNotIn("SOVERSION 1", source_cmake)
        self.assertNotIn("install(TARGETS yume_abi", source_cmake)

        control = (ROOT / "debian/control").read_text(encoding="utf-8")
        rules = (ROOT / "debian/rules").read_text(encoding="utf-8")
        self.assertNotIn("Package: libyume1", control)
        self.assertNotIn("Package: libyume-dev", control)
        self.assertIn("Package: yume\n", control)
        self.assertIn("Package: yume-daemon\n", control)
        self.assertIn("-DYUME_BUILD_TRANSPORT_V2=ON", rules)
        self.assertIn("-DYUME_BUILD_SHARED_ABI=OFF", rules)
        self.assertIn("-DYUME_STATIC_OPENSSL=OFF", rules)

        debian_readme = (ROOT / "debian/README.source").read_text(
            encoding="utf-8")
        self.assertIn("deliberately fails against stock Debian", debian_readme)
        self.assertIn("patches/openssl/series", debian_readme)

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
        for document in (
                "CONTRIBUTING.md", "docs/ABI.md", "docs/WHY_YUME.md",
                "docs/protocol/YTP_1.md", "docs/IMPLEMENTATION_STATUS.md"):
            self.assertTrue((ROOT / document).is_file(), document)

        documentation_map = (ROOT / "docs/README.md").read_text(
            encoding="utf-8")
        self.assertIn("ABI.md", documentation_map)
        self.assertIn("WHY_YUME.md", documentation_map)
        self.assertIn("protocol/YTP_1.md", documentation_map)
        self.assertIn("IMPLEMENTATION_STATUS.md", documentation_map)
        self.assertIn("docs/agents/", documentation_map)

    def test_website_documentation_uses_one_sync_path(self) -> None:
        sync_script = (ROOT / "scripts/sync_website_docs.sh").read_text(
            encoding="utf-8")
        for workflow_name in ("ci.yml", "pages.yml"):
            workflow = (ROOT / ".github/workflows" / workflow_name).read_text(
                encoding="utf-8")
            self.assertIn("bash scripts/sync_website_docs.sh", workflow)
            self.assertNotIn("sync_website_docs.sh --check", workflow)

        pages_workflow = (ROOT / ".github/workflows/pages.yml").read_text(
            encoding="utf-8")
        self.assertIn('"CONTRIBUTING.md"', pages_workflow)
        self.assertIn('"scripts/sync_website_docs.sh"', pages_workflow)

        self.assertIn('docs/protocol/*.md', sync_script)
        self.assertIn('docs/release/*.md', sync_script)
        self.assertIn('docs/agents/', sync_script)
        self.assertIn('docs/man/', sync_script)
        self.assertIn('CONTRIBUTING.md', sync_script)
        self.assertIn('github.com/FixCraft-Inc/yume/blob/main', sync_script)

        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("website/docs/**/*.md", gitignore)

    def test_audited_cli_help_and_man_options_are_synchronized(self) -> None:
        client_args = (ROOT / "src/client/cli/config/args.cpp").read_text(
            encoding="utf-8")
        parser_options = set(re.findall(
            r'"(--[a-z][a-z0-9-]*)', client_args))
        help_source = (ROOT / "src/client/cli/display/help.cpp").read_text(
            encoding="utf-8")
        help_body = help_source.split("void print_help()", 1)[1]
        help_options = set(re.findall(
            r'(--[a-z][a-z0-9-]*)', help_body))
        self.assertFalse(
            parser_options - help_options,
            f"client help is missing parser options: "
            f"{sorted(parser_options - help_options)}",
        )

        client_man = (ROOT / "docs/man/yume.1").read_text(encoding="utf-8")
        for option in parser_options:
            self.assertRegex(
                client_man,
                rf"{re.escape(option)}(?![a-z0-9-])",
                f"client man page is missing option token {option}",
            )

        server_help = (ROOT / "src/server/cli/help.cpp").read_text(
            encoding="utf-8")
        server_man = (ROOT / "docs/man/yumed.8").read_text(encoding="utf-8")
        self.assertIn("--admin-keys <path>", server_help)
        self.assertIn("--keys-admin", server_help)
        self.assertIn("--tls_cert <path>", server_help)
        self.assertIn("--tls_key <path>", server_help)
        self.assertIn("--allow-exec", server_help)
        self.assertIn("--admin-keys ", server_man)
        self.assertIn("--keys-admin", server_man)
        self.assertIn("--tls_cert ", server_man)
        self.assertIn("--tls_key ", server_man)
        self.assertIn("--allow-exec", server_man)

    def test_native_openssl_runtime_contract_is_fail_closed(self) -> None:
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertRegex(
            cmake,
            r'option\(YUME_STATIC_OPENSSL[\s\S]*?runtime libssl dependency"'
            r'\s+\$\{YUME_BUILD_TRANSPORT_V2\}\)',
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

    def test_dependency_patch_metadata_is_complete_and_typed(self) -> None:
        original = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
        invalid_documents = []

        missing_license = copy.deepcopy(original)
        del missing_license["dependencies"]["openssl"]["patch_license"]
        invalid_documents.append(missing_license)

        orphan_license = copy.deepcopy(original)
        del orphan_license["dependencies"]["openssl"]["patch_series"]
        invalid_documents.append(orphan_license)

        invalid_source_version = copy.deepcopy(original)
        invalid_source_version["dependencies"]["openssl"]["source_version"] = "main"
        invalid_documents.append(invalid_source_version)

        invalid_patch_license = copy.deepcopy(original)
        invalid_patch_license["dependencies"]["openssl"]["patch_license"] = (
            "Apache-2.0 AND AGPL-3.0-or-later"
        )
        invalid_documents.append(invalid_patch_license)

        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            for index, document in enumerate(invalid_documents):
                path = self.write_json(
                    directory, f"dependencies-{index}.json", document
                )
                with self.subTest(index=index), self.assertRaises(DependencyError):
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

    def test_active_profile_must_match_evidence_profile(self) -> None:
        document = json.loads(DEFAULT_REGISTRY.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            path = self.write_json(pathlib.Path(temporary), "profiles.json", document)
            with self.assertRaises(ProfileError):
                generate(path, evidence_profile_id="different-profile-v1")

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

    def test_vendored_json_matches_its_recorded_upstream_hashes(self) -> None:
        """Vendored nlohmann files are verbatim upstream release assets.

        third_party/nlohmann_json/PROVENANCE.md records the release URL and
        sha256 of each file. Pinning them here means a local edit to a
        25,000-line amalgamation cannot pass quietly: updating is a
        re-download plus a hash update, and anything else fails. A deviation
        that ever becomes unavoidable belongs in a named patch applied on top
        of the pristine asset, the way patches/openssl/series does.
        """
        vendor = ROOT / "third_party" / "nlohmann_json"
        provenance = vendor / "PROVENANCE.md"
        self.assertTrue(provenance.is_file(), "vendored nlohmann provenance is missing")
        recorded = dict(
            re.findall(
                r"^(\S+\.hpp)\s+sha256\s+([0-9a-f]{64})$",
                provenance.read_text(encoding="utf-8"),
                re.MULTILINE,
            )
        )
        self.assertEqual(
            sorted(recorded),
            ["json.hpp", "json_fwd.hpp"],
            "PROVENANCE.md must record a sha256 for each vendored header",
        )
        for name, digest in sorted(recorded.items()):
            path = vendor / "nlohmann" / name
            self.assertTrue(path.is_file(), f"vendored {name} is missing")
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(
                actual,
                digest,
                f"{path.relative_to(ROOT)} does not match the upstream asset "
                f"recorded in PROVENANCE.md. Re-download it rather than "
                f"editing it, then update the hash.",
            )

    def test_vendored_json_tree_supplies_every_included_header(self) -> None:
        """The bundled nlohmann tree must satisfy every <nlohmann/...> include.

        third_party/nlohmann_json comes first on the include path, so any
        header it does not provide silently falls through to whatever the
        build host has installed. That mixes two versions of one library in a
        single translation unit: the bundled json.hpp declared basic_json and
        json_pointer one way while a distribution json_fwd.hpp declared them
        another, and every CI build lane failed inside the vendored header
        while developer machines whose distribution version happened to match
        built fine.
        """
        bundled = ROOT / "third_party" / "nlohmann_json" / "nlohmann"
        self.assertTrue(bundled.is_dir(), "vendored nlohmann tree is missing")
        pattern = re.compile(r"#\s*include\s*<(nlohmann/[^>]+)>")
        missing: dict[str, list[str]] = {}
        for source in list(ROOT.glob("src/**/*.[ch]pp")) + list(
            ROOT.glob("include/**/*.h*")
        ):
            for header in pattern.findall(source.read_text(encoding="utf-8", errors="ignore")):
                name = header.split("/", 1)[1]
                if not (bundled / name).is_file():
                    missing.setdefault(header, []).append(
                        str(source.relative_to(ROOT))
                    )
        self.assertEqual(
            missing,
            {},
            "these <nlohmann/...> includes are not provided by the vendored "
            "tree and resolve to whatever the host has installed: "
            + "; ".join(
                f"{header} (from {', '.join(sorted(users))})"
                for header, users in sorted(missing.items())
            ),
        )

        # The same rule one level down. Vendoring a header that itself pulls a
        # header the tree does not carry moves the fall-through rather than
        # closing it: the first attempt at this vendored the multi-header
        # json_fwd.hpp, which includes nlohmann/detail/abi_macros.hpp, and CI
        # went from a template-mismatch error to a missing-file error.
        # Commented includes are how the amalgamation records its provenance
        # and do not count.
        live = re.compile(r"^\s*#\s*include\s*<(nlohmann/[^>]+)>", re.MULTILINE)
        unsatisfied: dict[str, list[str]] = {}
        for vendored in sorted(bundled.rglob("*.hpp")):
            text = vendored.read_text(encoding="utf-8", errors="ignore")
            for header in live.findall(text):
                name = header.split("/", 1)[1]
                if not (bundled / name).is_file():
                    unsatisfied.setdefault(header, []).append(vendored.name)
        self.assertEqual(
            unsatisfied,
            {},
            "vendored nlohmann headers include headers the vendored tree does "
            "not provide, so they resolve against the host: "
            + "; ".join(
                f"{header} (from {', '.join(sorted(users))})"
                for header, users in sorted(unsatisfied.items())
            ),
        )

    def test_source_archive_rejects_private_and_malformed_paths(self) -> None:
        prefix = "yume-0.3.0~dev1"
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
            self.assertIn("yume-0.3.0~dev1/CONTRIBUTING.md", names)
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
            self.assertIn("yume-0.3.0~dev1/CONTRIBUTING.md", names)
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
                (root.parent / "yume_0.3.0~dev1.orig.tar.xz").exists())

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
            prefix = "yume-0.3.0~dev1"
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
                archive = parent / "yume_0.3.0~dev1.orig.tar.xz"
                if mode == "directory":
                    self.assertTrue(archive.is_dir())
                else:
                    self.assertTrue(archive.is_symlink())
                self.assertEqual(list(archive.iterdir()), [])

    def test_dpkg_source_ignores_secret_roots(self) -> None:
        options = (ROOT / "debian/source/options").read_text(encoding="utf-8")
        self.assertIn(r"\.private", options)
        self.assertIn(r"\.secrets", options)
        self.assertIn(r"website/docs/.*\.md", options)
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
