#!/usr/bin/env python3
"""Exercise native release archives using compiled ELF contract fixtures."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import package_linux_release as package
import release_manifest
import release_preflight as preflight
import yume_capture_binary_provenance as provenance


class NativeReleasePackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace = tempfile.TemporaryDirectory(prefix="yume-package-test-")
        cls.addClassCleanup(cls.workspace.cleanup)
        cls.root = Path(cls.workspace.name)
        cls.version = "0.3.0-dev1"
        cls.commit = "a" * 40
        cls.transport = package.active_profile_metadata()
        source = cls.root / "fixture.c"
        source.write_text(
            '#include <stdio.h>\n'
            'int main(void) {\n'
            '  puts(PROGRAM " 0.3.0-dev1");\n'
            '  puts("transport YTP/1, config schema 1, suite ytp1-tls13-h2");\n'
            '  return 0;\n}\n', encoding="utf-8")
        for name in ("yume", "yumed", "yume-setup", "yume-doctor"):
            subprocess.run(
                ["cc", str(source), f'-DPROGRAM="{name}"', "-o", str(cls.root / name)],
                check=True, capture_output=True, text=True, timeout=30)
        for name in ("LICENSE", "NOTICES", "QUICKSTART"):
            (cls.root / name).write_text(f"Fixture {name}\n", encoding="utf-8")

    def setUp(self) -> None:
        self.output = tempfile.TemporaryDirectory(prefix="yume-package-output-")
        self.addCleanup(self.output.cleanup)
        self.output_dir = Path(self.output.name)
        self.args = argparse.Namespace(
            yume=self.root / "yume", yumed=self.root / "yumed",
            setup=self.root / "yume-setup", doctor=self.root / "yume-doctor",
            license=self.root / "LICENSE", notices=self.root / "NOTICES",
            quick_start=self.root / "QUICKSTART", output_dir=self.output_dir,
            version=self.version, source_commit=self.commit)

    def package(self) -> None:
        with mock.patch.object(package, "parse_args", return_value=self.args):
            with contextlib.redirect_stdout(io.StringIO()):
                package.main()

    def validate(self) -> dict[str, object]:
        preflight.validate_artifacts(
            self.output_dir, self.version, self.commit, self.transport)
        return preflight.validate_bundle(
            self.output_dir / package.BUNDLE_NAME,
            self.version, self.commit, self.transport)

    def rewrite_bundle(self, *, duplicate: bool = False,
                       wrong_identity: bool = False,
                       root_mode: int | None = None,
                       root_is_file: bool = False) -> None:
        bundle = self.output_dir / package.BUNDLE_NAME
        with tarfile.open(bundle, "r:xz") as original:
            entries = [(member, original.extractfile(member).read()
                        if member.isfile() else None)
                       for member in original.getmembers()]
        with tarfile.open(bundle, "w:xz", format=tarfile.PAX_FORMAT) as changed:
            for member, payload in entries:
                if member.name == package.BUNDLE_DIRECTORY:
                    if root_mode is not None:
                        member.mode = root_mode
                    if root_is_file:
                        member.type = tarfile.REGTYPE
                        member.size = 0
                        payload = b""
                if wrong_identity and member.name.endswith("/manifest.json"):
                    manifest = json.loads(payload)
                    manifest["transport"] = "transport-v2"
                    payload = json.dumps(manifest).encode()
                    member.size = len(payload)
                changed.addfile(member, io.BytesIO(payload) if payload is not None else None)
                if duplicate and member.name.endswith("/yume"):
                    changed.addfile(member, io.BytesIO(payload))

    def test_native_package_roundtrip_and_reproducible_archive(self) -> None:
        self.package()
        first = (self.output_dir / package.BUNDLE_NAME).read_bytes()
        manifest = self.validate()
        self.assertEqual(manifest["transport"], "YTP/1")
        names = {entry["file"] for entry in manifest["files"]}
        self.assertIn("yume-setup", names)
        self.assertIn("yume-doctor", names)
        self.assertNotIn("yume-chrome-tls-helper", names)
        self.assertNotIn("argon2", manifest["required_features"])
        self.package()
        self.assertEqual(first, (self.output_dir / package.BUNDLE_NAME).read_bytes())

    def test_reference_binary_identity_is_rejected(self) -> None:
        with mock.patch.object(package, "version_output", return_value=(
                f"yume {self.version}\ntransport-v2 wire 0.2.0-dev6")):
            with self.assertRaisesRegex(SystemExit, "not the native"):
                self.package()
        self.assertEqual(list(self.output_dir.iterdir()), [])

    def test_missing_provisioner_is_rejected(self) -> None:
        self.args.setup = self.root / "absent-tool"
        with self.assertRaisesRegex(SystemExit, "Missing regular schema-1 setup"):
            self.package()

    def test_script_provisioner_is_rejected(self) -> None:
        # A release ships native setup and doctor programs, never a script
        # that needs an interpreter and an openssl command at run time.
        script = self.root / "yume-doctor.py"
        script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        script.chmod(0o755)
        self.args.doctor = script
        with self.assertRaisesRegex(SystemExit, "schema-1 doctor program is not ELF"):
            self.package()
        self.assertEqual(list(self.output_dir.iterdir()), [])

    def test_duplicate_archive_member_is_rejected(self) -> None:
        self.package()
        self.rewrite_bundle(duplicate=True)
        with self.assertRaisesRegex(SystemExit, "unexpected files"):
            self.validate()

    def test_unsafe_archive_root_is_rejected(self) -> None:
        for changes in ({"root_mode": 0o777}, {"root_is_file": True}):
            with self.subTest(changes=changes):
                self.package()
                self.rewrite_bundle(**changes)
                with self.assertRaisesRegex(SystemExit, "root"):
                    self.validate()

    def test_reference_manifest_identity_is_rejected(self) -> None:
        self.package()
        self.rewrite_bundle(wrong_identity=True)
        with self.assertRaisesRegex(SystemExit, "native schema-1"):
            self.validate()

    def test_changed_server_is_rejected(self) -> None:
        self.package()
        with (self.output_dir / package.SERVER_NAME).open("ab") as handle:
            handle.write(b"tampered")
        with self.assertRaisesRegex(SystemExit, "SHA-256 mismatch|size mismatch"):
            self.validate()

    def test_capture_provenance_uses_native_bundle_contract(self) -> None:
        self.package()
        with mock.patch.object(provenance, "source_version", return_value=self.version):
            digests = provenance.validate_capture_binaries(
                self.output_dir / package.BUNDLE_NAME, self.args.yume, self.args.yumed,
                self.commit)
        self.assertEqual(digests, (package.sha256_file(self.args.yume),
                                   package.sha256_file(self.args.yumed)))

    def test_release_index_does_not_invent_library_features(self) -> None:
        self.package()
        bundle_manifest = self.validate()
        manifest = release_manifest.build_manifest(self.output_dir, None)
        entries = {entry["file"]: entry for entry in manifest["files"]}
        self.assertEqual(set(entries), {package.BUNDLE_NAME, package.SERVER_NAME})
        for name, component, linkage in (
                (package.BUNDLE_NAME, "yume", "bundle"),
                (package.SERVER_NAME, "yumed", "dynamic")):
            with self.subTest(artifact=name):
                entry = entries[name]
                self.assertEqual(entry["component"], component)
                self.assertEqual(entry["arch"], "amd64")
                self.assertEqual(entry["os"], "linux")
                self.assertEqual(entry["linkage"], linkage)
                self.assertEqual(entry["sha256"],
                                 package.sha256_file(self.output_dir / name))
                self.assertNotIn("features", entry)
        # The validated package contract owns primitive support. Native PQ
        # support does not establish an Argon2, liboqs or liblzma dependency.
        self.assertTrue(bundle_manifest["required_features"]["post_quantum"])


class NativeLaneGuardTests(unittest.TestCase):
    """The CI lanes that build the native graph embed the patched OpenSSL."""

    SETUP = ("source scripts/ensure-openssl.sh\n"
             "          yume_openssl_ensure\n"
             "          source scripts/ensure-nghttp2.sh\n"
             "          yume_nghttp2_ensure")

    def lane(self, *options: str, setup: bool = True) -> str:
        text = (self.SETUP + "\n") if setup else ""
        body = " \\\n            ".join(options)
        return text + "          cmake -S . -B build \\\n            " + body + "\n"

    def native(self) -> str:
        return "".join(self.lane("-DYUME_STATIC_OPENSSL=ON") for _ in range(3))

    def test_three_native_lanes_pass(self) -> None:
        preflight.check_native_lanes(self.native(), self.SETUP)

    def test_a_gui_lane_needs_no_openssl(self) -> None:
        gui = self.lane("-DYUME_BUILD_NATIVE_APPLICATION=OFF", "-DYUME_BUILD_GUI=ON",
                        setup=False)
        preflight.check_native_lanes(self.native() + gui, self.SETUP)

    def test_a_native_lane_without_openssl_is_refused(self) -> None:
        bare = self.lane("-DYUME_BUILD_GUI=ON", setup=False)
        with self.assertRaises(SystemExit):
            preflight.check_native_lanes(self.native() + bare, self.SETUP)
        unembedded = self.lane("-DYUME_STATIC_OPENSSL=OFF")
        with self.assertRaises(SystemExit):
            preflight.check_native_lanes(self.native() + unembedded, self.SETUP)

    def test_a_lane_without_the_application_builds_no_shared_abi(self) -> None:
        abi = self.lane("-DYUME_BUILD_NATIVE_APPLICATION=OFF", "-DYUME_BUILD_SHARED_ABI=ON",
                        setup=False)
        with self.assertRaises(SystemExit):
            preflight.check_native_lanes(self.native() + abi, self.SETUP)

    def test_the_real_workflow_passes(self) -> None:
        ci_yml = (preflight.ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        preflight.check_native_lanes(ci_yml, self.SETUP)


class DependencyFallbackTests(unittest.TestCase):
    """The source fallbacks stop at the first failed step and leave no prefix.

    Their callers test the fallback's status, which turns set -e off inside
    it, so each run reproduces that context with ``|| echo refused``. Fake
    curl, make and cmake stand in for the network and the builds.
    """

    CURL = """#!/bin/sh
[ -n "$FAKE_TARBALL" ] || exit 22
while [ $# -gt 1 ]
do
    if [ "$1" = "--output" ]
    then
        exec cp "$FAKE_TARBALL" "$2"
    fi
    shift
done
exit 22
"""
    # OpenSSL: Configure records the prefix, the build passes and install_sw
    # fails after creating part of the prefix.
    CONFIGURE = """#!/bin/sh
for arg in "$@"
do
    if [ "${arg#--prefix=}" != "$arg" ]
    then
        printf '%s\\n' "${arg#--prefix=}" > prefix.txt
    fi
done
"""
    MAKE = """#!/bin/sh
if [ "$1" = "install_sw" ]
then
    mkdir -p "$(cat prefix.txt)/ssl" "$(cat prefix.txt)/bin"
    exit 2
fi
"""
    # nghttp2: configuring and building pass, installing fails after writing
    # the pkg-config file that detection reads.
    CMAKE = """#!/bin/sh
if [ "$1" = "-S" ]
then
    mkdir -p "$4"
    for arg in "$@"
    do
        if [ "${arg#-DCMAKE_INSTALL_PREFIX=}" != "$arg" ]
        then
            printf '%s\\n' "${arg#-DCMAKE_INSTALL_PREFIX=}" > "$4/prefix.txt"
        fi
    done
elif [ "$1" = "--install" ]
then
    mkdir -p "$(cat "$2/prefix.txt")/lib/pkgconfig"
    touch "$(cat "$2/prefix.txt")/lib/pkgconfig/libnghttp2.pc"
    exit 2
fi
"""

    def fallback(self, script: str, hash_name: str, call: str,
                 source: dict[str, str] | None) -> tuple[str, list[str]]:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            for name, text in (("curl", self.CURL), ("make", self.MAKE), ("cmake", self.CMAKE)):
                (bin_dir / name).write_text(text, encoding="utf-8")
                (bin_dir / name).chmod(0o700)
            env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": temp, "TMPDIR": temp}
            digest = "0" * 64
            if source is not None:
                tarball = root / "source.tar.gz"
                with tarfile.open(tarball, "w:gz") as archive:
                    for name, text in source.items():
                        data = text.encode("utf-8")
                        info = tarfile.TarInfo(f"source/{name}")
                        info.size = len(data)
                        info.mode = 0o755
                        archive.addfile(info, io.BytesIO(data))
                env["FAKE_TARBALL"] = str(tarball)
                digest = hashlib.sha256(tarball.read_bytes()).hexdigest()
            cache = root / "cache"
            text = f"source {script}\n{hash_name}={digest}\n{call} || echo refused\n"
            result = subprocess.run(["bash", "-c", text, "fallback", str(cache)],
                                    cwd=preflight.ROOT, env=env, capture_output=True,
                                    text=True, timeout=60, check=False)
            return result.stdout + result.stderr, sorted(p.name for p in cache.iterdir())

    def openssl(self, source: dict[str, str] | None) -> tuple[str, list[str]]:
        prefix = '"$1/openssl-${YUME_OPENSSL_SOURCE_VERSION}-test"'
        return self.fallback("scripts/ensure-openssl.sh", "YUME_OPENSSL_SOURCE_SHA256",
                             f'yume_openssl_build_fallback "$1" {prefix} /nonexistent', source)

    def nghttp2(self, source: dict[str, str] | None) -> tuple[str, list[str]]:
        return self.fallback("scripts/ensure-nghttp2.sh", "YUME_NGHTTP2_SOURCE_SHA256",
                             'yume_nghttp2_build_fallback "$1" "$1/nghttp2-test"', source)

    def test_a_failed_download_is_named(self) -> None:
        for label, run in (("OpenSSL", self.openssl), ("nghttp2", self.nghttp2)):
            output, entries = run(None)
            self.assertIn(f"Could not download the {label}", output)
            self.assertIn("refused", output)
            self.assertNotIn("sha256sum or shasum", output)
            self.assertEqual(entries, ["downloads", "locks"])

    def test_a_failed_openssl_install_fails_and_leaves_no_prefix(self) -> None:
        output, entries = self.openssl({"Configure": self.CONFIGURE,
                                        "apps/openssl.cnf": "# fake\n"})
        self.assertIn("The OpenSSL 3.5.7 build failed", output)
        self.assertIn("refused", output)
        self.assertEqual(entries, ["downloads", "locks"])

    def test_a_failed_nghttp2_install_fails_and_leaves_no_prefix(self) -> None:
        output, entries = self.nghttp2({"CMakeLists.txt": "# fake\n"})
        self.assertIn("build failed", output)
        self.assertIn("refused", output)
        self.assertEqual(entries, ["downloads", "locks"])


if __name__ == "__main__":
    unittest.main()
