#!/usr/bin/env python3
"""Check Android source qualification and fail-closed OpenSSL builds.

The OpenSSL cases run the real builder and patch helper in a temporary tree
with a tiny archive and mocked build commands; no NDK build or download runs.
"""

import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "tools/build_android_shared_abi.sh"


BUILD_COMMAND = r'''
import os
from pathlib import Path
import shutil
import subprocess
import sys

name = Path(sys.argv[0]).name
arguments = sys.argv[1:]

def record(step: str) -> None:
    with open(os.environ["YUME_TEST_EVENTS"], "a", encoding="utf-8") as output:
        output.write(step + "\n")

def fail_if_requested(step: str) -> None:
    if os.environ.get("YUME_TEST_FAIL_STEP") == step:
        print("fixture failure: " + step, file=sys.stderr)
        raise SystemExit(73)

if name == "tar":
    record("extract")
    subprocess.run([os.environ["YUME_TEST_REAL_TAR"], *arguments],
                   check=True, timeout=10)
    # Leave an extracted tree behind on failure, so later mocked steps could
    # succeed if the builder ignored the nonzero extraction status.
    fail_if_requested("extract")
elif name == "patch":
    patch = next(arg.split("=", 1)[1] for arg in arguments
                 if arg.startswith("--input="))
    step = "patch:" + Path(patch).name
    record(step)
    fail_if_requested(step)
    subprocess.run([os.environ["YUME_TEST_REAL_PATCH"], *arguments],
                   check=True, timeout=10)
elif name == "Configure":
    record("configure")
    prefix = next(arg.split("=", 1)[1] for arg in arguments
                  if arg.startswith("--prefix="))
    Path(".fixture-prefix").write_text(prefix, encoding="utf-8")
    fail_if_requested("configure")
elif name == "make":
    step = {"build_libs": "build", "install_dev": "install"}[arguments[-1]]
    record(step)
    if step == "install":
        prefix = Path(Path(".fixture-prefix").read_text(encoding="utf-8"))
        (prefix / "lib").mkdir(parents=True, exist_ok=True)
        for library in ("libssl.a", "libcrypto.a"):
            (prefix / "lib" / library).write_bytes(b"fixture archive\n")
    # A failed install leaves partial artifacts for the builder to remove.
    fail_if_requested(step)
elif name == "vcpkg":
    record("vcpkg")
    installed = Path(next(arg.split("=", 1)[1] for arg in arguments
                          if arg.startswith("--x-install-root=")))
    triplet = arguments[arguments.index("--triplet") + 1]
    for header in ("zlib.h", "zstd.h", "brotli/encode.h"):
        path = installed / triplet / "include" / header
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
elif name == "cmake":
    if arguments[0] == "--build":
        record("yume-build")
        library = Path(arguments[1]) / "src/libyume.so"
        library.parent.mkdir(parents=True, exist_ok=True)
        library.write_bytes(b"fixture ABI\n")
    elif arguments[:2] == ["-E", "copy"]:
        record("copy")
        shutil.copyfile(arguments[2], arguments[3])
    elif "-S" in arguments and "-B" in arguments:
        record("yume-configure")
    else:
        raise SystemExit("unexpected CMake command")
else:
    raise SystemExit("unexpected command: " + name)
'''


class AndroidOpenSslBuildTest(unittest.TestCase):
    STEPS = ["vcpkg", "extract", "patch:first.patch", "patch:second.patch",
             "configure", "build", "install", "yume-configure", "yume-build", "copy"]

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="yume android build ")
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.repo = self.root / "source"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.events = self.root / "events"
        self.work = self.root / "work"
        self.work.mkdir()
        self.real_tar = shutil.which("tar")
        self.real_patch = shutil.which("patch")
        self.assertIsNotNone(self.real_tar, "the fixture needs tar")
        self.assertIsNotNone(self.real_patch, "the fixture needs patch")

        self.builder = self.repo / "tools" / SCRIPT.name
        self.builder.parent.mkdir(parents=True)
        shutil.copyfile(SCRIPT, self.builder)
        header = self.repo / "include/yume/yume.h"
        header.parent.mkdir(parents=True)
        header.write_text("/* fixture header */\n", encoding="utf-8")

        helper = SCRIPT.parents[1] / "scripts/ensure-openssl.sh"
        helper_text = helper.read_text(encoding="utf-8")
        version = re.search(r'^YUME_OPENSSL_SOURCE_VERSION="([^"]+)"$', helper_text, re.M)
        self.assertIsNotNone(version)
        self.archive_name = f"openssl-{version.group(1)}.tar.gz"
        source = self.root / "archive-source"
        source.mkdir()
        self.write_command(source / "Configure")
        (source / "first").write_text("old\n", encoding="utf-8")
        (source / "second").write_text("old\n", encoding="utf-8")
        self.archive = self.root / self.archive_name
        with tarfile.open(self.archive, "w:gz") as archive:
            archive.add(source, arcname="openssl-fixture")

        # Only the fixture's source pin changes. Keep all helper function
        # bodies, including patch iteration and failure propagation, intact.
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        helper_text, replacements = re.subn(
            r'^YUME_OPENSSL_SOURCE_SHA256="[^"]+"$',
            f'YUME_OPENSSL_SOURCE_SHA256="{digest}"', helper_text, flags=re.M)
        self.assertEqual(replacements, 1)
        fixture_helper = self.repo / "scripts/ensure-openssl.sh"
        fixture_helper.parent.mkdir(parents=True)
        fixture_helper.write_text(helper_text, encoding="utf-8")
        patches = self.repo / "patches/openssl"
        patches.mkdir(parents=True)
        (patches / "series").write_text("first.patch\nsecond.patch\n", encoding="utf-8")
        for name in ("first", "second"):
            (patches / f"{name}.patch").write_text(
                f"--- a/{name}\n+++ b/{name}\n@@ -1 +1 @@\n-old\n+patched\n",
                encoding="utf-8")

        self.ndk = self.root / "ndk"
        toolchain = self.ndk / "build/cmake/android.toolchain.cmake"
        toolchain.parent.mkdir(parents=True)
        toolchain.touch()
        (self.ndk / "source.properties").write_text(
            "Pkg.Revision = 27.0.fixture\n", encoding="utf-8")
        self.write_command(self.ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/clang")
        self.vcpkg = self.root / "vcpkg"
        toolchain = self.vcpkg / "scripts/buildsystems/vcpkg.cmake"
        toolchain.parent.mkdir(parents=True)
        toolchain.touch()
        self.write_command(self.vcpkg / "vcpkg")
        for command in ("tar", "patch", "make", "cmake", "curl", "wget"):
            self.write_command(self.bin / command)

    def write_command(self, path: pathlib.Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"#!{sys.executable}\n" + BUILD_COMMAND, encoding="utf-8")
        path.chmod(0o700)

    def run_builder(self, output: pathlib.Path, failure: str = "") -> subprocess.CompletedProcess[str]:
        downloads = output / ".openssl/downloads"
        downloads.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.archive, downloads / self.archive_name)
        self.events.write_text("", encoding="utf-8")
        environment = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                           TMPDIR=str(self.work), YUME_TEST_EVENTS=str(self.events),
                           YUME_TEST_FAIL_STEP=failure, YUME_TEST_REAL_TAR=self.real_tar,
                           YUME_TEST_REAL_PATCH=self.real_patch)
        return subprocess.run(
            ["bash", str(self.builder), "--unverified-source", "--ndk", str(self.ndk),
             "--vcpkg", str(self.vcpkg), "--abi", "x86_64", "--out", str(output),
             "--jobs", "2"], cwd=self.repo, env=environment, capture_output=True,
            text=True, timeout=30)

    def recorded_steps(self) -> list[str]:
        return self.events.read_text(encoding="utf-8").splitlines()

    def test_each_failed_step_stops_before_publication(self) -> None:
        for failure in self.STEPS[1:7]:
            with self.subTest(step=failure):
                output = self.root / ("output-" + failure.replace(":", "-"))
                result = self.run_builder(output, failure)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("OpenSSL build failed", result.stderr)
                self.assertIn("fixture failure: " + failure, result.stderr)
                self.assertEqual(self.recorded_steps(), self.STEPS[:self.STEPS.index(failure) + 1])
                self.assertEqual(list((output / ".openssl/x86_64").glob("openssl-*")), [])
                self.assertFalse((output / "x86_64/libyume.so").exists())
                self.assertEqual(list(self.work.iterdir()), [])

    def test_success_marks_prefix_and_reuses_it(self) -> None:
        output = self.root / "output"
        result = self.run_builder(output)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.recorded_steps(), self.STEPS)
        markers = list((output / ".openssl/x86_64").glob("openssl-*/.yume-android-build"))
        self.assertEqual(len(markers), 1)
        self.assertEqual(markers[0].read_text(encoding="utf-8"), "api=28 ndk=27.0.fixture")
        for name in ("libssl.a", "libcrypto.a"):
            self.assertTrue((markers[0].parent / "lib" / name).is_file())
        self.assertTrue((output / "x86_64/libyume.so").is_file())
        self.assertEqual(list(self.work.iterdir()), [])
        result = self.run_builder(output)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.recorded_steps(), ["vcpkg", "yume-configure", "yume-build", "copy"])


class AndroidSourceProvenanceTest(unittest.TestCase):
    def test_source_qualification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yume-source-test-") as temporary:
            root = pathlib.Path(temporary)
            repo = root / "source"
            (repo / "tools").mkdir(parents=True)
            script = repo / "tools" / SCRIPT.name
            shutil.copy2(SCRIPT, script)

            def run(*args: str, success: bool = True) -> subprocess.CompletedProcess[str]:
                result = subprocess.run(args, cwd=repo, capture_output=True, text=True, timeout=30)
                if success:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                return result

            key = root / "signing-key"
            run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
            allowed = root / "allowed-signers"
            allowed.write_text("fixture@example.invalid " + key.with_suffix(".pub").read_text())
            run("git", "init", "-q")
            for name, value in {
                "user.name": "Qualification fixture", "user.email": "fixture@example.invalid",
                "gpg.format": "ssh", "user.signingkey": str(key),
                "gpg.ssh.allowedSignersFile": str(allowed),
            }.items():
                run("git", "config", name, value)
            run("git", "add", "tools")
            run("git", "commit", "-q", "-S", "-m", "Signed baseline")
            baseline = run("git", "rev-parse", "HEAD").stdout.strip()

            def check(success: bool = True, unverified: bool = False) -> None:
                arguments = ["bash", str(script), "--verify-source-only", "--expected-baseline", baseline]
                if unverified:
                    arguments.append("--unverified-source")
                run(*arguments, success=success)

            check()
            (repo / "input").write_text("unsigned\n")
            run("git", "add", "input")
            run("git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Unsigned descendant")
            check(success=False)
            check(unverified=True)
            run("git", "commit", "--allow-empty", "-q", "-S", "-m", "Signed head")
            check()
            (repo / "input").write_text("changed\n")
            check(success=False)
            check(unverified=True)
            run("git", "add", "input")
            check(success=False)
            run("git", "commit", "-q", "-S", "-m", "Signed update")
            (repo / "untracked").write_text("untracked\n")
            check(success=False)
            (repo / "untracked").unlink()
            check()
            shutil.rmtree(repo / ".git")
            check(success=False)
            check(unverified=True)


if __name__ == "__main__":
    unittest.main()
