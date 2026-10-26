#!/usr/bin/env python3
"""Exercise build/clean exclusion without dependency or compiler work."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "ezbuild.sh"


class BuildLockTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="yume-build-lock-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        shutil.copyfile(SCRIPT, self.repo / "ezbuild.sh")
        (self.repo / "scripts/lib").mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/lib/user_context.sh",
                        self.repo / "scripts/lib/user_context.sh")
        for dependency in ("openssl", "nghttp2"):
            (self.repo / f"scripts/ensure-{dependency}.sh").write_text(
                f"yume_{dependency}_ensure() {{ return 0; }}\n")
        programs = self.root / "programs"
        programs.mkdir()
        cmake = programs / "cmake"
        cmake.write_text('#!/bin/sh\necho "$*" >> "$CMAKE_CALLS"\n')
        cmake.chmod(0o700)
        self.build = self.repo / "build"
        self.build.mkdir()
        self.sentinel = self.build / "owned-evidence"
        self.sentinel.write_text("preserve while locked\n")
        self.alias = self.repo / "alias"
        self.alias.symlink_to(self.build, target_is_directory=True)
        self.locks = self.root / "locks"
        self.locks.mkdir()
        self.calls = self.root / "cmake-calls"
        self.environment = {
            **os.environ, "YUME_SKIP_DEPS": "1", "YUME_LOCK_ROOT": str(self.locks),
            "YUME_CACHE_ROOT": str(self.root / "cache"),
            "YUME_TMP_ROOT": str(self.root / "temporary"),
            "CMAKE_CALLS": str(self.calls),
            "PATH": str(programs) + os.pathsep + os.environ["PATH"],
        }

    def invoke(self, directory: str, clean: bool = False) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(self.repo / "ezbuild.sh"), "--clean" if clean else "--no-pull"],
            cwd=self.repo, env={**self.environment, "YUME_BUILD_DIR": directory},
            text=True, capture_output=True, timeout=10, check=False)

    @contextlib.contextmanager
    def held(self):
        # Use the OS lock identity of the canonical tree, independent of the
        # spelling the invocation chooses.
        digest = hashlib.sha256(str(self.build.resolve()).encode()).hexdigest()
        with (self.locks / f"build-{digest}.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield

    def test_build_aliases_share_one_lock(self) -> None:
        with self.held():
            for directory in ("build", "./build", str(self.build), "alias", "missing/../build"):
                with self.subTest(directory=directory):
                    result = self.invoke(directory)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("is busy", result.stdout + result.stderr)
                    self.assertFalse(self.calls.exists(), "locked build still invoked CMake")

    def test_clean_uses_the_same_lock_and_preserves_evidence(self) -> None:
        with self.held():
            result = self.invoke("./build", clean=True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("is busy", result.stdout + result.stderr)
        self.assertTrue(self.sentinel.is_file(), "clean deleted an active build")

    def test_unlocked_build_and_clean_work(self) -> None:
        result = self.invoke("./build")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.calls.read_text().splitlines()), 2)
        result = self.invoke(str(self.build), clean=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.build.exists())

    def test_clean_refuses_source_and_ancestors(self) -> None:
        # Even a broken safety check must only delete this test's own tree.
        for directory in (str(self.repo), str(self.root)):
            with self.subTest(directory=directory):
                result = self.invoke(directory, clean=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("must not be the source checkout", result.stdout + result.stderr)
                self.assertTrue((self.repo / "ezbuild.sh").is_file())

    def test_unusable_shared_lock_root_fails_closed(self) -> None:
        obstacle = self.root / "not-a-directory"
        obstacle.write_text("file\n")
        self.environment["YUME_LOCK_ROOT"] = str(obstacle / "locks")
        result = self.invoke("build")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot use the shared build lock directory", result.stdout + result.stderr)
        self.assertFalse(self.calls.exists())


if __name__ == "__main__":
    unittest.main()
