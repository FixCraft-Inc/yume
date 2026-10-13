#!/usr/bin/env python3
"""Exercise Android source qualification with real, temporary SSH signatures."""

import pathlib
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "tools/build_android_shared_abi.sh"


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
