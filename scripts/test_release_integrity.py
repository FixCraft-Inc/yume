#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import release_integrity as integrity
import release_preflight as preflight


TAG = "v0.3.0-rc1"
REPOSITORY = "fixture/yume"


class ReleaseIntegrityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="yume-release-integrity-test-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.base = pathlib.Path(cls.temporary.name)
        cls.keyring = cls.base / "keys"
        cls.keyring.mkdir(mode=0o700)
        cls.environment = integrity.command_env(cls.keyring)
        cls.addClassCleanup(cls.cleanup_keyring)
        for identity in ("Trusted Fixture <trusted@example.invalid>",
                         "Foreign Fixture <foreign@example.invalid>"):
            cls.execute(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase-fd", "0",
                         "--quick-generate-key", identity, "ed25519", "sign", "0"],
                        data=b"fixture passphrase\n" if identity.startswith("Trusted") else b"\n")
        keys = cls.execute(["gpg", "--with-colons", "--list-keys"]).decode()
        cls.trusted, cls.foreign = [line.split(":")[9] for line in keys.splitlines()
                                    if line.startswith("fpr:")]
        cls.private_key = cls.execute(["gpg", "--batch", "--pinentry-mode", "loopback",
                                       "--passphrase-fd", "0", "--armor", "--export-secret-keys",
                                       cls.trusted], data=b"fixture passphrase\n").decode()
        cls.foreign_key = cls.execute(["gpg", "--batch", "--armor", "--export-secret-keys",
                                       cls.foreign]).decode()
        signer = cls.base / "fixture-signer"
        signer.write_text(f"#!{sys.executable}\n" + '''import os
import subprocess
import sys

read_fd, write_fd = os.pipe()
os.write(write_fd, b"fixture passphrase\\n")
os.close(write_fd)
try:
    result = subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback",
                             "--passphrase-fd", str(read_fd), *sys.argv[1:]],
                            pass_fds=(read_fd,), timeout=30, check=False)
finally:
    os.close(read_fd)
raise SystemExit(result.returncode)
''')
        signer.chmod(0o755)
        cls.template = cls.base / "template"
        cls.execute(["git", "init", "-q", str(cls.template)])
        cls.git_at(cls.template, "config", "user.name", "Release Fixture")
        cls.git_at(cls.template, "config", "user.email", "release@example.invalid")
        cls.git_at(cls.template, "config", "user.signingkey", cls.trusted)
        cls.git_at(cls.template, "config", "gpg.program", str(signer))
        cls.git_at(cls.template, "remote", "add", "origin", f"https://github.com/{REPOSITORY}")
        public_key = cls.template / integrity.PUBLIC_KEY
        public_key.parent.mkdir(parents=True)
        public_key.write_bytes(cls.execute(["gpg", "--armor", "--export", cls.trusted]))
        cls.git_at(cls.template, "add", ".")
        cls.git_at(cls.template, "commit", "-q", "-S", "-m", "Signed fixture")
        cls.git_at(cls.template, "tag", "-s", "-m", "Signed release fixture", TAG)

    @classmethod
    def cleanup_keyring(cls) -> None:
        subprocess.run(["gpgconf", "--homedir", str(cls.keyring), "--kill", "gpg-agent"],
                       env=cls.environment, check=True, timeout=10,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def execute(cls, command: list[str], *, data: bytes | None = None) -> bytes:
        result = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=cls.environment, timeout=30, check=False)
        if result.returncode:
            raise AssertionError(f"Fixture command failed: {command[0]}")
        return result.stdout

    @classmethod
    def git_at(cls, root: pathlib.Path, *arguments: str) -> str:
        return cls.execute(["git", "-C", str(root), *arguments]).decode().strip()

    def setUp(self) -> None:
        self.work = pathlib.Path(tempfile.mkdtemp(dir=self.base, prefix="case-"))
        self.addCleanup(shutil.rmtree, self.work)
        self.root = self.work / "repo"
        shutil.copytree(self.template, self.root)
        self.artifacts = self.work / "artifacts"
        self.artifacts.mkdir()
        for name in integrity.EXPECTED_ARTIFACTS:
            (self.artifacts / name).write_bytes(f"fixture for {name}\n".encode())
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(integrity, "TRUSTED_FINGERPRINT", self.trusted).start()
        mock.patch.dict(os.environ, {"GPG_PRIVATE_KEY": self.private_key,
                                     "GPG_PASSPHRASE": "fixture passphrase"}).start()

    def git(self, *arguments: str) -> str:
        return self.git_at(self.root, *arguments)

    def retag(self, *, signed: bool = True, identity: str | None = None,
              target: str | None = None) -> None:
        self.git("tag", "-d", TAG)
        arguments = ["tag", "-s" if signed else "-a", "-m", "Replacement fixture"]
        if identity is not None:
            arguments.extend(("-u", identity))
        arguments.append(TAG)
        if target is not None:
            arguments.append(target)
        self.git(*arguments)

    def sign(self) -> None:
        integrity.sign_artifacts(self.root, self.artifacts, TAG)

    def fake_github(self, *, conflict: str | None = None, late_conflict: bool = False,
                    moved_tag: bool = False, upload_failure: bool = False,
                    second_page: bool = False) -> None:
        """Run the real helper against a local gh stand-in, recording every call."""
        bin_directory = self.work / "bin"
        bin_directory.mkdir()
        state = self.work / "github-state.json"
        state.write_text(json.dumps({
            "calls": [], "asset_reads": 0, "tag_object": self.git("rev-parse", f"refs/tags/{TAG}"),
            "tag": TAG, "conflict": conflict, "late_conflict": late_conflict,
            "moved_tag": moved_tag, "upload_failure": upload_failure, "second_page": second_page,
        }))
        executable = bin_directory / "gh"
        executable.write_text("""#!/usr/bin/env python3
import json
import os
import pathlib
import sys

state_path = pathlib.Path(os.environ["YUME_FAKE_GH_STATE"])
state = json.loads(state_path.read_text())
arguments = sys.argv[1:]
state["calls"].append(arguments)
response = None
exit_code = 0
if arguments[:2] == ["release", "upload"]:
    exit_code = 1 if state["upload_failure"] else 0
elif arguments[0] != "api":
    exit_code = 2
elif "/git/ref/tags/" in arguments[1]:
    response = {"ref": "refs/tags/" + state["tag"], "object": {
        "type": "tag", "sha": "0" * 40 if state["moved_tag"] else state["tag_object"]}}
elif "/releases/tags/" in arguments[1]:
    response = {"id": 17, "tag_name": state["tag"]}
elif "/releases/17/assets?" in arguments[1]:
    page = int(arguments[1].rsplit("=", 1)[1])
    if page == 1:
        state["asset_reads"] += 1
    conflict = state["conflict"]
    if state["late_conflict"] and state["asset_reads"] < 2:
        conflict = None
    if state["second_page"] and page == 1:
        response = [{"id": i, "name": "unrelated-" + str(i)} for i in range(100)]
    else:
        response = [{"id": 1001, "name": conflict}] if conflict else []
else:
    exit_code = 2
state_path.write_text(json.dumps(state))
if response is not None:
    print(json.dumps(response))
sys.exit(exit_code)
""")
        executable.chmod(0o755)
        patcher = mock.patch.dict(os.environ, {
            "PATH": str(bin_directory) + os.pathsep + os.environ["PATH"],
            "YUME_FAKE_GH_STATE": str(state),
        })
        patcher.start()
        self.addCleanup(patcher.stop)

    def github_calls(self) -> list[list[str]]:
        return json.loads((self.work / "github-state.json").read_text())["calls"]

    def assert_no_upload(self) -> None:
        self.assertFalse(any(call[:2] == ["release", "upload"] for call in self.github_calls()))

    def test_accepts_trusted_signed_source_and_publication(self) -> None:
        expected = self.git("rev-parse", f"refs/tags/{TAG}")
        self.assertEqual(integrity.verify_source(self.root, TAG), expected)
        self.sign()
        self.fake_github()
        integrity.upload_artifacts(self.root, self.artifacts, TAG, REPOSITORY)
        uploads = [call for call in self.github_calls() if call[:2] == ["release", "upload"]]
        self.assertEqual(uploads, [["release", "upload", TAG,
                                   *(str(self.artifacts / name) for name in integrity.PUBLISHED_FILES),
                                   "--repo", "github.com/" + REPOSITORY]])
        manifest = json.loads((self.artifacts / "release-manifest.json").read_text())
        self.assertTrue(all(row["signature"] for row in manifest["files"]))

    def test_rejects_missing_private_key_before_signing(self) -> None:
        with mock.patch.dict(os.environ, {"GPG_PRIVATE_KEY": ""}):
            with self.assertRaisesRegex(SystemExit, "GPG_PRIVATE_KEY is required"):
                self.sign()
        self.assertEqual({p.name for p in self.artifacts.iterdir()}, set(integrity.EXPECTED_ARTIFACTS))

    def test_rejects_foreign_private_key(self) -> None:
        with mock.patch.dict(os.environ, {"GPG_PRIVATE_KEY": self.foreign_key}):
            with self.assertRaisesRegex(SystemExit, "trusted primary identity"):
                self.sign()

    def test_rejects_wrong_passphrase_for_protected_private_key(self) -> None:
        with mock.patch.dict(os.environ, {"GPG_PASSPHRASE": "wrong fixture passphrase"}):
            with self.assertRaisesRegex(SystemExit, "Sign release asset .* failed"):
                self.sign()
        self.assertFalse((self.artifacts / "release-manifest.json").exists())

    def test_rejects_lightweight_and_unsigned_tags(self) -> None:
        self.git("tag", "-d", TAG)
        self.git("tag", TAG)
        with self.assertRaisesRegex(SystemExit, "annotated and signed"):
            integrity.verify_source(self.root, TAG)
        self.retag(signed=False)
        with self.assertRaisesRegex(SystemExit, "Trusted verify-tag failed"):
            integrity.verify_source(self.root, TAG)

    def test_rejects_nested_and_alias_tags(self) -> None:
        self.git("tag", "-s", "-m", "Inner", "inner")
        self.retag(target="inner")
        with self.assertRaisesRegex(SystemExit, "point directly"):
            integrity.verify_source(self.root, TAG)
        self.git("update-ref", f"refs/tags/{TAG}", self.git("rev-parse", "refs/tags/inner"))
        with self.assertRaisesRegex(SystemExit, "name and point directly"):
            integrity.verify_source(self.root, TAG)

    def test_rejects_foreign_tag_signature(self) -> None:
        self.retag(identity=self.foreign)
        with self.assertRaisesRegex(SystemExit, "Trusted verify-tag failed"):
            integrity.verify_source(self.root, TAG)

    def test_preflight_rejects_unsigned_release_tag(self) -> None:
        with mock.patch.object(preflight, "ROOT", self.root):
            commit = self.git("rev-parse", "HEAD")
            preflight.validate_tag(TAG, "0.3.0-rc1", commit)
            self.retag(signed=False)
            with self.assertRaisesRegex(SystemExit, "Trusted verify-tag failed"):
                preflight.validate_tag(TAG, "0.3.0-rc1", commit)

    def test_ignores_repository_and_inherited_signature_verifier_settings(self) -> None:
        marker = self.work / "fake-verifier-ran"
        verifier = self.work / "fake-gpg"
        verifier.write_text("#!/usr/bin/env python3\nimport pathlib\n"
                            f"pathlib.Path({str(marker)!r}).touch()\nraise SystemExit(1)\n")
        verifier.chmod(0o755)
        self.git("config", "gpg.openpgp.program", str(verifier))
        global_config = self.work / "global.gitconfig"
        global_config.write_text(f"[gpg]\n\tformat = ssh\n\tprogram = {verifier}\n")
        hostile_environment = {
            "GIT_CONFIG_GLOBAL": str(global_config), "GIT_CONFIG_SYSTEM": str(global_config),
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "gpg.format", "GIT_CONFIG_VALUE_0": "ssh",
            "GIT_DIR": str(self.work / "wrong-repository"),
        }
        with mock.patch.dict(os.environ, hostile_environment):
            integrity.verify_source(self.root, TAG)
        self.assertFalse(marker.exists())

    def test_rejects_unsigned_and_foreign_commits(self) -> None:
        self.git("commit", "--allow-empty", "-q", "--no-gpg-sign", "-m", "Unsigned")
        self.retag()
        with self.assertRaisesRegex(SystemExit, "Trusted verify-commit failed"):
            integrity.verify_source(self.root, TAG)
        self.git("-c", f"user.signingkey={self.foreign}", "commit", "--allow-empty", "-q",
                 "-S", "-m", "Foreign signed")
        self.retag()
        with self.assertRaisesRegex(SystemExit, "Trusted verify-commit failed"):
            integrity.verify_source(self.root, TAG)

    def test_rejects_branch_name_and_commit_mismatch(self) -> None:
        self.git("tag", "-d", TAG)
        self.git("branch", TAG)
        with self.assertRaisesRegex(SystemExit, "Git source inspection failed"):
            integrity.verify_source(self.root, TAG)
        self.git("tag", "-s", "-m", "Signed tag", TAG)
        self.git("commit", "--allow-empty", "-q", "-S", "-m", "Later signed")
        with self.assertRaisesRegex(SystemExit, "point directly"):
            integrity.verify_source(self.root, TAG)

    def test_rejects_replaced_tracked_public_key(self) -> None:
        (self.root / integrity.PUBLIC_KEY).write_bytes(
            self.execute(["gpg", "--armor", "--export", self.foreign]))
        self.git("add", ".")
        self.git("commit", "-q", "-S", "-m", "Replace public key")
        self.retag()
        with self.assertRaisesRegex(SystemExit, "not the trusted identity"):
            integrity.verify_source(self.root, TAG)

    def test_rejects_tag_moved_during_verification(self) -> None:
        original_git = integrity.git
        reads = 0

        def move_ref(root: pathlib.Path, *arguments: str) -> str:
            nonlocal reads
            result = original_git(root, *arguments)
            if arguments == ("rev-parse", "--verify", f"refs/tags/{TAG}"):
                reads += 1
                if reads == 2:
                    return "0" * 40
            return result

        with mock.patch.object(integrity, "git", side_effect=move_ref):
            with self.assertRaisesRegex(SystemExit, "tag moved"):
                integrity.verify_source(self.root, TAG)

    def test_keeps_passphrase_off_argv_and_secrets_out_of_child_environment(self) -> None:
        original_run = subprocess.run
        observed_signatures = []

        def inspect(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            self.assertNotIn("fixture passphrase", command)
            env = kwargs.get("env", {})
            self.assertTrue("GPG_PRIVATE_KEY" not in env, "Private key inherited by subprocess")
            self.assertTrue("GPG_PASSPHRASE" not in env, "Passphrase inherited by subprocess")
            if "--detach-sign" in command:
                self.assertIn("--passphrase-fd", command)
                self.assertEqual(kwargs["input"], b"fixture passphrase\n")
                home = pathlib.Path(command[command.index("--homedir") + 1])
                self.assertEqual(home.stat().st_mode & 0o777, 0o700)
                observed_signatures.append(home)
            return original_run(command, **kwargs)

        with mock.patch.object(integrity.subprocess, "run", side_effect=inspect):
            self.sign()
        self.assertEqual(len(observed_signatures), len(integrity.SIGNED_FILES))
        self.assertTrue(all(not home.exists() for home in observed_signatures))

    def test_rejects_corrupt_signatures_before_network_writes(self) -> None:
        self.sign()
        self.fake_github()
        for name in integrity.SIGNED_FILES:
            with self.subTest(name=name):
                signature = self.artifacts / f"{name}.sig"
                original = signature.read_bytes()
                signature.write_bytes(b"not a valid OpenPGP signature\n")
                with self.assertRaisesRegex(SystemExit, "Verify release signature"):
                    integrity.upload_artifacts(self.root, self.artifacts, TAG, REPOSITORY)
                signature.unlink()
                self.execute(["gpg", "--batch", "--local-user", self.foreign, "--armor",
                              "--detach-sign", "--output", str(signature), str(self.artifacts / name)])
                with self.assertRaisesRegex(SystemExit, "Verify release signature"):
                    integrity.upload_artifacts(self.root, self.artifacts, TAG, REPOSITORY)
                signature.write_bytes(original)
                self.assert_no_upload()
        self.assertEqual(self.github_calls(), [])

    def test_rejects_changed_manifest_before_network_writes(self) -> None:
        self.sign()
        self.fake_github()
        manifest = self.artifacts / "release-manifest.json"
        original = manifest.read_bytes()
        manifest.write_bytes(original.replace(b'"release_tag": "v0.3.0-rc1"',
                                              b'"release_tag": "v0.3.0-rc2"'))
        with self.assertRaises(SystemExit):
            integrity.upload_artifacts(self.root, self.artifacts, TAG, REPOSITORY)
        self.assertEqual(self.github_calls(), [])

    def test_rejects_unexpected_and_symlink_assets(self) -> None:
        extra = self.artifacts / "unexpected"
        extra.write_text("unexpected")
        with self.assertRaisesRegex(SystemExit, "artifact set"):
            integrity.require_exact_files(self.artifacts, integrity.EXPECTED_ARTIFACTS)
        extra.unlink()
        artifact = self.artifacts / integrity.EXPECTED_ARTIFACTS[0]
        artifact.unlink()
        artifact.symlink_to(self.artifacts / integrity.EXPECTED_ARTIFACTS[1])
        with self.assertRaisesRegex(SystemExit, "nonempty regular file"):
            integrity.require_exact_files(self.artifacts, integrity.EXPECTED_ARTIFACTS)

    def test_rejects_existing_asset_on_later_page(self) -> None:
        self.sign()
        self.fake_github(conflict=integrity.PUBLISHED_FILES[-1], second_page=True)
        with self.assertRaisesRegex(SystemExit, "immutable; name already exists"):
            integrity.upload_artifacts(self.root, self.artifacts, TAG, REPOSITORY)
        self.assert_no_upload()
        self.assertTrue(any("page=2" in argument for call in self.github_calls() for argument in call))

    def test_rejects_asset_race_before_upload(self) -> None:
        self.sign()
        self.fake_github(conflict=integrity.PUBLISHED_FILES[0], late_conflict=True)
        with self.assertRaisesRegex(SystemExit, "immutable; name already exists"):
            integrity.upload_artifacts(self.root, self.artifacts, TAG, REPOSITORY)
        self.assert_no_upload()

    def test_rejects_moved_remote_tag(self) -> None:
        self.sign()
        self.fake_github(moved_tag=True)
        with self.assertRaisesRegex(SystemExit, "differs from the trusted local"):
            integrity.upload_artifacts(self.root, self.artifacts, TAG, REPOSITORY)
        self.assert_no_upload()

    def test_rejects_different_repository_before_network_writes(self) -> None:
        self.sign()
        self.fake_github()
        with self.assertRaisesRegex(SystemExit, "must match this checkout"):
            integrity.upload_artifacts(self.root, self.artifacts, TAG, "elsewhere/yume")
        self.assertEqual(self.github_calls(), [])

    def test_pins_github_host_and_repository_under_inherited_gh_settings(self) -> None:
        self.sign()
        self.fake_github()
        with mock.patch.dict(os.environ, {"GH_HOST": "elsewhere.example.invalid",
                                          "GH_REPO": "elsewhere.example.invalid/other/repo"}):
            integrity.upload_artifacts(self.root, self.artifacts, TAG, REPOSITORY)
        for call in self.github_calls():
            if call[0] == "api":
                self.assertIn("--hostname", call)
                self.assertEqual(call[call.index("--hostname") + 1], "github.com")
            else:
                self.assertEqual(call[call.index("--repo") + 1], "github.com/" + REPOSITORY)

    def test_upload_failure_never_retries_or_replaces_assets(self) -> None:
        self.sign()
        self.fake_github(upload_failure=True)
        with self.assertRaisesRegex(SystemExit, "Immutable release asset upload failed"):
            integrity.upload_artifacts(self.root, self.artifacts, TAG, REPOSITORY)
        uploads = [call for call in self.github_calls() if call[:2] == ["release", "upload"]]
        self.assertEqual(len(uploads), 1)
        self.assertNotIn("--clobber", uploads[0])


if __name__ == "__main__":
    unittest.main()
