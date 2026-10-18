#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

"""Authenticate release inputs and attach a complete immutable asset set."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Iterator

from release_manifest import EXPECTED_ARTIFACTS, build_manifest, check_manifest, digest_file


ROOT = pathlib.Path(__file__).resolve().parents[1]
TRUSTED_FINGERPRINT = "967278FF6FA436F504CBB0058A1588B5E2598DB1"
PUBLIC_KEY = "third_party/prebuilt/yume-release-key.asc"
SIGNED_FILES = (*EXPECTED_ARTIFACTS, "SHA256SUMS.txt", "release-manifest.json")
PUBLISHED_FILES = (*EXPECTED_ARTIFACTS,
                   *(f"{name}.sha256" for name in EXPECTED_ARTIFACTS),
                   "SHA256SUMS.txt", "release-manifest.json",
                   *(f"{name}.sig" for name in SIGNED_FILES))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def command_env(home: pathlib.Path | None = None) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    # Only GnuPG receives key material, through its standard input.
    env.pop("GPG_PRIVATE_KEY", None)
    env.pop("GPG_PASSPHRASE", None)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    if home is not None:
        env["GNUPGHOME"] = str(home)
    return env


def run(command: list[str], description: str, *, data: bytes | None = None,
        env: dict[str, str] | None = None, timeout: int = 60) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(command, input=data, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=env or command_env(),
                                check=False, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise SystemExit(f"{description} timed out") from error
    except OSError as error:
        raise SystemExit(f"Cannot run {description}") from error
    # Import/sign diagnostics can contain private input; never echo them.
    require(result.returncode == 0, f"{description} failed")
    return result


def git(root: pathlib.Path, *arguments: str) -> str:
    return run(["git", "-C", str(root), *arguments], "Git source inspection").stdout.decode().strip()


def validate_tag_name(tag: str) -> None:
    require(bool(re.fullmatch(r"v0\.3\.0(?:-rc[1-9][0-9]*)?", tag)),
            "Release tag must be v0.3.0-rcN or v0.3.0")


def trusted_public_key(root: pathlib.Path) -> bytes:
    spec = f"HEAD:{PUBLIC_KEY}"
    size = git(root, "cat-file", "-s", spec)
    require(size.isdecimal() and 0 < int(size) <= 64 * 1024,
            "Tracked release public key exceeds its size bound")
    return run(["git", "-C", str(root), "show", spec],
               "Read tracked release public key").stdout


def gpg_command(home: pathlib.Path, *arguments: str) -> list[str]:
    gpg = shutil.which("gpg")
    require(gpg is not None, "GnuPG is required for release integrity")
    return [gpg, "--homedir", str(home), "--no-options", "--batch", "--no-tty",
            "--no-auto-key-retrieve", "--auto-key-locate", "clear", *arguments]


def primary_fingerprints(home: pathlib.Path, *, secret: bool = False) -> set[str]:
    output = run(gpg_command(home, "--with-colons", "--list-secret-keys" if secret else
                             "--list-keys"), "Inspect release signing identity",
                 env=command_env(home)).stdout.decode()
    fingerprints = set()
    want_primary = False
    for line in output.splitlines():
        fields = line.split(":")
        if fields[0] in {"pub", "sec"}:
            want_primary = True
        elif fields[0] in {"sub", "ssb"}:
            want_primary = False
        elif fields[0] == "fpr" and want_primary:
            fingerprints.add(fields[9])
            want_primary = False
    return fingerprints


@contextmanager
def trusted_keyring(root: pathlib.Path) -> Iterator[pathlib.Path]:
    gpgconf = shutil.which("gpgconf")
    require(gpgconf is not None, "gpgconf is required to clean up release signing keys")
    with tempfile.TemporaryDirectory(prefix="yume-release-gnupg-") as directory:
        home = pathlib.Path(directory)
        home.chmod(0o700)
        try:
            run(gpg_command(home, "--import"), "Import tracked release public key",
                data=trusted_public_key(root), env=command_env(home))
            require(primary_fingerprints(home) == {TRUSTED_FINGERPRINT},
                    "Tracked release public key is not the trusted identity")
            yield home
        finally:
            # The signing key's agent must not outlive its temporary keyring.
            run([gpgconf, "--homedir", str(home), "--kill", "gpg-agent"],
                "Release signing agent cleanup", env=command_env(home), timeout=10)


def require_trusted_signature(status: bytes, description: str) -> None:
    signatures = []
    for line in status.decode("utf-8", errors="replace").splitlines():
        if line.startswith("[GNUPG:] VALIDSIG "):
            fields = line.split()[2:]
            if len(fields) >= 10:
                signatures.append(fields[-1])
    require(signatures == [TRUSTED_FINGERPRINT],
            f"{description} must have one valid signature from the trusted primary key")


def verify_source(root: pathlib.Path, tag: str) -> str:
    """Return the authenticated annotated tag object bound directly to HEAD."""
    validate_tag_name(tag)
    commit = git(root, "rev-parse", "--verify", "HEAD^{commit}")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", commit)), "Cannot resolve release commit")
    tag_object = git(root, "rev-parse", "--verify", f"refs/tags/{tag}")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", tag_object)), "Cannot resolve release tag")
    require(git(root, "cat-file", "-t", tag_object) == "tag",
            "Release tag must be annotated and signed")
    for object_id in (tag_object, commit):
        size = git(root, "cat-file", "-s", object_id)
        require(size.isdecimal() and 0 < int(size) <= 1024 * 1024,
                "Release source signature object exceeds its size bound")
    header = git(root, "cat-file", "-p", tag_object).split("\n\n", 1)[0].splitlines()
    require(len(header) >= 3 and header[0] == f"object {commit}" and
            header[1] == "type commit" and header[2] == f"tag {tag}",
            "Release tag must name and point directly to the checked-out commit")
    with trusted_keyring(root) as home:
        gpg = shutil.which("gpg")
        require(gpg is not None, "GnuPG is required for release integrity")
        for operation, object_id in (("verify-tag", tag_object), ("verify-commit", commit)):
            result = run(["git", "-C", str(root), "-c", "gpg.format=openpgp",
                          "-c", f"gpg.program={gpg}", "-c", f"gpg.openpgp.program={gpg}",
                          operation, "--raw", object_id],
                         f"Trusted {operation}", env=command_env(home))
            require_trusted_signature(result.stderr, operation)
    # Recheck the ref after verification; a moved ref invalidates the result.
    require(git(root, "rev-parse", "--verify", f"refs/tags/{tag}") == tag_object,
            "Release tag moved during source verification")
    require(git(root, "rev-parse", "--verify", "HEAD^{commit}") == commit,
            "Release source changed during verification")
    return tag_object


def require_exact_files(directory: pathlib.Path, names: tuple[str, ...]) -> None:
    require(directory.is_dir() and not directory.is_symlink(),
            "Release artifacts must be in a regular directory")
    paths = list(directory.iterdir())
    require({path.name for path in paths} == set(names),
            "Release artifact set is incomplete or unexpected")
    for path in paths:
        metadata = path.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_size > 0,
                f"Release asset must be a nonempty regular file: {path.name}")
        limit = 512 * 1024 * 1024 if path.name in EXPECTED_ARTIFACTS else 1024 * 1024
        require(metadata.st_size <= limit, f"Release asset exceeds size bound: {path.name}")


def verify_assets(directory: pathlib.Path, tag: str, home: pathlib.Path) -> None:
    require_exact_files(directory, PUBLISHED_FILES)
    check_manifest(directory, tag, require_signatures=True)
    for name in SIGNED_FILES:
        result = run(gpg_command(home, "--status-fd", "1", "--verify",
                                 str(directory / f"{name}.sig"), str(directory / name)),
                     f"Verify release signature for {name}", env=command_env(home))
        require_trusted_signature(result.stdout, name)


def sign_artifacts(root: pathlib.Path, directory: pathlib.Path, tag: str) -> None:
    private_key = os.environ.get("GPG_PRIVATE_KEY", "")
    require(bool(private_key.strip()), "GPG_PRIVATE_KEY is required for publication")
    passphrase = os.environ.get("GPG_PASSPHRASE", "")
    require("\n" not in passphrase and "\r" not in passphrase,
            "GPG_PASSPHRASE must contain a single line")
    verify_source(root, tag)
    require_exact_files(directory, EXPECTED_ARTIFACTS)
    with trusted_keyring(root) as home:
        run(gpg_command(home, "--import"), "Import private release signing key",
            data=private_key.encode("utf-8"), env=command_env(home))
        require(primary_fingerprints(home) == {TRUSTED_FINGERPRINT} and
                primary_fingerprints(home, secret=True) == {TRUSTED_FINGERPRINT},
                "Private release key must belong only to the trusted primary identity")
        rows = []
        for name in EXPECTED_ARTIFACTS:
            row = f"{digest_file(directory / name, 'sha256')}  {name}\n"
            (directory / f"{name}.sha256").write_text(row, encoding="utf-8")
            rows.append(row)
        (directory / "SHA256SUMS.txt").write_text("".join(rows), encoding="utf-8")

        def sign(name: str) -> None:
            run(gpg_command(home, "--pinentry-mode", "loopback", "--passphrase-fd", "0",
                            "--local-user", TRUSTED_FINGERPRINT, "--armor", "--detach-sign",
                            "--output", str(directory / f"{name}.sig"), str(directory / name)),
                f"Sign release asset {name}", data=(passphrase + "\n").encode("utf-8"),
                env=command_env(home))

        for name in SIGNED_FILES[:-1]:
            sign(name)
        manifest = build_manifest(directory, tag, require_signatures=True)
        (directory / "release-manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        sign("release-manifest.json")
        verify_assets(directory, tag, home)


def github_repository(root: pathlib.Path, repository: str) -> None:
    require(bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)),
            "Invalid GitHub release repository")
    origin = git(root, "remote", "get-url", "origin")
    match = re.fullmatch(r"(?:https://github\.com/|git@github\.com:)([^/]+/[^/]+?)(?:\.git)?", origin)
    require(match is not None and match.group(1).lower() == repository.lower(),
            "Release repository must match this checkout's GitHub origin")


def github_api(endpoint: str) -> object:
    result = run(["gh", "api", endpoint, "--hostname", "github.com"],
                 "Read GitHub release state", timeout=90)
    require(len(result.stdout) <= 2 * 1024 * 1024, "GitHub release response exceeds size bound")
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeError) as error:
        raise SystemExit("Invalid GitHub release response") from error


def verify_remote_tag(repository: str, tag: str, tag_object: str) -> None:
    ref = github_api(f"repos/{repository}/git/ref/tags/{tag}")
    require(isinstance(ref, dict) and ref.get("ref") == f"refs/tags/{tag}" and
            isinstance(ref.get("object"), dict) and ref["object"].get("type") == "tag" and
            ref["object"].get("sha") == tag_object,
            "GitHub release tag differs from the trusted local annotated tag")


def reject_existing_assets(repository: str, release_id: int) -> None:
    for page in range(1, 101):
        assets = github_api(f"repos/{repository}/releases/{release_id}/assets?per_page=100&page={page}")
        require(isinstance(assets, list) and len(assets) <= 100,
                "Invalid GitHub release asset page")
        for asset in assets:
            require(isinstance(asset, dict) and isinstance(asset.get("name"), str),
                    "Invalid GitHub release asset metadata")
            require(asset["name"] not in PUBLISHED_FILES,
                    f"Published release assets are immutable; name already exists: {asset['name']}")
        if len(assets) < 100:
            return
    raise SystemExit("GitHub release asset listing exceeds page bound")


def upload_artifacts(root: pathlib.Path, directory: pathlib.Path, tag: str,
                     repository: str) -> None:
    github_repository(root, repository)
    tag_object = verify_source(root, tag)
    with trusted_keyring(root) as home:
        verify_assets(directory, tag, home)
        release = github_api(f"repos/{repository}/releases/tags/{tag}")
        require(isinstance(release, dict) and release.get("tag_name") == tag and
                type(release.get("id")) is int and release["id"] > 0,
                "Existing GitHub release does not match the requested tag")
        verify_remote_tag(repository, tag, tag_object)
        reject_existing_assets(repository, release["id"])
        # Repeat immediately before upload. A concurrent later upload still
        # fails at GitHub because gh is never allowed to replace an asset.
        verify_assets(directory, tag, home)
        require(verify_source(root, tag) == tag_object,
                "Local release tag changed before upload")
        verify_remote_tag(repository, tag, tag_object)
        reject_existing_assets(repository, release["id"])
        run(["gh", "release", "upload", tag,
             *(str(directory / name) for name in PUBLISHED_FILES),
             "--repo", f"github.com/{repository}"],
            "Immutable release asset upload", timeout=300)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("sign", "upload"))
    parser.add_argument("artifacts", type=pathlib.Path)
    parser.add_argument("tag")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    args = parser.parse_args()
    directory = args.artifacts.absolute()
    if args.operation == "sign":
        sign_artifacts(ROOT, directory, args.tag)
    else:
        upload_artifacts(ROOT, directory, args.tag, args.repo)
    print(f"Release {args.operation} verified: {args.tag}")


if __name__ == "__main__":
    main()
