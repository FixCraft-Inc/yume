#!/usr/bin/env python3

import pathlib
import shutil
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
BASEFWX_REPO = "https://github.com/F1xGOD/basefwx.git"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def read_ref() -> str:
    ref_file = ROOT / ".basefwx-ref"
    require(ref_file.is_file(), "Missing .basefwx-ref")
    ref = ref_file.read_text(encoding="utf-8").strip()
    require(ref, ".basefwx-ref is empty")
    return ref


def validate_ref(ref: str) -> None:
    tmpdir = tempfile.mkdtemp(prefix="yume-basefwx-ref-")
    try:
        subprocess.run(["git", "init", "-q", tmpdir], check=True)
        subprocess.run(["git", "-C", tmpdir, "remote", "add", "origin", BASEFWX_REPO], check=True)
        subprocess.run(["git", "-C", tmpdir, "fetch", "--depth", "1", "origin", ref], check=True)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def validate_expected_artifacts() -> None:
    # Names match exactly what the release workflow uploads. The dynamic
    # "busybox" variants were dropped because a glibc-dynamic binary
    # can't run on a real busybox/musl target; only the truly-static
    # `*-busybox-static` artifacts are published, and the workflow's
    # static-link assertion enforces that.
    expected = [
        # Linux CLI
        "yume-amd64-linux",
        "yumed-amd64-linux",
        "yume-amd64-linux-static",
        "yumed-amd64-linux-static",
        "yume-armv7-linux",
        "yumed-armv7-linux",
        "yume-armv8-linux",
        "yumed-armv8-linux",
        # OpenWRT MIPS (user normally attaches manually, workflow may skip)
        "yume-mips-openwrt",
        "yumed-mips-openwrt",
        # Embedded / BusyBox-style: static only
        "yume-armv7-busybox-static",
        "yumed-armv7-busybox-static",
        "yume-armv8-busybox-static",
        "yumed-armv8-busybox-static",
        "yume-x86-busybox-static",
        "yumed-x86-busybox-static",
        # Windows CLI (tar.xz bundle of .exe + runtime DLLs)
        "yume-amd64-windows.tar.xz",
        "yumed-amd64-windows.tar.xz",
        # macOS CLI (arm64 today; Intel/x86_64 can be added via the
        # build-macos matrix in release.yml)
        "yume-armv8-mac",
        "yumed-armv8-mac",
        # Desktop GUI builds (best-effort in the workflow; if the GUI
        # build fails it is logged but does not block the rest of the
        # release).
        "yume-gui-amd64-linux",
        "yume-gui-amd64-windows.exe",
        "yume-gui-armv8-mac",
    ]
    require(len(expected) == len(set(expected)), "Duplicate expected release artifact names detected")


def validate_workflow_guards() -> None:
    release_yml = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    ci_yml = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    # YUME_REQUIRE_ARGON2 and YUME_REQUIRE_OQS are both strict (=1) in
    # release builds. PQ is provisioned for every reachable target via
    # scripts/build-liboqs-target.sh (host + armv7 + armv8 + i386 cross
    # before fullau runs); musl-only busybox-armv7/armv8 and openwrt-mips
    # are skipped at build time, not by relaxing the guard.
    for needle in ("export YUME_REQUIRE_ARGON2=1", "export YUME_REQUIRE_OQS=1"):
        require(needle in release_yml, f"release.yml is missing required guard: {needle}")
    for needle in ("SHA256SUMS.txt", "MD5SUMS.txt", "release-manifest.json", "gpg --batch --verify"):
        require(needle in release_yml, f"release.yml is missing release-integrity step: {needle}")
    for needle in ("-DBASEFWX_REQUIRE_ARGON2=ON", "-DBASEFWX_REQUIRE_OQS=ON", "-DBASEFWX_REQUIRE_LZMA=ON"):
        require(needle in ci_yml, f"ci.yml is missing required guard: {needle}")
    require("branches: [main, DEV]" in ci_yml, "ci.yml must cover main and DEV")
    require("workflow_dispatch releases must be started from main." in release_yml,
            "release.yml is missing the workflow_dispatch main-branch guard")


def main() -> None:
    ref = read_ref()
    validate_ref(ref)
    validate_expected_artifacts()
    validate_workflow_guards()
    print(f"Preflight OK: BaseFWX ref {ref} is reachable and release guards are present.")


if __name__ == "__main__":
    main()
