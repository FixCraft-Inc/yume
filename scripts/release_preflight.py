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
    expected = [
        "yume-amd64-linux",
        "yumed-amd64-linux",
        "yume-amd64-linux-static",
        "yumed-amd64-linux-static",
        "yume-mips-openwrt",
        "yumed-mips-openwrt",
        "yume-armv7-linux",
        "yumed-armv7-linux",
        "yume-armv7-busybox",
        "yumed-armv7-busybox",
        "yume-armv7-busybox-static",
        "yumed-armv7-busybox-static",
        "yume-armv8-linux",
        "yumed-armv8-linux",
        "yume-armv8-busybox",
        "yumed-armv8-busybox",
        "yume-armv8-busybox-static",
        "yumed-armv8-busybox-static",
        "yume-x86-busybox",
        "yumed-x86-busybox",
        "yume-x86-busybox-static",
        "yumed-x86-busybox-static",
        "yume-amd64-windows.tar.xz",
        "yumed-amd64-windows.tar.xz",
        "yume-armv8-mac",
        "yumed-armv8-mac",
    ]
    require(len(expected) == len(set(expected)), "Duplicate expected release artifact names detected")


def validate_workflow_guards() -> None:
    release_yml = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    ci_yml = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for needle in ("export YUME_REQUIRE_ARGON2=1", "export YUME_REQUIRE_OQS=1"):
        require(needle in release_yml, f"release.yml is missing required guard: {needle}")
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
