#!/usr/bin/env python3
"""Generate and verify YUME's deterministic declared-dependency SBOM."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

from yume_dependencies import DependencyError, load_dependencies


ROOT = Path(__file__).resolve().parents[1]
DEPENDENCIES = ROOT / "config/dependencies.json"
VCPKG = ROOT / "vcpkg.json"
OUTPUT = ROOT / "docs/release/SBOM.spdx.json"
REVISION = re.compile(r"[0-9a-f]{40}\Z")
ALLOWED_REPOSITORIES = {
    "https://github.com/F1xGOD/basefwx.git",
    "https://github.com/openssl/openssl.git",
    "https://github.com/open-quantum-safe/liboqs.git",
}


class SbomError(RuntimeError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SbomError(f"cannot read {path.relative_to(ROOT)}: {exc}") from exc
    if not isinstance(value, dict):
        raise SbomError(f"{path.relative_to(ROOT)} must contain an object")
    return value


def validated_inputs() -> tuple[dict[str, Any], dict[str, Any]]:
    dependency_root = load_json(DEPENDENCIES)
    if dependency_root.get("schema") != 1:
        raise SbomError("config/dependencies.json schema must be numeric 1")
    try:
        dependencies = load_dependencies(DEPENDENCIES)
    except (OSError, DependencyError) as exc:
        raise SbomError(f"invalid dependency manifest: {exc}") from exc
    dependency_root = {"schema": 1, "dependencies": dependencies}
    for name, entry in dependencies.items():
        if not isinstance(name, str) or not isinstance(entry, dict):
            raise SbomError("dependency entries must be named objects")
        repository = entry.get("repository")
        revision = entry.get("revision")
        license_id = entry.get("license")
        if repository not in ALLOWED_REPOSITORIES:
            raise SbomError(f"unreviewed repository for dependency {name}")
        if not isinstance(revision, str) or not REVISION.fullmatch(revision):
            raise SbomError(f"dependency {name} must pin a 40-hex revision")
        if not isinstance(license_id, str) or not license_id:
            raise SbomError(f"dependency {name} must declare an SPDX license")

    vcpkg = load_json(VCPKG)
    baseline = vcpkg.get("builtin-baseline")
    if not isinstance(baseline, str) or not REVISION.fullmatch(baseline):
        raise SbomError("vcpkg builtin-baseline must be a 40-hex revision")
    if vcpkg.get("version-string") != "0.3.0-dev1":
        raise SbomError("vcpkg product version is not 0.3.0-dev1")
    return dependency_root, vcpkg


def source_date() -> str:
    raw = os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        epoch = int(raw, 10)
        if epoch < 0:
            raise ValueError
    except ValueError as exc:
        raise SbomError("SOURCE_DATE_EPOCH must be a non-negative integer") from exc
    value = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def package_id(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9.-]", "-", name)
    return f"SPDXRef-Package-{cleaned}"


def build_sbom(dependency_root: dict[str, Any], vcpkg: dict[str, Any]) -> dict[str, Any]:
    canonical = json.dumps(
        {"dependencies": dependency_root, "vcpkg": vcpkg},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    namespace_hash = hashlib.sha256(canonical).hexdigest()
    packages: list[dict[str, Any]] = [
        {
            "SPDXID": "SPDXRef-Package-YUME",
            "name": "YUME",
            "versionInfo": vcpkg["version-string"],
            "downloadLocation": "https://github.com/FixCraft-Inc/yume",
            "licenseConcluded": "AGPL-3.0-or-later",
            "licenseDeclared": "AGPL-3.0-or-later",
            "filesAnalyzed": False,
        }
    ]
    relationships: list[dict[str, str]] = []
    for name, entry in sorted(dependency_root["dependencies"].items()):
        spdx_id = package_id(name)
        package = {
            "SPDXID": spdx_id,
            "name": name,
            "versionInfo": entry.get("source_version", entry["minimum_version"]),
            "downloadLocation": entry["repository"],
            "licenseConcluded": entry["license"],
            "licenseDeclared": entry["license"],
            "filesAnalyzed": False,
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "git",
                    "referenceLocator": entry["revision"],
                }
            ],
        }
        patch_license = entry.get("patch_license")
        if patch_license is not None:
            package["licenseConcluded"] = (
                f"{entry['license']} AND {patch_license}"
            )
            package["comment"] = (
                f"YUME applies the downstream patch series "
                f"{entry['patch_series']}, declared {patch_license}."
            )
        packages.append(package)
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package-YUME",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": spdx_id,
            }
        )

    for dependency in vcpkg.get("dependencies", []):
        name = dependency if isinstance(dependency, str) else dependency.get("name")
        if not isinstance(name, str):
            raise SbomError("vcpkg dependency name must be a string")
        spdx_id = package_id(f"vcpkg-{name}")
        packages.append(
            {
                "SPDXID": spdx_id,
                "name": name,
                "versionInfo": f"vcpkg-baseline-{vcpkg['builtin-baseline']}",
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "filesAnalyzed": False,
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package-YUME",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": spdx_id,
            }
        )

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "YUME source dependency SBOM",
        "documentNamespace": (
            "https://github.com/FixCraft-Inc/yume/sbom/" + namespace_hash
        ),
        "creationInfo": {
            "created": source_date(),
            "creators": ["Tool: scripts/check_dependency_sbom.py"],
        },
        "documentDescribes": ["SPDXRef-Package-YUME"],
        "packages": packages,
        "relationships": relationships,
    }


def encoded(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()

    try:
        dependencies, vcpkg = validated_inputs()
        content = encoded(build_sbom(dependencies, vcpkg))
        if args.write:
            OUTPUT.write_text(content, encoding="utf-8")
        elif not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != content:
            raise SbomError(
                "docs/release/SBOM.spdx.json is stale; run "
                "SOURCE_DATE_EPOCH=0 scripts/check_dependency_sbom.py --write"
            )
    except SbomError as exc:
        print(f"dependency/SBOM check: {exc}", file=sys.stderr)
        return 1
    print("dependency/SBOM check: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
