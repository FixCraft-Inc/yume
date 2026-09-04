#!/usr/bin/env python3
"""Read and validate YUME's single-source dependency manifest."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any
from urllib.parse import urlparse


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "config" / "dependencies.json"
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?")
NAME_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}")
LICENSE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,63}")
REQUIRED_FIELDS = {"repository", "revision", "minimum_version", "license"}
OPTIONAL_FIELDS = {"patch_license", "patch_series", "source_version"}
FIELDS = REQUIRED_FIELDS | OPTIONAL_FIELDS


class DependencyError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DependencyError(message)


def load_dependencies(path: pathlib.Path = DEFAULT_MANIFEST) -> dict[str, dict[str, str]]:
    require(path.is_file(), f"missing dependency manifest: {path}")
    require(path.stat().st_size <= 64 * 1024, "dependency manifest exceeds 64 KiB")
    try:
        document: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DependencyError(f"cannot parse dependency manifest: {error}") from error
    require(isinstance(document, dict) and document.get("schema") == 1,
            "dependency manifest schema must be 1")
    dependencies = document.get("dependencies")
    require(isinstance(dependencies, dict) and dependencies,
            "dependency manifest must contain dependencies")

    validated: dict[str, dict[str, str]] = {}
    for name, fields in dependencies.items():
        require(isinstance(name, str) and NAME_RE.fullmatch(name) is not None,
                f"invalid dependency name: {name!r}")
        require(isinstance(fields, dict) and
                REQUIRED_FIELDS <= set(fields) <= FIELDS,
                f"{name} must contain {sorted(REQUIRED_FIELDS)} and only "
                f"optional fields {sorted(OPTIONAL_FIELDS)}")
        require(all(isinstance(value, str) and value for value in fields.values()),
                f"{name} fields must be non-empty strings")
        repository = fields["repository"]
        parsed = urlparse(repository)
        require(parsed.scheme == "https" and bool(parsed.netloc) and
                not parsed.username and not parsed.password and
                not parsed.query and not parsed.fragment,
                f"{name}.repository must be a credential-free HTTPS URL")
        require(COMMIT_RE.fullmatch(fields["revision"]) is not None,
                f"{name}.revision must be an exact lowercase 40-hex commit")
        require(VERSION_RE.fullmatch(fields["minimum_version"]) is not None,
                f"{name}.minimum_version is invalid")
        if "source_version" in fields:
            require(VERSION_RE.fullmatch(fields["source_version"]) is not None,
                    f"{name}.source_version is invalid")
        require(("patch_series" in fields) == ("patch_license" in fields),
                f"{name}.patch_series and patch_license must be declared together")
        require(LICENSE_RE.fullmatch(fields["license"]) is not None,
                f"{name}.license must be one SPDX license identifier")
        if "patch_license" in fields:
            require(LICENSE_RE.fullmatch(fields["patch_license"]) is not None,
                    f"{name}.patch_license must be one SPDX license identifier")
        if "patch_series" in fields:
            patch_series = pathlib.PurePosixPath(fields["patch_series"])
            require(not patch_series.is_absolute() and ".." not in patch_series.parts,
                    f"{name}.patch_series must be a repository-relative path")
        validated[name] = dict(fields)
    return validated


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=pathlib.Path, default=DEFAULT_MANIFEST)
    subparsers = parser.add_subparsers(dest="command", required=True)
    get_parser = subparsers.add_parser("get")
    get_parser.add_argument("dependency")
    get_parser.add_argument("field", choices=sorted(FIELDS))
    subparsers.add_parser("verify")
    args = parser.parse_args()
    try:
        dependencies = load_dependencies(args.manifest.resolve())
        if args.command == "get":
            require(args.dependency in dependencies,
                    f"unknown dependency: {args.dependency}")
            require(args.field in dependencies[args.dependency],
                    f"{args.dependency}.{args.field} is not defined")
            print(dependencies[args.dependency][args.field])
    except (OSError, DependencyError) as error:
        print(f"dependency manifest error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
