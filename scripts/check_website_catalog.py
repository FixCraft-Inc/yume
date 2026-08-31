#!/usr/bin/env python3
"""Validate the website documentation catalog against the live tree."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "website" / "_data" / "docs.json"
SITE_CONFIG_PATH = REPO_ROOT / "website" / "_config.yml"
REQUIRED_FIELDS = ("title", "summary", "url", "source", "landing_group", "order")
GROUPS = {
    "home_group": {"Start here", "Operating", "Internals and status"},
    "landing_group": {
        "Start here",
        "Security and transport",
        "Operating",
        "Reference and development",
    },
}
FENCE_RE = re.compile(r"^```(?P<language>[^`]*)$")


def fail(message: str) -> None:
    raise ValueError(message)


def load_catalog() -> list[dict[str, Any]]:
    try:
        data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read {CATALOG_PATH.relative_to(REPO_ROOT)}: {exc}")
    if not isinstance(data, list):
        fail("documentation catalog must be a JSON array")
    return data


def local_page_exists(url: str) -> bool:
    route = url.split("#", 1)[0].strip("/")
    if not route:
        return (REPO_ROOT / "website" / "index.html").is_file()
    route_path = Path(route)
    candidates = (
        REPO_ROOT / "website" / route_path.with_suffix(".html"),
        REPO_ROOT / "website" / route_path.with_suffix(".md"),
        REPO_ROOT / "website" / route_path / "index.html",
    )
    return any(candidate.is_file() for candidate in candidates)


def published_sources() -> list[Path]:
    sources = sorted((REPO_ROOT / "docs").glob("*.md"))
    sources.extend(sorted((REPO_ROOT / "docs" / "protocol").glob("*.md")))
    sources.extend(sorted((REPO_ROOT / "docs" / "release").glob("*.md")))
    sources.append(REPO_ROOT / "CONTRIBUTING.md")
    return sources


def generated_path(source: Path) -> Path:
    relative = source.relative_to(REPO_ROOT)
    if relative == Path("CONTRIBUTING.md"):
        return REPO_ROOT / "website" / "docs" / "CONTRIBUTING.md"
    return REPO_ROOT / "website" / relative


def expected_route(source: Path) -> str:
    relative = source.relative_to(REPO_ROOT)
    if relative == Path("CONTRIBUTING.md"):
        return "/docs/CONTRIBUTING/"
    return f"/{relative.with_suffix('')}/"


def validate_published_markdown() -> None:
    for source in published_sources():
        relative = source.relative_to(REPO_ROOT)
        lines = source.read_text(encoding="utf-8").splitlines()
        if not lines or not lines[0].startswith("# "):
            fail(f"{relative}: first line must be a level-one title")

        opening: int | None = None
        for line_number, line in enumerate(lines, start=1):
            match = FENCE_RE.match(line)
            if not match:
                continue
            if opening is None:
                language = match.group("language").strip()
                if not language:
                    fail(f"{relative}:{line_number}: code fence has no language tag")
                if any(character.isspace() for character in language):
                    fail(f"{relative}:{line_number}: code fence language must be one token")
                opening = line_number
            else:
                if match.group("language").strip():
                    fail(f"{relative}:{line_number}: closing code fence has a language tag")
                opening = None
        if opening is not None:
            fail(f"{relative}:{opening}: code fence is not closed")

        output = generated_path(source)
        if not output.is_file():
            fail(f"generated page is missing: {output.relative_to(REPO_ROOT)}")
        generated_text = output.read_text(encoding="utf-8")
        marker = f"generated_from: {relative.as_posix()}"
        if marker not in generated_text.splitlines()[:8]:
            fail(f"{output.relative_to(REPO_ROOT)} has no canonical source marker")
        if re.search(r"\]\(/docs/", generated_text):
            fail(f"{output.relative_to(REPO_ROOT)} has a baseurl-unsafe /docs/ link")


def validate_product_version() -> None:
    source_text = (REPO_ROOT / "src" / "core" / "version.hpp").read_text(encoding="utf-8")
    source_match = re.search(r'constexpr const char kVersion\[\] = "([^"]+)";', source_text)
    config_text = SITE_CONFIG_PATH.read_text(encoding="utf-8")
    config_match = re.search(r"^product_version:\s*([^\s#]+)\s*$", config_text, re.MULTILINE)
    if not source_match or not config_match:
        fail("cannot read the product version from source and website config")
    if source_match.group(1) != config_match.group(1):
        fail(
            "website product_version does not match src/core/version.hpp: "
            f"{config_match.group(1)} != {source_match.group(1)}"
        )


def validate() -> None:
    validate_product_version()
    validate_published_markdown()
    seen_urls: set[str] = set()
    seen_orders: set[int] = set()
    seen_groups = {field: set() for field in GROUPS}
    previous_order = -1
    for index, entry in enumerate(load_catalog(), start=1):
        if not isinstance(entry, dict):
            fail(f"entry {index} must be an object")
        for field in REQUIRED_FIELDS:
            value = entry.get(field)
            if value is None or isinstance(value, str) and not value.strip():
                fail(f"entry {index} has no {field}")

        for field in ("title", "summary", "url", "source", "landing_group"):
            if not isinstance(entry[field], str):
                fail(f"entry {index} field {field} must be a string")

        title = entry["title"]
        url = entry["url"]
        source = (REPO_ROOT / entry["source"]).resolve()
        order = entry["order"]
        if not isinstance(order, int) or order < 0:
            fail(f"{title}: order must be a non-negative integer")
        if order <= previous_order:
            fail(f"{title}: order values must increase through the catalog")
        if url in seen_urls:
            fail(f"{title}: duplicate URL {url}")
        if order in seen_orders:
            fail(f"{title}: duplicate order {order}")
        if not source.is_relative_to(REPO_ROOT):
            fail(f"{title}: source escapes the repository")
        if not source.is_file():
            fail(f"{title}: source does not exist: {source.relative_to(REPO_ROOT)}")
        if not (url.startswith("/") or url.startswith("https://")):
            fail(f"{title}: URL must be a local route or HTTPS URL")
        if url.startswith("/") and not local_page_exists(url):
            fail(f"{title}: local page does not exist for {url}")
        if url.startswith("/") and url != expected_route(source):
            fail(f"{title}: URL {url} does not match canonical source route {expected_route(source)}")

        for field, valid_groups in GROUPS.items():
            group = entry.get(field)
            if group is None and field == "home_group":
                continue
            if not isinstance(group, str) or group not in valid_groups:
                fail(f"{title}: unknown {field} {group!r}")
            seen_groups[field].add(group)

        seen_urls.add(url)
        seen_orders.add(order)
        previous_order = order

    for field, valid_groups in GROUPS.items():
        missing = valid_groups - seen_groups[field]
        if missing:
            fail(f"{field} has no entries for: {', '.join(sorted(missing))}")


def main() -> int:
    try:
        validate()
    except ValueError as exc:
        print(f"website catalog: {exc}", file=sys.stderr)
        return 1
    print("website catalog: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
