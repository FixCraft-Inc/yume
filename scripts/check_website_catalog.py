#!/usr/bin/env python3
"""Verify published pages and catalog metadata against their .doc owners."""
import re
import sys
from pathlib import Path
import yume_docs

REPO_ROOT = Path(__file__).resolve().parents[1]
SITE_CONFIG_PATH = REPO_ROOT / "website/_config.yml"

def fail(message: str) -> None:
    raise ValueError(message)

def validate_product_version() -> None:
    source_text = (REPO_ROOT / "src" / "common" / "version.hpp").read_text(encoding="utf-8")
    source_match = re.search(
        r'(?:inline\s+)?constexpr(?:\s+const)?\s+char\s+kVersion\[\]\s*=\s*"([^"]+)";',
        source_text,
    )
    config_text = SITE_CONFIG_PATH.read_text(encoding="utf-8")
    config_match = re.search(r"^product_version:\s*([^\s#]+)\s*$", config_text, re.MULTILINE)
    if not source_match or not config_match:
        fail("cannot read the product version from source and website config")
    if source_match.group(1) != config_match.group(1):
        fail(
            "website product_version does not match src/common/version.hpp: "
            f"{config_match.group(1)} != {source_match.group(1)}"
        )


# A page may link to other sites, but everything it loads to render comes from
# this site: CONTRIBUTING rules out remote fonts and third-party scripts.
# site.js reads GitHub's release API on purpose. That is data, not page markup.
REMOTE_RESOURCE_PATTERNS = (
    re.compile(r"@import\s+(?:url\()?\s*['\"]?(?:https?:)?//", re.IGNORECASE),
    re.compile(r"url\(\s*['\"]?(?:https?:)?//", re.IGNORECASE),
    re.compile(r"<(?:script|img|iframe|source|video|audio|embed)\b[^>]*\bsrc=['\"]?(?:https?:)?//", re.IGNORECASE),
    re.compile(r"<link\b(?=[^>]*\brel=['\"]?(?:stylesheet|preload|icon|modulepreload)\b)[^>]*\bhref=['\"]?(?:https?:)?//", re.IGNORECASE),
)


def validate_local_resources() -> None:
    website = REPO_ROOT / "website"
    for path in sorted(website.rglob("*")):
        if path.suffix not in {".html", ".css"} or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in REMOTE_RESOURCE_PATTERNS:
            match = pattern.search(text)
            if match:
                line = text.count("\n", 0, match.start()) + 1
                fail(f"{path.relative_to(REPO_ROOT)}:{line} loads a resource from another host")


def main() -> int:
    try:
        validate_product_version()
        validate_local_resources()
        return yume_docs.main([sys.argv[0], "website", "--check", "--all-languages"])
    except (ValueError, OSError) as exc:
        print(f"website catalog: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
