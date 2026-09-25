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


def main() -> int:
    try:
        validate_product_version()
        return yume_docs.main([sys.argv[0], "website", "--check", "--all-languages"])
    except (ValueError, OSError) as exc:
        print(f"website catalog: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
