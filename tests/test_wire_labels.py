#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Every wire, KDF and AAD label in the source is the one its contract names.

A label is a domain-separation string such as `yume/ytp/1/aad/v1` or a
storage format such as `yume-kit/1`. Changing one changes the protocol, so it
may only change together with its contract page, and a label the page names
must exist in the source. Known-answer vectors pin the bytes the labels
produce, but a regenerated vector file would follow a changed label, so this
check ties each label to the page a reviewer reads.

Each label family has exactly one contract page. A label of an unknown family
fails until its family and page are added here.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGES = ROOT / "docs" / "src" / "en_US" / "pages"

# A domain label ends in a version, and a format name carries one.
LABEL = re.compile(
    r"(?:EXPORTER-)?yume/[a-z0-9.]+(?:/[a-z0-9.-]+)*/v[0-9]+"
    r"|yume-[a-z-]+(?:/[0-9]+|-v[0-9]+(?:/[a-z0-9-]+)?)")
LITERAL = re.compile(r'"([^"\\\n]*)"')
# A label in page text: code spans, code blocks and formulas all count, but
# not a longer token that merely contains one.
EDGE = r"[A-Za-z0-9/._-]"
PAGE_LABEL = re.compile(rf"(?<!{EDGE})(?:{LABEL.pattern})(?!{EDGE})")

# Label family prefix -> the contract page that owns it.
FAMILIES = {
    "EXPORTER-yume/ytp/": "ytp_1.doc",
    "yume/ytp/": "ytp_1.doc",
    "yume/circuit/": "circuit_1.doc",
    "yume/relay/": "relay_channel.doc",
    "yume/2.0/": "relay_channel.doc",
    "yume-relay-": "relay_channel.doc",
    "yume-kit/": "sealed_kit_1.doc",
    "yume-cluster-": "cluster_1.doc",
}


def owner(label: str) -> str | None:
    matches = [prefix for prefix in FAMILIES if label.startswith(prefix)]
    return FAMILIES[max(matches, key=len)] if matches else None


def is_test_source(relative: str) -> bool:
    name = relative.rsplit("/", 1)[-1]
    return (name.endswith(("_test.cpp", "_test.c")) or "/tests/" in relative
            or "/testdata/" in relative or relative.startswith("src/test_support/"))


def source_labels(root: Path = ROOT) -> dict[str, set[str]]:
    """Each label a production source spells as a string literal, and where."""
    found: dict[str, set[str]] = {}
    for path in sorted((root / "src").rglob("*")):
        if path.suffix not in (".c", ".cc", ".cpp", ".h", ".hpp"):
            continue
        relative = path.relative_to(root).as_posix()
        if is_test_source(relative):
            continue
        for literal in LITERAL.findall(path.read_text(encoding="utf-8", errors="replace")):
            if LABEL.fullmatch(literal):
                found.setdefault(literal, set()).add(relative)
    return found


def page_labels(page: Path) -> set[str]:
    """The labels a contract page names anywhere in its text."""
    return set(PAGE_LABEL.findall(page.read_text(encoding="utf-8")))


class WireLabels(unittest.TestCase):
    def test_every_source_label_is_in_its_contract(self) -> None:
        labels = source_labels()
        self.assertTrue(labels, "no labels found, so the pattern is broken")
        problems = []
        for label, sources in sorted(labels.items()):
            page = owner(label)
            if page is None:
                problems.append(f"{label} ({', '.join(sorted(sources))}) belongs to no "
                                "known family: add it and its contract page to FAMILIES")
            elif label not in page_labels(PAGES / page):
                problems.append(f"{label} ({', '.join(sorted(sources))}) is missing "
                                f"from its contract docs/src/en_US/pages/{page}")
        self.assertEqual(problems, [], "\n".join(problems))

    def test_every_contract_label_exists_in_the_source(self) -> None:
        labels = source_labels()
        problems = []
        for page in sorted(set(FAMILIES.values())):
            for label in sorted(page_labels(PAGES / page)):
                if owner(label) == page and label not in labels:
                    problems.append(f"{page} names {label}, which no production source "
                                    "defines")
        self.assertEqual(problems, [], "\n".join(problems))

    def test_the_pattern_recognizes_each_family(self) -> None:
        for label in ("yume/ytp/1/aad/v1", "EXPORTER-yume/ytp/1/channel-binding/v1",
                      "yume/2.0/aad/v2", "yume/circuit/1/layer-aad/v1", "yume-kit/1",
                      "yume-cluster-list/1", "yume-relay-key-v1",
                      "yume-relay-secret-v1/pbkdf2-sha256"):
            self.assertTrue(LABEL.fullmatch(label), label)
            self.assertIsNotNone(owner(label), label)
        for text in ("yume/yume.h", "yume/kits", "yume-module", "yume-gui",
                     "yume-module-XXXXXX"):
            self.assertIsNone(LABEL.fullmatch(text), text)

    def test_a_changed_label_is_caught(self) -> None:
        """The check itself: a source label absent from its page fails."""
        page = page_labels(PAGES / "ytp_1.doc")
        self.assertIn("yume/ytp/1/aad/v1", page)
        self.assertNotIn("yume/ytp/1/aad/v2", page)


if __name__ == "__main__":
    unittest.main()
