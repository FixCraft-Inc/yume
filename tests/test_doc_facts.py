#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""A fact that several documents repeat changes in all of them or none.

docs/src/facts.json lists such facts. Each names the source text that decides
it, usually a constant, and every document or page that states it. When a
change to the source removes that text, this check fails and lists every
statement to revisit. When a document drops or rewords a statement, the check
fails until its entry is updated, so the registry keeps pointing at real text.

Matching is literal after line breaks and runs of spaces collapse to one
space, because the .doc sources wrap their text at about 80 columns.
"""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "docs" / "src" / "facts.json"
FACT_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
# Statements live in sources a person edits. Generated Markdown, manuals and
# the website mirror are rewritten by the sync, so a statement there would
# point an agent at the wrong file.
EDITABLE_STATEMENT = re.compile(
    r"docs/src/en_US/.+\.(?:doc|part|cli)|docs/diagrams/[^/]+\.json"
    r"|website/(?!docs/)(?!_includes/diagrams/).+\.html")


def collapse(text: str) -> str:
    return " ".join(text.split())


def check(registry: dict, root: Path) -> list[str]:
    """Every problem with the registry and the files it names, as messages."""
    problems: list[str] = []
    if registry.get("schema") != 1:
        return ["docs/src/facts.json: schema must be 1"]
    texts: dict[str, str | None] = {}

    def contains(path: str, text: str) -> bool | None:
        if path not in texts:
            file = root / path
            texts[path] = (collapse(file.read_text(encoding="utf-8"))
                           if file.is_file() else None)
        content = texts[path]
        return None if content is None else collapse(text) in content

    seen: set[str] = set()
    for fact in registry.get("facts", []):
        fact_id = fact.get("id", "")
        if not FACT_ID.fullmatch(fact_id) or fact_id in seen:
            problems.append(f"fact {fact_id!r}: the id must be unique lowercase words "
                            "joined by hyphens")
            continue
        seen.add(fact_id)
        if not fact.get("fact") or not fact.get("source") or not fact.get("stated"):
            problems.append(f"{fact_id}: needs 'fact', at least one 'source' and at "
                            "least one 'stated' entry")
            continue
        stated = [entry["path"] for entry in fact["stated"]]
        revisit = ", ".join(dict.fromkeys(stated))
        for entry in fact["source"]:
            found = contains(entry["path"], entry["text"])
            if found is None:
                problems.append(f"{fact_id}: source {entry['path']} does not exist")
            elif not found:
                problems.append(
                    f"{fact_id}: {entry['path']} no longer contains {entry['text']!r}. "
                    f"If the fact changed, update every statement of it ({revisit}) "
                    "and then this entry in docs/src/facts.json.")
        for entry in fact["stated"]:
            if not EDITABLE_STATEMENT.fullmatch(entry["path"]):
                problems.append(f"{fact_id}: {entry['path']} is not an editable source; "
                                "name the .doc, .part, diagram JSON or hand-written page")
                continue
            found = contains(entry["path"], entry["text"])
            if found is None:
                problems.append(f"{fact_id}: {entry['path']} does not exist")
            elif not found:
                problems.append(
                    f"{fact_id}: {entry['path']} no longer states {entry['text']!r}. "
                    "Restore the statement, or update this entry to the new wording "
                    "after checking it still agrees with the source.")
    return problems


class DocFacts(unittest.TestCase):
    def test_every_fact_holds_in_source_and_documents(self) -> None:
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        self.assertTrue(registry.get("facts"), "the registry lists no facts")
        problems = check(registry, ROOT)
        self.assertEqual(problems, [], "\n".join(problems))

    def test_a_changed_source_lists_every_statement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src" / "limit.hpp").write_text("kLimit = 64U;\n", encoding="utf-8")
            pages = root / "docs" / "src" / "en_US" / "pages"
            pages.mkdir(parents=True)
            (pages / "a.doc").write_text("holds at most\n64 items\n", encoding="utf-8")
            (pages / "b.doc").write_text("at most 64 items", encoding="utf-8")
            registry = {"schema": 1, "facts": [{
                "id": "limit", "fact": "At most 64 items.",
                "source": [{"path": "src/limit.hpp", "text": "kLimit = 64U;"}],
                "stated": [{"path": "docs/src/en_US/pages/a.doc", "text": "at most 64 items"},
                           {"path": "docs/src/en_US/pages/b.doc", "text": "at most 64 items"}]}]}
            self.assertEqual(check(registry, root), [])

            (root / "src" / "limit.hpp").write_text("kLimit = 128U;\n", encoding="utf-8")
            problems = check(registry, root)
            self.assertEqual(len(problems), 1, problems)
            self.assertIn("docs/src/en_US/pages/a.doc, docs/src/en_US/pages/b.doc",
                          problems[0])

            (pages / "b.doc").write_text("at most 128 items", encoding="utf-8")
            problems = check(registry, root)
            self.assertEqual(len(problems), 2, problems)
            self.assertIn("b.doc no longer states", problems[1])

    def test_a_generated_output_is_not_a_statement(self) -> None:
        for path in ("docs/EXPLAINED.md", "README.md", "docs/man/yume.1",
                     "website/docs/EXPLAINED.md",
                     "website/_includes/diagrams/key_rotation-key.html"):
            self.assertIsNone(EDITABLE_STATEMENT.fullmatch(path), path)
        for path in ("docs/src/en_US/pages/explained.doc",
                     "docs/src/en_US/parts/shared/native_cli.part",
                     "docs/src/en_US/cli/yume.cli", "docs/diagrams/key_rotation.json",
                     "website/index.html", "website/hashes/index.html"):
            self.assertIsNotNone(EDITABLE_STATEMENT.fullmatch(path), path)


if __name__ == "__main__":
    unittest.main()
