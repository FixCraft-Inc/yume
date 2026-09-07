#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Tests for the diagram specification, ASCII renderer, and SVG renderer."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import yume_diagram_ascii
import yume_diagram_svg
import yume_diagram_spec
from yume_diagram_spec import NARROW_WIDTH, WIDE_WIDTH, SpecError

REPO_ROOT = Path(__file__).resolve().parents[1]

MINIMAL = {
    "name": "example",
    "type": "route",
    "title": "Example route",
    "summary": "Two nodes joined by one tunnelled hop.",
    "targets": {"web": True},
    "nodes": [
        {"id": "client", "kind": "client", "title": "YUME CLIENT", "sub": "carrier source"},
        {"id": "server", "kind": "server", "title": "YUMED SERVER", "sub": "direct egress"},
    ],
    "edges": [{"from": "client", "to": "server", "channel": "tunnel"}],
}


def write_spec(directory: Path, document: dict, name: str = "example") -> Path:
    path = directory / f"{name}.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


class SpecValidation(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.directory = Path(self._temp.name)
        self.addCleanup(self._temp.cleanup)

    def parse(self, mutate) -> yume_diagram_spec.Spec:
        document = json.loads(json.dumps(MINIMAL))
        mutate(document)
        return yume_diagram_spec.parse(write_spec(self.directory, document))

    def test_minimal_specification_parses(self) -> None:
        spec = self.parse(lambda document: None)
        self.assertEqual(spec.name, "example")
        self.assertEqual(len(spec.nodes), 2)
        self.assertTrue(spec.web)

    def test_unknown_top_level_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(SpecError, "unknown keys: colour"):
            self.parse(lambda document: document.update(colour="pink"))

    def test_unknown_node_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(SpecError, "unknown keys: shape"):
            self.parse(lambda document: document["nodes"][0].update(shape="hexagon"))

    def test_unknown_node_kind_is_rejected(self) -> None:
        with self.assertRaisesRegex(SpecError, "unknown kind"):
            self.parse(lambda document: document["nodes"][0].update(kind="satellite"))

    def test_edge_naming_a_missing_node_is_rejected(self) -> None:
        with self.assertRaisesRegex(SpecError, "unknown node 'ghost'"):
            self.parse(lambda document: document["edges"][0].update({"to": "ghost"}))

    def test_route_must_be_an_ordered_chain(self) -> None:
        def mutate(document: dict) -> None:
            document["nodes"].append(
                {"id": "target", "kind": "target", "title": "TARGET SITE", "sub": "sees server IP"}
            )

        with self.assertRaisesRegex(SpecError, "a route needs 2 edges"):
            self.parse(mutate)

    def test_label_too_long_for_the_box_is_rejected(self) -> None:
        with self.assertRaisesRegex(SpecError, "only 68 fit"):
            self.parse(lambda document: document["nodes"][0].update(title="Y" * 69))

    def test_name_must_match_the_file(self) -> None:
        document = json.loads(json.dumps(MINIMAL))
        document["name"] = "other"
        with self.assertRaisesRegex(SpecError, "must match the file name"):
            yume_diagram_spec.parse(write_spec(self.directory, document))

    def test_missing_target_file_is_rejected(self) -> None:
        with self.assertRaisesRegex(SpecError, "does not exist"):
            self.parse(lambda document: document["targets"].update(man=["docs/man/absent.1"]))

    def test_channel_token_leads_the_ascii_label(self) -> None:
        spec = self.parse(lambda document: document["edges"][0].update(label="encrypted DATA"))
        self.assertEqual(spec.edges[0].ascii_label(), "==YUME==> encrypted DATA")

    def test_plain_channel_without_a_label_is_silent(self) -> None:
        spec = self.parse(lambda document: document["edges"][0].pop("channel"))
        self.assertEqual(spec.edges[0].ascii_label(), "")


class AsciiRendering(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.spec = yume_diagram_spec.parse(write_spec(Path(self._temp.name), MINIMAL))

    def test_box_widths_match_the_ascii_gate(self) -> None:
        lines = yume_diagram_ascii.render(self.spec).rstrip("\n").split("\n")
        for line in lines:
            if line.startswith("+") or line.startswith("|"):
                self.assertIn(len(line), (NARROW_WIDTH, WIDE_WIDTH), line)
            if line.startswith("|"):
                self.assertEqual(line[1], " ", line)
                self.assertEqual(line[-2], " ", line)

    def test_channel_token_is_drawn_on_the_arrow(self) -> None:
        self.assertIn("| ==YUME==>", yume_diagram_ascii.render(self.spec))

    def test_output_is_stable(self) -> None:
        first = yume_diagram_ascii.render(self.spec)
        self.assertEqual(first, yume_diagram_ascii.render(self.spec))


class SvgRendering(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.spec = yume_diagram_spec.parse(write_spec(Path(self._temp.name), MINIMAL))

    def test_both_layouts_render(self) -> None:
        for layout in ("vertical", "horizontal"):
            markup = yume_diagram_svg.render(self.spec, layout)
            self.assertTrue(markup.startswith("<svg "), layout)
            self.assertIn(f'class="dgm dgm-{layout}"', markup)
            self.assertIn("</svg>", markup)

    def test_unknown_layout_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            yume_diagram_svg.render(self.spec, "diagonal")

    def test_output_is_deterministic(self) -> None:
        first = yume_diagram_svg.render(self.spec)
        self.assertEqual(first, yume_diagram_svg.render(self.spec))

    def test_no_colour_literals_reach_the_markup(self) -> None:
        # The palette lives in website/assets/tokens.css. A colour here would
        # be a second palette that the theme toggle cannot reach.
        for layout in ("vertical", "horizontal"):
            markup = yume_diagram_svg.render(self.spec, layout)
            self.assertNotIn("#", markup, layout)
            self.assertNotIn("rgb(", markup, layout)
            self.assertNotIn("oklch(", markup, layout)

    def test_the_packet_travels_the_whole_route(self) -> None:
        markup = yume_diagram_svg.render(self.spec)
        self.assertIn("--dgm-path:path(", markup)
        self.assertIn("dgm-packet-core", markup)
        self.assertIn("dgm-packet-glow", markup)

    def test_text_is_escaped(self) -> None:
        def mutate(document: dict) -> dict:
            document["nodes"][0]["sub"] = "<onion> & 'quoted'"
            return document

        spec = yume_diagram_spec.parse(
            write_spec(Path(self._temp.name), mutate(json.loads(json.dumps(MINIMAL))))
        )
        markup = yume_diagram_svg.render(spec)
        self.assertIn("&lt;onion&gt; &amp; &#x27;quoted&#x27;", markup)
        self.assertNotIn("<onion>", markup)


class ShippedSpecifications(unittest.TestCase):
    def test_every_specification_loads_and_renders(self) -> None:
        specs = yume_diagram_spec.load_all()
        self.assertTrue(specs)
        for spec in specs:
            yume_diagram_ascii.render(spec)
            for layout in ("vertical", "horizontal"):
                yume_diagram_svg.render(spec, layout)

    def test_check_reports_the_tree_as_current(self) -> None:
        # CTest must work without a prior website build. Generate ignored SVGs
        # in a fresh fixture; keep the copied canonical ASCII unchanged so
        # `check` still catches drift.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(REPO_ROOT / "docs", root / "docs")
            for name in ("README.md", "CONTRIBUTING.md"):
                shutil.copy2(REPO_ROOT / name, root / name)
            (root / "scripts").mkdir()
            for source in (REPO_ROOT / "scripts").glob("yume_diagram*.py"):
                shutil.copy2(source, root / "scripts" / source.name)
            for command in ("svg", "check"):
                result = subprocess.run(
                    [sys.executable, str(root / "scripts" / "yume_diagrams.py"), command],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
