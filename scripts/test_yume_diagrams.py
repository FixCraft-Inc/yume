#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Tests for the diagram specification, ASCII renderer, and SVG renderer."""

from __future__ import annotations

import json
import math
import json
import re
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
import yume_diagram_theme
import yume_diagrams
from yume_diagram_spec import SpecError

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


def _stylesheet(markup: str) -> str:
    return markup.split("<style>", 1)[1].split("</style>", 1)[0]


def _path_points(markup: str) -> list[tuple[float, float]]:
    """The vertices of the packet path, in order."""
    drawn = re.search(r"--dgm-path:path\('([^']+)'\)", markup)
    assert drawn, "no packet path"
    return [
        (float(x), float(y))
        for x, y in re.findall(r"[ML] (-?[\d.]+) (-?[\d.]+)", drawn.group(1))
    ]


def _windows(markup: str) -> list[tuple[int, float, float]]:
    """Each card's presence window, as (node index, lit from, lit to)."""
    found = []
    for block in re.finditer(
        r"@keyframes dgm-[\w-]+-here-(\d+) \{(.*?)\n  \}", markup, re.S
    ):
        live = re.search(r"([\d.]+)%, ([\d.]+)% \{ fill: var\(--dgm-live\)", block.group(2))
        found.append((int(block.group(1)), float(live.group(1)), float(live.group(2))))
    return found


def _arrow_tips(markup: str) -> list[tuple[float, float]]:
    """The point of every arrow head, which is where its hop ends."""
    return [
        (float(x), float(y))
        for x, y in re.findall(
            r'class="dgm-arrow[^"]*"[^>]*?L(-?[\d.]+) (-?[\d.]+)Z', markup
        )
    ]


GROUPED = {
    "name": "grouped",
    "type": "route",
    "title": "Grouped route",
    "summary": "Two adjacent servers share one enclosure between two clients.",
    "targets": {"web": True},
    "nodes": [
        {"id": "client_a", "kind": "client", "title": "CLIENT A", "sub": "first end"},
        {"id": "server_a", "kind": "server", "title": "SERVER A",
         "sub": "first member", "group": "CLUSTER"},
        {"id": "server_b", "kind": "server", "title": "SERVER B",
         "sub": "second member", "group": "CLUSTER"},
        {"id": "client_b", "kind": "client", "title": "CLIENT B", "sub": "second end"},
    ],
    "edges": [
        {"from": "client_a", "to": "server_a", "label": "first hop"},
        {"from": "server_a", "to": "server_b", "label": "member link"},
        {"from": "server_b", "to": "client_b", "label": "last hop"},
    ],
}


def _grouped_spec() -> yume_diagram_spec.Spec:
    """A specification whose group lifts nodes onto a plateau."""
    with tempfile.TemporaryDirectory() as directory:
        return yume_diagram_spec.parse(write_spec(Path(directory), GROUPED, "grouped"))


def _cards(markup: str) -> list[tuple[float, float]]:
    """The top-left corner of every card, in document order."""
    return [
        (float(x), float(y))
        for x, y in re.findall(
            r'class="dgm-card"[^>]*? x="([\d.]+)" y="([\d.]+)"', markup
        )
    ]


def _body(markup: str) -> str:
    """What the figure draws, with the stylesheet's rule names left out."""
    return markup.split("</style>", 1)[1]


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

    def test_document_placement_cannot_be_repeated_in_a_spec(self) -> None:
        with self.assertRaisesRegex(SpecError, "unknown keys"):
            self.parse(lambda document: document["targets"].update(man=["docs/man/absent.1"]))

    def test_channel_token_leads_the_ascii_label(self) -> None:
        spec = self.parse(lambda document: document["edges"][0].update(label="encrypted DATA"))
        self.assertEqual(spec.edges[0].ascii_label(), "==YUME==> encrypted DATA")

    def test_plain_channel_without_a_label_is_silent(self) -> None:
        spec = self.parse(lambda document: document["edges"][0].pop("channel"))
        self.assertEqual(spec.edges[0].ascii_label(), "")


class Grouping(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.directory = Path(self._temp.name)
        self.addCleanup(self._temp.cleanup)

    def parse(self, mutate) -> yume_diagram_spec.Spec:
        document = json.loads(json.dumps(MINIMAL))
        mutate(document)
        return yume_diagram_spec.parse(write_spec(self.directory, document))

    def three(self, *assigned: str) -> yume_diagram_spec.Spec:
        def mutate(document: dict) -> None:
            document["nodes"].append(
                {"id": "target", "kind": "target", "title": "TARGET SITE", "sub": "x"}
            )
            document["edges"].append({"from": "server", "to": "target"})
            for node, group in zip(document["nodes"], assigned):
                if group:
                    node["group"] = group

        return self.parse(mutate)

    def test_adjacent_members_form_one_run(self) -> None:
        spec = self.three("PAIR", "PAIR", "")
        self.assertEqual(yume_diagram_spec.groups(spec), [(0, 1, "PAIR")])

    def test_a_split_group_is_rejected(self) -> None:
        with self.assertRaisesRegex(SpecError, "is split"):
            self.three("PAIR", "", "PAIR")

    def test_a_group_of_one_is_rejected(self) -> None:
        with self.assertRaisesRegex(SpecError, "has one member"):
            self.three("ALONE", "", "")

    def test_an_over_long_group_title_is_rejected(self) -> None:
        with self.assertRaisesRegex(SpecError, "longer than"):
            self.three("G" * 29, "G" * 29, "")

    def test_the_ascii_form_ignores_a_group(self) -> None:
        # The man page draws the same node chain either way, which is why a
        # group title may only name the nodes it encloses.
        grouped = self.three("PAIR", "PAIR", "")
        plain = self.three("", "", "")
        self.assertEqual(
            yume_diagram_ascii.render(grouped), yume_diagram_ascii.render(plain)
        )

    def test_a_group_is_enclosed_and_named_in_both_layouts(self) -> None:
        spec = self.three("PAIR", "PAIR", "")
        for layout in ("vertical", "horizontal"):
            body = _body(yume_diagram_svg.render(spec, layout))
            self.assertIn("dgm-group", body, layout)
            self.assertIn(">PAIR<", body, layout)

    def test_a_group_lifts_its_members_across_the_page(self) -> None:
        # The plateau is what gives a grouped route its silhouette, and the
        # hops on and off it are the diagonals.
        grouped = _cards(yume_diagram_svg.render(self.three("PAIR", "PAIR", ""), "horizontal"))
        plain = _cards(yume_diagram_svg.render(self.three("", "", ""), "horizontal"))
        self.assertEqual(len({y for _x, y in plain}), 1)
        self.assertEqual(len({y for _x, y in grouped}), 2)

    def test_a_hop_inside_a_group_runs_forwards(self) -> None:
        # Snapping both ends of an internal hop to the enclosure walls would
        # draw it backwards, arrow first.
        markup = yume_diagram_svg.render(self.three("PAIR", "PAIR", ""), "horizontal")
        for start, end in re.findall(
            r'class="dgm-link[^"]*"[^>]*d="M([\d.]+) [\d.]+L([\d.]+) ', markup
        ):
            self.assertLess(float(start), float(end))


class Translation(unittest.TestCase):
    """A second language supplies strings and keeps the topology."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name)
        self._saved = yume_diagram_spec.STRINGS_DIR
        yume_diagram_spec.STRINGS_DIR = self.root
        self.addCleanup(setattr, yume_diagram_spec, "STRINGS_DIR", self._saved)
        self.spec_path = write_spec(self.root, MINIMAL)

    def strings(self, document: dict, language: str = "de_DE") -> None:
        directory = self.root / language
        directory.mkdir(parents=True, exist_ok=True)
        (directory / yume_diagram_spec.STRINGS_NAME).write_text(
            json.dumps(document), encoding="utf-8"
        )

    def translated(self, language: str = "de_DE") -> yume_diagram_spec.Spec:
        spec = yume_diagram_spec.parse(self.spec_path)
        return yume_diagram_spec.apply_strings(
            spec, yume_diagram_spec.load_strings(language), language
        )

    def test_the_source_language_needs_no_file(self) -> None:
        self.assertEqual(yume_diagram_spec.load_strings("en_US"), {})

    def test_a_node_label_is_replaced(self) -> None:
        self.strings({MINIMAL["name"]: {"nodes": {"client": {"title": "KLIENT"}}}})
        spec = self.translated()
        self.assertEqual(spec.nodes[0].title, "KLIENT")
        self.assertIn("KLIENT", yume_diagram_ascii.render(spec))
        self.assertIn("KLIENT", yume_diagram_svg.render(spec, "vertical"))

    def test_an_untranslated_string_keeps_the_source(self) -> None:
        # A partly finished language still renders, which is what lets a
        # translation land one document at a time.
        self.strings({MINIMAL["name"]: {"title": "Direkte Route"}})
        spec = self.translated()
        self.assertEqual(spec.title, "Direkte Route")
        self.assertEqual(spec.nodes[0].title, MINIMAL["nodes"][0]["title"])

    def test_the_topology_is_not_translatable(self) -> None:
        source = yume_diagram_spec.parse(self.spec_path)
        self.strings({MINIMAL["name"]: {"nodes": {"client": {"title": "KLIENT"}}}})
        spec = self.translated()
        self.assertEqual(
            [(e.source, e.target, e.channel) for e in spec.edges],
            [(e.source, e.target, e.channel) for e in source.edges],
        )
        self.assertEqual([n.kind for n in spec.nodes], [n.kind for n in source.nodes])

    def test_an_unknown_node_is_rejected(self) -> None:
        self.strings({MINIMAL["name"]: {"nodes": {"nowhere": {"title": "X"}}}})
        with self.assertRaisesRegex(SpecError, "unknown node"):
            self.translated()

    def test_an_unknown_key_is_rejected(self) -> None:
        self.strings({MINIMAL["name"]: {"colour": "blue"}})
        with self.assertRaisesRegex(SpecError, "unknown keys"):
            self.translated()

    def test_an_over_long_translated_label_is_rejected(self) -> None:
        # A translation can break the drawing as easily as a source string,
        # so the width rule runs again after the strings are applied.
        self.strings({MINIMAL["name"]: {"nodes": {"client": {"title": "K" * 80}}}})
        with self.assertRaisesRegex(SpecError, "characters but only"):
            self.translated()

    def test_a_language_reports_what_it_still_needs(self) -> None:
        spec = yume_diagram_spec.parse(self.spec_path)
        complete = yume_diagram_spec.missing_strings(spec, {})
        self.assertIn(f"{spec.name}.title", complete)
        self.strings({MINIMAL["name"]: {"title": "T"}})
        after = yume_diagram_spec.missing_strings(spec, yume_diagram_spec.load_strings("de_DE"))
        self.assertNotIn(f"{spec.name}.title", after)
        self.assertLess(len(after), len(complete))

    def test_each_language_draws_into_its_own_directory(self) -> None:
        self.assertEqual(yume_diagrams.svg_dir("en_US"), yume_diagrams.SVG_DIR)
        self.assertEqual(
            yume_diagrams.svg_dir("de_DE"), yume_diagrams.SVG_DIR / "de_DE"
        )


class AsciiRendering(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.spec = yume_diagram_spec.parse(write_spec(Path(self._temp.name), MINIMAL))

    def test_every_box_is_sized_to_the_figure_and_padded(self) -> None:
        # Boxes are no longer drawn at one of two fixed widths. Each figure
        # sizes its own, so what has to hold is that they agree with each
        # other and that scripts/check_ascii_diagrams.py would accept them.
        lines = yume_diagram_ascii.render(self.spec).rstrip("\n").split("\n")
        widths = set()
        for line in lines:
            body = line.strip()
            if body.startswith(("+", "|")) and body.endswith(("+", "|")):
                widths.add(len(body))
            if body.startswith("|"):
                self.assertEqual(body[1], " ", line)
                self.assertEqual(body[-2], " ", line)
        self.assertEqual(len(widths), 1, widths)
        self.assertEqual(widths.pop(), self.spec.ascii_width())

    def test_the_block_stays_inside_the_budget(self) -> None:
        for spec in yume_diagram_spec.load_all():
            block = yume_diagram_ascii.render(spec).rstrip("\n").split("\n")
            widest = max(len(line) for line in block)
            self.assertLessEqual(widest, yume_diagram_ascii.BUDGET, spec.name)

    def test_a_hop_leaves_and_lands_on_a_border_port(self) -> None:
        # A connector that does not touch a box reads as a line passing near
        # one. The tee on the border is what makes the figure connected.
        lines = yume_diagram_ascii.render(self.spec).rstrip("\n").split("\n")
        borders = [line for line in lines if line.strip().startswith("+")]
        self.assertIn("+", borders[1].strip()[1:-1], borders[1])
        self.assertNotIn("+", borders[-1].strip()[1:-1], borders[-1])

    def test_a_leaning_hop_is_drawn_with_diagonals(self) -> None:
        drawing = yume_diagram_ascii.render(self.spec)
        self.assertGreater(yume_diagram_ascii.step_for(self.spec), 0)
        self.assertIn("\\", drawing)

    def test_a_route_that_cannot_lean_falls_back_to_a_descent(self) -> None:
        # A figure a terminal would fold is worse than a straight one, so the
        # layout gives up the stairs rather than the budget.
        spec = yume_diagram_spec.parse(write_spec(Path(self._temp.name), MINIMAL))
        # A box exactly as wide as the budget leaves no room to step sideways.
        spec.nodes[0].title = "W" * (yume_diagram_ascii.BUDGET - 5)
        self.assertEqual(yume_diagram_ascii.step_for(spec), 0)
        block = yume_diagram_ascii.render(spec).rstrip("\n").split("\n")
        self.assertLessEqual(max(len(line) for line in block), yume_diagram_ascii.BUDGET)

    def test_a_roff_figure_escapes_its_backslashes(self) -> None:
        # roff reads a backslash as an escape, and one at the end of a line
        # joins that line to the next. An unescaped diagonal therefore
        # disappears from the rendered manual and takes its arrow with it.
        block = yume_diagrams.render_block(self.spec, Path("manual.1"))
        drawing = "\n".join(block)
        self.assertIn("\\e", drawing)
        for line in block:
            self.assertFalse(
                line.endswith("\\") and not line.endswith("\\e"),
                f"a line ending in a bare backslash continues into the next: {line!r}",
            )

    def test_a_markdown_figure_keeps_its_backslashes(self) -> None:
        # Markdown has no escape to undo, so the same drawing is literal.
        block = yume_diagrams.render_block(self.spec, Path("page.md"))
        self.assertNotIn("\\e", "\n".join(block))
        self.assertIn("\\", "\n".join(block))

    def test_channel_token_is_drawn_beside_the_arrow(self) -> None:
        self.assertIn("v ==YUME==>", yume_diagram_ascii.render(self.spec))

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

    def test_every_colour_defers_to_a_website_token(self) -> None:
        # A bare colour in the stylesheet would be a second palette the theme
        # toggle cannot reach. Every one is a fallback behind a token instead.
        for layout in ("vertical", "horizontal"):
            style = _stylesheet(yume_diagram_svg.render(self.spec, layout))
            for colour in re.findall(r"#[0-9a-f]{3,8}\b", style):
                self.assertRegex(
                    style,
                    r"var\(--color-[a-z-]+, " + re.escape(colour) + r"\)",
                    f"{layout}: {colour} is not behind a token",
                )

    def test_named_tokens_exist_in_the_website_palette(self) -> None:
        # A renamed token would leave every page on the fallback and nothing
        # would say so, because a missing custom property is not an error.
        tokens = (REPO_ROOT / "website" / "assets" / "tokens.css").read_text(
            encoding="utf-8"
        )
        for _local, token, _light, _dark in yume_diagram_svg.PALETTE:
            self.assertIn(f"{token}:", tokens, token)

    def test_a_renderer_without_css_still_draws_the_figure(self) -> None:
        # Presentation attributes lose to any stylesheet rule, so they change
        # nothing in a browser and are the whole rendering in librsvg. Without
        # them SVG's default fill is black, which is what a broken preview is.
        for layout in ("vertical", "horizontal"):
            markup = yume_diagram_svg.render(self.spec, layout)
            for element in re.findall(r"<(?:rect|path|circle) [^>]*>", markup):
                if 'class="dgm' not in element:
                    continue
                self.assertTrue(
                    "fill=" in element or "stroke=" in element,
                    f"{layout}: unpainted {element}",
                )

    def test_definition_ids_carry_the_diagram_and_layout(self) -> None:
        # A page may inline several diagrams. Shared ids would make one figure
        # reference another's filter.
        for layout in ("vertical", "horizontal"):
            markup = yume_diagram_svg.render(self.spec, layout)
            for identifier in re.findall(r'id="([^"]+)"', markup):
                self.assertTrue(
                    identifier.startswith(f"dgm-example-{layout}-"), identifier
                )

    def test_one_packet_travels_the_route(self) -> None:
        body = _body(yume_diagram_svg.render(self.spec))
        self.assertIn("--dgm-path:path(", body)
        self.assertEqual(body.count("dgm-packet-core"), 1)
        self.assertEqual(body.count("dgm-packet-glow"), 1)

    def test_the_packet_follows_the_arrow_it_is_drawn_beside(self) -> None:
        # Building the path from card centres gives a diagonal a different
        # slope from its own arrow, and the packet visibly misses the line.
        # Every arrow tip is a vertex of the path it travels.
        for spec in (self.spec, _grouped_spec()):
            for layout in ("vertical", "horizontal"):
                markup = yume_diagram_svg.render(spec, layout)
                route = set(_path_points(markup))
                tips = _arrow_tips(markup)
                self.assertTrue(tips)
                for tip in tips:
                    self.assertIn(tip, route, f"{spec.name}/{layout}: {tip}")

    def test_a_diagonal_hop_bends_the_packet_path(self) -> None:
        markup = yume_diagram_svg.render(_grouped_spec(), "horizontal")
        points = _path_points(markup)
        slanted = [
            (a, b)
            for a, b in zip(points, points[1:])
            if a[0] != b[0] and a[1] != b[1]
        ]
        self.assertTrue(slanted, "a plateau route has no diagonal segment")

    def test_the_packet_moves_at_one_rate_in_every_figure(self) -> None:
        # Timing the loop by hop count made the same route cross its stacked
        # drawing at half the speed of its across-the-page drawing, which said
        # something about the layout rather than about the route.
        rates = []
        for spec in [*yume_diagram_spec.load_all(), _grouped_spec()]:
            # A layers figure has no packet. Its rings light in wrapping order.
            if not spec.web or spec.type == "layers":
                continue
            for layout in ("vertical", "horizontal"):
                markup = yume_diagram_svg.render(spec, layout)
                seconds =float(re.search(r"--dgm-dur:([\d.]+)s", markup).group(1))
                points = _path_points(markup)
                length = sum(
                    math.dist(a, b) for a, b in zip(points, points[1:])
                )
                rates.append(length / seconds)
        self.assertAlmostEqual(min(rates), max(rates), delta=1.0)
        self.assertAlmostEqual(
            sum(rates) / len(rates), yume_diagram_svg.PIXELS_PER_SECOND, delta=1.0
        )

    def test_nothing_staggers_a_packet_that_has_no_second(self) -> None:
        markup = yume_diagram_svg.render(self.spec)
        self.assertNotIn("--dgm-phase", markup)
        self.assertNotIn("animation-delay", markup)

    def test_a_node_is_lit_exactly_while_the_packet_is_inside_it(self) -> None:
        # The packet is always either on a wire or in a node, and the figure
        # draws both. Without this the loop is blank for as long as the cards
        # are wide, which reads as the figure having stopped.
        for spec in (self.spec, _grouped_spec()):
            for layout in ("vertical", "horizontal"):
                markup = yume_diagram_svg.render(spec, layout)
                windows = _windows(markup)
                self.assertEqual(
                    [index for index, _a, _b in windows], list(range(len(spec.nodes)))
                )
                for (_i, _a, before), (_j, after, _b) in zip(windows, windows[1:]):
                    self.assertLessEqual(before, after, f"{spec.name}/{layout} overlap")

    def test_the_lit_time_is_the_time_the_packet_is_out_of_sight(self) -> None:
        # The two halves have to be complementary, or a node lights up while
        # the packet is somewhere else.
        markup = yume_diagram_svg.render(_grouped_spec(), "horizontal")
        lit = sum(leave - enter for _index, enter, leave in _windows(markup)) / 100
        points = _path_points(markup)
        total = sum(math.dist(a, b) for a, b in zip(points, points[1:]))
        cards = [
            (float(x), float(y), float(w), float(h))
            for x, y, w, h in re.findall(
                r'class="dgm-card"[^>]*? x="([\d.]+)" y="([\d.]+)" '
                r'width="([\d.]+)" height="([\d.]+)"',
                markup,
            )
        ]

        def hidden(point):
            return any(
                x <= point[0] <= x + w and y <= point[1] <= y + h
                for x, y, w, h in cards
            )

        inside = 0
        for step in range(2000):
            want = total * step / 2000
            run = 0.0
            for a, b in zip(points, points[1:]):
                span = math.dist(a, b)
                if run + span >= want and span:
                    k = (want - run) / span
                    if hidden((a[0] + (b[0] - a[0]) * k, a[1] + (b[1] - a[1]) * k)):
                        inside += 1
                    break
                run += span
        self.assertAlmostEqual(lit, inside / 2000, delta=0.02)

    def test_the_glyph_changes_with_the_chip_it_sits_on(self) -> None:
        # Leaving the glyph on the accent while the chip fills with the accent
        # puts light on light and the icon smears instead of reading.
        style = _stylesheet(yume_diagram_svg.render(self.spec))
        self.assertIn("--dgm-live-line: var(--dgm-card)", style)
        body = _body(yume_diagram_svg.render(self.spec))
        for element in re.findall(r'<(?:svg|circle) class="dgm-glyph[^"]*"', body):
            self.assertIn("dgm-here-", element, element)

    def test_presence_rules_are_scoped_to_their_own_figure(self) -> None:
        # Keyframe names are global to the page that inlines the SVG, and two
        # figures' windows differ, so an unscoped name would drive both.
        markup = yume_diagram_svg.render(self.spec, "horizontal")
        self.assertIn('data-dgm="example-horizontal"', markup)
        for name in re.findall(r"@keyframes (\S+)", markup):
            if "here" in name:
                self.assertTrue(name.startswith("dgm-example-horizontal-"), name)
        for rule in re.findall(r"(\[data-dgm=[^\]]+\] \.dgm-here-\d+)", markup):
            self.assertIn('"example-horizontal"', rule)

    def test_motion_is_switched_off_for_reduced_motion(self) -> None:
        style = _stylesheet(yume_diagram_svg.render(self.spec))
        self.assertIn("prefers-reduced-motion: reduce", style)
        self.assertIn("prefers-color-scheme: dark", style)

    def test_a_tunnelled_hop_is_drawn_as_a_conduit(self) -> None:
        # The channel decides the treatment, so the SVG and the ASCII cannot
        # disagree about which hop is the protected one.
        for layout in ("vertical", "horizontal"):
            body = _body(yume_diagram_svg.render(self.spec, layout))
            self.assertIn("dgm-conduit-flow", body, layout)

        def plain(document: dict) -> None:
            document["edges"][0].pop("channel")

        spec = self.parse_variant(plain)
        self.assertNotIn("dgm-conduit", _body(yume_diagram_svg.render(spec)))
        self.assertIn("dgm-link-plain", _body(yume_diagram_svg.render(spec)))

    def parse_variant(self, mutate) -> yume_diagram_spec.Spec:
        document = json.loads(json.dumps(MINIMAL))
        mutate(document)
        return yume_diagram_spec.parse(write_spec(Path(self._temp.name), document))

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


class MarkdownBlock(unittest.TestCase):
    def test_a_markdown_block_shows_the_figure_and_keeps_the_text(self) -> None:
        spec = yume_diagram_spec.load("direct_route")
        target = REPO_ROOT / "docs" / "EXPLAINED.md"
        lines = yume_diagrams.render_block(spec, target)
        image = lines[0]
        self.assertTrue(image.startswith("<img src="), image)
        source = image.split('src="', 1)[1].split('"', 1)[0]
        self.assertTrue((target.parent / source).is_file(), source)
        self.assertIn("```text", lines)
        drawing = "\n".join(lines)
        self.assertIn(yume_diagram_ascii.render(spec).rstrip("\n"), drawing)

    def test_an_empty_marker_pair_is_filled_by_sync(self) -> None:
        # This is how docs/diagrams/README.md says to place a new diagram.
        specs = {"direct_route": yume_diagram_spec.load("direct_route")}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "EXPLAINED.md"
            target.write_text(
                "# Doc\n\n<!-- yume-diagram: direct_route -->\n"
                "<!-- /yume-diagram -->\n",
                encoding="utf-8",
            )
            content, stale = yume_diagrams.rewrite(target, specs)
        self.assertTrue(stale)
        self.assertIn("<img src=", content)
        self.assertIn("```text", content)

    def test_a_man_block_stays_ascii(self) -> None:
        spec = yume_diagram_spec.load("direct_route")
        lines = yume_diagrams.render_block(spec, REPO_ROOT / "docs" / "man" / "yume.1")
        self.assertEqual(lines[0], ".nf")
        self.assertEqual(lines[-1], ".fi")
        self.assertNotIn("<img", "\n".join(lines))


FLOW = {
    "name": "example",
    "type": "flow",
    "title": "Example flow",
    "summary": "A chain whose middle node turns some requests aside.",
    "targets": {"web": True},
    "nodes": [
        {"id": "client", "kind": "client", "title": "YUME CLIENT", "sub": "carrier source"},
        {
            "id": "door",
            "kind": "gate",
            "title": "FRONT DOOR",
            "sub": "admission",
            "note": "Checks a token.",
            "source": ["scripts/"],
        },
        {"id": "target", "kind": "target", "title": "TARGET", "sub": "egress"},
        {"id": "cover", "kind": "site", "title": "COVER SITE", "sub": "pages", "side": True},
    ],
    "edges": [
        {"from": "client", "to": "door", "channel": "tunnel"},
        {"from": "door", "to": "target", "label": "valid"},
        {"from": "door", "to": "cover", "label": "no token"},
    ],
}

LAYERS = {
    "name": "example",
    "type": "layers",
    "title": "Example layers",
    "summary": "Three wrappings, innermost first.",
    "targets": {"web": True},
    "nodes": [
        {"id": "data", "role": "data", "title": "BYTES", "sub": "payload"},
        {"id": "seal", "role": "keys", "title": "SEALED", "sub": "AEAD"},
        {"id": "wire", "role": "neutral", "title": "TCP", "sub": "outermost"},
    ],
    "edges": [],
}


MERGE = {
    "name": "example",
    "type": "flow",
    "title": "Example merge",
    "summary": "Two inputs feed one derivation.",
    "targets": {"web": True},
    "nodes": [
        {"id": "left", "kind": "key", "title": "LEFT SECRET", "sub": "first input", "side": True},
        {"id": "right", "kind": "key", "title": "RIGHT SECRET", "sub": "second input", "side": True},
        {"id": "root", "kind": "process", "title": "ROOT KEY", "sub": "derivation"},
        {"id": "use", "kind": "key", "title": "MESSAGE KEY", "sub": "used once"},
    ],
    "edges": [
        {"from": "root", "to": "use", "label": "chain"},
        {"from": "left", "to": "root"},
        {"from": "right", "to": "root"},
    ],
}


class FlowInputs(unittest.TestCase):
    def load(self, document: dict) -> yume_diagram_spec.Spec:
        with tempfile.TemporaryDirectory() as directory:
            return yume_diagram_spec.parse(write_spec(Path(directory), document))

    def variant(self, change) -> dict:
        document = json.loads(json.dumps(MERGE))
        change(document)
        return document

    def test_inputs_feed_the_first_chain_node(self) -> None:
        spec = self.load(MERGE)
        self.assertEqual([node.id for _edge, node in spec.inputs()], ["left", "right"])
        self.assertEqual([node.id for node in spec.chain()], ["root", "use"])
        self.assertEqual(spec.nodes[0].tone, "keys")

    def test_an_input_into_a_later_node_is_rejected(self) -> None:
        with self.assertRaises(SpecError):
            self.load(self.variant(lambda document: document["edges"][1].update(to="use")))

    def test_an_input_takes_no_label(self) -> None:
        with self.assertRaises(SpecError):
            self.load(self.variant(lambda document: document["edges"][1].update(label="mix")))

    def test_the_ascii_inputs_drop_onto_the_first_port(self) -> None:
        lines = yume_diagram_ascii.render(self.load(MERGE)).split("\n")
        joins = [line.rstrip().rfind("+") for line in lines if "SECRET" in line]
        self.assertEqual(len(set(joins)), 1)
        bus = joins[0]
        arrow = next(index for index, line in enumerate(lines) if len(line) > bus and line[bus] == "v")
        self.assertEqual(lines[arrow + 1][bus], "+")
        self.assertIn("ROOT KEY", lines[arrow + 2])

    def test_inputs_join_one_bus_that_ends_on_the_first_card(self) -> None:
        spec = self.load(MERGE)
        for layout in ("vertical", "horizontal"):
            markup = yume_diagram_svg.render(spec, layout)
            body = _body(markup)
            self.assertEqual(body.count('class="dgm-junction"'), 2, layout)
            self.assertNotIn("dgm-here-", body.split('data-node="right"', 1)[1].split("</g>", 1)[0])
            cards = _cards(markup)
            first = cards[2]
            tips = _arrow_tips(markup)
            if layout == "horizontal":
                self.assertTrue(any(abs(x - (first[0] - yume_diagram_svg.CARD_CLEARANCE)) < 0.01 for x, _y in tips))
            else:
                self.assertTrue(any(abs(y - (first[1] - yume_diagram_svg.CARD_CLEARANCE)) < 0.01 for _x, y in tips))


class FlowsAndLayers(unittest.TestCase):
    def load(self, document: dict) -> yume_diagram_spec.Spec:
        with tempfile.TemporaryDirectory() as directory:
            return yume_diagram_spec.parse(write_spec(Path(directory), document))

    def variant(self, base: dict, change) -> dict:
        document = json.loads(json.dumps(base))
        change(document)
        return document

    def test_a_flow_separates_its_chain_from_its_branch(self) -> None:
        spec = self.load(FLOW)
        self.assertEqual([node.id for node in spec.chain()], ["client", "door", "target"])
        self.assertEqual(
            [(parent, node.id) for parent, _edge, node in spec.branches()], [(1, "cover")]
        )

    def test_a_side_node_needs_exactly_one_branch(self) -> None:
        with self.assertRaises(SpecError):
            self.load(self.variant(FLOW, lambda document: document["edges"].pop()))

    def test_a_node_sends_at_most_one_branch(self) -> None:
        def second(document: dict) -> None:
            document["nodes"].append({"id": "probe", "kind": "site", "title": "PROBE", "side": True})
            document["edges"].append({"from": "door", "to": "probe"})

        with self.assertRaises(SpecError):
            self.load(self.variant(FLOW, second))

    def test_a_route_cannot_hold_a_side_node(self) -> None:
        with self.assertRaises(SpecError):
            self.load(self.variant(MINIMAL, lambda document: document["nodes"][1].update(side=True)))

    def test_layers_take_roles_and_no_edges(self) -> None:
        with self.assertRaises(SpecError):
            self.load(self.variant(LAYERS, lambda document: document["nodes"][0].pop("role")))
        with self.assertRaises(SpecError):
            self.load(
                self.variant(
                    LAYERS, lambda document: document["edges"].append({"from": "data", "to": "seal"})
                )
            )

    def test_an_unknown_role_is_rejected(self) -> None:
        with self.assertRaises(SpecError):
            self.load(self.variant(FLOW, lambda document: document["nodes"][0].update(role="pink")))

    def test_a_kind_implies_a_role(self) -> None:
        tones = {node.id: node.tone for node in self.load(FLOW).nodes}
        self.assertEqual(
            tones, {"client": "client", "door": "server", "target": "outside", "cover": "disguise"}
        )

    def test_a_source_that_escapes_the_repository_is_rejected(self) -> None:
        with self.assertRaises(SpecError):
            self.load(
                self.variant(FLOW, lambda document: document["nodes"][1].update(source=["../outside"]))
            )

    def test_a_missing_source_is_reported(self) -> None:
        spec = self.load(
            self.variant(
                FLOW,
                lambda document: document["nodes"][1].update(source=["scripts/", "no/such/file.cpp"]),
            )
        )
        problems = yume_diagram_spec.missing_sources(spec, REPO_ROOT)
        self.assertEqual(len(problems), 1)
        self.assertIn("no/such/file.cpp", problems[0])

    def test_the_ascii_branch_leaves_its_parent_on_the_title_row(self) -> None:
        lines = yume_diagram_ascii.render(self.load(FLOW)).split("\n")
        row = next(line for line in lines if "FRONT DOOR" in line)
        self.assertRegex(row, r"\+-+>\|  COVER SITE")
        self.assertIn("no token", lines[lines.index(row) + 1])

    def test_ascii_layers_nest_outermost_first_at_one_width(self) -> None:
        lines = yume_diagram_ascii.render(self.load(LAYERS)).rstrip("\n").split("\n")
        self.assertEqual(len({len(line) for line in lines}), 1)
        titles = [line.strip("| ").split()[0] for line in lines if "|" in line and line.strip("|+- ")]
        self.assertEqual([title for title in titles if title[0].isalpha()], ["TCP", "SEALED", "BYTES"])
        self.assertLessEqual(len(lines[0]), yume_diagram_ascii.BUDGET)

    def test_a_side_card_is_never_lit_by_the_packet(self) -> None:
        for layout in ("vertical", "horizontal"):
            markup = yume_diagram_svg.render(self.load(FLOW), layout)
            self.assertEqual({index for index, _lit, _dark in _windows(markup)}, {0, 1, 2}, layout)
            self.assertNotIn("dgm-here-", markup.split('data-node="cover"', 1)[1], layout)

    def test_a_branch_is_dashed_in_the_role_it_turns_towards(self) -> None:
        body = _body(yume_diagram_svg.render(self.load(FLOW), "horizontal"))
        self.assertIn('<g class="dgm-branch dgm-role-disguise">', body)
        self.assertIn("dgm-link-branch", body)

    def test_the_stacked_flow_runs_its_path_down_the_glyph_rail(self) -> None:
        markup = yume_diagram_svg.render(self.load(FLOW), "vertical")
        cards = _cards(markup)
        rail = cards[0][0] + yume_diagram_svg.RAIL_X
        self.assertEqual(len([tip for tip in _arrow_tips(markup) if tip[0] == rail]), 2)
        self.assertEqual(max(x for x, _y in cards) - cards[0][0], yume_diagram_svg.SIDE_INDENT)

    def test_layers_light_innermost_first(self) -> None:
        for layout in ("vertical", "horizontal"):
            markup = yume_diagram_svg.render(self.load(LAYERS), layout)
            self.assertEqual(_body(markup).count('<rect class="dgm-ring '), 3)
            windows = sorted(_windows(markup))
            self.assertEqual([index for index, _lit, _dark in windows], [0, 1, 2])
            self.assertTrue(all(a[1] < b[1] for a, b in zip(windows, windows[1:])))
            self.assertNotIn("dgm-packet", _body(markup))

    def test_every_role_has_its_own_website_tokens(self) -> None:
        tokens = {local: token for local, token, _light, _dark in yume_diagram_svg.PALETTE}
        for role in yume_diagram_spec.ROLES:
            if role == "neutral":
                continue
            for suffix in ("", "-strong", "-soft"):
                self.assertEqual(tokens[f"{role}{suffix}"], f"--color-role-{role}{suffix}")

    def test_a_site_without_role_tokens_draws_roles_in_its_accent(self) -> None:
        css = (
            ":root { --paper: oklch(98% 0.01 305); --surface: oklch(99% 0.01 305);"
            " --text: oklch(20% 0.01 305); --text-3: oklch(50% 0.01 305);"
            " --rule: oklch(85% 0.01 305); --accent: oklch(60% 0.15 306);"
            " --accent-hover: oklch(70% 0.12 306); --accent-wash: oklch(95% 0.03 306);"
            ' --font-display: "A"; --font-mono: "B"; }'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tokens.css"
            path.write_text(css, encoding="utf-8")
            palette, _display, _mono = yume_diagram_theme.load(path, yume_diagram_spec.ROLES)
        tokens = {local: token for local, token, _light, _dark in palette}
        self.assertEqual(tokens["server"], "--accent")
        self.assertEqual(tokens["neutral-strong"], "--text-3")

    def test_the_key_lists_each_noted_part_with_its_role(self) -> None:
        key = yume_diagrams.key_html(self.load(FLOW))
        self.assertEqual(key.count('class="diagram-key-item"'), 1)
        self.assertIn('data-node="door" data-role="server"', key)
        self.assertIn("<code>scripts/</code>", key)

    def test_markdown_links_each_source_from_the_document(self) -> None:
        block = yume_diagrams.render_block(self.load(FLOW), REPO_ROOT / "docs" / "EXAMPLE.md")
        self.assertIn("- **FRONT DOOR**: Checks a token. ([`scripts/`](../scripts))", block)


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
            shutil.copy2(REPO_ROOT / "scripts/yume_doc_spec.py", root / "scripts/yume_doc_spec.py")
            # `check` also proves that every node source still exists, so the
            # fixture sees the same top-level trees those sources point into.
            tops = {
                source.split("/")[0]
                for spec in yume_diagram_spec.load_all()
                for node in spec.nodes
                for source in node.sources
            }
            for top in sorted(tops):
                if not (root / top).exists():
                    (root / top).symlink_to(REPO_ROOT / top)
            website = root / "website" / "assets"
            website.mkdir(parents=True)
            shutil.copy2(
                REPO_ROOT / "website" / "assets" / "tokens.css", website / "tokens.css"
            )
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
