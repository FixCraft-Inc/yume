#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Tests for the generated CLI help text and bash completion script.

Run with `python3 scripts/test_yume_cli.py`.

The cases fall into three groups. The layout grammar has to reject a malformed
source rather than print something surprising. The two renderers have to place
a help entry on the column the source asks for and build a completion script
that completes the same words whatever order they are written in. The tracked
headers have to stay current, which is the same comparison the CI gate runs.
"""

from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import yume_cli
import yume_doc_spec
from yume_cli import CliError

MANUAL = """#!yume-doc 1
name:        sample
kind:        man
title:       sample-tool
summary:     an example command
man:         docs/man/sample.1
man-section: 1
man-date:    2026-01-02
man-source:  YUME 0.3.0-dev1
man-manual:  YUME Manual
---
@synopsis
**sample-tool** [ *options* ]
@end

## OPTIONS

@options
@opt **-s, --sample** *path*
@cli file: yes
@cli spell: -s, --sample <path>
@cli help: Read the sample from a file

Read the sample from a file.
@opt **--mode** *name*
@cli values: fast slow
@cli spell: --mode <name>
@cli help: fast or slow

Pick a mode.
@opt **--quiet**

Say less. Completed, never printed.
@end
"""

LAYOUT = """#!yume-cli 1
binary:    sample
manual:    sample
output:    src/client/sample_text.hpp
namespace: yume::sample
---
@usage
sample --sample <path>
@end

@section Options
-s
--mode
"""


class Harness(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name)
        (self.root / "en_US" / "man").mkdir(parents=True)
        (self.root / "en_US" / "cli").mkdir(parents=True)
        for module in (yume_cli, yume_doc_spec):
            saved = module.SOURCE_ROOT
            module.SOURCE_ROOT = self.root
            self.addCleanup(setattr, module, "SOURCE_ROOT", saved)

    def write(self, manual: str = MANUAL, layout: str = LAYOUT) -> yume_cli.Layout:
        (self.root / "en_US" / "man" / "sample.doc").write_text(manual, encoding="utf-8")
        path = self.root / "en_US" / "cli" / "sample.cli"
        path.write_text(layout, encoding="utf-8")
        return yume_cli.parse_layout(path)

    def resolve(self, **kwargs):
        return yume_cli.resolve(self.write(**kwargs))

    def help_lines(self, **kwargs) -> list[str]:
        layout = self.write(**kwargs)
        ordered, _ = yume_cli.resolve(layout)
        return yume_cli.render_help(layout, ordered)

    def completion(self, **kwargs) -> list[str]:
        layout = self.write(**kwargs)
        _, completed = yume_cli.resolve(layout)
        return yume_cli.render_completion(layout, completed)


class Grammar(Harness):
    def test_a_valid_layout_parses(self) -> None:
        layout = self.write()
        self.assertEqual(layout.binary, "sample")
        self.assertEqual([item.kind for item in layout.items][:2], ["usage", "section"])

    def test_the_magic_line_is_required(self) -> None:
        with self.assertRaisesRegex(CliError, "first line"):
            self.write(layout=LAYOUT.replace("#!yume-cli 1", "# not a layout"))

    def test_an_unknown_header_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(CliError, "unknown header key"):
            self.write(layout=LAYOUT.replace("namespace: yume::sample", "colour:    red"))

    def test_an_unknown_output_kind_is_rejected(self) -> None:
        with self.assertRaisesRegex(CliError, "output-kind must be"):
            self.write(layout=LAYOUT.replace("---", "output-kind: arbitrary\n---"))

    def test_a_missing_header_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(CliError, "the header has no"):
            self.write(layout=LAYOUT.replace("namespace: yume::sample\n", ""))

    def test_the_binary_must_match_the_file_name(self) -> None:
        with self.assertRaisesRegex(CliError, "must match the file name"):
            self.write(layout=LAYOUT.replace("binary:    sample", "binary:    other"))

    def test_an_unknown_directive_is_rejected(self) -> None:
        with self.assertRaisesRegex(CliError, "unknown directive"):
            self.write(layout=LAYOUT.replace("@section Options", "@chapter Options"))

    def test_an_unclosed_block_is_rejected(self) -> None:
        with self.assertRaisesRegex(CliError, "not closed by @end"):
            self.write(layout=LAYOUT.replace("sample --sample <path>\n@end", "sample --sample <path>"))

    def test_a_section_adds_its_own_colon(self) -> None:
        with self.assertRaisesRegex(CliError, "adds the colon"):
            self.write(layout=LAYOUT.replace("@section Options", "@section Options:"))

    def test_a_stray_word_is_not_an_option_reference(self) -> None:
        with self.assertRaisesRegex(CliError, "neither a directive nor an option"):
            self.write(layout=LAYOUT + "not a flag\n")

    def test_a_layout_opens_with_usage(self) -> None:
        with self.assertRaisesRegex(CliError, "opens with @usage"):
            self.write(layout=LAYOUT.replace("@usage\nsample --sample <path>\n@end\n\n", ""))


class CrossChecks(Harness):
    def test_a_reference_with_no_option_is_rejected(self) -> None:
        with self.assertRaisesRegex(CliError, "has no @opt"):
            self.resolve(layout=LAYOUT + "--missing\n")

    def test_an_option_the_layout_never_prints_is_rejected(self) -> None:
        with self.assertRaisesRegex(CliError, "never prints"):
            self.resolve(layout=LAYOUT.replace("--mode\n", ""))

    def test_an_option_printed_twice_is_rejected(self) -> None:
        with self.assertRaisesRegex(CliError, "more often than"):
            self.resolve(layout=LAYOUT + "--mode\n")

    def test_a_second_printed_entry_is_matched_in_order(self) -> None:
        manual = MANUAL.replace(
            "@cli help: fast or slow",
            "@cli help: fast or slow\n@cli spell: --mode <n>\n@cli help: numeric form",
        )
        lines = self.help_lines(manual=manual, layout=LAYOUT + "--mode\n")
        self.assertIn("  --mode <name>            fast or slow", lines)
        self.assertIn("  --mode <n>               numeric form", lines)

    def test_a_manual_the_layout_does_not_name_is_rejected(self) -> None:
        with self.assertRaisesRegex(CliError, "no such manual"):
            self.resolve(layout=LAYOUT.replace("manual:    sample", "manual:    absent"))


class HelpGeometry(Harness):
    def test_a_description_sits_on_the_default_column(self) -> None:
        lines = self.help_lines()
        entry = next(line for line in lines if line.startswith("  -s,"))
        self.assertEqual(entry.index("Read"), yume_cli.COLUMN)

    def test_a_column_override_moves_the_description(self) -> None:
        manual = MANUAL.replace(
            "@cli help: Read the sample from a file",
            "@cli help: Read the sample from a file\n@cli column: 30",
        )
        lines = self.help_lines(manual=manual)
        entry = next(line for line in lines if line.startswith("  -s,"))
        self.assertEqual(entry.index("Read"), 30)

    def test_a_long_term_wraps_onto_its_own_line(self) -> None:
        manual = MANUAL.replace(
            "@cli spell: -s, --sample <path>",
            "@cli spell: -s, --sample <a-very-long-argument-spelling>",
        )
        lines = self.help_lines(manual=manual)
        index = next(i for i, line in enumerate(lines) if line.startswith("  -s,"))
        self.assertEqual(lines[index].rstrip(), lines[index])
        self.assertEqual(lines[index + 1].index("Read"), yume_cli.COLUMN)

    def test_later_lines_sit_on_the_continuation_column(self) -> None:
        manual = MANUAL.replace(
            "@cli help: Read the sample from a file",
            "@cli help: Read the sample from a file\n@cli help: and keep reading",
        )
        lines = self.help_lines(manual=manual)
        self.assertIn(" " * yume_cli.CONTINUATION + "and keep reading", lines)

    def test_a_leading_space_indents_one_line_further(self) -> None:
        manual = MANUAL.replace(
            "@cli help: Read the sample from a file",
            "@cli help: Read the sample from a file\n@cli help:   nested",
        )
        lines = self.help_lines(manual=manual)
        self.assertIn(" " * (yume_cli.CONTINUATION + 2) + "nested", lines)

    def test_a_section_is_preceded_by_one_blank_line(self) -> None:
        lines = self.help_lines()
        self.assertEqual(lines[lines.index("Options:") - 1], "")

    def test_a_gap_prints_one_blank_line(self) -> None:
        lines = self.help_lines(layout=LAYOUT.replace("-s\n", "-s\n@gap\n"))
        self.assertEqual(lines[lines.index("  --mode <name>            fast or slow") - 1], "")


class Completion(Harness):
    def facts(self, **kwargs) -> tuple[list[str], list[str], dict[str, list[str]]]:
        text = "\n".join(self.completion(**kwargs))
        words = re.search(r'local opts="([^"]*)"', text).group(1).split()
        files = re.search(r'local file_opts="([^"]*)"', text).group(1).split()
        arms = {
            name.strip(): match.group(2).split()
            for match in re.finditer(
                r"\n    ([^\n]*?)\)\n\s*COMPREPLY=\( \$\(compgen -W \"([^\"]*)\"", text
            )
            for name in match.group(1).split("|")
        }
        return words, files, arms

    def test_every_flag_bearing_option_completes(self) -> None:
        words, _, _ = self.facts()
        self.assertEqual(words, ["-s", "--mode", "--quiet", "--sample"])

    def test_documented_rejected_options_can_be_excluded_from_completion(self) -> None:
        manual = MANUAL.replace("@opt **--quiet**", "@opt **--quiet**\n@cli complete: no")
        words, files, arms = self.facts(manual=manual)
        self.assertNotIn("--quiet", words + files + list(arms))

    def test_a_file_option_reaches_the_file_list(self) -> None:
        _, files, _ = self.facts()
        self.assertEqual(files, ["-s", "--sample"])

    def test_a_value_enum_becomes_a_case_arm(self) -> None:
        _, _, arms = self.facts()
        self.assertEqual(arms["--mode"], ["fast", "slow"])

    def test_the_end_of_options_marker_is_not_a_completion_word(self) -> None:
        manual = MANUAL.replace("@opt **--quiet**", "@opt **--**")
        words, _, _ = self.facts(manual=manual)
        self.assertNotIn("--", words)

    def test_the_word_order_does_not_depend_on_declaration_order(self) -> None:
        first, _, _ = self.facts()
        shuffled = MANUAL.replace(
            "@opt **--quiet**\n\nSay less. Completed, never printed.\n", ""
        ).replace("## OPTIONS\n\n@options\n", "## OPTIONS\n\n@options\n@opt **--quiet**\n\nSay less.\n")
        second, _, _ = self.facts(manual=shuffled)
        self.assertEqual(first, second)


class Interpolation(Harness):
    def test_a_known_value_becomes_a_stream_expression(self) -> None:
        manual = MANUAL.replace(
            "@cli help: fast or slow", "@cli help: fast or slow (default {{reverse-port-min}})"
        )
        layout = self.write(manual=manual)
        ordered, completed = yume_cli.resolve(layout)
        text = yume_cli.render_header(layout, ordered, completed)
        self.assertIn("<< yume::policy::kReversePortMinDefault", text)
        self.assertIn('#include "core/protocol/runtime_policy.hpp"', text)

    def test_an_unknown_value_is_rejected(self) -> None:
        manual = MANUAL.replace("@cli help: fast or slow", "@cli help: fast or slow {{nonsense}}")
        layout = self.write(manual=manual)
        ordered, completed = yume_cli.resolve(layout)
        with self.assertRaisesRegex(CliError, "unknown interpolation"):
            yume_cli.render_header(layout, ordered, completed)

    def test_a_single_brace_stays_literal(self) -> None:
        manual = MANUAL.replace("@cli help: fast or slow", "@cli help: permissions.{a,b}")
        layout = self.write(manual=manual)
        ordered, completed = yume_cli.resolve(layout)
        self.assertIn('"  --mode <name>            permissions.{a,b}\\n"',
                      yume_cli.render_header(layout, ordered, completed))


class StaticHelp(Harness):
    def layout(self, manual: str = MANUAL) -> yume_cli.Layout:
        return self.write(manual=manual, layout=LAYOUT.replace("---", "output-kind: static-help\n---"))

    def test_static_help_is_an_include_free_literal(self) -> None:
        layout = self.layout()
        text = yume_cli.build(layout)
        self.assertIn("inline constexpr char kHelpBody[] =", text)
        self.assertNotIn("#include", text)
        self.assertNotIn("write_bash_completion", text)

    def test_static_help_escapes_quotes_and_backslashes(self) -> None:
        layout = self.layout(MANUAL.replace("fast or slow", 'read "C:\\sample"'))
        text = yume_cli.build(layout)
        self.assertIn(r'read \"C:\\sample\"\n"', text)

    def test_static_help_rejects_runtime_interpolation(self) -> None:
        for value in ("reverse-port-min", "absent"):
            with self.subTest(value=value):
                layout = self.layout(MANUAL.replace("fast or slow", "{{" + value + "}}"))
                with self.assertRaisesRegex(CliError, "static-help cannot interpolate"):
                    yume_cli.build(layout)


class Tracked(unittest.TestCase):
    """The real sources, and the headers a clone builds from."""

    def setUp(self) -> None:
        self.layouts = yume_cli.load_layouts()

    def test_each_native_binary_has_one_layout(self) -> None:
        self.assertEqual(sorted(item.binary for item in self.layouts), ["yume", "yumed"])

    def test_native_help_has_exactly_the_parser_options(self) -> None:
        for layout in self.layouts:
            with self.subTest(binary=layout.binary):
                ordered, _ = yume_cli.resolve(layout)
                self.assertEqual({flag for entry in ordered for flag in entry.flags},
                                 {"--config", "--validate", "--version", "--help", "-h"})
                self.assertEqual(layout.output_kind, "static-help")

    def test_every_generated_header_is_current(self) -> None:
        # The same comparison `scripts/yume_cli.py check` runs in CI.
        for layout in self.layouts:
            path = yume_cli.REPO_ROOT / layout.output
            self.assertTrue(path.is_file(), layout.output)
            self.assertEqual(
                path.read_text(encoding="utf-8"),
                yume_cli.build(layout),
                f"{layout.output} is stale, so run scripts/yume_cli.py sync",
            )

    def test_every_generated_header_carries_the_banner(self) -> None:
        for layout in self.layouts:
            path = yume_cli.REPO_ROOT / layout.output
            self.assertIn(yume_cli.BANNER, path.read_text(encoding="utf-8").split("\n")[0])

    def test_the_help_and_the_manual_describe_the_same_options(self) -> None:
        for layout in self.layouts:
            ordered, completed = yume_cli.resolve(layout)
            self.assertTrue(ordered)
            printed = {flag for entry in ordered for flag in entry.flags}
            declared = {flag for option in completed for flag in yume_doc_spec.cli_flags(option)}
            self.assertTrue(printed <= declared, layout.binary)


if __name__ == "__main__":
    unittest.main(verbosity=1)
