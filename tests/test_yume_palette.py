#!/usr/bin/env python3
"""Exercise palette validation, generation and the non-mutating drift gate."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import yume_palette as palette


class PaletteTests(unittest.TestCase):
    def test_checked_in_views_match_the_source(self) -> None:
        loaded = palette.load()
        self.assertEqual(palette.generate(palette.render(loaded, ROOT), check=True), [])

    def test_themes_are_separate_and_the_mark_keeps_its_colours(self) -> None:
        themes = palette.load()['themes']
        self.assertEqual(set(themes), {'light', 'dark', 'amoled'})
        light, dark = themes['light'], themes['dark']
        self.assertNotEqual(light['page'].hex, dark['page'].hex)
        self.assertNotEqual(light['button'].hex, dark['button'].hex)
        self.assertEqual(themes['amoled']['page'].hex, '#000000')
        # The colours the original translucent mark shows over white.
        self.assertEqual((light['logoFrom'].hex, light['logoTo'].hex), ('#FFCBF3', '#E59FD1'))
        # A light theme keeps light surfaces under dark text and a light button.
        self.assertGreater(palette.luminance(light['surface'].hex), palette.luminance(light['page'].hex))
        self.assertGreater(palette.luminance(light['button'].hex), 0.6)

    def test_oklch_conversion_matches_known_colours(self) -> None:
        self.assertEqual(palette.Colour([1.0, 0.0], 0, 'white').hex, '#FFFFFF')
        self.assertEqual(palette.Colour([0.0, 0.0], 0, 'black').hex, '#000000')
        self.assertEqual(palette.Colour([0.62796, 0.25768, 29.2339], 0, 'red').hex, '#FF0000')

    def test_validation_refuses_low_contrast_and_unknown_tokens(self) -> None:
        source = json.loads((ROOT / palette.SOURCE).read_text(encoding='utf-8'))
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'palette.json'
            faint = copy.deepcopy(source)
            faint['themes']['light']['muted'] = [0.8, 0.01]
            path.write_text(json.dumps(faint))
            with self.assertRaisesRegex(ValueError, 'muted on'):
                palette.load(path)
            unknown = copy.deepcopy(source)
            unknown['variants']['amoled']['tokens']['sparkle'] = [0.5, 0.1]
            path.write_text(json.dumps(unknown))
            with self.assertRaisesRegex(ValueError, 'unknown tokens'):
                palette.load(path)
            missing = copy.deepcopy(source)
            del missing['themes']['dark']['hover']
            path.write_text(json.dumps(missing))
            with self.assertRaisesRegex(ValueError, 'missing'):
                palette.load(path)

    def test_cli_detects_drift_without_rewriting_and_targets_android(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'native'
            android = Path(temp) / 'android'
            for name in ('scripts/yume_palette.py', str(palette.SOURCE), str(palette.WEB_OUTPUT),
                         str(palette.MARK_SOURCE)):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            foreground = android / palette.ANDROID_MARK_OUTPUT
            foreground.parent.mkdir(parents=True)
            foreground.write_text('<gradient>\n<item android:offset="0" android:color="#DCFFC3F1"/>\n'
                                  '<item android:offset="1" android:color="#DBE18FCA"/>\n</gradient>\n')
            command = [sys.executable, str(root / 'scripts/yume_palette.py'), 'generate', '--android-root', str(android)]

            def run(*args: str) -> subprocess.CompletedProcess:
                return subprocess.run(command + list(args), capture_output=True, text=True, timeout=20)
            self.assertNotEqual(run('--check').returncode, 0)
            self.assertFalse((root / palette.QML_OUTPUT).exists())
            self.assertEqual(run().returncode, 0, run().stderr)
            self.assertEqual(run('--check').returncode, 0)
            self.assertIn('android:color="#FFFFCBF3"', foreground.read_text())
            target = android / palette.ANDROID_OUTPUT
            self.assertIn('internal val YumeAmoled', target.read_text())
            target.write_text('drift\n')
            self.assertNotEqual(run('--check').returncode, 0)
            self.assertEqual(target.read_text(), 'drift\n')


if __name__ == '__main__':
    unittest.main()
