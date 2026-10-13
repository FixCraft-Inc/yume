#!/usr/bin/env python3
"""Exercise credit generation, validation and the non-mutating drift gate."""
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
import yume_credits as credits


class CreditsTests(unittest.TestCase):
    def test_checked_in_views(self) -> None:
        data, messages = credits.load()
        self.assertEqual(credits.generate(credits.render(data, messages, ROOT), check=True), [])
        helpers = [p for p in data['contributors'] if p['name'] in ('Codex', 'Claude')]
        self.assertEqual(len(helpers), 2)
        self.assertEqual(helpers[0]['role'], helpers[1]['role'])
        self.assertEqual(helpers[0]['contribution'], helpers[1]['contribution'])
        self.assertNotIn('libsystemd', [c['name'] for c in data['components']['native']])
        self.assertEqual(data['components']['android'][0]['license'], 'LGPL-3.0-or-later')

    def test_cli_detects_drift_without_rewriting_and_targets_android(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'native'
            android = Path(temp) / 'android'
            (android / 'app').mkdir(parents=True)
            for name in ('scripts/yume_credits.py', 'scripts/yume_translations.py', 'config/credits.json', 'translations/catalog.json'):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            command = [sys.executable, str(root / 'scripts/yume_credits.py'), 'generate', '--android-root', str(android)]
            def run(*args: str) -> subprocess.CompletedProcess:
                return subprocess.run(command + list(args), capture_output=True, text=True, timeout=20)
            self.assertNotEqual(run('--check').returncode, 0)
            self.assertFalse((root / 'src').exists())
            self.assertEqual(run().returncode, 0)
            self.assertEqual(run('--check').returncode, 0)
            self.assertFalse((root / 'app').exists())
            target = android / credits.ANDROID_OUTPUT
            target.write_text('drift\n')
            self.assertNotEqual(run('--check').returncode, 0)
            self.assertEqual(target.read_text(), 'drift\n')

    def test_malformed_input_fails_even_under_optimized_python(self) -> None:
        data, _ = credits.load()
        for mutate in (
            lambda d: d.update(schema=True),
            lambda d: d['contributors'][0].update(role='missing.id'),
            lambda d: d['contributors'].append(d['contributors'][0]),
            lambda d: d['components']['native'][0].update(license=''),
        ):
            malformed = copy.deepcopy(data)
            mutate(malformed)
            with tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / 'credits.json'
                path.write_text(json.dumps(malformed))
                with self.assertRaises(ValueError):
                    credits.load(path)

    def test_source_escaping_and_typed_localization(self) -> None:
        value = 'O\'Brien "quoted" \\ path $template 日本語'
        self.assertEqual(json.loads(credits.literal(value)), value)
        self.assertIn(r'\$template', credits.literal(value, kotlin=True))
        data, messages = credits.load()
        data['contributors'][0]['name'] = value
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outputs = credits.render(data, messages, root, root / 'android')
            kotlin = outputs[root / 'android' / credits.ANDROID_OUTPUT]
            self.assertIn('role: MessageId', kotlin)
            self.assertIn('MessageId.CREDITS_HELPER_CONTRIBUTION', kotlin)
            self.assertNotIn('libsystemd', kotlin)
            self.assertIn('mlkitComponents', kotlin)
            self.assertIn(credits.literal(value, kotlin=True), kotlin)


if __name__ == '__main__':
    unittest.main()
