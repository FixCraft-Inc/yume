#!/usr/bin/env python3
"""The multi-loop fixture owns children as soon as each spawn succeeds."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import run_native_loops_test as loops


class LoopCleanupTest(unittest.TestCase):
    def test_later_spawn_failure_reaps_every_started_child(self) -> None:
        for failed_spawn in (3, loops.CLIENTS + 1):
            with self.subTest(failed_spawn=failed_spawn):
                self.check_spawn_failure(failed_spawn)

    def check_spawn_failure(self, failed_spawn: int) -> None:
        children: list[subprocess.Popen] = []
        target = mock.Mock()

        def provision(kit: Path, *args: object) -> None:
            (kit / "server/credentials").mkdir(parents=True)
            (kit / "server/yumed.json").write_text(json.dumps({"endpoint": {}}))
            (kit / "server/credentials/authorized-keys.json").write_text(
                json.dumps({"keys": [{} for _ in range(loops.CLIENTS)]}))
            client(kit / "client")

        def client(bundle: Path) -> None:
            bundle.mkdir()
            (bundle / "yume.json").write_text(json.dumps({"endpoint": {}, "adapters": []}))

        def add_client(_setup: Path, arguments: list[str], _environment: dict) -> None:
            client(Path(arguments[arguments.index("--output") + 1]))

        def start(*args: object) -> subprocess.Popen:
            if len(children) + 1 == failed_spawn:
                raise OSError("injected later spawn refusal")
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
            children.append(child)
            return child

        try:
            with mock.patch.multiple(
                loops.session, openssl_environment=mock.Mock(return_value={}),
                setup_program=mock.Mock(return_value=Path("setup")),
                free_ports=mock.Mock(return_value=list(range(loops.CLIENTS + 2))),
                provision_kit=provision, configure_kit=mock.Mock(), run_setup=add_client,
                serve_payload=mock.Mock(return_value=target), wait_for_port=mock.Mock(),
            ), mock.patch.object(loops, "start", side_effect=start):
                with self.assertRaisesRegex(OSError, "later spawn refusal"):
                    loops.run(Path("yumed"), Path("yume"), Path("openssl"), None)
            target.shutdown.assert_called_once_with()
            self.assertEqual(len(children), failed_spawn - 1)
            self.assertTrue(all(child.poll() is not None for child in children),
                            "the fixture leaked an earlier child after a later spawn failed")
        finally:
            # The removed-fix control must not leave the leaked children behind.
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
