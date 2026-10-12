#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""GUI subprocess fixture; real schema validation is covered by setup/live tests."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> int:
    args = sys.argv[1:]
    if len(args) != 5 or args[:2] != ["tune", "--config"]:
        return 2
    path = Path(args[2])
    config = json.loads(path.read_text())
    if args[3] == "--preset":
        table = json.loads((Path(__file__).resolve().parents[2] / "config/tuning_presets.json").read_text())
        config.setdefault("limits", {}).update(next(p["limits"] for p in table["presets"] if p["id"] == args[4]))
    elif args[3] == "--set":
        key, value = args[4].split("=", 1)
        # An explicit fixture refusal, not a second schema implementation.
        if value == "0":
            print("fixture refused zero")
            return 1
        config.setdefault("limits", {})[key] = json.loads(value)
    else:
        return 2
    path.write_text(json.dumps(config))
    if "YUME_FAKE_SETUP_PARTIAL" in os.environ:
        print("directory durability was not confirmed")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
