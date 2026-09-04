#!/usr/bin/env python3
"""Exit-code contract for ``yume-gui --headless``.

The headless command used to print a friendly line and return 0 for every
outcome, including a missing configuration and a valid session that failed to
start.  That made it useless as an acceptance gate: a green run proved nothing
had been exercised rather than that everything had passed.

The contract it is held to now:

* ``2`` -- nothing could be exercised.  An explicitly named config file that
  does not exist, a config file that does not parse, or no configuration at
  all in either the named or the default location.
* ``1`` -- something was exercised and a lifecycle leg failed.
* ``0`` -- every exercised lifecycle passed end to end.

This module covers the negative half, which needs no server, no keys and no
network.  The positive half (connect / stop / reconnect against a live dev6
``yumed``) is a separate integration gate; see ``.private/ai/GUI.md``.
"""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

EXIT_OK = 0
EXIT_LIFECYCLE_FAILED = 1
EXIT_NOTHING_EXERCISED = 2

TIMEOUT = 60


class Failure(Exception):
    pass


def run_headless(gui: Path, home: Path, *args: str) -> subprocess.CompletedProcess:
    """Run the GUI headless with an isolated HOME.

    Redirecting HOME keeps the default-config probe pointed at an empty
    directory, so a developer's real ~/.yume can never turn a negative case
    into an accidental pass.
    """
    env = {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "PATH": "/usr/bin:/bin",
    }
    return subprocess.run(
        [str(gui), "--headless", *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
    )


def expect_code(result: subprocess.CompletedProcess, want: int, case: str) -> None:
    if result.returncode != want:
        raise Failure(
            f"{case}: expected exit {want}, got {result.returncode}\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )


def case_no_configuration(gui: Path, home: Path) -> None:
    """No config named and none in the default location -> nothing to do."""
    result = run_headless(gui, home)
    expect_code(result, EXIT_NOTHING_EXERCISED, "no configuration")
    if "nothing to exercise" not in result.stderr:
        raise Failure(
            "no configuration: expected the failure to say nothing was "
            f"exercised, got:\n{result.stderr}"
        )


def case_named_file_missing(gui: Path, home: Path) -> None:
    """An explicitly named config that does not exist is an error, not a skip."""
    missing = home / "definitely-absent.json"
    result = run_headless(gui, home, "--client-config", str(missing))
    expect_code(result, EXIT_NOTHING_EXERCISED, "named client config missing")

    result = run_headless(gui, home, "--server-config", str(missing))
    expect_code(result, EXIT_NOTHING_EXERCISED, "named server config missing")


def case_unparseable(gui: Path, home: Path) -> None:
    """A file that is not JSON at all."""
    broken = home / "broken.json"
    broken.write_text("{ this is not json", encoding="utf-8")
    result = run_headless(gui, home, "--client-config", str(broken))
    expect_code(result, EXIT_NOTHING_EXERCISED, "unparseable client config")


def case_wrong_types(gui: Path, home: Path) -> None:
    """Well-formed JSON whose fields have the wrong types."""
    typed = home / "wrong-types.json"
    typed.write_text(
        json.dumps({"server": 12345, "port": "not-a-port"}),
        encoding="utf-8",
    )
    result = run_headless(gui, home, "--client-config", str(typed))
    expect_code(result, EXIT_NOTHING_EXERCISED, "wrong-typed client config")


def case_invalid_server_config(gui: Path, home: Path) -> None:
    """Parses, but omits material the 2.0 runtime cannot start without.

    obfs_secret_file, inner_psk_file, real_backend and a cover source for the
    HTTP/2 decoy are all mandatory in prepare_v2_security_config().  A config
    missing them must be reported as invalid rather than started and then
    failed, and the report must name the fields so the user can act on it.
    """
    cfg = home / "server-incomplete.json"
    cfg.write_text(
        json.dumps(
            {
                "listen_port": 8443,
                "tls_cert": str(home / "cert.pem"),
                "tls_key": str(home / "key.pem"),
            }
        ),
        encoding="utf-8",
    )
    result = run_headless(gui, home, "--server-config", str(cfg))
    if result.returncode == EXIT_OK:
        raise Failure(
            "incomplete server config: headless reported success for a config "
            f"the runtime cannot start\n--- stdout ---\n{result.stdout}"
        )
    combined = result.stdout + result.stderr
    for field in (
        "obfs_secret_file",
        "inner_psk_file",
        "real_backend",
        "real_index_path",
    ):
        if field not in combined:
            raise Failure(
                f"incomplete server config: report never mentions {field}\n"
                f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
            )


def case_help_still_succeeds(gui: Path, home: Path) -> None:
    """The stricter contract must not have broken the plain help path."""
    env = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
    result = subprocess.run(
        [str(gui), "--help"], env=env, capture_output=True, text=True, timeout=TIMEOUT
    )
    expect_code(result, EXIT_OK, "--help")


CASES = (
    case_no_configuration,
    case_named_file_missing,
    case_unparseable,
    case_wrong_types,
    case_invalid_server_config,
    case_help_still_succeeds,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gui", required=True, type=Path,
                        help="path to the yume-gui executable")
    args = parser.parse_args()

    if not args.gui.is_file():
        print(f"yume-gui not found at {args.gui}", file=sys.stderr)
        return 1

    failures = []
    for case in CASES:
        with tempfile.TemporaryDirectory(prefix="yume-gui-headless-") as tmp:
            home = Path(tmp)
            (home / ".config").mkdir()
            try:
                case(args.gui, home)
            except Failure as exc:
                failures.append(f"{case.__name__}: {exc}")
            except subprocess.TimeoutExpired:
                failures.append(
                    f"{case.__name__}: timed out after {TIMEOUT}s"
                )
            else:
                print(f"ok: {case.__name__}")

    if failures:
        print("", file=sys.stderr)
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        return 1

    print(f"all {len(CASES)} headless contract cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
