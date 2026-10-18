<!-- Generated from docs/src/en_US/pages/agents_readme.doc by scripts/yume_docs.py. Edit that file, not this one. -->
# Automation guidance

Use [CONTRIBUTING.md](../../CONTRIBUTING.md#decision-and-review-discipline) for
decision and review rules, including challenging incorrect premises and your
own proposed solutions. Its project-direction, interface and documentation
sections apply to automation too. Check live Git status and source before
changing files, preserve unrelated work, and finish with `git diff --check`.

## Repository contracts

The [source map](../SOURCE_MAP.md) covers the native implementation. Transport
v2 has been removed, and commit `9070b0a` is the last that contains it. YTP/1,
schema 1, and the C ABI are experimental.
Product and protocol versions are independent. Changing a product label does
not change a wire constant, cryptographic domain, schema, or ABI.

`basefwx/` is a separate ignored Git checkout pinned by
`config/dependencies.json`. Review and validate a dependency change separately
before advancing its pin.

`cmake/YumeLayering.cmake` checks exact link dependencies and which layers
each `src/` directory may include, at configure time. The
[source map](../SOURCE_MAP.md#layering-and-where-it-is-enforced) lists the
layers.

## Checks and documentation

| Changed surface | Contract and checks |
| --- | --- |
| Transport, AUTH, ratchet | [YTP/1](../protocol/YTP_1.md) and its construction vectors, the [relay channel](../protocol/RELAY_CHANNEL.md) for the relay module, focused protocol and security tests |
| C ABI and endpoint backend | [ABI](../ABI.md), header, symbol map, candidate Debian symbols, C/C++ and stream integration tests |
| Config parsers | Both roles' readers, writers, validation and startup consumers, paired rejection/rollback tests, the [configuration reference](../CONFIGURATION.md), the complete documents in `tests/fixtures/config` that `yume_config_v1_closure` probes, CLI help and manuals |
| Server policy and cover | [Operations](../OPERATIONS.md), [YTP/1 development guide](../development/ytp1/README.md), daemon manual |
| yume-setup, yume-doctor or generated kit layout | The setup and doctor manuals, [Operations](../OPERATIONS.md), [cluster 1](../protocol/CLUSTER_1.md), quickstarts, and the setup/doctor tests |
| Packaging, systemd or installed paths | Debian README and unit, [packaging](../PACKAGING.md), [Operations](../OPERATIONS.md), and every path the generated configuration writes at runtime |
| Cover or outer-carrier behavior | [Stealth](../STEALTH.md), including its remaining differences, and [transport profiles](../TRANSPORT_PROFILES.md) |
| UI text | `translations/catalog.json`, translation validation/generation, and translation tests |
| YTP/1 engine and providers | [Architecture](../ARCHITECTURE.md), [YTP/1](../protocol/YTP_1.md), [development guide](../development/ytp1/README.md), provider tests |
| Product version or packaging | Version header, package metadata, README, [status](../IMPLEMENTATION_STATUS.md), [packaging](../PACKAGING.md), metadata tests |
| Dependencies | Manifest, dependency/SBOM check, third-party notices |
| Control socket | [Control protocol 1](../protocol/CONTROL_1.md) and its additive rules, control socket, CLI and native runtime tests, and the GUI tests |
| Desktop GUI | [Desktop GUI](../GUI.md), `yume_gui_test`, `yume_gui_ui_test`, `yume_gui_ui_rtl_test`, `yume_gui_live_test`, a page capture reviewed as images, and a build against Qt 6.4 |
| Documentation | `docs/src` source, unified sync/drift and website catalog checks, affected links, manuals and CLI help/completion |
| Wire, KDF or AAD labels | The label's contract page, `tests/test_wire_labels.py` and the protocol's vectors |
| New directories, libraries or functions | The layer table in `cmake/YumeLayering.cmake`, an exact link assertion for each library, and `scripts/check_reachability.py` over a Debug gc-sections tree, as CI's `reachability` job runs it, with `config/reachability.json` for code kept on purpose |
| Any commit | `scripts/check_repository_hygiene.py --staged` before committing: whitespace in staged files, and in CI each pushed commit's format and signature |

CI’s `libcxx` job builds the native application, optional module libraries
and shared ABI with Clang 18 and libc++, and runs their tests. Its archive
tools use the same LLVM version so runner-image GNU ar plugins cannot index
new bitcode with an older reader. A moved-from
`std::function` may remain callable under that library; callbacks taken from
stored state must be explicitly emptied before that state can be settled again.

Keep current behavior in the linked contracts and support limits in
[implementation status](../IMPLEMENTATION_STATUS.md). Record behavior changes
in [development notes](../release/CHANGELOG.md).

Documentation is generated from `docs/src/en_US/`: edit the source a
generated file's banner names and run the commands in
[the source guide](../src/README.md).

Search `docs/src/en_US` and the touched source comments for every name or
guarantee you changed. A passing drift check confirms generated output, not
that the written behavior still agrees with the live code.

[CONTRIBUTING](../../CONTRIBUTING.md#documentation-and-review) says what
public documents hold and where task state and evidence go instead. A fresh
clone must contain everything a contributor needs to build and understand
YUME. Source and executable tests decide whether a claim is true.

## Shared credits

`config/credits.json` owns contributors, licenses and per-consumer dependency
lists. Its role, contribution and use fields reference stable IDs in
`translations/catalog.json`. The desktop embeds this catalog directly;
CLI, Android and website views are generated. Run:

```bash
python3 scripts/yume_credits.py validate
python3 scripts/yume_credits.py generate --android-root /path/to/Yume
python3 scripts/yume_credits.py generate --check --android-root /path/to/Yume
python3 tests/test_yume_credits.py
```

Omit `--android-root` when the separate Android checkout is unavailable; that
checks only native and website outputs. `--check` never writes and fails for
missing or stale output. Android lists common native transport dependencies,
its own application dependencies, and ML Kit only in the optional ML Kit
build. Linux integration and desktop Qt dependencies have separate groups.

## Shared palette

`config/palette.json` owns every colour of the desktop GUI, the Android app
and the website: separate light and dark themes, the true-black dark variant,
the role colours of states and figures, and the contrast each theme must
keep. Values are OKLCH on one hue, the mark's, except the mark's own two
colours, which are exact. The desktop's `Palette.js` and `palette.hpp`, the
colour regions of `website/assets/tokens.css`, `website/assets/yume-mark.svg`,
and Android's `GeneratedPalette.kt`, launcher gradient and launcher tile are
generated. The README banner combines these colours and the mark with its
layout source, `docs/assets/readme-banner.svg.in`. The mark's shape stays in
`src/gui/assets/icon.svg`. Run:

```bash
python3 scripts/yume_palette.py validate
python3 scripts/yume_palette.py report
python3 scripts/yume_palette.py generate --android-root /path/to/Yume
python3 scripts/yume_palette.py generate --check --android-root /path/to/Yume
python3 scripts/yume_diagrams.py sync
python3 tests/test_yume_palette.py
```

`report` lists each colour with its contrast on the card colour. Change a
colour only in the JSON, and resynchronise the diagrams, whose fallback
colours come from `tokens.css`. A new consumer, such as an iOS app, gets a
renderer in `scripts/yume_palette.py` rather than its own copy of the values.
