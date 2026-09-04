# Public automation context

Start with the root `AGENTS.md`; its "Before you act" and "Before you finish"
checks apply to automation as well. Work from live Git and source state,
preserve unrelated changes, and finish with focused checks plus
`git diff --check`.

## Repository boundaries

- This checkout owns native YUME, its C ABI, CLIs, daemon, and adapters.
- `basefwx/` is a separate ignored checkout pinned by
  `config/dependencies.json`.
- Android is a separate repository and consumes public YUME interfaces.
- `.private/ai/` may contain ignored local evidence but never overrides source,
  tests, or tracked contracts.

## Current version axes

The product development label, runnable transport v2/AUTH v2/relay v2,
experimental YTP/1, config schema 1, replacement C ABI candidate, provider
versions, cryptographic backend, and evidence-profile version are independent.
Do not rename domains or bump ABI/schema merely to match the product version.

## Temporary: no compatibility debt while nothing depends on us

**Delete this section once the project has real deployed users.** Nothing
consumes these interfaces yet, so a wire format, flag, config key, status
code, or version may be changed outright. Do not add an alias, fallback,
deprecation shim, or silent default for a caller that does not exist, and
remove one when you find it. A surface that looks like compatibility support
must name the consumer it serves. Two rules outlive this section: write
careful lasting code anyway, and never accept redundancy at any stage.

## What to update when you change something

| You changed | Update in the same change |
| --- | --- |
| `src/core/`, `src/outbound/`, wire or AUTH behaviour | `docs/protocol/YUME_2_0_WIRE.md`, `docs/SECURITY_MODES.md`, the focused test beside the file |
| `include/yume/yume.h`, `src/abi/`, `src/facade/session/` | `docs/ABI.md`, `src/abi/yume.map`, the ABI contract tests, `docs/IMPLEMENTATION_STATUS.md` |
| `src/config/client_document_keys.hpp`, either client config parser | both parsers, `client_config_io_test.cpp`, `docs/man/yume.1`, `docs/ABI.md` dialect text |
| `src/server/` startup checks, permissions, cover | `docs/PERMISSIONS.md`, `docs/OPERATIONS.md`, `docs/FILTERING_SELF_DPI.md`, `docs/man/yumed.8` |
| `src/client/cli/` options or help | `docs/man/yume.1`, `docs/QUICKSTART.md`, `tests/test_project_metadata.py` help-parity checks |
| `src/client/transfer/share_file*` | `docs/OPERATIONS.md` share section, `share_file_test.cpp` |
| `src/engine/`, `src/ytp/`, `src/providers/`, `src/config/v1/` | `docs/protocol/YTP_1.md`, `docs/ARCHITECTURE.md`, `docs/development/ytp1/README.md` |
| `src/core/version.hpp`, packaging, `debian/` | `README.md`, `docs/README.md`, `docs/IMPLEMENTATION_STATUS.md`, `docs/PACKAGING.md`, `docs/release/CHANGELOG.md`, `debian/changelog` |
| `config/dependencies.json`, BaseFWX pin, OpenSSL overlay | `docs/release/THIRD-PARTY-NOTICES.md`, `docs/release/SBOM.spdx.json` via its script, `docs/WHY_YUME.md` |
| any `docs/*.md` | run `scripts/sync_website_docs.sh --check` and `scripts/check_website_catalog.py` |

Every behaviour change also gets a line under the current section of
`docs/release/CHANGELOG.md`. If a row above is missing for the directory you
touched, add the row.

## Documentation authority

- code layout, which of the two stacks a file belongs to, and the enforced
  layering: `docs/SOURCE_MAP.md`;
- current support and gates: `docs/IMPLEMENTATION_STATUS.md`;
- YTP/1 replacement contracts, not a map of the running code:
  `docs/ARCHITECTURE.md`;
- current transport-v2 facade: `docs/CONTROL_API.md`;
- experimental replacement C contract: `docs/ABI.md`;
- current and replacement wires: `docs/protocol/YUME_2_0_WIRE.md` and
  `docs/protocol/YTP_1.md`;
- contributor flow: `CONTRIBUTING.md`.

YTP/1 has no compatibility path for transport v2 or AUTH v2, and schema 1 has
no old aliases. That wire break does not retire the default-built 0.2 product.
Keep its GUI, federation, relay applications, command execution, codecs,
self-DPI controls, and security modes separate from YTP/1 until each surface
has a reviewed replacement or retirement milestone.

Layering is checked at configure time by `cmake/YumeLayering.cmake`, which pins
exact link dependencies for several targets and rejects cross-layer includes by
direction. A new cross-layer dependency means changing an assertion on purpose,
not routing around it.

Keep engine and YTP sources independent of OpenSSL, nghttp2, sockets, JSON,
filesystem, CLI, and GUI. Register exact providers on each `EngineBuilder`;
never add a global mutable registry, runtime `dlopen()`, or provider fallback.
Contain exceptions at the C ABI and callback boundaries, validate untrusted
input before allocation, and keep queues and asynchronous work bounded.

Before finishing a behavior change, update its focused tests, comments, public
contract, status boundary, and manually maintained website claim in the same
change. Regenerate ignored website mirrors from canonical Markdown. If the
local `.private/ai/` overlay records lasting state or an open queue, correct the
existing lasting file rather than appending a session narrative; never stage
that overlay. Delete temporary handoffs once their durable facts have moved to
the proper tracked or private lasting document.
