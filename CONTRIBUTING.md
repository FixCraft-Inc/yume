# Contributing to YUME

YUME is experimental security and networking software. Read the
[documentation map](docs/README.md) and the relevant protocol or API contract
before editing a subsystem. Keep changes focused and verify the behavior they
affect.

## Project direction

YUME develops its own embeddable stealth transport and wire protocols. Xray,
VLESS, and REALITY are comparison subjects, not implementation sources or
compatibility targets. Keep the independent implementation and declared
dependency boundary described in [Why YUME](docs/WHY_YUME.md).

Review changes in the order stealth, security, then usable speed. A comparison
must preserve authentication, channel binding, ratchet limits, authorization,
and resource bounds; weakening those to improve a score changes the product
being measured. Record an intentional behavior change and its evidence rather
than calling it a behavior-preserving cleanup.

Keep ownership and dependency direction explicit. The current source graph is
in [SOURCE_MAP.md](docs/SOURCE_MAP.md); the replacement contracts are in
[ARCHITECTURE.md](docs/ARCHITECTURE.md). Preserve the runnable transport until
its replacement passes the documented parity gates. A smaller file, a familiar
competitor feature, or a passing build alone is not an architectural benefit.

## Build

The normal developer build is:

```bash
./ezbuild.sh --tests
```

Tests are off by default; omit `--tests` only when you do not intend to run
`ctest`.

This prepares the exact BaseFWX revision and YUME's checksum-pinned,
default-off patched OpenSSL build. A normal full CMake configuration rejects
stock OpenSSL because the default `openssl-chrome151` backend requires the
additive capability. Minimal/transport-core-only configurations have their own
documented dependency boundary.

Do not delete or replace an existing `basefwx/` developer checkout. To request
the exact clean pin explicitly, use:

```bash
BASEFWX_SYNC_MODE=pinned ./ezbuild.sh
```

## Test

Run focused tests for the files changed, followed by the proportional suite:

```bash
ctest --test-dir build --output-on-failure -R '<focused-regex>'
ctest --test-dir build --output-on-failure
git diff --check
```

Use isolated build directories for the experimental shared ABI,
transport-v2/client-only, YTP/1-foundation-only, sanitizer, static, or GUI
configurations. Do not reuse evidence from an older source hash as if it
qualified the current candidate. Long remote matrices should run detached and
write a final machine-readable summary; polling them repeatedly is not useful
evidence.

`YUME_BUILD_FUZZERS=ON` requires Clang and selects
`YUME_SANITIZE=address+undefined`, disables LTO, and adds fuzz coverage to
source-built libraries as well as the harnesses. Use a separate build directory
for TSan. Verify instrumentation in the parser objects and compile commands
before treating a fuzz run as parser coverage; harness-only flags are insufficient.

## C++, API, and naming

Use `.clang-format` for changed lines and `.clang-tidy` for focused analysis.
Avoid reformatting unrelated code. For example:

```bash
git-clang-format --diff
clang-tidy -p <build-dir> src/path/to/file.cpp
```

- For new or meaningfully touched YUME code, use `PascalCase` for types, enums,
  and enum values; `snake_case` for functions and methods; `kPascalCase` for
  constants; `ALL_CAPS` for macros; and a trailing underscore for members.
  Preserve constructors, external overrides/APIs, C ABI names, CLI/JSON/wire
  fields, and coherent untouched interfaces. Do not use this rule to justify a
  mass rename or full-tree formatting pass.
- Prefer clear subsystem names over generic `Manager`/`Runtime` names at public
  boundaries; within an existing namespace, follow the established type name.
- Use `std::size_t` for counts, fixed-width integers for wire fields, and
  `std::chrono` for durations and time points.
- Destructors and C destroy functions must catch or otherwise contain cleanup
  exceptions; none may escape. Use error-code overloads for cancellation/close
  paths that cannot report failure.
- Validate externally supplied JSON roots and field types before dispatch.
- Transport-v2 operation JSON uses `{ "ok": false, "error": "..." }`.
  Replacement ABI, transport, and lifecycle failures use typed statuses; never
  parse human error strings to recover a status.
- Product version, transport v2, AUTH v2, relay v2, YTP/1, config schema 1,
  the replacement ABI candidate, and helper IPC v1 are different identifiers.
  Preserve existing versioned cryptographic domains and wire labels; add new
  domains for intentional protocol migrations.

YUME has no deployed users. Remove compatibility shims without a current
consumer, and update active in-tree callers together. New features and planned
work still need deliberate design decisions. An old name or an uncalled
function alone does not prove that a feature is obsolete.

## Experimental replacement ABI changes

The role-neutral ABI v1 surface is an experimental build-tree candidate. It is
not the stable installed boundary and may break before its endpoint, stream,
packet, and clean-prefix gates pass. Every change still updates and tests all
of:

1. `include/yume/yume.h` declarations and behavioral comments;
2. `src/abi/yume.map` export control;
3. candidate `debian/libyume1.symbols` metadata without emitting an ABI package;
4. the exception-contained implementation;
5. strict C/C++ ABI tests, buffer sizing, lifecycle, and error paths;
6. `docs/ABI.md`.

Record ownership and behavioral breaks explicitly even while compatibility is
unfrozen. The transport-v2 JSON control API remains a separate current-runtime
contract in `docs/CONTROL_API.md`; do not route it through the replacement ABI.

## Documentation and review

Update comments and operator-facing docs in the same patch as behavior. Put
normative wire requirements under `docs/protocol/`; current support boundaries
in `docs/IMPLEMENTATION_STATUS.md`; and release notes under `docs/release/`.
Search CLI help, man pages, release material, and manually maintained website
pages for duplicate claims. Regenerate website documentation with
`scripts/sync_website_docs.sh`, then run `scripts/check_website_catalog.py`.
Generated `website/docs/**/*.md` files are ignored: CI and Pages regenerate
them from canonical Markdown before validating and building the site. Local
`--check` mode only compares an already-generated local mirror; it is useful
after generation but is not a clean-checkout drift gate. Every fenced block in
published Markdown must have a language tag. Do not leave a corrected contract
only in a private review note.
Keep public docs focused on setup, behavior, design, and supported interfaces.
Keep machine evidence, task queues, and agent handoffs in the ignored private
overlay. Public [automation guidance](docs/agents/README.md) contains only
repository facts that apply to a fresh clone.

The `website/` tree publishes the static project site. Edit canonical Markdown under `docs/`, not generated
`website/docs/*.md`, and keep website claims within the implementation,
threat, stealth, packaging, and release documents. Preserve
accurate no-release and no-JavaScript defaults; enable artifact links only
after the release API returns each exact expected asset.

Keep the site usable with a keyboard, narrow viewport, zoomed text, reduced
motion, failed JavaScript, and unavailable GitHub metadata. Do not add secrets,
captures, private paths, analytics, telemetry, remote fonts, or third-party
scripts. Validate the CI and Pages documentation transformations, Jekyll build,
internal links, generated routes, browser behavior, and accessibility affected
by the change. A website build qualifies only the static publication surface,
not runtime or security behavior.

Before handoff, review the complete diff, confirm no secrets or generated
machine state are present, record tests actually run (not intended), and list
every meaningful unrun gate.
