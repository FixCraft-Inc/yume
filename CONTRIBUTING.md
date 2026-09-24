<!-- Generated from docs/src/en_US/pages/contributing.doc by scripts/yume_docs.py. Edit that file, not this one. -->
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

YUME is a reusable transport. Applications own their account, device,
enrollment and business rules outside YUME. Expose a missing general transport
capability through a cohesive interface with tests; do not add consumer-specific
branches, names, policy or build dependencies to the engine. An application
should integrate through configuration and supported interfaces without patching
YUME's source. This is a design requirement; the experimental ABI does not yet
provide every required capability.

The source graph is in [SOURCE_MAP.md](docs/SOURCE_MAP.md), and the
contracts and rationale are in [ARCHITECTURE.md](docs/ARCHITECTURE.md). The
default build is native YTP/1. Transport v2 stays as an opt-in reference and a
source of reusable components. Moving a feature does not require finishing the
reference runtime's audit backlog, tuning it, or porting every historical
feature. Qualify the required behavior before retiring its only working
implementation.

## Decision and review discipline

Before editing, state the requested outcome and check its premise against live
source, callers and tests. Separate observed behavior, product requirements,
proposals and test results. Agent notes and previous plans cannot establish
owner approval. Explain an unfamiliar term by its operation and consequences
before asking the owner to decide about it. Make routine engineering decisions
within the authorized scope.

Challenge an incorrect premise or a poor solution whether it came from the
owner, another contributor, an agent, or your own draft. Give concrete evidence,
explain the consequence in plain language, and recommend a sound alternative.
An informed owner decision may change direction; record its actual trade-off
at the relevant contract. Do not invent agreement or treat uncertainty as proof.

Source and executable tests establish what happens, not what ought to happen.
When an implementation violates an intended security or lifecycle requirement,
fix the defect or explicitly resolve the design conflict. Do not weaken the
requirement, expected result, or test fixture merely to make the code pass.
Review the final diff against the original purpose as well as the tests.

For a disputed feature or interface, identify its behavior, actual callers,
intended requirement and validation path. Then choose direct reuse, a tested
port, temporary retention for a named development need, or removal. A code
change on the older runtime needs a surviving component or requirement, or a
concrete replacement blocker. Past effort alone justifies neither retaining
an implementation nor rewriting it.

Distinguish dead-code removal from deliberate retirement. Prove unreachability
through callers, guards, the signed baseline and relevant integration tests
before calling a path dead. Reachable code can be retired by an authorized
change that updates controlled callers and preserves required behavior.
Record rejected removals and disproved claims once at their topic owner.

Keep ownership and dependency direction explicit. Split code at a demonstrated
trust, lifetime, dependency or testing boundary. Moving a large class across
files does not separate its state ownership. Give one contract one owner;
independent copies of its validation or policy are defects. Distinct trust or
state types may intentionally have identical fields. A smaller file, a familiar
competitor feature, or a passing build alone is not an architectural benefit.

## Build

Native Linux applications require libsystemd development headers and libraries
(`libsystemd-dev` on Debian/Ubuntu). The managed TUN adapter uses rtnetlink for
addresses/routes and systemd-resolved's D-Bus API for per-link DNS. DNS-free
TUN configurations do not require a running resolved service. The C ABI and
engine do not link the Linux network manager.

Linux transport-v2 server builds require liblzma and libarchive 3.6.0 or newer
(`liblzma-dev` and `libarchive-dev` on Debian/Ubuntu). They are explicit YUME
filter-archive dependencies. Static builds also need the transitive static
libraries reported by `pkg-config --static --libs libarchive`.

The normal developer build is:

```bash
./ezbuild.sh --tests
```

Tests are off by default; omit `--tests` only when you do not intend to run
`ctest`.

This prepares YUME's checksum-pinned, default-off patched OpenSSL build.
The native application does not use BaseFWX; the explicit transport-v2 reference
graph retains its independent BaseFWX pin. A normal full CMake configuration rejects
stock OpenSSL because the default `openssl-chrome151` backend requires the
additive capability. Minimal/transport-core-only configurations have their own
documented dependency boundary.

Do not delete or replace an existing `basefwx/` developer checkout. For reference
qualification, use an isolated checkout at the exact pin. Native `ezbuild.sh`
leaves BaseFWX untouched; GUI, selftest and topology tools still require explicit
reference builds and are not native application capabilities.

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

The following predeployment rule applies while YUME has no deployed users.
Before the first deployment to real users, replace this exception with an
explicit policy naming the supported interfaces and their migration obligations.
Do not infer deployment status from an old instruction, memory or version label.

Do not add aliases, fallback dialects, silent
defaults or no-op options for hypothetical callers. Update controlled readers,
writers and tests together. A temporary compatibility path must name its
verified consumer and retirement condition; a source-level caller is no release
or ABI freeze. New features and planned work still need deliberate design
decisions. An old name or an uncalled function alone does not prove that a
feature is obsolete.

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
pages for duplicate claims. Use the unified workflow below for generated views.

Documentation is authored under `docs/src/en_US/`. Edit the `.doc` source
named in a generated file's banner. Keep one document per aspect; share a
`.part` only when several documents use it. Titles, descriptions, card labels,
catalog groups and routes live in the same source as the text.

```sh
python3 scripts/yume_docs.py sync --all-languages
python3 scripts/yume_docs.py check --all-languages
python3 scripts/check_website_catalog.py
```

The sync covers Markdown, manuals, website pages and catalog, and diagram
SVGs. Diagram placement is `@diagram <name>` in the document, with topology
and source labels in `docs/diagrams/<name>.json`. `en_US` is the only active
locale; missing-content reports are preparation for translations, not proof
that a translation is current. See [the source guide](docs/src/README.md).

YUME's `@opt` and `@cli` entries also generate CLI help and completion
headers; help grouping lives in `docs/src/en_US/cli/`. The native parser
remains the behavior authority. Do not edit generated help headers.

YUME's website Markdown and inlined SVG copies are ignored. CI verifies
tracked artifacts before generating those copies. The format and diagram
guides, agent instructions and website layout guidance are edited directly;
the changelog is a `.doc` source. Review hand-authored site landing-page
claims with each behavior change.

Keep public docs focused on setup, behavior, design, and supported interfaces.
Keep task queues, checkpoints, run summaries, and agent handoffs in ignored
private `TEMP_*.md` notes with explicit deletion conditions. Lasting private
guides contain rules, decisions, and technical rationale, with raw evidence in
private artifact storage. Public [automation guidance](docs/agents/README.md)
contains only repository facts that apply to a fresh clone.

The `website/` tree publishes the static project site. Edit the canonical
`docs/src/` source, never the generated `docs/*.md` or
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
