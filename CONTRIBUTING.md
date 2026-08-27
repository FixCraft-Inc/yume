# Contributing to YUME

YUME is experimental security and networking software. Small patches still
need an explicit trust boundary, bounded failure behavior, and evidence that
matches the claim being made.

Read the [documentation map](docs/README.md) and the relevant
architecture/protocol page before editing a subsystem. If this checkout has a
machine-local `.private/ai/AGENTS.md`, use it only as a navigation overlay and
verify its claims against tracked source and tests.

## Build

The normal developer build is:

```bash
./ezbuild.sh
```

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

Use isolated build directories for shared-ABI, client-only, sanitizer, static,
or GUI configurations. Do not reuse evidence from an older source hash as if it
qualified the current candidate. Long remote matrices should run detached and
write a final machine-readable summary; polling them repeatedly is not useful
evidence.

## C++, API, and naming

- Prefer clear subsystem names over generic `Manager`/`Runtime` names at public
  boundaries; within an existing namespace, follow the established type name.
- Use `std::size_t` for counts, fixed-width integers for wire fields, and
  `std::chrono` for durations and time points.
- Destructors and C destroy functions must catch or otherwise contain cleanup
  exceptions; none may escape. Use error-code overloads for cancellation/close
  paths that cannot report failure.
- Validate externally supplied JSON roots and field types before dispatch.
- Operation-level JSON failures use `{ "ok": false, "error": "..." }`.
  ABI/transport/lifecycle failures use the typed status enum; never parse human
  error strings to recover a status.
- The product version, transport v2, AUTH v2, relay v2, ABI v1, and helper IPC
  v1 are different identifiers. Preserve versioned cryptographic domains and
  wire labels unless a reviewed protocol migration intentionally changes them.

## Public ABI changes

The stable native boundary is C ABI v1. For every additive symbol, update and
test all of:

1. `include/yume/yume.h` declarations and behavioral comments;
2. `src/abi/yume.map` export control;
3. `debian/libyume1.symbols` packaging metadata;
4. full and client-only implementations;
5. strict C/C++ ABI tests, buffer sizing, lifecycle, and error paths;
6. `docs/ABI.md` and, for operation JSON, `docs/CONTROL_API.md`.

Changing a function's existing parameters, ownership, return convention, or
payload meaning is not additive even while the product is pre-1.0.

## Documentation and review

Update comments and operator-facing docs in the same patch as behavior. Put
normative wire requirements under `docs/protocol/`; current support boundaries
in `docs/IMPLEMENTATION_STATUS.md`; release evidence/gates in the stabilization
and release pages; and historical evidence only in clearly labelled history.

Before handoff, review the complete diff, confirm no secrets or generated
machine state are present, record tests actually run (not intended), and list
every meaningful unrun gate.
