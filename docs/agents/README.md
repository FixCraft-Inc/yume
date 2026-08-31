# Public automation context

This directory contains repository context that is useful to coding tools but
is safe to publish. It is not part of the user documentation path.

Start with the root [AGENTS.md](../../AGENTS.md). It defines the repository
boundaries, engineering rules, and validation policy. The source tree and tests
remain authoritative.

## Repository boundaries

- This repository owns the native YUME client, daemon, C ABI, CLI, and optional
  desktop GUI.
- `basefwx/` is a separate Git checkout. Its required revision comes from
  `config/dependencies.json`.
- The Android application and browser are separate repositories.
- `.private/ai/`, when present, is an ignored local overlay. It may contain
  current task state and machine evidence, but it never overrides tracked
  source, tests, or public contracts.

## Documentation boundary

Keep durable public material in the narrowest matching document:

- current support and release limits in `docs/IMPLEMENTATION_STATUS.md`
- component ownership in `docs/ARCHITECTURE.md`
- public C and JSON contracts in `docs/ABI.md` and `docs/CONTROL_API.md`
- normative wire rules in `docs/protocol/`
- contributor workflow in `CONTRIBUTING.md`

Dated handoffs, dirty-tree inventories, machine paths, benchmark artifacts,
session narrative, rejected experiments, and task queues belong in the ignored
private overlay or Git history. Do not create a public status file for each
work session.

The product version recorded in `src/core/version.hpp`, transport v2, AUTH v2,
relay v2, C ABI v1, and helper IPC v1 are separate identifiers. Do not rename
wire domains or protocol files to match the product version.

## Safe changes

Preserve unrelated dirty work. Validate untrusted JSON before reading typed
fields, keep queues bounded, contain all C ABI errors, and use explicit
ownership and nonthrowing cleanup. Update tests and human documentation with
behavior changes in the same patch. Search for duplicate claims in CLI help,
man pages, release material, and manually maintained website pages; regenerate
website documentation through `scripts/sync_website_docs.sh` rather than
editing its ignored output. A private handoff does not close a tracked
documentation obligation. Finish with focused checks and `git diff --check`.
