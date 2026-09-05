# Automation guidance

Use [CONTRIBUTING.md](../../CONTRIBUTING.md) for build, test, naming, and review
rules. Check live Git status and source before changing files, preserve unrelated
work, and finish with `git diff --check`.

## Repository contracts

The [source map](../SOURCE_MAP.md) covers both implementations. Transport v2 is
the default client/daemon runtime. YTP/1, schema 1, and the C ABI are experimental.
Product and protocol versions are independent. Changing a product label does
not change a wire constant, cryptographic domain, schema, or ABI.

`basefwx/` is a separate ignored Git checkout pinned by
`config/dependencies.json`. Review and validate a dependency change separately
before advancing its pin.

`cmake/YumeLayering.cmake` checks exact link dependencies and include direction
at configure time. Keep `yume_embed` independent of GUI-facing `yume_facade`.
The C ABI links the embedding layer. Engine and YTP code stay independent of
sockets, TLS libraries, JSON, filesystem, CLI, and GUI code.

## Checks and documentation

| Changed surface | Contract and checks |
| --- | --- |
| Transport, AUTH, ratchet | [Transport-v2 wire](../protocol/YUME_2_0_WIRE.md), [security modes](../SECURITY_MODES.md), focused protocol/security tests |
| C ABI and endpoint backend | [ABI](../ABI.md), header, symbol map, candidate Debian symbols, C/C++ and stream integration tests |
| Config parsers | Both parsers for the role, shared key table, parser tests, CLI help and manuals |
| Server policy and cover | [Permissions](../PERMISSIONS.md), [operations](../OPERATIONS.md), [cover behavior](../FILTERING_SELF_DPI.md), daemon manual |
| YTP/1 engine and providers | [Architecture](../ARCHITECTURE.md), [YTP/1](../protocol/YTP_1.md), [development guide](../development/ytp1/README.md), provider tests |
| Product version or packaging | Version header, package metadata, README, [status](../IMPLEMENTATION_STATUS.md), [packaging](../PACKAGING.md), metadata tests |
| Dependencies | Manifest, dependency/SBOM check, third-party notices |
| Documentation | Website sync and catalog checks, affected links and manuals |

Keep current behavior in the linked contracts and support limits in
[implementation status](../IMPLEMENTATION_STATUS.md). Record behavior changes
in [development notes](../release/CHANGELOG.md).

Generate website mirrors with `scripts/sync_website_docs.sh`, then check them
with `--check` and `scripts/check_website_catalog.py`. Edit canonical Markdown,
not the generated copies.

Local agent instructions, task queues, machine paths, captures, and run logs
belong in ignored private storage. A fresh clone must contain everything a
contributor needs to build and understand YUME. Private notes can locate
evidence, but source and executable tests decide whether a claim is true.
