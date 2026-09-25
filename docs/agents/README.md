<!-- Generated from docs/src/en_US/pages/agents_readme.doc by scripts/yume_docs.py. Edit that file, not this one. -->
# Automation guidance

Use [CONTRIBUTING.md](../../CONTRIBUTING.md#decision-and-review-discipline) for
decision and review rules, including challenging incorrect premises and your
own proposed solutions. Its project-direction, interface and documentation
sections apply to automation too. Check live Git status and source before
changing files, preserve unrelated work, and finish with `git diff --check`.

## Repository contracts

The [source map](../SOURCE_MAP.md) covers both implementations. Native YTP/1 is
the default client/daemon runtime; transport v2 remains an explicitly enabled,
uninstalled reference graph. YTP/1, schema 1, and the C ABI are experimental.
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
| Transport, AUTH, ratchet | [YTP/1](../protocol/YTP_1.md) and its construction vectors, the [relay channel](../protocol/RELAY_CHANNEL.md) for the relay module, focused protocol and security tests |
| C ABI and endpoint backend | [ABI](../ABI.md), header, symbol map, candidate Debian symbols, C/C++ and stream integration tests |
| Config parsers | Both roles' readers, writers, validation and startup consumers, paired rejection/rollback tests, CLI help and manuals |
| Server policy and cover | [Operations](../OPERATIONS.md), [YTP/1 development guide](../development/ytp1/README.md), daemon manual |
| YTP/1 engine and providers | [Architecture](../ARCHITECTURE.md), [YTP/1](../protocol/YTP_1.md), [development guide](../development/ytp1/README.md), provider tests |
| Product version or packaging | Version header, package metadata, README, [status](../IMPLEMENTATION_STATUS.md), [packaging](../PACKAGING.md), metadata tests |
| Dependencies | Manifest, dependency/SBOM check, third-party notices |
| Documentation | `docs/src` source, unified sync/drift and website catalog checks, affected links, manuals and CLI help/completion |

Keep current behavior in the linked contracts and support limits in
[implementation status](../IMPLEMENTATION_STATUS.md). Record behavior changes
in [development notes](../release/CHANGELOG.md).

Documentation is authored under `docs/src/en_US/`. Edit the `.doc` source
named in a generated file's banner. Keep one document per aspect; share a
`.part` only when several documents use it. Titles, descriptions, card labels,
catalog groups and routes live in the same source as the text.

```sh
python3 scripts/yume_docs.py sync --all-languages
python3 scripts/yume_docs.py check --all-languages
python3 scripts/check_website_catalog.py
```

The sync covers Markdown, manuals, website pages and catalog, enabled diagram
SVGs, and YUME CLI help and Bash completion headers. Diagram placement is
`@diagram <name>` in the document, with topology
and source labels in `docs/diagrams/<name>.json`. `en_US` is the only active
locale; missing-content reports are preparation for translations, not proof
that a translation is current. See [the source guide](../src/README.md).

Keep local workflow rules and technical rationale in lasting private guides.
Task state, queues, run summaries, and handoffs belong only in private
`TEMP_*.md` notes with deletion conditions. Raw logs and captures stay in ignored
artifact storage. A fresh clone must contain everything a contributor needs to
build and understand YUME. Source and executable tests decide whether a claim
is true.
