<!-- Generated from docs/src/en_US/pages/docs_readme.doc by scripts/yume_docs.py. Edit that file, not this one. -->
# YUME documentation

YUME `0.3.0-dev1` is development software. The installed `yume` and `yumed`
speak YTP/1. Transport v2, the protocol before it, has been removed.

## Run YUME

- [Quick start](QUICKSTART.md): build, create a kit, and connect.
- [Operations](OPERATIONS.md): server deployment, client identities, limits,
  reloads and troubleshooting.
- [Preventing SOCKS bypass](LEAK_TIGHT.md): browser settings and route checks.
- [Client manual](man/yume.1) and [daemon manual](man/yumed.8).
- [Packaging](PACKAGING.md): install layout and Debian packages.

## Understand YUME

- [YUME explained](EXPLAINED.md): how a connection opens, the keys, and what
  each party can see.
- [Why YUME](WHY_YUME.md): goals, priorities and dependency choices.
- [Threat model](THREAT_MODEL.md): attackers, operators and metadata limits.
- [Stealth](STEALTH.md) and [transport profiles](TRANSPORT_PROFILES.md): the
  browser-shaped carrier and what captures show.
- [Implementation status](IMPLEMENTATION_STATUS.md): what is tested and what
  still blocks a release.
- [Glossary](GLOSSARY.md).

## Develop and embed

- [Source map](SOURCE_MAP.md) and [contributor guide](../CONTRIBUTING.md).
- [Architecture](ARCHITECTURE.md): component ownership and dependency
  direction.
- [YTP/1](protocol/YTP_1.md): the wire and security contract.
- [Relay channel](protocol/RELAY_CHANNEL.md): the end-to-end channel the relay
  module keeps for the planned chat and file modules.
- [C ABI](ABI.md): embedding the client or server. The ABI is experimental and
  its install contract is not frozen.
- [Modules](MODULES.md): running a program behind a stream service, and
  writing one.
- [YTP/1 development guide](development/ytp1/README.md): build options, setup
  tools, embedding and verification gates.
- [Developer diagnostics](DIAGNOSTICS.md): timing helpers, warnings,
  sanitizers and fuzzing.
- [Development notes](release/CHANGELOG.md), [SBOM](release/SBOM.spdx.json)
  and [automation guidance](agents/README.md).

Source and tests win when prose disagrees. Generated pages come from `.doc`
sources under [docs/src](src/README.md). Edit the source named in the banner,
then run the sync described there.
