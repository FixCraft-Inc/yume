# YUME documentation

These pages describe the current source tree. Source code and executable tests
are the final authority for implemented behavior. If a document disagrees with
them, fix the document and the test that states the intended contract.

## Start and operate YUME

- [YUME explained](EXPLAINED.md) describes the traffic path and who can see
  what.
- [Quick start](QUICKSTART.md) builds a local server and client.
- [Linux release quick start](release/LINUX-QUICKSTART.md) verifies and
  unpacks a published x86-64 release archive.
- [Operations](OPERATIONS.md) covers services, public deployment, endpoint
  policy, and troubleshooting.
- [Preventing SOCKS bypass](LEAK_TIGHT.md) explains the browser and operating
  system routing boundary.
- [Permissions](PERMISSIONS.md) documents client keys and privileged features.
- [Packaging](PACKAGING.md) covers installation and Debian packages.
- [yume.1](man/yume.1), [yumed.8](man/yumed.8), and
  [yume-gui.1](man/yume-gui.1) are the installed manual pages for the client,
  the daemon, and the desktop UI.

## Understand the design

- [Architecture](ARCHITECTURE.md) maps components and ownership.
- [Threat model](THREAT_MODEL.md) states the trust and attacker boundaries.
- [Stealth transport](STEALTH.md) records the browser-shaped carrier and its
  known residuals.
- [Security modes](SECURITY_MODES.md) explains the rekey policies.
- [Transport profiles](TRANSPORT_PROFILES.md) explains how captured browser
  identities enter the registry.
- [Filtering and self-DPI](FILTERING_SELF_DPI.md) describes probe and cover
  behavior.

## Integrate and test

- [C ABI](ABI.md) is the public native interface.
- [Control API](CONTROL_API.md) defines JSON operations and responses.
- [Application codecs](APP_CODECS.md), [host controller](HOST_CONTROLLER.md),
  and [packet-native bulk mode](PACKET_NATIVE_BULK.md) cover optional surfaces.
- [Benchmarks and self-test](SELFTEST.md) and [diagnostics](DIAGNOSTICS.md)
  explain validation tools and their limits.
- [Transport v2 wire](protocol/YUME_2_0_WIRE.md) and the
  [federation transit design](protocol/YUME_2_0_FEDERATION_TRANSIT.md) are the
  protocol documents. Federation transit is design-only.

## Current support

[Implementation status](IMPLEMENTATION_STATUS.md) is the single public status
page. It records what exists, what has focused tests, and what still blocks a
stable release. Dated handoffs, lab transcripts, rejected experiments, dirty
tree inventories, and agent task queues are private working material. They do
not belong in the public reader path.

Release material sits under `docs/release/`. The
[changelog](release/CHANGELOG.md) records what changed per version, the
[1.1 release notes](release/RELEASE-NOTES-1.1.md) keep the superseded 1.x plan
as history, and the [third-party notices](release/THIRD-PARTY-NOTICES.md) list
the licenses of the software distributed with a Linux build.

Contributors should also read [CONTRIBUTING.md](../CONTRIBUTING.md). Public
automation context is isolated under [docs/agents/](agents/README.md) and is
not required to use YUME.

The product version recorded in source, transport v2, AUTH v2, relay v2, C ABI
v1, and helper IPC v1 are independent identifiers. Protocol filenames and
cryptographic domains keep their version numbers until a reviewed protocol
migration changes them.
