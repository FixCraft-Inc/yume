# YUME documentation

YUME `0.3.0-dev1` is development software. The default `yume` and `yumed`
binaries use the transport-v2 wire `0.2.0-dev6`. YTP/1 is an experimental
replacement whose components do not yet form a working endpoint.

## Run YUME

- [Quick start](QUICKSTART.md): build, generate credentials, and connect.
- [Operations](OPERATIONS.md): configuration, services, keys, and release verification.
- [Permissions](PERMISSIONS.md): identities, destination access, and administration.
- [Client manual](man/yume.1), [daemon manual](man/yumed.8), and [GUI manual](man/yume-gui.1).
- [Packet mode](PACKET_NATIVE_BULK.md) and [preventing SOCKS bypass](LEAK_TIGHT.md).
- [Diagnostics](DIAGNOSTICS.md) and [self-test tools](SELFTEST.md).

## Understand the transport

- [YUME explained](EXPLAINED.md): a connection from application to destination.
- [Why YUME](WHY_YUME.md): the transport's goals and dependencies.
- [Implementation status](IMPLEMENTATION_STATUS.md): supported paths and open release gates.
- [Transport-v2 wire](protocol/YUME_2_0_WIRE.md), [security modes](SECURITY_MODES.md),
  and [probe and cover behavior](FILTERING_SELF_DPI.md).
- [Stealth](STEALTH.md) and [transport profiles](TRANSPORT_PROFILES.md): capture
  requirements and measured limits.
- [Control API](CONTROL_API.md), [application codecs](APP_CODECS.md), and
  [host controller](HOST_CONTROLLER.md).

## Develop and embed YUME

Start with the [source map](SOURCE_MAP.md) and [contributor guide](../CONTRIBUTING.md).
The [C ABI](ABI.md) is an opt-in build-tree library. Its transport-v2 backend
supports named streams. Packet channels and schema-1 endpoint start remain
unsupported, and the install contract is unfrozen.

The replacement has its own references:

- [YTP/1 development guide](development/ytp1/README.md): build options,
  schema-1 setup tools, and integration work.
- [Architecture](ARCHITECTURE.md) and [YTP/1 protocol](protocol/YTP_1.md).
- [Threat model](THREAT_MODEL.md).

The [federation transit proposal](protocol/YUME_2_0_FEDERATION_TRANSIT.md) is
design-only. Current federation is single-hop.

## Reference ownership

Source and executable tests take precedence when prose disagrees. Update the
relevant contract with each behavior change. Keep product, wire, configuration,
ABI, provider, and evidence-profile versions independent.

[Packaging](PACKAGING.md) defines installation and package contents.
[Development notes](release/CHANGELOG.md) record changes, and
[SBOM.spdx.json](release/SBOM.spdx.json) lists declared dependencies.
[Automation guidance](agents/README.md) covers repository-specific checks.
