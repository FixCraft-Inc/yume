# YUME documentation

YUME is moving from its working 0.2 tunnel toward an embeddable stealth
universal transport with a stable C ABI. The default transition build keeps the runnable
`0.2.0-dev6` `yume` and `yumed` runtime available while YTP/1, schema 1, and the
new session engine are developed alongside it. The replacement is not yet an
end-to-end tunnel and does not make the working runtime disposable.

Source and executable tests are authoritative when prose disagrees. Product,
wire, configuration, ABI, provider, cryptographic-backend, and evidence-profile
versions are independent and are reported together by the compatibility
manifest.

## Choose the correct documentation track

- [Quick start](QUICKSTART.md), [operations](OPERATIONS.md),
  [permissions](PERMISSIONS.md), [diagnostics](DIAGNOSTICS.md),
  [packet-native bulk mode](PACKET_NATIVE_BULK.md), [preventing SOCKS
  bypass](LEAK_TIGHT.md), and the [client](man/yume.1) and
  [daemon](man/yumed.8) manuals describe the current runnable
  transport-v2/AUTH-v2 product.
- The complete signed 0.2 contracts, diagrams, manuals, and product records
  are in Git at [`f0cc9e7`](https://github.com/FixCraft-Inc/yume/tree/f0cc9e7/docs/README.md). They are not mirrored into
  the working tree; Git is the archive.
- Active transport-v2 references remain at their stable source paths while the
  runtime builds by default: the [wire contract](protocol/YUME_2_0_WIRE.md),
  [control API](CONTROL_API.md), [security modes](SECURITY_MODES.md),
  [probe and cover behavior](FILTERING_SELF_DPI.md),
  [application codecs](APP_CODECS.md), and
  [host controller](HOST_CONTROLLER.md). The
  [federation transit document](protocol/YUME_2_0_FEDERATION_TRANSIT.md) remains
  design-only.
- The documents below describe the modular replacement and mark every path
  that is still a contract or scaffold rather than live runtime behavior.

## Build and inspect the replacement foundation

- [YTP/1 foundation quick start](development/ytp1/QUICKSTART.md) describes the
  experimental `yume-setup-ytp1` / `yume-doctor-ytp1` path; its
  setup-to-SOCKS runtime is not implemented yet.
- [YTP/1 operations](development/ytp1/OPERATIONS.md),
  [authorization](development/ytp1/PERMISSIONS.md),
  [packet channels](development/ytp1/PACKET_NATIVE_BULK.md), and
  [verification](development/ytp1/SELFTEST.md) preserve the replacement
  contracts without installing them as current-runtime documentation.
- [Packaging](PACKAGING.md) defines the installed binaries, SDK, and package
  boundaries.
- [C ABI](ABI.md) is the experimental candidate for a future stable
  cross-language contract. In a default build it starts the runnable
  transport-v2 runtime and carries authenticated named byte streams. Packet
  channels and the YTP/1 backend are not live yet.
- [Implementation status](IMPLEMENTATION_STATUS.md) is the single public record
  of what is implemented, tested, qualified, or still gated.

The top-level [yume.1](man/yume.1) and [yumed.8](man/yumed.8) pages document the
runnable transport-v2 binaries installed by the default build. The intended
replacement CLI sketches are preserved under
[`docs/development/ytp1/`](development/ytp1/README.md), not installed as if
they worked. The existing optional GUI belongs to the runnable 0.2 surface; it
is not yet an installed-ABI consumer for the replacement.

## Design and security

- [Source map](SOURCE_MAP.md) says which directory owns what, which of the two
  stacks you are looking at, where the layering is enforced, and the known
  rough edges. Start here.
- [Architecture](ARCHITECTURE.md) defines the fixed dependency flow and
  provider ownership.
- [YUME Transport Protocol 1](protocol/YTP_1.md) is the normative contract for
  the implemented YTP/1 kernel, session engine, and opt-in OpenSSL security
  provider candidate. It explicitly marks the candidate as unwired from the
  TLS/HTTP/2 runtime and ABI, and as unqualified.
- [Threat model](THREAT_MODEL.md) defines the YTP/1 actor, credential,
  admission, authorization, resource, and evidence boundaries.
- [Transport profiles](TRANSPORT_PROFILES.md) separates browser evidence from
  authenticated YTP semantics.
- [Why YUME](WHY_YUME.md) explains the product category, originality
  declaration, and reproducible dependency policy.

## Version and freeze policy

The modular development line begins at `0.3.0-dev1` with YTP/1, numeric config
schema 1, and a replacement C ABI v1 scaffold. Breaking changes are permitted
during `0.3.0-dev*`. These interfaces freeze independently only after their
release gates pass; the replacement ABI must not be presented as stable merely
because it currently uses version number 1.

YTP/1 requires exactly one cryptographic and transport composition. It does
not negotiate suites or parse transport-v2/AUTH-v2 peers. That deliberate wire
break is separate from the build transition: the working 0.2 binaries remain
available until the replacement reaches tunnel, cover, routing, embedding,
packaging, and qualification parity. The YTP/1 constants and codecs exist; the
opt-in security-provider candidate also exists, but live provider wiring and
the YTP/1 runtime do not yet.

## Evidence and release material

Release material lives under `docs/release/`. The deterministic source
dependency inventory is [SBOM.spdx.json](release/SBOM.spdx.json); it is not by
itself proof of source ancestry or independent implementation. Security,
performance, setup, and ingress claims require reproducible candidate-specific
evidence; historical development results are not release qualification.

Contributors should also read [CONTRIBUTING.md](../CONTRIBUTING.md). Durable
automation context is isolated under [docs/agents/](agents/README.md).
