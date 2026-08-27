# YUME documentation map

Documents have different authority. Source and executable tests are the final
authority for implemented behavior; when prose disagrees, update the prose and
add or repair the test that states the intended contract.

| Need | Authoritative document |
| --- | --- |
| Contributor/agent workflow | [`CONTRIBUTING.md`](../CONTRIBUTING.md); optional machine-local `.private/ai/AGENTS.md` |
| Component ownership | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| Current high-level support boundary | [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) |
| Current development and release gates | [`YUME_2_0_STABILIZATION.md`](YUME_2_0_STABILIZATION.md) |
| Public C ABI | [`ABI.md`](ABI.md) |
| JSON operation API | [`CONTROL_API.md`](CONTROL_API.md) |
| Wire contracts | [`protocol/`](protocol/) |
| Threat and trust model | [`THREAT_MODEL.md`](THREAT_MODEL.md) |
| Stealth claims and residuals | [`STEALTH.md`](STEALTH.md), [`TRANSPORT_PROFILES.md`](TRANSPORT_PROFILES.md) |
| Deployment | [`QUICKSTART.md`](QUICKSTART.md), [`OPERATIONS.md`](OPERATIONS.md) |

Files named `YUME_2_0_*` retain the transport-generation terminology and some
historical filenames. The product itself is `0.2.0-dev6` on the path to
`0.2.0`; AUTH v2, relay v2, ABI v1, and helper IPC v1 are independent version
axes. Do not infer product maturity from a wire-generation number.

`YUME_2_0_DEV6_HANDOFF.md` is historical provenance, not a current task list.
Machine-local `.private/ai/` notes, when present, are ignored overlays and are
never required to understand a fresh clone.
