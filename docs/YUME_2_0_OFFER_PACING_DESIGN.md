# YUME 2.0 outbound rekey-offer pacing design

Status: **premise withdrawn 2026-08-22 — do not implement.** Subsequent capture
and controlled experiments attributed the live ceilings to pinned TCP buffers,
H2 receive credit, and the negotiated ratchet window; mark pacing was not one of
them. The current bounded-credit result is in `YUME_2_0_WAN_BEHAVIOR.md`. This
document changes no wire/runtime behavior and is retained only for its invariant
analysis, rejected shortcuts, and evidence methodology.

## Review verdict (2026-08-22)

**Rejected on premise, not on construction.** The mechanism this design exists
to fix was not measured. The design is internally sound and consistent with the
`SessionRatchet::Impl` invariants in the private crypto note — window cap,
contiguous deques, ACK-prepares-does-not-enter, frozen per-offer deadlines, hard
byte/frame/active-time maxima, authenticated-only inputs — and it correctly
refuses peer timestamps, idle timers, and random rotation. None of that is in
question. The problem statement is.

*The finding.* `ProbeDelayedPath`, the only evidence for the mutual-gate
mechanism, forwarded only `REKEY_INIT` frames to the peer and never the sealed
application frames. Records carry a per-direction sequence, so the peer expected
sequence N while receiving N+1 and rejected every offer after the first at the
record layer; the probe's `catch` swallowed it. One ACK returned per run, which
is the whole reason preparation appeared to stall at one epoch.

*The control.* Same library, same RTT, same frames, one variable changed — the
sealed application frames are delivered too. Preparation depth then tracks the
negotiated window (1, 1, 3, 4, 12 prepared at windows 1, 2, 4, 8, 16) and
delivered bytes rise 13.8x from window 1 to window 16, with zero refusals. The
per-round-trip serialisation is gone. Production's call-site ordering — both
`outbound/write.cpp` and `server/session/streams.cpp` test
`ApplicationWriteBlocked` first and break before reaching `ShouldStartRekey` —
was tested as a separate variant and changed the result by 0.3%.

*Therefore:* mark pacing does not cap preparation depth, the negotiated window
is reachable, and this design's target is not the defect. Implementing it would
add a capture-gated, wire-visible estimator to a mechanism that is not binding.

*What survives.* The historical WAN throughput table is real — it was measured
with real binaries over emulated latency and is untouched by the probe defect.
Its then-missing attribution was resolved later by TCP-window capture and H2 /
ratchet-window sweeps. Prepared-epoch depth still has not been directly
instrumented on a live path, but there is no throughput evidence that requires
reviving this design.

*Required before any future adaptive-pacing proposal.*

1. Instrument prepared depth, offers in flight, and blocked-write time on an
   actual delayed path; do not infer them from this synthetic probe.
2. Preserve the negotiated prepared-root retention bound and hard epoch
   byte/frame/active-time limits.
3. Demonstrate a remaining problem after the landed H2/manual-credit and queue
   controls, then pass the capture/classifier gates below. A plausible adaptive
   mechanism without a measured problem is not a reason to revive this design.

The evidence gates below are unchanged and still bind any fix that turns out to
be wire-visible. `TestDelayedPathWindowIsReachable` now pins the corrected
result and asserts zero offer refusals so the harness defect cannot return
silently.

## Decision gate

Implementation and landing are blocked on both of these evidence gates:

1. An owner signs off the numeric ceilings in
   `config/classifier_gate_v1.json` while its status is still
   `draft-pending-signoff`. The ceilings must be frozen before candidate labels
   are examined and must not be moved to accommodate a result.
2. A capture campaign supplies at least 40 complete sessions per arm across at
   least four independent groups spanning capture day, host, network, and
   provider. Captures made before the network-namespace isolation fix are
   invalid. A five-run, one-host campaign is expected to return `INSUFFICIENT`
   and is not evidence to tune around.

Rekey offers alter TLS-record sizes and timing, so this is a classifier-visible
change even though the authenticated rekey wire format is unchanged. No pacing
constant, target-depth rule, or early-offer distribution should be selected
from an undersized campaign.

## Problem statement and measured scope

> **Superseded.** The mutual-gate mechanism described in the next two paragraphs
> was withdrawn on 2026-08-22; see the review verdict above. The RTT table is
> still valid measurement. Everything after it is retained for the invariant and
> evidence analysis, not as a description of a live defect.

`SessionRatchet::Impl::ShouldStartRekey` currently permits a second outstanding
offer only after the active outbound epoch's `(epoch, application-frame-count)`
mark changes. An exhausted epoch cannot make that progress until a prepared
epoch exists, and a prepared epoch cannot exist until the oldest offer's ACK
returns. Preparation and application progress therefore gate each other.

The delayed-path campaign isolated one prepared epoch at peak for negotiated
windows 1, 8, and 32. At 1 Gbit/s with no loss or jitter and a negotiated window
of 8, download throughput tracks one 256 KiB epoch per RTT:

| RTT | Upload | Download | Download / one epoch per RTT | Upload bytes per RTT |
| --- | ---: | ---: | ---: | ---: |
| 40 ms | 16.6 Mbit/s | 55.4 Mbit/s | 1.06 | 83.0 KB |
| 60 ms | 10.8 Mbit/s | 37.5 Mbit/s | 1.07 | 81.0 KB |
| 120 ms | 5.5 Mbit/s | 18.9 Mbit/s | 1.08 | 82.5 KB |
| 210 ms | 3.1 Mbit/s | 10.7 Mbit/s | 1.07 | 81.4 KB |

Offer pacing is therefore one known download ceiling, not the whole delayed-
path problem. Upload remains quantized near 82 KB per RTT, close to the 64 KiB
relay read geometry. Effective H2 credit, WINDOW_UPDATE cadence, or TCP credit
may become the next ceiling after offer pacing changes. Those are separate
measurements; this design must not hide them by weakening an epoch policy.

## Proposed mechanism

Replace application-progress gating with a local, authenticated-ACK-informed
offer pacer. It changes only when an already-required future epoch is prepared;
it does not change the epoch derivation, rekey messages, or security budgets.

The pacer has four inputs, all local or authenticated:

- the negotiated outbound window;
- the existing authenticated, offer-ordered ACK `SRTT` and `RTTVAR` estimate;
- a local `steady_clock` observation of application drain rate; and
- current `pending_outbound + prepared_outbound` depth.

It computes a target preparation depth sufficient to cover locally observed
drain over a bounded preparation horizon, clamped to `[1, outbound_window]`.
The exact estimator gains, horizon, minimum spacing, and hysteresis are capture-
selected parameters and deliberately remain unspecified before the gate.

An offer becomes eligible only when all of the following hold:

1. `DirectionalRatchet::ShouldPrepareRekey` says preparation is needed.
2. Total pending-plus-prepared depth is below both the target and negotiated
   window.
3. The local monotonic pacing deadline has arrived.
4. An application frame is already being selected for transmission.

The first offer remains immediately eligible. Later offers are spaced across
the preparation horizon. The next deadline advances from
`max(previous_deadline, now)`, and only one offer may be emitted per selector
pass; missed deadlines never cause a catch-up burst. No background timer emits
offers on an idle direction, preserving idle silence.

ACK samples enter the estimator only after the existing AEAD authentication and
strict epoch/order checks. Peer timestamps and unauthenticated traffic never
steer pacing. Before the first authenticated sample, use a conservative static
bootstrap chosen before candidate evaluation; do not infer RTT from wall-clock
or peer fields.

## Invariants that do not change

- Byte, application-frame, and sender-active-time epoch limits remain hard
  maxima. RTT and host speed never enlarge the cryptographic compromise window.
- The negotiated window remains the absolute cap on pending and retained future
  epochs in each direction.
- Epochs remain contiguous and are offered, acknowledged, prepared, committed,
  and retired in order. A duplicate, reordered, skipped, unsolicited, or
  unauthenticated ACK remains fatal.
- Existing per-offer deadlines remain frozen at creation and bounded by the
  reviewed overall maximum. Pacing cannot extend a retained root indefinitely.
- Resource pressure fails closed. It cannot reduce ML-KEM/X25519 work, disable
  ratcheting, select a wider epoch policy, or alter the cover profile.
- Rekey INIT remains ordered before application data on the carrier, and DATA
  remains blocked at a spent epoch when no prepared successor exists.
- No random-millisecond rotation or padding is introduced. Any distribution
  visible on the wire must be justified by held-out capture evidence.

## Rejected shortcuts

- Increasing `rekey_window` alone: still the wrong lever, but for a revised
  reason -- nothing has shown the ratchet to be the binding constraint on a live
  path. The earlier "all windows reach a prepared depth of one" result came from
  the broken probe and does not support this bullet.
- Selecting a softer security profile: it buys throughput by widening byte,
  frame, or time exposure and conceals the pacing defect.
- Emitting the entire window immediately: it creates a stable burst of large
  PQ rekey records and front-loads CPU and retained-key pressure.
- Peer-reported RTT or timestamps: they let an untrusted peer steer local
  retention and traffic shape.
- A periodic idle timer: it breaks the sender-active/idle-silent model and adds
  a new classifier feature.
- Tuning around an `INSUFFICIENT` classifier verdict: missing session volume or
  group diversity is an evidence failure, not a parameter-selection signal.

## Implementation and evidence plan after the gate

Keep the change inside `SessionRatchet::Impl` and expose only read-only pacing
telemetry needed by the existing client/server diagnostics: target depth,
pending depth, prepared depth, offer spacing, authenticated ACK estimate, drain
estimate, blocked-write time, and timeout count. Do not add a wire field.

Focused tests must prove:

- delayed-path prepared depth can exceed one and is bounded by the negotiated
  window;
- no offers occur before the preparation threshold or while idle;
- missed pacing deadlines do not burst-fill the window;
- window 1 retains current ordering and bounded-resource behavior;
- byte/frame/active-time limits are identical before and after adaptation;
- reordered, duplicate, skipped, unsolicited, and tampered ACKs fail closed;
- a slow or stalled peer cannot retain pending roots beyond the deadline cap;
- key retirement and destruction still wipe every superseded or abandoned
  secret on success, timeout, disconnect, and partial preparation.

Performance evidence must use matched binaries and policies at 60, 100, and
210 ms RTT at 100 Mbit/s and approximately 1 Gbit/s, in upload, download, and
bidirectional directions with loss, plus the 30-minute 210 ms soak. Report the
separate ~82 KB/RTT upload ceiling and any H2/TCP ceiling that surfaces; do not
attribute all delayed-path throughput to offer pacing.

Classifier evidence must compare complete baseline and candidate sessions
under the pre-signed gate, with at least 40 sessions per arm and at least four
held-out groups. Landing requires both the cryptographic negative suite and the
classifier verdict.

`TODO(yume/offer-pacing)` stays open, but its meaning has changed: it now tracks
re-attributing the delayed-path ceiling, not implementing this pacer. Current
runtime behavior remains authoritative, and the evidence gates above bind
whatever fix the re-measurement identifies.
