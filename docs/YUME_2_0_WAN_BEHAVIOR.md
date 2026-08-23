# YUME 2.0 WAN behavior and release gate

Status: line-rate on the tested one-gigabit LAN. The exact default single-
tunnel path has a three-repeat matched 60-ms result and two-repeat 100/210-ms
diagnostics; the broader rate/loss/bidirectional/soak release matrix remains
open.

All measurements and formulas below use the now-named Extreme policy
(256 KiB, 512 frames, 500 ms). Normal, Soft, and Ultimate were introduced in
dev6 and have not been WAN-validated; substitute their negotiated byte budget
in the model, but do not treat that model as measured performance.

## What dev2 fixed

Dev1 stopped all application writes as soon as it sent `REKEY_INIT`. Dev2 sends
the INIT before consuming the current epoch and permits authenticated old-epoch
DATA until the unchanged hard boundary. This hid the exchange on the tested
sub-millisecond LAN: matched one-stream binaries sustained about 931 Mbit/s in
both directions on a 940-941 Mbit/s raw link.

Security limits did not change: one direction still carries at most 256 KiB or
512 application frames, or remains active for at most 500 ms, before advancing.
Dev2 allowed exactly one pending future epoch, so if its ACK had not arrived
when the current epoch reached a hard boundary, application writes had to wait.

## What dev3 fixed

Dev3 negotiates a bounded window of authenticated, strictly contiguous future
epochs (`--rekey-window`, `rekey_window`, default 8, range 1..64) and prepares
them ahead of use. An ACK now prepares the next sending epoch rather than
entering it, so each prepared epoch delivers its whole byte budget instead of
being skipped. `docs/protocol/YUME_2_0_WIRE.md` has the exact rules.

No per-epoch limit changed: 256 KiB, 512 application frames, and 500 ms of
activity still bound every epoch, and the receiver still enforces the byte and
frame limits on authenticated plaintext. Depth is what changed, and it is
bounded in both directions — a peer can force at most `w` ML-KEM
encapsulations and `w` retained roots per session, and an endpoint compromise
exposes at most `w` prepared future epochs rather than one.

## RTT ceilings for one busy direction

For a byte-saturated direction whose ACK takes approximately one RTT, the
upper-bound model is:

```text
single-direction rate <= window * 256 KiB * 8 / rekey RTT
```

| Rekey RTT | dev2 (window 1) | dev3 default (window 8) | dev3 maximum (window 64) | 1 Gbit/s BDP | Window that covers 1 Gbit/s |
|---:|---:|---:|---:|---:|---:|
| 40 ms | 52.4 Mbit/s | 419 Mbit/s | 3.36 Gbit/s | 5.00 MB | 20 |
| 60 ms | 35.0 Mbit/s | 280 Mbit/s | 2.24 Gbit/s | 7.50 MB | 29 |
| 100 ms | 21.0 Mbit/s | 168 Mbit/s | 1.34 Gbit/s | 12.50 MB | 48 |
| 210 ms | 10.0 Mbit/s | 80 Mbit/s | 640 Mbit/s | 26.25 MB | 101 |

This is a protocol model, not a measured WAN result. It is also only an upper
bound: the window has to fill first, and the limits below still apply.

### Historical first measured 60 ms result (superseded)

This subsection records the pre-autotuning, pre-8-MiB-window candidate. Its
2-MiB H2/window and explicitly pinned TCP-buffer statements are not current;
they are retained to show how the later root cause was isolated. Current flow
control is described under "Landed: 8 MiB plus server-side sink-coupled
receive credit" below.

A bounded emulation on one 32-core host — both processes inside an unprivileged
user/network namespace, `netem delay 30ms` on loopback for a 60.4 ms RTT, one
8 MiB SOCKS download per run, three runs per depth — measured:

| Depth | Median |
|---:|---:|
| 1 (dev2 behavior) | 23.7-23.8 Mbit/s |
| 2, 8, 32 | 25.3 Mbit/s |

An untunneled fetch over the same delayed loopback measured 122.7 Mbit/s, so
the remaining gap is inside YUME rather than in the emulation.

Read this carefully. Depth 1 lands in the same range as the 35 Mbit/s
single-exchange model, which is consistent with the ratchet being a binding
constraint there. But raising the depth did not move throughput beyond about
25 Mbit/s, and depth 32 was no better than depth 2: **a second, tighter ceiling
now binds, and removing the ratchet ceiling alone does not deliver the modeled
rate.** That ceiling has not been identified — it is well below the 280 Mbit/s
of one-RTT H2 credit, so it is not explained by the H2 window alone. Finding it
is the next performance task, ahead of any further ratchet work.

This is emulation on one host with a single logical stream, not a WAN result,
and it does not satisfy the release gate below.

Two other unchanged hard limits matter:

- Time preparation starts 100 ms before the 500 ms active limit. At window 1 a
  continuous low-byte flow at 210 ms RTT therefore reaches the hard time
  boundary about 110 ms before its ACK, for a rough duty-cycle ceiling of
  `500 / (500 + 110)`, or 82%, even when it never fills 256 KiB. A prepared
  epoch removes that wait; the lead only has to cover the first exchange.
- Message preparation leaves 64 of 512 application-frame slots. Very high
  small-frame rates can exhaust that allowance before an ACK even when neither
  the byte nor time limit is first.

Sparse/interactive traffic with no additional write at a hard boundary does
not wait merely because an exchange is pending, so it should usually remain
responsive. The five-second rekey timeout is about 24 RTTs even at 210 ms;
ordinary latency alone should not close a session, while a multi-second outage
still closes fail-closed as designed.

Offers are paced by application progress rather than emitted as one burst, so
the window fills over several epochs. A flow that never approaches an epoch
boundary never offers, and depth stays at zero.

With the ratchet ceiling removed, two more high-BDP limits need measurement:

- the authenticated H2 connection/stream receive window is 2 MiB, equivalent to
  only about 419/280/168/80 Mbit/s of one-RTT credit at 40/60/100/210 ms. That
  is the same order as the dev3 default window, so on a saturated high-RTT link
  H2 credit is now expected to bind before the ratchet does;
- client and server request 2 MiB TCP socket buffers, while a 1 Gbit/s path
  needs 7.5-26.25 MB of bandwidth-delay product across this RTT range. Kernel
  autotuning behavior and effective buffer sizes must be recorded rather than
  inferred from the request alone.

TCP retransmission and head-of-line blocking also become visible on lossy WANs.
H2/WebSocket masking and the mandatory inner cryptography do not prevent TCP
from recovering loss, but a lost segment delays later ordered bytes.

## What the dev3 window left open (historical)

Implemented: contiguous authenticated offers, multiple prepared ML-KEM-1024 +
X25519 + PSK roots, per-session bounds on offers/ACKs/retained keys, fatal gaps
and duplicates and window overflow, progress-paced offers, and wiping of
retired secrets. Unit coverage is in `src/core/security/session_ratchet_test.cpp`
and `src/core/security/auth_v2_test.cpp`.

At that point, the following work was not yet done:

1. Adaptive preparation. Partially closed in dev6. The authenticated-ACK
   estimator now exists and drives the rekey deadline (see "Authenticated-ACK
   deadline adaptation" below), but preparation depth and lead time are still
   the static negotiated cap: the estimator does not yet pick a target depth,
   and it deliberately will not until capture evidence exists, because depth
   and lead are visible on the wire and the deadline is not. A static cap is
   the conservative choice and never lets a peer request unbounded work.
2. H2/TCP credit. The then-current 2 MiB connection/stream window and requested
   socket buffers were the next ceiling. The current candidate instead uses an
   8 MiB authenticated window, kernel TCP autotuning, and server-role manual
   receive credit with bounded queues; see the landed section below.
3. Traffic-shape review. Offers are paced, but the effect of a filling window
   on record size and timing distributions has not been captured or compared
   against the Chrome/Node fixture.
4. WAN measurement. Every number in the table above is a protocol model.

### Authenticated-ACK deadline adaptation (implemented, dev6)

The fixed five-second rekey ACK deadline is gone. `SessionRatchet` now keeps an
RFC 6298-shaped estimator and grants each offer a clamped deadline:

    allowance = clamp(SRTT + 4 * RTTVAR, 5 s, 30 s)

The whole change rests on one distinction, and it is worth stating plainly
because it is the reason this was safe to implement before the classifier work:

| Parameter | Wire-visible? | Security bound? | Adaptive now? |
| --- | --- | --- | --- |
| Epoch byte/frame/active-time limits | no | **yes** | **never** |
| Preparation depth and lead time | **yes** | no | no - gated on capture evidence |
| Rekey ACK deadline | no | no | **yes** |

The deadline has no observable consequence on the wire except that a session
fails to die. Nothing about the record stream changes when it moves, so it
carries no classifier surface and needs no cover-traffic evidence to be raised.
Preparation depth and lead time are the opposite: they decide when `REKEY_INIT`
records appear, so adapting them to RTT would write measured network conditions
into the traffic shape. That is a distinguisher, and it stays behind the
capture gate. The epoch limits are a third category entirely and are simply not
negotiable against latency.

Properties the implementation holds, each covered by
`src/core/security/session_ratchet_test.cpp`:

- **Authenticated samples only.** The estimator is updated in
  `HandleRekeyAckLocked`, after the ACK has been AEAD-authenticated by the
  inbound chain and matched strictly against the oldest outstanding offer's
  epoch. The sample is this endpoint's own `steady_clock` delta. No peer
  timestamp is read and no wire field was added. An off-path attacker cannot
  inject a sample; an on-path attacker can only delay a genuine ACK, which
  enlarges a liveness allowance and no security limit.
- **The measured interval is an upper bound on RTT, never an underestimate.**
  It runs from offer-send to ACK-accept and therefore includes the offer's wait
  behind ordered carrier traffic. That is the conservative direction: it is
  exactly the delay the deadline has to tolerate.
- **Deadlines are frozen at offer time.** A later estimator update never moves a
  deadline that was already granted. The server arms a one-shot Asio timer at
  that instant, so a deadline that moved outward would fire early and never
  re-arm.
- **Queue deadlines are non-decreasing.** ACKs are answered in offer order, so a
  later offer is waiting on the earlier ones and must not expire before them.
  The front of the queue therefore still bounds the whole queue.
- **Fail-closed stays bounded.** The front expires at most 30 s after the oldest
  unanswered offer was sent. The cap sits below the 60 s transport keepalive
  stall bound, so the ratchet still fails closed first and the watchdog remains
  an independent outer bound.
- **The floor reproduces the old behaviour exactly.** A session with no
  authenticated sample - including every session's first exchange - uses the
  same five seconds it used before.
- **Hysteresis is the 1/8 gain**, roughly an eight-sample time constant. A
  single jitter spike moves the deadline by an eighth of its excess.

One honest cost: a stalled exchange may now hold its retained ephemeral ML-KEM
and X25519 private keys for up to 30 s instead of 5 s. The exposure is bounded
by the negotiated window (at most 64 offers, each capped at 30 s) and covers
keys for a future epoch that has carried no data, whose root an attacker could
only complete by already holding the current root and PSK. It is a real widening
of that one window and is recorded here rather than argued away.

Note also what the estimator does *not* do. A path that swings between 1 ms and
6 s gets a **wider** allowance than either endpoint alone, because RTTVAR is
updated from the deviation against the old SRTT before SRTT itself moves. That
is intended: variance, not mean latency, is what breaks a fixed deadline.

### Safe boundary for remaining RTT adaptation

High RTT must not select a weaker security policy. The negotiated per-epoch
byte, application-frame and sender-active-time limits remain hard maxima and
the receiver continues to enforce authenticated byte/frame usage. In
particular, do not turn “ping is high” into a larger cryptographic blast radius
or extend an epoch so that fewer rekeys are needed.

A future implementation may instead adapt only pipeline mechanics:

1. Done in dev6: each locally sent offer is timestamped with `steady_clock` and
   the SRTT/RTTVAR estimator is updated only when the matching authenticated ACK
   is accepted. A peer timestamp or unauthenticated packet is never an RTT
   sample.
2. Still open, and gated on capture evidence because it is wire-visible.
   Combine the estimator with observed local send/drain rate to choose a target
   number of prepared epochs, clamped to the already negotiated `rekey_window`.
   Apply hysteresis and rate limits so short jitter bursts cannot make the
   depth oscillate or create a timing signature. The first exchange uses the
   conservative static fallback because no sample exists yet.
3. Done in dev6: the fixed five-second ACK deadline is now
   `clamp(SRTT + 4 * RTTVAR, 5 s, 30 s)`, frozen per offer, with the existing
   60 s keepalive stall bound as the separate no-progress watchdog. Loss and
   outage still close fail-closed after the bounded allowance; no root or
   session is retained indefinitely.
4. Done in dev6 for the deadline path: `SessionRatchet::rekey_rtt_estimate()`
   returns sample count, SRTT, RTTVAR and the allowance the next offer would
   receive. It is read-only, local, and adds no wire field. Extend it, on the
   same terms, when depth adaptation lands. Keep telemetry aggregate and local: estimated RTT/variance, chosen target
   depth, wait count and timeout reason. It must not export secret material or
   add an identifying wire field.

A future depth/lead adaptation could fill enough future epochs to cover a
legitimate high-latency path's bandwidth-delay product; the ACK deadline itself
is already locally RTT-adaptive within 5..30 seconds. Neither mechanism makes
ordered TCP immune to loss or a multi-second outage, and any depth/lead change
requires its own resource, capture, and adversarial tests.

Do not add an arbitrary “randomish millisecond blast radius.” If future
capture evidence shows that early rotations help match the cover workload,
sample only from a bounded, versioned distribution derived from that workload,
never exceed the negotiated hard maximum, freeze the overhead budget, and show
held-out classifier improvement. Uniform jitter, host-specific constants, or
RTT-derived rotation cadence can become a stronger YUME signature.

The exact `--outer-carrier-evidence` lifecycle is intentionally incompatible
with WAN benchmark modes other than its frozen one-shot workload. Use it to
seal same-session behavior inputs first. Its one MiB each way is an exact
message-echo correctness contract, not a throughput trial. Run the matched
WAN/loss matrices as separate frozen trials with identical binaries and
profile. Do not relabel the 42-second capture quiet interval or its
terminal-close evidence as WAN/throughput/soak qualification.

Multiple independent tunnels still aggregate, but that was never a fix for
one-tunnel semantics.

## Measured delayed-path ceiling (2026-08-22)

First real measurement of the ceiling, on `192.168.1.165` through the
`scripts/yume_bench_wan.py` veth/netem lab: 32 MiB per direction, 4 streams,
link rate pinned to 1000 Mbit/s and loss and jitter to zero so only RTT varies.
Binaries from `build-selftest`, `openssl-diagnostic` backend, window negotiated
at 8 and policy at 256 KiB / 512 frames / 500 ms in every run.

| RTT | Upload | Download | Total | 1 epoch/RTT | Down / bound | Up bytes/RTT |
| --- | --- | --- | --- | --- | --- | --- |
| 2 ms | 277.5 Mbit/s | 706.6 Mbit/s | 398.4 Mbit/s | 1048.6 Mbit/s | 0.67 | - |
| 40 ms | 16.6 Mbit/s | 55.4 Mbit/s | 25.5 Mbit/s | 52.4 Mbit/s | 1.06 | 83.0 KB |
| 60 ms | 10.8 Mbit/s | 37.5 Mbit/s | 16.7 Mbit/s | 35.0 Mbit/s | 1.07 | 81.0 KB |
| 120 ms | 5.5 Mbit/s | 18.9 Mbit/s | 8.5 Mbit/s | 17.5 Mbit/s | 1.08 | 82.5 KB |
| 210 ms | 3.1 Mbit/s | 10.7 Mbit/s | 4.8 Mbit/s | 10.0 Mbit/s | 1.07 | 81.4 KB |

Across a fivefold change in latency both ratios move by under two percent. At
2 ms neither quantum binds and other costs dominate, which is why that row sits
below its bound instead of at it.

Two things fall out, and both are quantization by round trip rather than by
bandwidth.

**Download tracks one 256 KiB unit per round trip**, at 1.06x to 1.08x that
bound from 40 ms through 210 ms. The window was negotiated at 8 in these runs,
so if the epoch were the binding quantum, eight epochs of 256 KiB -- 2 MiB --
would have been in flight, giving 419 Mbit/s at 40 ms and 280 Mbit/s at 60 ms.
Something is holding delivery to one such unit per round trip. These runs did
not record prepared-epoch depth, so which quantum is binding is not established
by them; 256 KiB is both the epoch byte limit and a common H2 stream window.

**Upload is quantized at the relay frame, not the epoch.** It delivers 81 to
83 KB per round trip at every latency tested -- flat, and 1.24x to 1.27x the
64 KiB client relay read buffer that sets the outgoing DATA frame size. Whatever bounds upload is operating at frame granularity, below the epoch
boundary, and it is the reason totals sit near 25 Mbit/s at 40 ms.

So the ~25 Mbit/s figure is not a cryptographic throughput limit. The same
binaries do 1154-1624 Mbit/s over loopback and 706 Mbit/s down at 2 ms RTT; the
AEAD and the hybrid exchange are nowhere near the constraint. What binds is a
per-round-trip credit of one 256 KiB unit downstream and one relay-frame-sized
unit upstream. Identifying which layer issues each credit is open work; see the
next section for why the earlier answer was withdrawn.

### Mechanism: withdrawn, and why (2026-08-22)

An earlier revision of this section named `SessionRatchet::ShouldStartRekey` as
the proven cause: offers are paced against application progress, so issuing
offer N+1 needs another sealed frame, which once the epoch is spent needs a
prepared epoch, which needs offer N's ACK. That reasoning is retracted. It rested
on a probe that drove `SessionRatchet` directly and forwarded only `REKEY_INIT`
to the peer, never the sealed application frames.

Records carry a per-direction sequence. Withholding the data frames left the
peer expecting sequence N while receiving N+1, so it rejected every offer after
the first at the record layer, and the probe's `catch` discarded the rejection.
Exactly one ACK ever returned, which is the entire reason preparation appeared
to stall at one epoch. The published table measured the harness.

Re-running the same library over an ordered path that also delivers the
application frames, at 60 ms over twenty round trips with 64 KiB frames:

| Negotiated window | Peak prepared epochs | Peak offers in flight | Bytes moved | Epochs |
| --- | --- | --- | --- | --- |
| 1 | 1 | 1 | 5.2 MB | 19 |
| 2 | 1 | 2 | 10.2 MB | 38 |
| 4 | 3 | 4 | 20.2 MB | 76 |
| 8 | 4 | 8 | 39.3 MB | 149 |
| 16 | 12 | 16 | 72.3 MB | 275 |

Preparation depth and delivered bytes both track the negotiated window, and no
offer is refused. Window 1 does advance exactly one epoch per round trip, which
is what made the original reading plausible; window 8 advances about 7.5. Above
window 16 the figures flatten on the probe's own one-frame-per-millisecond tick,
not on anything in the ratchet. `TestDelayedPathWindowIsReachable` in
`src/core/security/session_ratchet_test.cpp` pins this and asserts the refusal
count is zero, so the harness defect cannot return silently.

Two conclusions follow, and the second is the important one.

Mark pacing is not the delayed-path ceiling. It does not serialise preparation,
and removing it would buy nothing measured. The rule's stated purpose stands:
without it an exhausted epoch re-offers on every selector pass and emits the
window as one classifier-visible burst.

**Historical position at this stage: the measured ceiling was unattributed.** The throughput
numbers were taken over an emulated WAN with real binaries and are unaffected by
the probe defect; only the explanation was wrong. Preparation depth has never
been observed on a live path — the only depth figures ever produced came from
the probe — so the first step is to instrument prepared depth, offers in flight,
and blocked-write time on an actual delayed path and find out whether the window
is filling there at all.

The leading hypothesis at that point was H2 stream flow control. A 256 KiB
epoch byte limit and a 256 KiB H2 window produce the same one-quantum-per-RTT
signature, and that
coincidence is what made the ratchet look guilty; download sitting at 1.06-1.08x
"one 256 KiB unit per RTT" is equally consistent with either. The separate
upload quantum near 82 KB per RTT still points at the 64 KiB relay read
geometry, below the epoch boundary, as noted above. Distinguishing these needs
one experiment: change the H2 window without touching the epoch limit and see
whether the ceiling moves.

Raising `rekey_window` remains the wrong lever for a different reason than
previously stated — not because it is ineffective in the ratchet, but because
nothing has yet shown the ratchet to be the binding constraint on a live path.

## Live-path re-attribution (2026-08-22)

The withdrawn mechanism above left the ceiling unexplained. These runs answer
part of it. Method: `scripts/yume_bench_wan.py` through the veth/netem lab on
`192.168.1.165`, 60 ms RTT, jitter and loss zero, link pinned at 1000 Mbit/s,
32 MiB per direction, 4 streams, `build-selftest` binaries, everything else
held constant.

### The ratchet is not the constraint

`--rekey-window` is now a harness option, so the negotiated depth can be swept
on a real path instead of in a model:

| Negotiated window | Upload | Download |
| ---: | ---: | ---: |
| 1 | 11.1 Mbit/s | 32.7 Mbit/s |
| 8 | 11.0 Mbit/s | 37.5 Mbit/s |
| 32 | 10.7 Mbit/s | 37.5 Mbit/s |

A 32-fold change in negotiated depth moves download by 15% and upload not at
all. Preparation depth is not what throughput is waiting on, and raising
`rekey_window` is confirmed useless as a tuning lever -- this time for the right
reason, measured where it matters.

### Upload is bistable: 33.5 Mbit/s or 10.9 Mbit/s, nothing between

The first sample of this looked like a 3x penalty whenever a download followed
in the same session. An interleaved control run refuted that. Six runs at
identical settings, alternating `--bench-direction`, server-side drain figures:

| Run | `--bench-direction` | Streams | Server drain |
| --- | --- | ---: | --- |
| 1 | `up` | 4 | 24.27 s -- 11.1 Mbit/s |
| 2 | `both` | 4 | 24.93 s -- 10.8 Mbit/s |
| 3 | `up` | 4 | **8.01 s -- 33.5 Mbit/s** |
| 4 | `both` | 4 | 24.94 s -- 10.8 Mbit/s |
| 5 | `both` | 1 | 24.26 s -- 11.1 Mbit/s |
| 6 | `up` | 1 | 24.93 s -- 10.8 Mbit/s |

Direction does not predict the outcome and neither does stream count. The
results fall into two tight clusters -- about 8.0 s (33.5 Mbit/s, ~252 KB per
round trip) or about 24.3-24.9 s (10.8-11.1 Mbit/s, ~82 KB per round trip) --
with nothing in between and under 3% spread inside each cluster. A session picks
one mode and stays there. Download shows no such split: every run measured
37.4-37.5 Mbit/s.

The ratio between the modes is 3.1x, and the slow mode sits at roughly 1.25
times a 64 KiB quantum while the fast mode sits at roughly 3.9 times it.

**This invalidates the published "upload is quantized at ~82 KB/RTT" figure.**
That is the slow mode, which the earlier campaign happened to sample every time.
It is not an intrinsic property of the upload path, and it was never evidence
about relay read geometry.

Do not average the two modes; the mean describes no run. Report the mode split
and the sample count. Root-causing the bistability is the top open item -- a
session that silently settles into a third of its achievable upload throughput
is a larger and more tractable problem than anything offer pacing addressed.

### Root cause: pinned socket buffers (fixed 2026-08-22)

Packet capture of a slow session settles it. Upload flow, 24.3 s, 33.8 MB:
**zero retransmissions**, and 405 sender gaps longer than 50 ms with a maximum
of 63.2 ms on a 60 ms path. 405 round trips is the entire transfer duration, so
the sender spent the run waiting for credit, not recovering from loss. That
eliminates netem queue drops and congestion collapse.

Reading the advertised TCP receive windows out of the same capture names the
credit:

| Direction | Advertised window (p50/max) | Measured throughput |
| --- | --- | --- |
| client -> server (upload) | 83 KB / 83 KB | 83 KB per round trip |
| server -> client (download) | 297 KB / 298 KB | ~275 KB per round trip |

Both directions delivered exactly the peer's advertised TCP receive window per
round trip. Nothing above TCP was ever the constraint.

The windows were pinned because YUME set them. The full audit found pins across
the primary and secondary client tunnels, accepted server sessions, outbound
and reverse-listener target connections, and the client SOCKS, forward, local-
forward, and reverse-forward TCP endpoints.

On Linux any explicit value sets `SOCK_RCVBUF_LOCK`/`SOCK_SNDBUF_LOCK` and
disables window autotuning for the connection's lifetime -- the size passed does
not matter, and 2 MiB is far below the 7.5 MB bandwidth-delay product at
60 ms/1 Gbit/s anyway. With autotuning off the window grows only through the
conservative slow path, which stalls at whatever equilibrium the first few round
trips produce. **That is the bistability**: a session that escaped early settled
near 250 KB per round trip, one that did not settled near 83 KB, and nothing
landed in between. It also explains why enabling packet capture pushed all ten
sampled runs into the slow mode -- extra per-packet latency biases the early
round trips.

**The fix is to stop pinning them.** Five runs after, at identical settings:

| | Before (slow mode) | Before (fast mode) | After |
| --- | ---: | ---: | ---: |
| Upload | 10.7-11.1 Mbit/s | 33.5 Mbit/s | **42.1-43.4 Mbit/s** |
| Download | 37.4-37.5 Mbit/s | 37.4 | 37.4-37.8 Mbit/s |
| Total | 16.7 Mbit/s | - | **~33 Mbit/s** |

Upload is now deterministic -- five runs inside 1.2% of each other, no mode
split -- and 3.9x the slow mode that every earlier measurement happened to
sample. Total throughput roughly doubles.

No YUME framing or record format changes. TCP advertised-window growth and the
sender timing it enables are passively observable, so the fix is not described
as invisible. Leaving remote TCP sizing to kernel autotuning is nevertheless
the browser-like socket policy and removes an artificial YUME-specific clamp.
The exit leg to the target was pinned the same way; that path is frequently the
longest in a real deployment and was fixed with the rest, though the
benchmark's loopback target could not show it.

`tests/test_socket_autotuning.py` scans every production source and verifies
each remaining direct pin and helper call by named function scope. The retained
`ClientTransportStream::set_socket_buffers` helper documents the hazard and has
no production call site. Only the enforced-loopback Monero RPC socket and the
AF_UNIX Chrome-helper socketpair are permitted production pins.

**Download is now the slower direction** at ~37.7 Mbit/s / ~283 KB per round
trip, and it did not move with the fix. It is the next thing to attribute; the
32 KiB server relay record (`util::server_relay_read_buf_size`) and the H2
carrier are the candidates. Do not assume it is the same cause.

### Historical post-autotuning position (before manual H2 credit)

Same lab, link raised to 10 Gbit/s so it cannot be the limit, 128-256 MiB per
direction, 8 streams:

| RTT | Upload | Download |
| ---: | ---: | ---: |
| 2 ms | **2290 Mbit/s** | **2212 Mbit/s** |
| 10 ms | 764 Mbit/s | 1293 Mbit/s |
| 60 ms | 125 Mbit/s | 253 Mbit/s |

At 60 ms that is upload 11.3x and download 6.7x what the same tree did at the
start of this work. Gigabit is reached and passed at 10 ms and below; the
remaining gap is entirely a delayed-path problem.

Note the second pin was found only after the first fix: `client/cli/entry.cpp`
pinned the client's tunnel socket before handing it to the transport, and the
capture showed the client frozen at a 297 KB advertised window while the
server's had autotuned to 1569 KB. The guard test now scans the whole tree and
requires every pin site to be explicitly exempt, rather than listing the sockets
that matter -- listing them is what let the first version miss this one.

### Historical rekey-window sweep after TCP autotuning

With TCP no longer the binding constraint, sweeping the negotiated window at
60 ms changes download substantially:

| Negotiated window | Download | `w x 256 KiB / RTT` |
| ---: | ---: | ---: |
| 4 | 124.3 Mbit/s | 140 |
| 8 | 250.1 Mbit/s | 280 |
| 16 | 350.0 Mbit/s | 560 |
| 32 | 365.9 Mbit/s | - |
| 64 | 365.4 Mbit/s | - |

Download tracks `w x epoch_byte_limit / RTT` at about 89% up to w=16, then
saturates near 366 Mbit/s on a different constraint. **This reverses the earlier
guidance that raising `rekey_window` is useless.** That was true only while the
pinned socket buffers held throughput an order of magnitude below the ratchet
ceiling. It is now the single largest available download lever at WAN latency:
w=8 to w=16 is +40%.

It is not free. The negotiated window is exactly how many prepared future roots
each side retains, so process-memory compromise exposes up to `w` of them
(`.private` crypto notes, compromise statements). Raising the default from 8 is
a security decision, not a tuning one, and it belongs to the owner. Raising
`epoch_byte_limit` instead would be strictly worse: it widens how much data one
key protects rather than how many bounded future keys are held.

Upload does **not** respond to the window at all -- flat at 126.8-128.5 Mbit/s
across w=4..64 -- so it is bound elsewhere. At 60 ms that is 937 KB per round
trip. The leading candidate is the client transport's single outstanding write
batch: `kMaxWriteBatchBytes` is 1 MiB and `write_in_flight_` permits one batch
at a time, giving 1 MiB/RTT = 140 Mbit/s at 60 ms, against 127 measured (91%).
That is the next thing to test, and it is not wire-visible in the framing sense.

### What the benchmark actually measures, and the honest denominator

Every number in this document was measured **entirely inside one host**
(`192.168.1.165`): a veth pair between two network namespaces, with `netem`
adding one-way delay and a rate cap on each side. No physical NIC and no
real network is involved, so link technology on the path to that host is
irrelevant to these figures.

That makes the denominator easy to establish. Through the identical
netns/netem path at 60 ms:

| Reference | Throughput |
| --- | ---: |
| raw TCP, 8 parallel streams | 3265 Mbit/s |
| raw TCP, **1 stream**, default kernel caps | **390 Mbit/s** |
| raw TCP, 1 stream, `tcp_rmem`/`tcp_wmem` max 64 MiB | **5291 Mbit/s** |

No Xray, VLESS, sing-box, or equivalent reference binary has been run in this
lab. The raw-TCP values isolate connection geometry; they do not establish a
matched product-to-product ratio.

Two things follow, and they explain most of the gap people expect to see
against per-connection proxies.

**The measured/default individual-key configuration multiplexes every logical
stream onto one tunnel**, so it inherits the single-connection ceiling, not the
8-stream one. A proxy that opens a fresh TCP connection per proxied connection
gets N independent congestion and receive windows; on this path that is an
8.4x head start before any crypto is considered. YUME does implement an
optional 2..16-tunnel pool for pure SOCKS mode with an explicitly admitted bulk
identity and the `openssl-diagnostic` backend. It was not exercised by this
matrix, other modes stay on the primary tunnel, and the `chrome151` helper
deliberately accepts exactly one outer tunnel. Therefore multi-tunnel is a
separate performance, identity-policy, and classifier experiment, not a hidden
denominator for these results.

**A single connection at 60 ms is bounded by kernel buffer caps, not by TCP.**
Debian's defaults (6 MiB read, 4 MiB write) cap one stream near 390 Mbit/s;
raising both maxima to 64 MiB takes the same stream to 5291 Mbit/s, 13.6x. Any
deployment that cares about high-latency throughput has to raise these.

**Raising them did nothing at this historical stage** -- 15.7 to 15.6 MiB/s
upload, unchanged -- which was the useful part of the experiment. YUME did not
fill the TCP window then, so its ceiling was above TCP. Sweeping
`--tcp-mem-max` is now the standard way to separate a deployment tuning limit
from a limit inside YUME.

### Historical isolation of the HTTP/2 ceiling

Two experiments, each changing one constant and measuring:

| Change | Upload | Download |
| --- | ---: | ---: |
| baseline | 15.7 MiB/s | 31.1 MiB/s |
| `kMaxWriteBatchBytes` 1 MiB -> 8 MiB | 15.8 | 31.3 |
| `kAuthenticatedReceiveWindow` 2 MiB -> 16 MiB | **29.9** | 31.1 |
| that, plus `--tcp-mem-max 64 --rekey-window 32` | **93.0 (780 Mbit/s)** | 45.5 (382 Mbit/s) |

The write-batch hypothesis is **refuted**: 8x the batch size moved upload 0.6%.
It had predicted 140 Mbit/s against 132 measured, which is a good reminder that
a close arithmetic match is not evidence.

The server's authenticated H2 receive window is the upload ceiling. Doubling
throughput needs nothing else; with kernel buffers and the ratchet window raised
alongside it, upload reaches **780 Mbit/s at 60 ms**, a 5.9x improvement. Note
that the ratchet window only starts mattering for upload once the H2 window is
lifted -- before that, upload is flat across w=4..64.

Download shows the same pattern one layer over: the client advertises Chrome's
`SETTINGS_INITIAL_WINDOW_SIZE` of 6 MiB, which at 60 ms allows 838 Mbit/s, and
delivers 382. Both directions land near 45% of `window / RTT`, which points at
WINDOW_UPDATE cadence rather than the advertised size.

The 16-MiB and tuned-kernel experiments in this table were reverted. A later
candidate landed 8 MiB plus server-role manual receive credit. The increment is
encrypted and fixed-size before TLS, but changed credit can still alter burst,
record, and timing geometry, so a further increase remains capture/classifier-
gated. The client's advertised profile remains a separate cover constraint.

### Landed: 8 MiB plus server-side sink-coupled receive credit

`kAuthenticatedReceiveWindow` in `core/stealth/h2_carrier.cpp` is 8 MiB. The
earlier 2-MiB value was a measured upload ceiling at WAN latency: a window of W
cannot deliver more than W/RTT, while the autotuned TCP window underneath had
already reached about 3.9 MB. Eight MiB slightly exceeds the nominal 7.5-MB
bandwidth-delay product of a 1-Gbit/s, 60-ms path, but that does **not** establish
uninterrupted 1-Gbit/s delivery. nghttp2 replenishes credit on a threshold, and
the default `rekey_window=8` separately gives an upper-bound model of 2 MiB per
rekey RTT.

The last pre-manual-credit measurements, retained as a historical baseline,
were four consecutive 60-ms runs with 128 MiB per direction and eight streams:

| | Before (2 MiB) | 8 MiB, automatic credit |
| --- | --- | --- |
| Upload | 15.6-28 MiB/s, **bimodal** | **27.9, 27.9, 27.9, 27.9** |
| Download | 27.5-31.1 | 30.1, 29.7, 21.4, 29.2 |

The current candidate enables `NGHTTP2_OPT_NO_AUTO_WINDOW_UPDATE` for both H2
roles. WebSocket framing, masking, cover traffic, and other non-tunnel bytes are
credited immediately. Decoded binary tunnel payload enters an exact receive
ledger and is credited only as downstream ownership releases it:

- TCP and UDP hold an exact frame token through destination socket-write
  completion;
- `ServiceStream` holds it until a full read or discard;
- codec streams hold it through backend request write completion or close.

Server credit release is deferred and coalesced on the Session strand; client
credit release is likewise coalesced on the Tunnel strand. Invalid
over-consumption and ledger overflow fail closed. Independently, server TCP/UDP
source reads pause at 64 queued frames or 4 MiB, resume at 16 frames and 1 MiB,
and retain hard 512-frame/32-MiB limits. Ratchet-blocked output counts against
the same hysteresis.

On the client, TCP SOCKS and TCP forward/reverse-forward local writes retain
their receive-credit tokens until socket-write completion. Their complete
executor backlog, queue, and in-flight data are serialized and bounded at 64
frames/16 MiB. SOCKS UDP-associate and UDP-forward use separate aggregate
pre-OPEN and local-send budgets of 64 datagrams/1 MiB per session or forwarding
server; a receive-credit token follows each accepted local send through its
completion. Both UDP paths drop the newest datagram on saturation so the
association can recover after drain, and run one `async_send_to` at a time.
Packet batches retain credit until the final packet is read or discarded, and
service/codec paths retain it through their corresponding bounded sink.
Handlers that synchronously consume or copy their complete input may release at
return; that is not used as a shortcut for a pending socket write.

The implementation is therefore sink-coupled rather than carrier-only.
Deterministic layer tests prove the H2 window stalls without released credit and
that a deliberately backpressured proxy socket releases none until it drains.
A real authenticated H2-through-proxy slow-reader integration is still required
before calling that composition externally qualified or using it as WAN/soak
evidence.

The WINDOW_UPDATE increment is encrypted and its H2 frame is fixed-size before
TLS, so a passive observer cannot read the numeric credit directly. Different
credit and release cadence can still alter outer bursts, TLS-record grouping,
and timing. Any increase beyond 8 MiB therefore remains capture/classifier-
gated, and raising the default rekey window remains a separate security choice.

### Exact matched validation of the bounded-credit candidate

The current candidate was compared with its frozen immediate predecessor on
the same i9-14900K host, interleaved, with identical harness and dependencies:
isolated user/network namespace, 60 ms RTT, zero jitter/loss, 1,000 Mbit/s,
128 MiB each direction, eight logical streams, default Extreme policy,
`rekey_window=8`, OpenSSL diagnostic TLS, and no browser load or packet capture.
The endpoint benchmark traverses the production DATA/ratchet/H2/WebSocket/TLS
path but excludes the local SOCKS and target TCP sockets.

| Candidate | Upload runs (Mbit/s) | Download runs (Mbit/s) | Median up/down |
| --- | --- | --- | ---: |
| Frozen pre-credit baseline | 238.7, 236.0, 238.8 | 253.6, 252.8, 253.8 | 238.7 / 253.6 |
| Server manual credit + bounded queues | 244.9, 239.5, 236.1 | 252.7, 252.4, 252.1 | **239.5 / 252.4** |

The median delta is +0.3% upload and -0.5% download: within run variation.
The correctness hardening does not impose a measurable default-throughput
penalty, nor does it claim a speedup by itself. At 2 ms RTT and the same
1,000-Mbit/s rate cap, the current binary reached 934.5/884.9 Mbit/s in one
sanity run. During the default 60-ms runs the client used a median 0.092 average
CPU cores and `yumed` 0.129, confirming CPU was not the binding resource.

A runtime-only rekey-window sweep, with source and H2 window unchanged, found:

| Negotiated window | Upload runs (Mbit/s) | Download runs (Mbit/s) | Median up/down | Median `yumed` peak RSS |
| ---: | --- | --- | ---: | ---: |
| 8 (default) | 244.9, 239.5, 236.1 | 252.7, 252.4, 252.1 | 239.5 / 252.4 | 24.0 MiB |
| 16 | 338.8, 334.9, 347.7 | 347.6, 350.4, 347.2 | **338.8 / 347.6** | 48.1 MiB |
| 32 | 337.1, 324.9, 341.7 | 357.3, 357.2, 356.6 | 337.1 / 357.2 | 67.0 MiB |

Window 16 improved the medians by 41.5% upload and 37.7% download. Window 32
added no upload and only 2.8% download over 16, while the short-run observed
server peak RSS increased again. This makes 16 the only plausible next value to
qualify, not an automatic default change: it doubles the number of prepared
future roots retained under process compromise and can change outer traffic
cadence. The source default remains 8.

Two-run diagnostic extensions at higher RTT found no manual-credit stall:

| RTT | Frozen default mean up/down | Current default mean up/down | Current window-16 mean up/down |
| ---: | ---: | ---: | ---: |
| 100 ms | 142.6 / 152.4 | 139.5 / 151.3 | **204.3 / 214.6 Mbit/s** |
| 210 ms | 68.9 / 72.8 | 69.5 / 73.4 | **96.4 / 103.3 Mbit/s** |

The default deltas are -2.2%/-0.7% at 100 ms and +0.9%/+0.8% at 210 ms.
These two-repeat arms are regression diagnostics, not substitutes for the
three-run, loss, and soak release gate. Their reports are under
`/home/f1xgod/yume-wan-e9a-highrtt-20260823T0352Z`.

One separate default capture reached 238.6/252.5 Mbit/s, recorded 36,166
packets with zero kernel drops, and retained a 275,650,672-byte pcap. It proves
capture integrity only; one session is not a classifier verdict. All reports,
resource traces, logs, and the capture are under
`/home/f1xgod/yume-wan-e9a-20260823T0342Z` on `192.168.1.165`.

Provenance: baseline tracked-diff SHA-256 `5697bef7...32c91c`, current
tracked-diff SHA-256 `e9a9fe81...4f7c97`; current `yume`/`yumed` SHA-256
`05cbf1ad...f5b311` / `49196676...029de`; harness SHA-256
`17f69694...f1a20`. Both used pinned OpenSSL 3.5.7. OpenSSL diagnostic TLS is
not Chrome ClientHello parity, so this matrix is performance evidence, not a
stealth qualification.

### Historical 32-MiB ceiling experiment

With `kAuthenticatedReceiveWindow` at 32 MiB and `--tcp-mem-max 64`, sweeping
the ratchet window at 60 ms:

| Negotiated window | Upload | Download |
| ---: | ---: | ---: |
| 8 | 28.5 MiB/s (239 Mbit/s) | 31.3 MiB/s (263 Mbit/s) |
| 32 | 88.9 (746) | 47.2 (396) |
| 64 | **139.8 MiB/s (1173 Mbit/s)** | 37.3 (313) |
| 64, 16 streams | 136.7 (1147) | 37.3 (313) |

**Upload reached gigabit in this experiment at 60 ms RTT** -- 1173 Mbit/s
against the then-current 132 Mbit/s, 8.9x. The 32-MiB H2 window was reverted;
the result demonstrates available headroom and does not describe the current
default or establish classifier parity.

The two directions are limited by different things, and only one of them is a
stealth constraint:

**Upload uses a YUME-owned limit.** `kAuthenticatedReceiveWindow` is not fixed
by the client cover profile, but changing it can change credit/burst cadence and
is therefore a capture/classifier measurement question.

**Download is stealth-limited.** The client advertises Chrome's
`SETTINGS_INITIAL_WINDOW_SIZE` of 6 MiB. At 60 ms that permits 838 Mbit/s and
the measurement tops out near 400. The advertised value cannot change without
breaking the fingerprint, so 838 Mbit/s is a real upper bound imposed by the
cover identity. The gap between 400 and 838 correlates with WINDOW_UPDATE
cadence -- both directions delivered about 45% of `window / RTT` -- but changing
cadence can still change observable timing and is not free at the classifier
gate.

So the structural explanation for this measured/default configuration is that
single-tunnel multiplexing receives one TCP/H2 connection's credit while a
per-connection proxy receives independent credit per proxied connection, and
Chrome's advertised H2 value upper-bounds download. There is no matched
Xray/VLESS binary or result on this lab, so this is an architectural explanation
against raw TCP denominators, not a measured YUME-versus-Xray speed ratio.
Neither the AEAD nor the hybrid exchange was the binding limit in these
experiments.

One structural avenue is worth recording rather than assumed away. A real
browser does not hold one HTTP/2 connection; it holds one per origin, and a
page load routinely touches ten to thirty origins. YUME's existing OpenSSL-only
SOCKS pool proves multiple tunnels are implementable, but does not prove that
its identity reuse, origin mapping, connection timing, or cross-tunnel
correlation is browser-plausible. The `chrome151` path remains intentionally
single-tunnel until that question is measured.

### Relaxing the ratchet does not buy throughput -- it costs it

The obvious question after the socket fix was how much the epoch policy is
costing, so the harness gained `--security-mode`. It writes a minimal config
file for both endpoints rather than adding a CLI flag, because the policy is a
security knob and should not become a casual switch. `session` is an `ultimate`
custom policy at the maximum permitted limits -- 1 TiB, 2^30 frames, 24 hours --
which is as close to one key for the whole session as the wire format allows.

Three interleaved repeats each, 60 ms, 128 MiB per direction, 8 streams, MiB/s:

| Policy | Epoch limits | Upload | Download |
| --- | --- | --- | --- |
| **extreme** (default) | 256 KiB / 512 frames / 500 ms | **15.2, 15.1, 15.1** | **29.3, 29.6, 28.8** |
| normal | 8 GiB / 256K frames / 60 s | 13.6, 13.6, 13.1 | 19.9, 34.8, 22.8 |
| session | 1 TiB / 2^30 frames / 24 h | 13.2, 12.3, 13.8 | 19.8, 19.9, 19.7 |

**The strongest policy is the fastest and the most consistent.** Against a
session-wide key, Extreme is about 15% faster on upload and about 47% faster on
download, and its spread across repeats is under 3% in both directions. There is
no throughput argument for weakening the epoch policy, which removes the usual
temptation: nobody has to trade compromise-window size for speed here.

Two honest caveats. `normal`'s download is erratic across repeats (19.9 to
34.8) and needs more samples before anything is said about it. And **why**
relaxing the policy is slower is not established -- with no epoch limit the
ratchet imposes no ceiling at all, so `session` ought to be at least as fast as
Extreme's `w x 256 KiB / RTT`, and it is not. Extreme's download of 29.2 MiB/s
(245 Mbit/s) is close to that ceiling while `session` sits at 19.8 MiB/s
(166 Mbit/s) with no such ceiling in force. Something about the rekey cycle is
helping rather than hurting. Do not repeat this measurement as an explanation;
it is a result looking for a mechanism.

### Two DATA geometry results

Upload chunk size, `--bench-direction up`:

| `--bench-chunk-kib` | Result |
| --- | --- |
| 16 | **fixed and revalidated**: 181.7 MiB/s loopback upload |
| 64 | 33.3 Mbit/s |
| 256 | 8.5 Mbit/s |

The old 16-KiB failure came from the benchmark's 8-MiB completion window
admitting 512 frames while the transport permits 448 outstanding bulk frames.
The producer now waits on `TransportCore::wait_send_data`, whose bounded
admission accounts for both frame and byte limits and consumes the payload only
after admission. It polls in short cancellation-aware slices under the existing
60-second stall deadline; the 448-frame cap was not raised. A real authenticated
16-MiB, one-stream, 16-KiB upload completed on `.165` at 181.7 MiB/s; artifacts
are in `/home/f1xgod/yume-16k-lan-client-results`. This loopback result proves
the admission fix, not WAN throughput. TCP SOCKS/forward upload paths likewise
wait for bounded send admission; download-side local queues are serialized and
bounded, and now retain client H2 credit through local socket-write completion.
The missing gate is an integrated authenticated slow-reader run, not a missing
ownership edge in those paths.

At 256 KiB each application frame consumes an entire 256 KiB Extreme epoch, so
every frame forces a rekey exchange. That one is expected, not a defect, and it
is why `kMaxProtectedPayload` and `epoch_byte_limit` being equal deserves a
comment wherever chunk sizing is chosen.

## Required validation

Before claiming WAN tolerance, run matched Release binaries through isolated
network namespaces or two controlled hosts at 60, 100, and 210 ms RTT. Test at
100 Mbit/s and approximately 1 Gbit/s, then add 0.1% and 1% loss profiles.
Collect three-run medians for upload, download, and both directions at one and
multiple logical streams. Record rekey wait distribution/timeouts, prepared
epoch depth, H2 window stalls, TCP retransmits/effective buffers, process CPU,
RSS, and exact binary hashes. A 30-minute 210 ms soak with no key/window leak or
queue growth is a release gate; a loopback or LAN benchmark is not a substitute.

Flow-control qualification also needs adversarial integrations. A real stalled
server backend must show WINDOW_UPDATE credit stopping, bounded queues reaching
a plateau without exceeding their caps, and clean pause/resume when the sink
drains. A real authenticated slow TCP client must show the 64-frame/16-MiB
local proxy cap, withheld H2 credit, and clean drain or fail-closed behavior.
Layer tests establish those ownership edges, including delayed-OPEN and
slow-receiver saturation/recovery for the now-bounded UDP paths, but do not
replace the integrated run.

After the release matrix is stable, add an extended high-latency tier at
approximately 600 and 1,200 ms RTT with controlled loss, jitter and a bounded
multi-second interruption. Verify that counters and epochs never diverge,
prepared roots remain within the negotiated cap, authenticated ACK adaptation
converges without oscillation, and recovery or fail-closed shutdown matches the
documented deadline. These are satellite/extreme-path qualification points,
not a reason to weaken the 60/100/210 ms release gate.
