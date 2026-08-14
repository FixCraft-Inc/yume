# YUME 2.0 WAN behavior and release gate

Status: line-rate on the tested one-gigabit LAN. dev3 removes the
single-exchange rekey ceiling in the protocol, but high-bandwidth, high-RTT
single-tunnel performance is still not WAN-validated.

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

### First measured 60 ms result

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

## What the dev3 window still leaves open

Implemented: contiguous authenticated offers, multiple prepared ML-KEM-1024 +
X25519 + PSK roots, per-session bounds on offers/ACKs/retained keys, fatal gaps
and duplicates and window overflow, progress-paced offers, and wiping of
retired secrets. Unit coverage is in `src/core/security/session_ratchet_test.cpp`
and `src/core/security/auth_v2_test.cpp`.

Not yet done:

1. Adaptive depth. The window is a static negotiated cap; it does not measure
   ACK RTT or drain rate to pick a target. A static cap is the conservative
   choice and never lets a peer request unbounded work.
2. H2/TCP credit. The 2 MiB connection/stream window and requested socket
   buffers are unchanged, so they, not the ratchet, are now the next ceiling at
   1 Gbit/s. Raising them needs explicit operator/server caps and resource
   tests against malicious peers.
3. Traffic-shape review. Offers are paced, but the effect of a filling window
   on record size and timing distributions has not been captured or compared
   against the Chrome/Node fixture.
4. WAN measurement. Every number in the table above is a protocol model.

The exact `--outer-carrier-evidence` lifecycle is intentionally incompatible
with WAN benchmark modes other than its frozen one-shot workload. Use it to
seal same-session behavior inputs first. Its one MiB each way is an exact
message-echo correctness contract, not a throughput trial. Run the matched
WAN/loss matrices as separate frozen trials with identical binaries and
profile. Do not relabel the 42-second capture quiet interval or its
terminal-close evidence as WAN/throughput/soak qualification.

Multiple independent tunnels still aggregate, but that was never a fix for
one-tunnel semantics.

## Required validation

Before claiming WAN tolerance, run matched Release binaries through isolated
network namespaces or two controlled hosts at 60, 100, and 210 ms RTT. Test at
100 Mbit/s and approximately 1 Gbit/s, then add 0.1% and 1% loss profiles.
Collect three-run medians for upload, download, and both directions at one and
multiple logical streams. Record rekey wait distribution/timeouts, prepared
epoch depth, H2 window stalls, TCP retransmits/effective buffers, process CPU,
RSS, and exact binary hashes. A 30-minute 210 ms soak with no key/window leak or
queue growth is a release gate; a loopback or LAN benchmark is not a substitute.
