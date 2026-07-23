# YUME 2.0 WAN behavior and release gate

Status: dev2 is line-rate on the tested one-gigabit LAN, but high-bandwidth,
high-RTT single-tunnel performance is not solved or WAN-validated.

## What dev2 fixed

Dev1 stopped all application writes as soon as it sent `REKEY_INIT`. Dev2 sends
the INIT before consuming the current epoch and permits authenticated old-epoch
DATA until the unchanged hard boundary. This hid the exchange on the tested
sub-millisecond LAN: matched one-stream binaries sustained about 931 Mbit/s in
both directions on a 940-941 Mbit/s raw link.

Security limits did not change: one direction still carries at most 256 KiB or
512 application frames, or remains active for at most 500 ms, before advancing.
Only one future epoch can currently be pending. If its ACK has not arrived when
the current epoch reaches a hard boundary, application writes must wait.

## RTT ceilings for one busy direction

For a byte-saturated direction whose ACK takes approximately one RTT, the
present upper-bound model is:

```text
single-direction rate <= 256 KiB * 8 / rekey RTT
```

| Rekey RTT | Epoch/RTT ceiling | 1 Gbit/s BDP | Minimum 256 KiB epochs covering BDP |
|---:|---:|---:|---:|
| 60 ms | 35.0 Mbit/s | 7.50 MB | 29 |
| 100 ms | 21.0 Mbit/s | 12.50 MB | 48 |
| 210 ms | 10.0 Mbit/s | 26.25 MB | 101 |

This is a protocol model, not a measured WAN result. Two other unchanged hard
limits matter:

- Time preparation starts 100 ms before the 500 ms active limit. A continuous
  low-byte flow at 210 ms RTT can therefore reach the hard time boundary about
  110 ms before its ACK. Its rough duty-cycle ceiling is
  `500 / (500 + 110)`, or 82%, even when it never fills 256 KiB. The 60 ms
  profile fits inside the lead; 100 ms is only the no-jitter edge.
- Message preparation leaves 64 of 512 application-frame slots. Very high
  small-frame rates can exhaust that allowance before an ACK even when neither
  the byte nor time limit is first.

Sparse/interactive traffic with no additional write at a hard boundary does
not wait merely because an exchange is pending, so it should usually remain
responsive. The five-second rekey timeout is about 24 RTTs even at 210 ms;
ordinary latency alone should not close a session, while a multi-second outage
still closes fail-closed as designed.

After the ratchet ceiling is removed, two more high-BDP limits need measurement:

- the authenticated H2 connection/stream receive window is 2 MiB, equivalent
  to only about 280/168/80 Mbit/s of one-RTT credit at 60/100/210 ms;
- client and server request 2 MiB TCP socket buffers, while a 1 Gbit/s path
  needs 7.5-26.25 MB of bandwidth-delay product across this RTT range. Kernel
  autotuning behavior and effective buffer sizes must be recorded rather than
  inferred from the request alone.

TCP retransmission and head-of-line blocking also become visible on lossy WANs.
H2/WebSocket masking and the mandatory inner cryptography do not prevent TCP
from recovering loss, but a lost segment delays later ordered bytes.

## Security-preserving dev3 direction

The appropriate next protocol change is a bounded window of independently
hybridized future directional epochs, negotiated as an exact dev3 capability:

1. Authenticate strictly contiguous future-epoch offers inside the existing
   encrypted direction.
2. Prepare multiple ML-KEM-1024 + X25519 + PSK roots ahead of use; keep every
   256 KiB / 512-frame / 500 ms per-epoch limit unchanged.
3. Bound offers, ACKs, retained keys, CPU, and memory per session; reject gaps,
   duplicates, window overflow, or wrong-direction records and wipe retired or
   aborted secrets.
4. Maintain a low-watermark instead of emitting a large, classifier-visible
   burst of rekey records. Measure ACK RTT and drain rate only to choose a
   bounded target depth; never let a peer request unbounded work.
5. Raise or adapt H2/TCP credit only after the ratchet window is proven, with
   explicit operator/server caps and resource tests against malicious peers.

At 1 Gbit/s and 210 ms, the table requires at least 101 prepared 256 KiB epochs
before safety margin. That is feasible in bandwidth (the hybrid exchange is a
small percentage of each epoch) but is not a trivial patch: ordering, secret
retention, admission accounting, CPU scheduling, and traffic shape all require
focused negative tests and review. Multiple independent tunnels can aggregate
around the current barrier, but it is not a fix for one-tunnel semantics.

## Required validation

Before claiming WAN tolerance, run matched Release binaries through isolated
network namespaces or two controlled hosts at 60, 100, and 210 ms RTT. Test at
100 Mbit/s and approximately 1 Gbit/s, then add 0.1% and 1% loss profiles.
Collect three-run medians for upload, download, and both directions at one and
multiple logical streams. Record rekey wait distribution/timeouts, prepared
epoch depth, H2 window stalls, TCP retransmits/effective buffers, process CPU,
RSS, and exact binary hashes. A 30-minute 210 ms soak with no key/window leak or
queue growth is a release gate; a loopback or LAN benchmark is not a substitute.
