# Packet-Native Bulk Mode

This is the staged path for making Yume behave more like a packet VPN
under load without giving up the current DPI profile.

## Shape

- Outer carrier stays the existing Chrome-shaped TLS 1.3 / HTTP/2-ish
  connection. No raw UDP mode is introduced for the default stealth path.
- Inner crypto stays mandatory when the peer requires it. Packet batches
  are carried inside normal encrypted `DATA` frames, so the AEAD AAD still
  binds the frame type and stream id.
- The future capability is `packet_bulk_v1`. A capable client opens one
  long-lived stream with `proto=packet-bulk-v1`; old servers reject it
  cleanly instead of misrouting it as TCP or UDP.
- The stream payload is a `YBP1` batch: header, monotonic 63-bit sequence,
  packet count, then raw IP packets as length-prefixed byte strings.

## Why This Fixes The Native-Direct Ceiling

The current native-direct route creates one Yume stream per lwIP TCP flow.
Many browser flows therefore mean many coroutine loops, JNI reads/writes,
server sockets, stream buffers, OPEN/CLOSE frames, and per-stream backpressure
decisions. A speedtest or modern browser page can turn small-object fanout
into scheduler pressure before the TLS pipe is full.

Packet-bulk mode moves the TUN boundary into Yume:

- Android reads TUN packets, batches them for up to a small byte/time budget,
  and sends one encrypted `DATA` frame on the packet stream.
- The server decodes the batch and writes packets to a server-side packet
  egress path/NAT instead of opening one remote socket per app flow.
- Downstream packets follow the same stream back to Android and are written
  directly to the TUN fd.

This preserves the "looks like Chrome talking to nginx" outer traffic shape
while removing per-application-stream work from the hot path.

## Security Invariants

- No change to the v1 top-level frame header.
- No plaintext packet payloads: packet batches are sent only after the current
  inner crypto setup has completed, and they use the same encrypted `DATA`
  path as TCP/UDP stream bytes.
- Sequence numbers are part of the encrypted batch payload and are reserved
  for replay/drop accounting in the packet engine.
- The packet egress path must keep existing policy gates: anonym checks,
  local-IP restrictions, relay permissions, and DNS leak policy cannot be
  bypassed by entering packet mode.

## Staging

1. Land shared batch codec and constants in C++ and Android. Inert by default.
2. Advertise `packet_bulk_v1` in server info only when the server packet
   egress is configured.
3. Add Android packet-engine plumbing behind an explicit config flag.
4. Add server packet egress/NAT and sequence/drop accounting.
5. Promote to the default native-direct path only after SOCKS-only and the
   existing route-core bridge both remain unchanged in regression tests.
