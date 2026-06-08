# Packet-Native Bulk Mode

This is the v1 packet-native path for making Yume behave more like a
packet VPN under load without giving up the current DPI profile.

## Shape

- Outer carrier stays the existing Chrome-shaped TLS 1.3 / HTTP/2-ish
  connection. No raw UDP mode is introduced for the default stealth path.
- Inner crypto stays mandatory when the peer requires it. Packet batches
  are carried inside normal encrypted `DATA` frames, so the AEAD AAD still
  binds the frame type and stream id.
- The capability is `packet_bulk_v1`. A capable client opens one long-lived
  stream with `proto=packet-bulk-v1`; old servers reject it cleanly instead
  of misrouting it as TCP or UDP.
- The stream payload is a `YBP1` batch: header, monotonic 63-bit sequence,
  packet count, then raw IP packets as length-prefixed byte strings.

## Why This Fixes The Native-Direct Ceiling

The old native-direct route created one Yume stream per lwIP TCP flow. Many
browser flows therefore meant many coroutine loops, JNI reads/writes, server
sockets, stream buffers, OPEN/CLOSE frames, and per-stream backpressure
decisions. A speedtest or modern browser page could turn small-object fanout
into scheduler pressure before the TLS pipe was full.

Packet-bulk mode moves the TUN boundary into Yume:

- Android reads TUN packets, batches them for up to a small byte/time budget,
  and sends one encrypted `DATA` frame on the packet stream.
- The server decodes the batch and writes packets to a server-side packet
  egress path/NAT instead of opening one remote socket per app flow.
- Downstream packets follow the same stream back to Android and are written
  directly to the TUN fd.

This preserves the "looks like Chrome talking to nginx" outer traffic shape
while removing per-application-stream work from the hot path.

## Server Egress V1

`yumed` only enables packet mode when explicitly configured:

```bash
yumed --packet-egress tun \
      --packet-tun-name yume-pkt0 \
      --packet-cidr 10.89.0.0/24 \
      --packet-mtu 1420
```

The Linux TUN address and NAT are operator-prepared in v1. `yumed` attaches
to that TUN, allocates client IPv4 addresses from the CIDR, writes validated
client packets to the TUN, and demuxes TUN replies by destination client IP.
If the TUN cannot be attached, packet mode fails closed and the server does
not advertise `packet_bulk_v1`.

## Security Invariants

- No change to the v1 top-level frame header.
- No plaintext packet payloads: packet batches are sent only after the current
  inner crypto setup has completed, and they use the same encrypted `DATA`
  path as TCP/UDP stream bytes.
- Sequence numbers are part of the encrypted batch payload and are reserved
  for replay/drop accounting in the packet engine.
- Android IPv6 is still fail-closed for packet-native v1.
- Packet egress is an operator-controlled server network path. Firewall and
  NAT policy for that TUN must enforce the site's allowed destinations.
