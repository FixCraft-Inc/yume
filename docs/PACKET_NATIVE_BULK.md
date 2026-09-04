# Packet-native bulk mode

> **Runnable transport-v2 path:** this document describes the current packet
> service. First-class YTP/1 packet channels are an unfinished replacement
> contract documented in the
> [YTP/1 foundation page](development/ytp1/README.md#packet-channels).

This is the v1 packet-native path for making Yume behave more like a
packet VPN under load without giving up the current DPI profile.

## Shape

- Outer carrier stays the existing browser-oriented TLS 1.3 / HTTP/2-opening
  connection. No raw UDP mode is introduced for the default stealth path.
- Inner crypto stays mandatory when the peer requires it. Packet batches
  are carried inside normal encrypted `DATA` frames, so the AEAD AAD still
  binds the frame type and stream id.
- The capability is `packet_bulk_v1`. A capable client opens one long-lived
  stream with `proto=packet-bulk-v1`; old servers reject it cleanly instead
  of misrouting it as TCP or UDP.
- The stream payload is a `YBP1` batch: header, monotonic 63-bit sequence,
  packet count, then raw IP packets as length-prefixed byte strings.

## Why this fixes the native-direct ceiling

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

## Server egress v1

`yumed` only enables packet mode when explicitly configured:

```bash
yumed --packet-egress tun \
      --packet-tun-name yume-pkt0 \
      --packet-cidr 10.89.0.0/24 \
      --packet-mtu 1420 \
      --dns-server 192.0.2.53
```

`--dns-server` is required, not defaulted. Its address is handed to every
client that enters packet mode, so whoever operates that resolver observes
every hostname those clients look up. Startup refuses packet egress until an
IPv4 resolver is named, so that observer is always an operator decision.

The Linux TUN address and NAT are operator-prepared in v1. `yumed` attaches
to that TUN, allocates client IPv4 addresses from the CIDR, writes validated
client packets to the TUN, and demuxes TUN replies by destination client IP.
If the TUN cannot be attached, packet mode fails closed and the server does
not advertise `packet_bulk_v1`.

### Optional host-network helper

`yumed` deliberately does not run firewall or routing commands. Linux
administrators who want a `wg-quick`-style setup can use the separate,
explicit `yume-packet-quick` helper. Review its complete plan first:

```bash
tools/yume_packet_quick.py up \
  --listen build-host.example:8443 \
  --allow-from 192.168.1.0/24 \
  --dry-run
```

Then apply it through `sudo`:

```bash
sudo tools/yume_packet_quick.py up \
  --listen build-host.example:8443 \
  --allow-from 192.168.1.0/24
```

The helper creates one user-owned TUN, enables IPv4 forwarding, creates one
named nftables NAT table scoped to the packet CIDR, and, when UFW is active,
adds only the matching TCP ingress and routed-egress rules. It prompts before
mutation, refuses to adopt an existing interface/table, never flushes or
changes default firewall policy, and records non-secret state under
`/run/yume-packet-quick/`. Remove only those recorded resources with:

```bash
sudo tools/yume_packet_quick.py down
```

Use `--firewall none` only when another firewall manager already supplies the
required input and forwarding policy. These changes remain opt-in and are not
performed by normal `yumed` startup.

## Linux client TUN

The CLI can attach the authenticated packet channel directly to an existing
Linux TUN without starting a SOCKS listener:

```bash
yume --config config/yume.json --packet-tun yume-client0
```

The interface must already exist and be accessible to the process. Yume opens
it as `IFF_TUN|IFF_NO_PI`, prints the server-assigned IPv4 address, MTU, and
DNS values, and moves complete IPv4 packets between the TUN and one
`packet-bulk-v1` stream. It does not create the interface or change addresses,
routes, DNS, firewall policy, persistence, ownership, or NAT.

The reusable packet engine admits writes all-or-none, batches for at most
2 ms up to 64 packets / 128 KiB, and bounds both directions to 1024 packets /
4 MiB. Sequence zero is required first and every later batch must increment
exactly. Malformed, duplicate, regressed, exhausted, IPv6, wrong-address, or
over-MTU traffic closes the packet channel while leaving the authenticated
tunnel available to other adapters.

After the packet engine dequeues and sequence-numbers a batch, the channel
retains that exact encoded payload until the bounded transport queue admits it.
Temporary saturation is retried in bounded slices rather than closing the
channel or skipping a sequence. Transport shutdown wakes the admission wait;
local channel shutdown is observed between slices, so teardown cannot wait
indefinitely on capacity. Deterministic saturation/recovery and stop tests pin
these guarantees. This closes the source-side loss defect but does not by
itself qualify the Android always-on VPN path.

## No packet C ABI in this tree

The 0.2 C ABI that exposed this engine through `yume_client_open_packet` and
the opaque `yume_packet` handle was replaced by the role-neutral ABI v1
candidate. That candidate starts and stops the transport, but
`yume_endpoint_open_packet` still returns `YUME_STATUS_UNSUPPORTED`, so it
opens no packet channel, and the `yume-abi-tun` diagnostic adapter that drove
the old handle is no longer a build target.

Until the replacement ABI has a live packet channel, this tree can produce
**no** packet-ABI throughput result. Use `yume --packet-tun` for the in-process
adapter. The retired `yume-abi-tun`/`iperf3` procedure is preserved in the
[0.2 archive](https://github.com/FixCraft-Inc/yume/tree/f0cc9e7/docs/PACKET_NATIVE_BULK.md) and in Git history; do not
run it against this tree.

## Security invariants

- No change to the v1 top-level frame header.
- No plaintext packet payloads: packet batches are sent only after the current
  inner crypto setup has completed, and they use the same encrypted `DATA`
  path as TCP/UDP stream bytes.
- Sequence numbers are part of the encrypted batch payload and are reserved
  for replay/drop accounting in the packet engine.
- Android IPv6 is still fail-closed for packet-native v1. The VPN must block it
  explicitly; feeding IPv6 into native closes the packet channel, while omitting
  an IPv6 route without a block can leak traffic outside the VPN.
- Packet egress is an operator-controlled server network path. Firewall and
  NAT policy for that TUN must enforce the site's allowed destinations.
