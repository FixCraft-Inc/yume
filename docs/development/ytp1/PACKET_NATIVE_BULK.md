# YUME 0.3 packet channels

Packet channels are a first-class YTP/1 service kind. They are not a legacy
byte stream carrying a private JSON or `YBP1` subprotocol.

- OPEN names a bounded packet service and may carry the strict built-in UDP
  destination encoding.
- Each application write is one opaque packet. Packet boundaries are
  preserved end to end.
- The ABI batches packet views for efficiency while retaining individual
  boundaries and all-or-none write admission.
- Packet size, batch count, stream count, queued bytes, pending opens, and
  outer/in-session flow credit are bounded before allocation.
- Capability advertisement is authenticated, but every packet OPEN is still
  independently authorized and resource checked.
- Direct UDP is an explicit `RouteProvider`; a future TUN adapter is an
  ordinary ABI consumer and cannot bypass route policy.

The YTP codec and ABI packet surface exist. An opt-in Asio direct-route
candidate implements bounded connected-UDP egress, but it is not wired into a
YTP/1 runtime. Packet handle creation, adapters, and the authenticated ABI
packet data path are not implemented yet. The retained transport-v2
`packet_bulk_v1`, server TUN/NAT helper contract, and private packet-stream
format remain part of the runnable transition product but are not YTP/1
compatibility surfaces.
