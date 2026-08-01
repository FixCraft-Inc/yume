# YUME security modes

YUME 2.0-dev5 supports four ratchet-policy modes. `extreme` remains the
default and exactly preserves the dev4 epoch limits. The mode changes how much
traffic may share one hybrid ML-KEM-1024 + X25519 epoch; it does not disable
TLS 1.3, the random PSK, HKDF, AES-256-GCM, or the fresh one-use key derived
for every protected frame.

| Mode | Epoch bytes | Epoch frames | Sender-active time | Purpose |
| --- | ---: | ---: | ---: | --- |
| `extreme` | 256 KiB | 512 | 500 ms | Current overkill default and smallest compromise window. |
| `normal` | 8 GiB | 262,144 | 60 s | Lower hybrid-rekey overhead on fast links. |
| `soft` | 256 GiB | 8,388,608 | 30 min | Throughput-first policy with a much wider epoch compromise window. |
| `ultimate` | user supplied | user supplied | exact user-supplied milliseconds | Expert-managed bounded policy. |

Normal and Soft pair their byte and frame limits at the current 32 KiB
production DATA-read geometry. At that geometry neither counter silently
dominates the other; the active-time limit normally remains the first boundary
on a roughly gigabit saturated direction. This is a design rationale, not a
WAN throughput claim.

An epoch rotates when the next application frame would cross the byte or frame
limit, or when active traffic reaches the time limit. The earliest condition
wins. Idle time does not consume the sender-active timer. Consequently,
changing only the time value cannot guarantee a particular rotation interval
on a busy connection.

Both endpoints advertise their accepted limits inside the authenticated AUTH
transcript. Each sending direction uses the component-wise stricter values, so
one endpoint can constrain a peer but cannot make the peer accept a wider
compromise budget. This negotiation is why dev5 intentionally does not
interoperate with dev4.

## Ultimate template

Merge these fields into both the client and server JSON configuration. Values
may differ; the connection negotiates the stricter value for each direction.

```json
{
  "security_mode": "ultimate",
  "security_custom": {
    "epoch_bytes": 4194304,
    "epoch_frames": 4096,
    "epoch_active_ms": 4281
  },
  "rekey_window": 8
}
```

The accepted bounds are:

- `epoch_bytes`: 262,144 through 1,099,511,627,776;
- `epoch_frames`: 1 through 1,073,741,824;
- `epoch_active_ms`: 1 through 86,400,000;
- `rekey_window`: unchanged at 1 through 64.

Invalid, incomplete, negative, or out-of-range values fail configuration or
AUTH instead of being clamped. `ultimate` without all three custom values also
fails closed.

## Security meaning

`normal` and `soft` do not use weaker algorithms and do not reuse an AES-GCM
message key. They retain one hybrid epoch root/chain for more traffic. A live
endpoint compromise can therefore expose a larger active-epoch window than in
`extreme`; the configured rekey window additionally bounds prepared future
epochs. Use `extreme` unless measured hybrid-rekey overhead justifies a wider
policy.

Transport DATA size, WebSocket/H2 geometry, padding, jitter, and cover-profile
behavior are deliberately unchanged in this security pass. The maximum
protected YUME frame remains 256 KiB, while production reads retain their
existing smaller geometry. Those classifier-visible controls belong to the
later stealth-profile pass and must be capture-driven.
