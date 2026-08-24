# YUME security modes

YUME 0.2.0-dev6 supports four ratchet-policy modes. `extreme` remains the
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
compromise budget. This negotiation is why dev6 intentionally does not
interoperate with dev4.

## Why legacy hop was removed

They share a goal -- the key in use changes over time -- and almost nothing
else. The difference decides which one may be relied on.

Hop derives its key as `HKDF-SHA256(base_key, "hop:" || hop_id)` where
`hop_id = (now_ms + offset) / interval_ms`. It is a pure function of one
long-lived base key and the wall clock. Nothing is exchanged, which is why it
needs no round trip and why both endpoints must tolerate clock skew by trying a
window of neighbouring ids. The consequence is the part that matters:
**recovering the base key yields every hop key that ever existed and every one
that ever will.** There is no forward secrecy and no recovery after a
compromise; rotation changes the bytes on the wire without bounding what a
single compromise exposes.

The ratchet re-runs a full ML-KEM-1024 + X25519 exchange for every epoch and
mixes the result into a one-way chain with the PSK. Past epoch keys cannot be
derived from a current one, and a compromised endpoint stops leaking once a
later exchange completes. That is what makes the epoch limits in this document
meaningful: they bound a real compromise window, where a hop interval bounds
nothing.

So hop is not a faster or lighter ratchet, and it is not a knob for the same
property. It is superseded, and the correct end state is that it has no callers
rather than that it is tuned.

**Current status.** Hop derivation, clock-skew trial decryption, transport and
session state, client/server/facade/GUI configuration fields, share-bundle
fields, and status output were removed after federation moved to AUTH v2. The
only live rotation control is the authenticated directional ratchet policy.
Old release notes describe the 1.x mechanism as history, not a supported 2.0
configuration surface.

## Choosing a mode

Rotation cadence on every core and CLI path is `security_mode` and nothing
else. There is no hop interval to lengthen; see the section above for why hop is
not the knob for this.

**A long rotation is already expressible.** `soft` rotates on a 30 minute
sender-active timer, and `ultimate` accepts any bounded value up to 24 hours, so
a one-hour epoch is a configuration, not a code change. Remember that the
earliest of the three limits wins: on a busy link the byte or frame limit is
reached long before a one-hour timer, so raising only the time value changes
very little. Raise all three together or the setting is decorative.

**Turning rotation off is deliberately not offered.** The minimums in
`ratchet_policy.hpp` are floors, not defaults, and there is no mode that removes
the limits. An epoch with no cap means one hybrid key protects an unbounded
amount of plaintext, and the compromise of that key exposes all of it. That is
the one property these modes exist to bound.

**"Maximum everything" is not currently a mode selection.** The old claim that
the negotiated multi-epoch window was unreachable came from a defective probe
that omitted sealed application frames and desynchronised the peer's record
sequence. Corrected tests reach the negotiated window, and live 60-ms sweeps
show `rekey_window=16` materially increases throughput over the default 8.
That headroom is not free: the window also bounds how many prepared future
roots each side retains under live process-memory compromise. Window 16 doubles
that exposure relative to 8, while 32 added little measured benefit and more
RSS. Keep `extreme` plus the default window 8 unless an explicit owner security
decision and capture/classifier campaign qualifies a different value.

Loosening epoch byte/frame/time limits is a separate and generally worse trade:
it protects more data with each root. The measured Extreme policy was faster
and more consistent than the tested session-wide-key profile, so there is no
current throughput argument for weakening the epoch policy.

The honest summary per purpose:

| Purpose | Setting | What it costs |
| --- | --- | --- |
| Default, and the best joint setting today | `extreme`, `rekey_window=8` | Shortest epoch budgets; up to eight prepared future roots may still be exposed by live process compromise. |
| Long-lived low-rate links where rekey overhead matters | `normal` | Up to 8 GiB or 60 s of traffic shares one epoch. |
| Bulk transfer where throughput outranks compromise window | `soft` | Up to 256 GiB or 30 min shares one epoch. |
| An exact operator-managed budget | `ultimate` | Whatever the chosen values allow, bounded by the floors and ceilings. |

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
