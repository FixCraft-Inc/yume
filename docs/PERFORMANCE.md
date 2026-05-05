# YUME performance

One fair benchmark run, April 2026. This is not a universal benchmark (single client, single relay, single network), but it is the working baseline for what YUME's overhead looks like on a real path with a distant relay.

## Setup

- Client in the United States.
- Relay in Japan.
- A fixed third endpoint used only for fair latency measurement, so RTTs aren't taken from speed-test "nearest server" pings.
- Client network had ~3 ms of unstable jitter during the run; one-off spikes are noted and filtered separately.

## Direct paths (YUME not involved)

| Path | Result |
| --- | ---: |
| Direct client download | 902.58 Mbps |
| Direct client upload | 39.34 Mbps |
| Relay-side download | 298.79 Mbps |
| Relay-side upload | 296.39 Mbps |
| RTT, client ↔ relay | 119.95 ms |
| RTT, relay ↔ fixed endpoint | 145.74 ms |
| RTT, client ↔ fixed endpoint | 55.53 ms |

The expected RTT for any traffic that's *forced* through the relay, even with zero proxy overhead, is the sum of the two relay legs: **265.68 ms**. That's the honest baseline to compare YUME against, not the 55.53 ms direct path.

## Through YUME (SOCKS proxy)

| Metric | Result |
| --- | ---: |
| Download | 233.99 Mbps |
| Upload | 36.10 Mbps |
| TCP-connect ping, 0 Hz hopping | 264.32 ms (filtered) |
| TCP-connect ping, 2 Hz hopping | 267.05 ms (filtered) |

Latency was sampled with TCP-connect timing through the YUME SOCKS proxy to the fixed endpoint, two 20-sample runs at 2 Hz. Each run had one outlier > 400 ms (typical jitter spike on the client's local network). Filtered averages remove that single outlier.

## YUME-only overhead

Against the 265.68 ms routed baseline:

| Mode | YUME-only overhead |
| --- | --- |
| 0 Hz hopping | effectively 0 ms |
| 2 Hz hopping | +1.4 ms typical (+2.7 ms vs 0 Hz) |

## Throughput context

| | Direct client | Through YUME | Retained |
| --- | ---: | ---: | ---: |
| Download | 902.58 Mbps | 233.99 Mbps | 25.9 % |
| Download (vs relay capacity) | 298.79 Mbps | 233.99 Mbps | **78.3 %** |
| Upload | 39.34 Mbps | 36.10 Mbps | **91.8 %** |

The naive "25 % retained" download number compares to the client's local internet. That is the wrong comparison; even a perfect zero-overhead proxy that routes through Japan can't deliver more bandwidth than the relay itself has. Against the relay's own measured download capacity, YUME retained 78 %. Upload was bottlenecked by the client uplink, not by YUME.

## Takeaways

- With hopping off, YUME's steady-state latency overhead is below the noise floor of the measurement.
- 2 Hz key hopping adds about 1–4 ms of typical latency.
- Throughput loss on a long route is dominated by the relay path and the relay's own bandwidth ceiling, not by YUME's framing or crypto.
- The headline "<1 % typical, <5 % always" claim refers to YUME's own processing overhead measured against the routed baseline. The total wall-clock latency a user sees is mostly geography.
