# YUME performance (historical 1.x datapoint)

This page preserves a historical 1.x WAN datapoint. It does not describe the
current 2.0 transport or its new multi-client resource telemetry. For current
2.0 throughput, concurrency, CPU, and RSS evidence, use
[YUME_2_0_IMPLEMENTATION_STATUS.md](YUME_2_0_IMPLEMENTATION_STATUS.md) and
[SELFTEST.md](SELFTEST.md). The dev2 high-RTT ceiling, the implemented dev3
window, and the remaining measured high-RTT ceiling are documented in
[YUME_2_0_WAN_BEHAVIOR.md](YUME_2_0_WAN_BEHAVIOR.md).

One benchmark run, April 2026. This is a useful real-path datapoint, not a universal benchmark or an isolated measurement of YUME's CPU/framing overhead. It used one client, one relay, and one network, and the repository does not contain the raw result artifacts or enough host detail to reproduce the exact run.

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

The sum of the two separately measured relay legs is **265.68 ms**. It is a better geographic reference than the 55.53 ms direct path, but it is still an estimate assembled from separate measurements rather than a simultaneous end-to-end control through the same proxy path.

## Through YUME (SOCKS proxy)

| Metric | Result |
| --- | ---: |
| Download | 233.99 Mbps |
| Upload | 36.10 Mbps |
| TCP-connect ping, 0 Hz hopping | 264.32 ms (filtered) |
| TCP-connect ping, 2 Hz hopping | 267.05 ms (filtered) |

Latency was sampled with TCP-connect timing through the YUME SOCKS proxy to the fixed endpoint, two 20-sample runs at 2 Hz. Each run had one outlier > 400 ms (typical jitter spike on the client's local network). Filtered averages remove that single outlier.

## Routed-latency comparison

Against the estimated 265.68 ms routed reference:

| Mode | Difference from routed reference |
| --- | --- |
| 0 Hz hopping | effectively 0 ms |
| 2 Hz hopping | +1.4 ms typical (+2.7 ms vs 0 Hz) |

## Throughput context

| | Direct client | Through YUME | Retained |
| --- | ---: | ---: | ---: |
| Download | 902.58 Mbps | 233.99 Mbps | 25.9 % |
| Download (vs relay capacity) | 298.79 Mbps | 233.99 Mbps | **78.3 %** |
| Upload | 39.34 Mbps | 36.10 Mbps | **91.8 %** |

The 25.9 % figure compares the distant routed result to the client's local access link and therefore includes geography and relay capacity. Comparing against the relay's separately measured download gives useful context (78.3 % retained), but it still does not isolate YUME: the target, route, test timing, and TCP behaviour are not controlled as a same-path bypass. Upload was close to the client uplink result in this run.

## Takeaways

- This route carried about 234 Mbps down and 36 Mbps up through YUME, which is enough for common interactive and streaming workloads.
- The two small latency samples are consistent with low added latency and a roughly 2.7 ms difference between hopping off and 2 Hz, but they are not strong enough to establish an "always" bound.
- Geography and relay capacity clearly mattered. This run cannot attribute the remaining throughput difference among YUME, TCP path effects, the relay, and the target.
- CPU utilization, cycles per byte, memory use, concurrency scaling, and a same-path non-YUME control were not recorded. Claims such as "<1 % typical, <5 % always" are therefore unsupported by this dataset.
