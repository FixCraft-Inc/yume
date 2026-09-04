# Chrome 151 / Node 24 reference fixture

This is YUME's single evidence-backed cover identity, transport profile
`chrome151-node24-v1`, shared by the transport-v2 runtime and the YTP/1
development suite. Five fresh,
normal (non-headless) Google Chrome `151.0.7922.71` profiles were captured on
Debian 13 against `tools/cover-node/server.mjs` under official Node
`24.18.0`.

Every run contains the TLS outcome, ordered HTTP/2 SETTINGS and headers, the
document/CSS/JavaScript asset sequence, RFC 8441 extended CONNECT, one MiB in
each WebSocket direction, fragmentation, ping/pong, flow-control recovery, a
42-second idle interval, and graceful close. The stable identity projection is
identical across all five runs. Flow-control stall counts and close timing are
retained as distributions rather than falsely treated as byte constants.

Chrome NetLog `IncludeSensitive` files contain local certificate and machine
details. The raw files are deliberately not committed; `manifest.json` records
their SHA-256 digests. The reviewed output of `sanitize_netlog.mjs` is committed
under `runs/`, and `chrome_h2_profile.json` is the canonical first run consumed
by production-profile tests.

## Reproduction

Use the exact binaries recorded in `manifest.json`. The capture script refuses
other versions or binary digests, performs no runtime downloads, creates an
independent Chrome profile per run, and reaps its browser and Node processes:

```text
DISPLAY=:<unprivileged-display> \
tools/cover-node/capture_chrome151_runs.sh \
  /tmp/yume-chrome151-capture \
  /path/to/node-v24.18.0-linux-x64/bin/node
```

The runner consumes the frozen page/transfer definition in
`tools/cover-node/workload-v1.json`, writes a source-bound mode-0600
`environment.json`, and executes a checksummed private snapshot of every
reopened capture source. It requires a clean exact-commit checkout and an
output outside that checkout; the runner rejects an inside-checkout canonical
path before it creates the directory. For a matched normal/YUME session, set
`YUME_CAPTURE_TLS_CERT`, `YUME_CAPTURE_TLS_KEY`, and `YUME_CAPTURE_SNI`; both
certificate variables must be present together, the key must not be
group/world accessible, and the certificate must cover the SNI. Without those
variables, the runner creates a standalone one-day certificate.

After every declared run and all final identity checks succeed, the runner
writes portable relative checksum manifests and creates mode-0600
`complete.json` last. The classifier-input validator rejects a bundle without
that marker or with changed runtime, certificate, run, sanitized, TLS-wire, or
opaque raw-NetLog hashes.

The script intentionally launches normal Chrome. `--headless` changes the
HTTP User-Agent to `HeadlessChrome` and therefore is not authoritative for the
transport profile.

The 42-second hold showed Chrome originating one HTTP/2 PING immediately before
its masked WebSocket CLOSE, with Node acknowledging it. No periodic idle
keepalive, random padding, or random timing jitter was observed, so YUME must
not invent those features without classifier evidence.

TLS first-flight ClientHello and ServerHello parity is evaluated separately;
NetLog's TLS summary is not a substitute for ordered wire evidence.

`chrome_tls_wire_profile.json` records the independently observed Chrome 151
and direct-Node first-flight structure. The gate preserves cipher, extension,
group, signature, version and ALPN order; key-share and GREASE-ECH geometry;
and TLS record lengths. It accepts Chrome's measured middle-extension shuffle
and GREASE-ECH length distribution, while rejecting a helper that emits one
stable order or size marker.

`helper_tls_wire_run_1.json` through `helper_tls_wire_run_5.json` are sanitized
first flights from five complete authenticated YUME flows using the pinned
uTLS helper and the same local certificate/ALPN conditions. The gate reports
`PARITY` for the Chrome ClientHello structural distribution and direct-Node
ServerHello structure: five distinct middle orders, three measured GREASE-ECH
lengths, and no stable helper marker. The five full normal-Chrome NetLog runs
predate relay integration, so a fresh same-session Chrome NetLog plus wire
recapture remains a release evidence-quality gate; it is not a known helper
wire drift.
