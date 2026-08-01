# Chrome 151 / Node 24 reference fixture

This is YUME 2.0-dev6's single evidence-backed cover identity. Five fresh,
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

The script intentionally launches normal Chrome. `--headless` changes the
HTTP User-Agent to `HeadlessChrome` and therefore is not authoritative for the
transport profile.

The 42-second hold showed Chrome originating one HTTP/2 PING immediately before
its masked WebSocket CLOSE, with Node acknowledging it. No periodic idle
keepalive, random padding, or random timing jitter was observed, so YUME must
not invent those features without classifier evidence.

TLS first-flight ClientHello and ServerHello parity is evaluated separately;
NetLog's TLS summary is not a substitute for ordered wire evidence.
