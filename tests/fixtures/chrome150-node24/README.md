# Chrome 150 / Node 24 reference fixture

This fixture was captured from Google Chrome `150.0.7871.114` on Debian 13
against `tools/cover-node/server.mjs` under Node `24.18.0`.

The committed JSON is deliberately reduced. Chrome NetLog in
`IncludeSensitive` mode contains local certificate and machine details, so the
raw file must remain outside the repository.

Reproduce it with a local certificate whose SAN covers the chosen hostname.
Start the exact Node runtime:

```text
YUME_COVER_HOST=127.0.0.1 YUME_COVER_PORT=<cover-port> \
YUME_COVER_TLS_KEY=<tls-key> YUME_COVER_TLS_CERT=<tls-cert> \
npx --yes node@24.18.0 tools/cover-node/server.mjs
```

Then start exact Chrome with a fresh profile, a loopback DevTools port, and a
raw NetLog path:

```text
google-chrome --headless=new --disable-gpu --no-first-run \
  --ignore-certificate-errors --remote-debugging-address=127.0.0.1 \
  --remote-debugging-port=<devtools-port> \
  --user-data-dir=<fresh-profile-dir> \
  --log-net-log=<raw-netlog.json> \
  --net-log-capture-mode=IncludeSensitive about:blank
```

Drive and sanitize the session:

```text
npx --yes node@24.18.0 tools/cover-node/capture_chrome.mjs \
  <devtools-port> https://localhost:<cover-port>/ 42000
npx --yes node@24.18.0 tools/cover-node/sanitize_netlog.mjs \
  <raw-netlog.json> localhost:<cover-port> > <sanitized.json>
```

The 42-second hold keeps the RFC 8441 stream active through graceful close. It
showed Chrome originating one H2 PING immediately before the masked WebSocket
CLOSE, with Node acknowledging it; it did not show a periodic idle keepalive
cadence.
