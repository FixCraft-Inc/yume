# YUME application codecs

Application codecs are protocol-aware local service shims. They are not raw TCP
forwards and do not grant LAN/private-IP bridging.

Current implementation and testing status, including the difference between
registry-driven built-ins and future dynamic plugin codecs, is tracked in
`docs/IMPLEMENTATION_STATUS.md`.

The first built-in codec is `monero-rpc-v1`:

```text
wallet -> 127.0.0.1:18089
       -> yume client parses Monero HTTP/RPC
       -> Yume DATA frames carry typed app-codec envelopes
       -> yumed validates the codec permission and RPC path/method
       -> yumed reconstructs HTTP to loopback monerod
       -> response returns as a typed app-codec envelope
```

## Monero RPC codec

Server side:

```bash
yumed --listen 443 \
  --codec-allow monero-rpc \
  --monero-rpc-backend 127.0.0.1:18089
```

The backend must be a loopback IP literal. The default backend is
`127.0.0.1:18089`, so `--monero-rpc-backend` is only needed when monerod uses a
different loopback port.

Per-key permission is separate from LAN bridging:

```json
{
  "client-fingerprint": {
    "permissions": {
      "allow_codecs": ["monero-rpc"]
    }
  }
}
```

`allow_monero_rpc: true` remains accepted as a compatibility alias, but new
configs should use the modular codec list.

Client side:

```bash
yume --server example.com -i id_ed25519 --monero-rpc
```

This listens on `127.0.0.1:18089` by default. Override with:

```bash
yume --server example.com -i id_ed25519 \
  --monero-rpc --monero-rpc-listen 127.0.0.1:18090
```

Wallet/curl smoke:

```bash
monero-wallet-cli --daemon-address 127.0.0.1:18089

curl http://127.0.0.1:18089/json_rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_info"}'
```

## Wire shape

The top-level Yume frame format is unchanged. Codec streams use a normal
encrypted `OPEN` payload:

```json
{"proto":"app-codec-v1","codec":"monero-rpc-v1"}
```

Each `DATA` payload is a Yume app-codec envelope with magic `YAC1`, version,
kind, metadata length, body length, JSON metadata, then the original HTTP body.
This keeps the v1 implementation compatible and inspectable without putting raw
HTTP request bytes on the Yume data path.

## Safety rules

- Codec listeners must bind loopback.
- Monero backend must be loopback.
- `allow_codecs` and legacy `allow_monero_rpc` do not imply `allow_local_ip`
  or `control_full`.
- The codec reconstructs HTTP and strips hop-by-hop headers.
- Request bodies are capped at 8 MiB; response bodies at 15 MiB.
- Client and backend operations use timeouts.
- Logs include method/path, byte counts, backend endpoint, and close reason; full
  request/response bodies are not logged by default.

## Extension point

Built-ins live under:

- `src/core/app_codec/` for shared envelope, HTTP, validation, and registry logic.
- `src/client/codec/` for local client-side service shims.
- `src/server/session/codecs.cpp` for server-side trusted reconstruction.

Future plugins should follow the same contract: parse the local app protocol,
validate it on both ends, carry typed codec envelopes over Yume streams, and
reconstruct only to a narrow trusted backend.

Dynamic `.so` / DLL codec plugins are not implemented yet. The current code
provides a built-in registry shape that future plugin descriptors should reuse.

Stable registry contract (since 1.1):

- A codec has a canonical id such as `monero-rpc-v1` plus stable user aliases
  such as `monero-rpc`.
- Server config enables codecs by name with `--codec-allow <name>` or
  `codec_allow: ["name"]`.
- Per-key auth grants codec use with `permissions.allow_codecs`.
- Built-ins and future plugin descriptors share the same id/alias/permission
  shape; the Monero handler is the first built-in implementation.
