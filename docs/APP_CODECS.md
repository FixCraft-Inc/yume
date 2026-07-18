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
- Codec backends must be loopback unless the descriptor sets
  `require_loopback_backend = false`. The check is applied from the descriptor,
  so it covers every codec rather than only the Monero handler.
- Dispatch is fail-closed. A descriptor without a `validate_request` hook admits
  no requests at all, so an unfinished codec cannot reach a backend by default.
- `allow_codecs` and legacy `allow_monero_rpc` do not imply `allow_local_ip`
  or `control_full`.
- The codec reconstructs HTTP and strips hop-by-hop headers.
- Body caps come from the descriptor. Monero RPC uses 8 MiB requests and 15 MiB
  responses.
- Client and backend operations use timeouts.
- Logs include method/path, byte counts, backend endpoint, and close reason; full
  request/response bodies are not logged by default.

## Codec layout

- `src/core/app_codec/codec.{hpp,cpp}` — codec-neutral envelope, HTTP parsing,
  lookup behavior, and the explicit built-in registry assembly point.
- `src/core/app_codec/builtin/` — one unit per built-in codec. Each owns its
  constants, its request policy, and its descriptor.
- `src/client/codec/` — local client-side service shims.
- `src/server/session/codecs.cpp` — server-side trusted reconstruction. Request
  validation, limits, and loopback policy come from the descriptor. A small
  adapter maps current codec-specific configuration fields to an endpoint.

A codec reaches the engine only by contributing a `CodecDescriptor` to
`builtin_registry()` in `codec.cpp`. That function is the single wiring point:
adding a codec adds a line, and removing one removes a line plus its unit.

## Writing a codec

Codecs are C++ units compiled into the binary. There is deliberately no
`dlopen()` path: a codec plugin would run inside `yumed`, which holds identity
and session key material, so in-process third-party code is not an acceptable
trade. Untrusted third-party codecs are planned as a sandboxed out-of-process
runner instead — see `docs/IMPLEMENTATION_STATUS.md`.

To add one:

1. Create `src/core/app_codec/builtin/<name>.{hpp,cpp}` in namespace
   `yume::app_codec::builtin`. Keep every codec-specific constant there.
2. Implement a `RequestValidator`. Allow-list what you accept — method, path,
   body size, and any payload rules. Returning `false` with a reason denies.
3. Expose a `const CodecDescriptor& <name>_descriptor()` carrying the id,
   aliases, permission key, display name, default endpoint, body caps, the
   validator, and the backend policy.
4. Add the descriptor to `builtin_registry()` and the `.cpp` to
   `src/CMakeLists.txt`.
5. If the codec needs a client-side shim, add it under `src/client/codec/`.

Users who want a local codec follow the same steps and rebuild; the compiler
enforces the contract.

Stable registry contract (since 1.1):

- A codec has a canonical id such as `monero-rpc-v1` plus stable user aliases
  such as `monero-rpc`.
- Server config enables codecs by name with `--codec-allow <name>` or
  `codec_allow: ["name"]`.
- Per-key auth grants codec use with `permissions.allow_codecs`.
- Every identity question (`is_supported_codec`, `canonical_codec_id`,
  `builtin_codec`) resolves through the registry, so a codec added to the
  registry is immediately visible to config, auth, and dispatch.
