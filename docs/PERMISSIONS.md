# YUME permission model

YUME splits authentication from authorization and uses three physical identity
stores:

- `authorized_keys` lists regular composite Ed25519 + ML-DSA-87 identities.
  Regular identities are either `individual` (the default, one authenticated
  session) or explicitly `bulk` (several separately counted sessions sharing
  one credential).
- `auth_keys.meta` (a JSON file) lists what each connected key is **allowed to do** once inside. Without an entry here, a normally authorized key can use unprivileged transport features but cannot exec, cannot reach LAN addresses, cannot use privileged application codecs, and cannot administer other clients.
- `operator_keys` and `operator_keys.meta` are the separate controller visitor
  layer. Operator identities are individual-only.
- `admin_keys` contains distinct second-factor composite identities and no
  policy metadata. Admin is proved by presenting and signing with one visitor
  identity plus one different identity from this list.

The server rejects overlap between either visitor store and `admin_keys`,
rejects overlap between regular and operator stores, rejects bulk operator
identities, and rejects `allow_inbound_admin`, `allow_outbound_admin`, or
`control_full` in visitor metadata. Those capabilities come from the verified
second identity, never a policy boolean.

## The three-layer gate for dangerous features

Server-side command execution and LAN/private-IP bridging are gated by **all
three** of:

1. **Build switch.** `cmake -DYUME_FEATURE_EXEC=ON` (or `_LAN_BRIDGE`, `_FULL_CONTROL`). Stock builds ship with all three OFF. The runtime CLI flag still parses but logs a warning and stays disabled.
2. **Server flag.** `--allow-exec`, `--allow-local-ip`, `--control-full` (or the equivalent JSON config field). This is the global "feature is allowed on this server" upper bound.
3. **Per-key meta entry.** `"allow_exec": true` (or `"allow_local_ip"`) in the
   visitor policy. Default is deny. The server flag never grants permission to
   an identity that does not opt in.

Unrestricted bridging uses the build switch and server `--control-full` flag,
but its identity gate is the verified distinct admin factor rather than a
visitor-policy field. A request is allowed only when every applicable layer
agrees.

## File layout

```
/etc/yume/
  authorized_keys           # pairs of public PEM blocks; regular visitors
  auth_keys.meta            # JSON mapping fingerprint → permissions; "what each may do"
  operator_keys             # pairs of public PEM blocks; controller visitors
  operator_keys.meta        # explicit operator permissions
  admin_keys                # distinct composite second factors; no metadata
```

A typical layout:

```text
$ cat /etc/yume/authorized_keys
# Alice's composite identity: Ed25519, then ML-DSA-87.
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA...alice-ed25519...
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
...alice-ml-dsa-87...
-----END PUBLIC KEY-----
```

```jsonc
// /etc/yume/auth_keys.meta
{
  "0d4f3a...alice-fingerprint...": {
    "alias": "alice",
    "key_type": "individual",
    "weight": 1.5,
    "permissions": {
      "allow_exec": true,
      "allow_local_ip": true,
      "allow_codecs": ["monero-rpc"],
      "allow_services": ["example-service-v1"],
      "allow_chat": true,
      "allow_file": true,
      "allow_bytes": true
    }
  },
  "9b21e8...bob-fingerprint...": {
    "alias": "bob",
    "permissions": {
      "allow_local_ip": true,
      "allow_chat": true,
      "allow_file": true
    }
  },
  "73ac12...shared-fingerprint...": {
    "alias": "shared-public-users",
    "key_type": "bulk",
    "weight": 1.0,
    "max_sessions": 100,
    "permissions": {
      "allow_chat": false,
      "allow_file": false
    }
  }
  // visitor key omitted (connects only, no extra permissions)
}
```

Generate fingerprints with `yumed --auth-keys /etc/yume/authorized_keys --keys-list`. Any field you omit defaults to the safe choice. Privileged permissions always default to deny; relay-side `chat` / `file` / `bytes` default to allow for individual keys and deny for bulk keys.

An operator controller is configured separately:

```jsonc
// /etc/yume/operator_keys.meta
{
  "a1092c...operator-fingerprint...": {
    "alias": "primary-admin",
    "weight": 0.5
  }
}
```

Start the daemon with `--operator-keys /etc/yume/operator_keys` and
`--operator-keys-meta /etc/yume/operator_keys.meta`. Operator keys are
individual-only and default to one concurrent authenticated session. Merely
placing an identity in `operator_keys` does not silently grant exec, LAN,
full-control, or admin permission. Admin additionally requires a different
identity in `--admin-keys` and `--admin-auth` on the client.

## Individual and bulk regular keys

An individual key represents one identity and admits one authenticated session.
Use a bulk key only when distributing one credential to many ordinary tunnel
users is an intentional operational tradeoff. Every bulk connection receives a
unique server session identity and a separate fair-share slot, and is counted
against all three limits:

- global `max_sessions` / `--max-sessions` (default 256);
- server `bulk_key_max_sessions` / `--bulk-key-max-sessions` (default 64); and
- optional per-key `max_sessions`, which overrides the bulk default.

A shared private key cannot cryptographically distinguish the humans holding
it. A user who has that key can open several sessions up to the configured cap.
For that reason, bulk policies are rejected if they request exec, LAN/private
access, full control, privileged codecs/services, inbound/outbound admin, or
federation identity. Bulk chat/file/bytes relay permissions default to deny and
must be explicitly enabled if the shared-identity risk is acceptable. Use
individual keys for privileged users and use the bulk cap to bound credential
abuse.

## Permission fields

| Field | Default | What it grants | Server flag required |
| --- | --- | --- | --- |
| `allow_exec` | deny | Permit the EXEC control feature. The active runtime forwards the request to an opted-in client; yumed does not execute arbitrary shell commands locally. | `--allow-exec` and `YUME_FEATURE_EXEC=ON` |
| `allow_local_ip` | deny | Open TCP/UDP streams to RFC1918 / loopback addresses through the server | `--allow-local-ip` and `YUME_FEATURE_LAN_BRIDGE=ON` |
| `control_full` | invalid in metadata | Open TCP/UDP streams to *any* address only after a distinct admin factor | `--control-full`, `YUME_FEATURE_FULL_CONTROL=ON`, and verified admin identity |
| `allow_codecs` | deny | Use named application codecs, for example `["monero-rpc"]` | `--codec-allow <name>` |
| `allow_services` | deny | Use native embed named-service streams, for example `["example-service-v1"]` | server config `allow_services` plus `yume_server_register_service` |
| `allow_monero_rpc` | deny | Compatibility alias for the built-in Monero RPC application codec against the server's loopback monerod backend | `--codec-allow monero-rpc` |
| `allow_inbound_admin` | invalid in metadata | Runtime opt-in for this admin-authenticated target | verified admin identity plus client opt-in |
| `allow_outbound_admin` | invalid in metadata | Runtime opt-in for this admin-authenticated operator caller | `operator_keys`, verified admin identity, and client opt-in |
| `allow_chat` | individual: allow; bulk: deny | This key can use the chat relay | none |
| `allow_file` | individual: allow; bulk: deny | This key can use the file relay | none |
| `allow_bytes` | individual: allow; bulk: deny | This key can use the raw-bytes relay | none |

Top-level resource fields are separate from `permissions`:

| Field | Default | Meaning |
| --- | --- | --- |
| `key_type` | `individual` | `individual` or explicitly shared `bulk` regular key |
| `weight` | `1.0` | Fair-egress multiplier in `0.1..100`; `1.5` receives 1.5 times the share of a competing `1.0` identity |
| `max_sessions` | 1 / server bulk default | Per-key authenticated-session cap; values above 1 require `key_type: bulk` |
| `priority` | unset | Legacy integer weight compatibility; prefer decimal `weight` |

`alias` is a free-form label used in logs.

## Bridge / admin modes: the four quadrants

Two relationships are independent:

- **server-controls-client** (S → C): the server sends the client commands or open requests, and the client executes them.
- **client-controls-server** (C → S): the client opens streams through the server (SOCKS, port-forward, exec) or attaches to administer other clients.

| Mode | Server side | Client side | Use case |
| --- | --- | --- | --- |
| **S→C, C→S (full bridge)** | `--allow-exec` (with key `allow_exec`) plus directional admin policy as described below | `--accept-server-control` AND open SOCKS/forward | Operator's own laptop tunnelling through their own server, with the server able to dispatch opted-in control requests |
| **S→C only** | `--allow-exec` (with key `allow_exec`) | `--accept-server-control`, no `--socks`/`-L`/`-R` | Server dispatches control requests to an opted-in client; the client doesn't tunnel anything outbound |
| **C→S only** | normal flags, key `allow_local_ip` etc. as needed | `--socks` / `-L` / `-R` (no `--accept-server-control`) | Most common: user wants a SOCKS proxy / port forward, server cannot push requests back |
| **neither (pure transport)** | no `--allow-exec`, no `--control-full`, no `--allow-local-ip`; key has no per-key permissions | no `--accept-server-control`, no SOCKS | Probe / handshake test only; useful for smoke-testing the tunnel without exposing either side |

The implemented client flag is `--accept-server-control`.

An admin channel between relayed clients is admitted only when all of these are true:

1. the caller registered `relay_mode=trusted`;
2. the caller authenticated with an `operator_keys` identity, also proved a
   distinct `admin_keys` identity, and enabled its outbound runtime opt-in; and
3. the target also proved a distinct `admin_keys` identity and enabled its
   inbound runtime opt-in.

Modern `admin.attach` also requires the target to accept the signed invite. The legacy attach message is retained for compatibility but is no longer caller-blind: it applies the same caller/target predicate and additionally requires the target's `--accept-server-control` opt-in. In federation, the authenticated source server enforces the caller half and the target server rechecks the target half; the current wire format does not carry an independently verifiable caller-policy proof across servers.

## Pre-authenticated service-only tier

`preauth_services` is a deliberately narrower admission path for embedded named services. A peer with any valid self-signed composite identity may enter it only when the server explicitly configures at least one preauth service. That peer is persisted as `PreauthServiceOnly`, not promoted to the normal authorized dispatcher.

The central post-auth gate permits only:

- `OPEN` for `proto=service.v1` when the requested service is in the configured preauth list and registered by the embedder;
- `DATA` and `CLOSE` on an already accepted named-service stream; and
- `PING` / `PONG` connection liveness frames.

Control, relay, admin, generic TCP/UDP opens, codecs, benchmark streams, packet egress, and every other frame family are rejected for this tier. Normal `allow_services` metadata still applies to keys admitted through `authorized_keys`; it does not broaden a preauth session.

## Operational tips

- **Editing auth_keys.meta is the recommended way to manage permissions.** The server's interactive `--ui` mode is brittle around per-key permissions; it's documented but you'll have a smoother time with a JSON editor.
- **Reload after edits.** Regular, operator, admin, and policy stores are immutable runtime snapshots. Use the authenticated reload operation where available, or `systemctl restart yumed`; a failed reload preserves the previous complete snapshot.
- **Application codecs.** Codec permissions are intentionally narrower than `allow_local_ip`: they only enable named protocol-aware codecs listed in `allow_codecs`. The Monero built-in validates allowed wallet RPC paths/methods and reconstructs HTTP only to a loopback backend configured by `--monero-rpc-backend`.
- **Native service streams.** `allow_services` is for embedded C ABI users and is intentionally separate from `allow_local_ip`, `control_full`, `allow_codecs`, and exec. For a normally authorized key, a service stream opens only when the server config lists the service, the key metadata lists the same service, and the embedding process registered it with `yume_server_register_service`. The separately configured preauth tier follows the narrower rules above.
- **Revoke a key.** Remove the public-key block from `authorized_keys`. The meta entry can stay; it'll be ignored.
- **Audit.** Startup logs `auth policy <permissions summary>` for any key that has a non-empty meta entry. Run `yumed --auth-keys ... --keys-list` to dump all configured keys with their aliases.
- **CI/scripted setup.** Use `yumed --keys-list` for composite fingerprints; a
  one-block `openssl pkey` pipeline hashes only the first half and is not the
  identity fingerprint.

## Security posture summary

- A server built without `YUME_FEATURE_EXEC` cannot run user commands even if every other layer is misconfigured.
- A server built with `YUME_FEATURE_EXEC=ON` but without `--allow-exec` cannot run user commands.
- A server with `--allow-exec` but no `auth_keys.meta` entry granting `allow_exec` cannot run user commands.
- The same applies to LAN bridging and unrestricted bridging.
- Outbound admin requires an operator visitor identity plus a distinct admin
  identity; inbound admin requires the target's distinct admin identity. Both
  directions also require runtime opt-in.
- Bulk keys are separately counted per session and cannot receive privileged controller, exec, LAN, full-control, codec/service, or federation policy.
- AUTH imports only ordered Ed25519 + ML-DSA-87 composite identities and verifies
  both challenge signatures with OpenSSL before either normal or preauth admission.
