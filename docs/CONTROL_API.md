# YUME JSON control API

> **Transport-v2 surface:** this is the command-oriented facade contract used
> by the runnable 0.2 product and optional GUI. The experimental role-neutral
> YTP/1 ABI does not expose a JSON operation bus.

This document defines the JSON operation envelope used by local runtime IPC and
by the in-process embedder entry points `client::RuntimeController::request` and
`server::RuntimeController::request`. The 1.x C ABI reached this bus through
`yume_client_request_json` / `yume_server_request_json`; those symbols no longer
exist, and the replacement role-neutral ABI deliberately exposes typed
lifecycle calls instead of a JSON operation bus. This contract is independent
of transport v2 and of `YUME_ABI_VERSION`.

## Envelope and error layers

Every well-formed operation returns one JSON object:

```json
{"ok": true, "result": {}}
```

or:

```json
{"ok": false, "error": "human-readable reason"}
```

`result` may be an object, array, Boolean, or another operation-specific JSON
value. `error` is diagnostic text and must never be parsed to recover a status.

The C calls have a separate outer status layer:

- invalid handles/op names or a non-object `args_json` return
  `YUME_STATUS_INVALID_ARGUMENT`;
- malformed or numerically unrepresentable JSON returns
  `YUME_STATUS_PARSE_ERROR`;
- an unavailable runtime returns `YUME_STATUS_NOT_RUNNING`;
- request transport/deadline failure returns its typed ABI status;
- a handled operation failure returns `YUME_STATUS_OK` and `ok=false` in the
  output envelope;
- sizing follows the normal ABI rule: `out == NULL` or insufficient storage
  returns `YUME_STATUS_BUFFER_TOO_SMALL`, and `needed` includes the final NUL.

The generic C request calls serialize requests per handle. A sizing call still
executes the operation, but YUME retains its completed handled response when it
does not fit. An immediate retry with the same operation and normalized
argument object copies that pending response without running the handler again;
successful delivery consumes it, while another too-small buffer preserves it.
Only one response is pending per handle, and a different well-formed request
discards it before execution, so callers should keep each sizing/retry pair
together. The cache uses a fixed-size digest rather than retaining plaintext
request JSON. `NULL`, an empty string, and `{}` are equivalent empty argument
objects. Typed transport, lifecycle, and deadline failures do not produce a
cacheable handled response.

`args_json == NULL` or an empty string means `{}`. Any nonempty value must
encode an object. The operation name must be a nonempty exact string. Operation
names are limited to 128 bytes and serialized arguments to 1 MiB, excluding
their terminating NULs; exceeding a bound returns
`YUME_STATUS_RESOURCE_EXHAUSTED` before dispatch.

## Authority and deadlines

The client request entry point runs as the connected local client identity. Its
explicit timeout bounds how long the caller waits and whether a queued handler
may start. If the deadline expires before the handler starts, that handler is
cancelled. If it has already started, it may finish after the caller receives
`YUME_STATUS_TIMEOUT`, including completing a mutation. A timeout is therefore
not a rollback result and callers must not blindly retry a mutating operation.
Remote `admin.*` operations also have an independent internal 8-second
request deadline and depend on an authenticated admin relay channel plus
remote authorization.

The owner-only local IPC socket exposes its process's complete local operation
set. Socket filesystem permissions are therefore part of the authorization
boundary.

The embedded server request entry point does not require IPC, but deliberately
exposes only bounded read operations. It has no timeout parameter. Mutating
admin-socket operations such as `runtime.stop`, `runtime.disconnect`, session
killing, and rules reload return a handled `ok=false` envelope here. Use typed
lifecycle and facade methods for embedded mutations.

## Client operations

Unless a row says otherwise, `{}` means exactly an empty object, listed string
fields are required and nonempty, and unknown fields are rejected. `text` and
`reason` may be empty strings. `peer` and `invite_selector` accept the same
exact-id-or-unambiguous-display-name selectors as the CLI.

| Operation | Args | Result |
| --- | --- | --- |
| `runtime.info`, `runtime.status` | `{}` | runtime/self/server/tunnel status object |
| `runtime.stop` | `{}` | `true` after local stop is requested |
| `directory.list` | `{}` | array of endpoint objects |
| `contacts.list` | `{}` | contact/presence document below |
| `contacts.forget` | exactly `{"endpoint_id": string}` | `{"removed": boolean}` |
| `history.list` | object containing only optional nonempty string `peer_id` and optional integer `limit` in `1..1000` (default `200`) | bounded history document below |
| `history.delete` | exactly one of `{"peer_id": nonempty string}` or `{"all": true}` | `true` after durable deletion/no-op |
| `invite.list` | `{}` | array of pending relay invites |
| `invite.accept` | `{"invite_selector": string}` plus optional one-of string `relay_secret`/`password` | `true` |
| `invite.reject` | `{"invite_selector": string}` plus optional string `reason` | `true` |
| `chat.open` | `{"peer": string}` plus optional one-of string `relay_secret`/`password` | `{"channel_id": string, "peer_id": string}` |
| `chat.send` | exactly `{"channel_id": string, "text": string}` | `true` |
| `chat.close` | exactly `{"channel_id": string}` | `true` |
| `file.send`, `bytes.send` | `{"peer": string, "path": string}` plus optional one-of string `relay_secret`/`password` | `true` once the outgoing invite is queued |
| `admin.attach` | exactly `{"peer": string}` | `true` after the request is sent |
| `admin.status` | `{}` | `{self, server_id, server_name, directory_size, pending_invites, active_channels}` from the administered peer |
| `admin.sessions` | `{}` | `{channels[], pending_invites[]}`, each channel `{stream_id, channel_id, channel_kind, peer_id, peer_name}` |
| `admin.stop` | `{}` | `{"stopping": true}` |

The three `admin.*` operations above are answered by the remote peer, so their
`result` is peer-controlled JSON and carries a second failure layer. A local
transport or internal remote-admin deadline failure gives `ok=false` as usual,
but an operation the remote peer does not implement returns `ok=true` with
`{"error": "unsupported op"}` inside `result`. Before use, require `result` to
be an object, check for an `error` member, and validate every required field and
element type against the shapes above. The outer C ABI caller deadline remains
a typed `YUME_STATUS_TIMEOUT`, not a JSON operation failure.

Operations that use a relay secret accept either `relay_secret` (the canonical
base64 encoding of a 32-byte derived secret) or `password` (which the local
runtime derives), never both members in one request. Either may be omitted when
the target operation does not require a password. Admin channels do not accept
a relay secret. Relay-secret/password inputs are sensitive even though the
response is not. Callers must minimize their lifetime and wipe mutable storage
after the call.

`contacts.list` returns durable trust even when live directory refresh fails:

```json
{
  "ok": true,
  "result": {
    "schema_version": 1,
    "directory_available": true,
    "directory_error": "",
    "contacts": [{
      "endpoint_id": "peer-id",
      "fingerprint": "composite-sha256",
      "trust_source": "tofu",
      "explicit_marker": false,
      "configured_mismatch": false,
      "in_directory": true,
      "online": true,
      "display_name": "Peer"
    }]
  }
}
```

`contacts.forget` removes only learned TOFU trust. Configured pins and durable
explicit authorization are refused rather than silently weakened.
Presence fields such as `online`, `display_name`, and the advertised relay
permissions are present only when `in_directory` is true.

`history.list` reports storage availability separately from an empty history:

```json
{
  "ok": true,
  "result": {
    "schema_version": 1,
    "available": true,
    "error": "",
    "truncated": false,
    "items": [{
      "ts_ms": 1780000000000,
      "peer_id": "peer-id",
      "peer_name": "Peer",
      "direction": "in",
      "text": "hello"
    }]
  }
}
```

Rows are ordered oldest-to-newest and contain at most `limit` items. A response
also retains at most 512 KiB of serialized record plaintext, and one operation
scans at most 64 MiB of protected history logs. The newest items are retained
and `truncated` is true when either the item or plaintext-response bound is hit.
Every current item contains the five required fields shown above: integer
`ts_ms` within the signed 64-bit range, nonempty string `peer_id`, string
`peer_name`, `direction` equal to `in` or `out`, and string `text`. The
protected on-disk record is a closed internal schema with exactly those five
fields. That storage rule does not close the public response schema: ABI-v1
consumers must ignore unknown additive result fields under the compatibility
rules below.
Protection, I/O, protected-scan, directory-scan, or record-integrity failure
yields `available:false`, a nonempty diagnostic, and an empty `items` array; it
is never silently reported as empty history.

History persistence is deliberately best-effort: a protection or I/O failure
does not tear down an otherwise valid relay channel. Consequently `available`
describes readability when `history.list` runs; it is not an acknowledgement
that every earlier chat append reached durable storage. An entry whose
serialized plaintext would exceed the 512 KiB result budget is dropped before
the history key or log is created, so the store does not write a record that it
must refuse to list.

`history.delete {"all":true}` validates and bounds the complete directory scan
before unlinking anything. Separate directory entries cannot be removed as one
filesystem transaction, however, so an unlink or directory-sync failure can
return `ok:false` after an earlier entry was removed. After such a failure,
callers should re-list before deciding whether to retry.

`runtime.info` and `runtime.status` return the same client object. Its
required fields are `self` (endpoint object), string `server_id` and
`server_name`, non-negative integer `directory_size`,
`pending_invites`, `active_channels`, `requested_tunnels`,
`authenticated_tunnels`, `live_tunnels`, `tunnel_sessions`,
`bytes_in`, and `bytes_out`. `active_chat_stream`,
`active_chat`, `active_admin_stream`, and `latest_lifecycle` are
present only when applicable.

Endpoint objects returned by `self` and `directory.list` always contain
string `endpoint_id`, `endpoint_kind`, `display_name`, `hostname`,
`client_platform`, `client_variant`, `client_version`,
`server_id`, and `relay_mode`; Boolean `allow_inbound_admin`,
`allow_outbound_admin`, `allow_chat`, `allow_file`,
`allow_bytes`, and `online`; and string arrays `controller_ids` and
`controlled_target_ids`. `server_name` and `auth_pubkey_b64` are
optional. A direct-federation row also has `remote:true` plus string
`federation_peer_id` and `remote_endpoint_id`.

`invite.list` rows always contain integer `relay_protocol_version` and
`created_ms`; string `invite_id`, `from_id`, `to_id`,
`channel_kind`, `metadata_json`, `handshake_request_b64`, and
`from_display_name`; and Boolean `requires_password` and `accepted`.
Identity/response fields are present only when supplied by that invite.

## Embedded-server read operations

The embedded server read allowlist is:

| Operation | Args | Result |
| --- | --- | --- |
| `runtime.info`, `runtime.status` | `{}` | server identity/configuration and endpoint-status snapshot |
| `runtime.sessions` | `{}` | active relay-channel rows |
| `runtime.events` | optional `{"limit": integer in 0..512}` (default `200`) | oldest-to-newest recent lifecycle-event rows |
| `directory.list` | `{}` | local and directly federated endpoint rows |
| `federation.status` | `{}` | redacted configuration/link document |
| `federation.topology` | `{}` | single-hop topology document |

Unknown arguments are rejected. The owner-only server IPC socket also
exposes these mutations. None is available through the embedded server read
entry point:

| Operation | Exact args | Result |
| --- | --- | --- |
| `runtime.stop` | `{}` | `true` only after a stop callback accepts the request |
| `runtime.disconnect` | `{"endpoint_id": nonempty string}` | `true` |
| `runtime.sessions.kill` | exactly one nonempty string member: `session_id`, `endpoint_id`, or `ip` | `true` |
| `runtime.rules.reload` | `{}` | `true` |

Selectors are typed: a `session_id` value is compared only with the canonical
decimal session id, an `endpoint_id` only with the exact endpoint id, and
`ip` only with the client address. Coincidentally equal text in another
field is not a match.

`runtime.info` and `runtime.status` return the same server object. Its required
fields are string `server_id` and `server_name`; integer `listen_port`;
Boolean `relay_enable` and `directory_enable`; non-negative integer
`endpoints` and `channels`; object `host`; and array `endpoint_statuses`.
Each endpoint-status row contains an `endpoint` object in the shape documented
above and an optional `latest_lifecycle` object.

`runtime.sessions` rows require string `channel_id`, `channel_kind`,
`left_endpoint_id`, and `right_endpoint_id`; non-negative integer
`left_stream_id` and `right_stream_id`; Boolean `e2ee_required`, `pending`, and
`federated`; and integer `route_hops`.

`runtime.events` rows require string `endpoint_id`, `display_name`, `state`,
`message`, `detail`, `client_platform`, `client_variant`, `client_version`,
`effective_protection`, `exit_ip`, and `error_code`; Boolean
`traffic_verified`; and integer `server_time_ms`.

Both federation documents currently carry `schema_version: 1`.
`federation.status` never returns raw peer JSON, PSK paths, carrier-secret
paths, or secret contents. Each peer row includes `peer_id`, redacted dial
configuration/presence flags, overall `state`/`ready`, separate
`outbound_state`/`outbound_ready`, `inbound_connections`,
`last_handshake_ms` as a Unix-epoch millisecond count (`0` before the first
handshake), and the canonical active-channel count. `last_error` is a maximum
of 512 printable ASCII bytes; configured federation key/CA/peer-secret paths
are replaced with `[redacted-path]`, and control or non-ASCII bytes are
replaced with `?`.
Configured peers remain visible as `not-started` rows even when federation
itself is disabled. An authenticated, hello-complete inbound-only peer appears
with `configuration:null`, `ready:true`,
`outbound_ready:false`, and `inbound_connections` greater than zero.
Entries that cannot be represented as a unique accepted peer are counted only
by `invalid_peer_entries`, because the raw text may contain secret paths.

The exact federation status shape is:

| Location | Required fields and types |
| --- | --- |
| top level | `schema_version` integer `1`; `enabled` Boolean; `self` object; `invalid_peer_entries` non-negative integer; `peers` array |
| `self` | string `server_id`/`server_name`; integer `listen_port`; non-negative integer `local_endpoints`; Boolean `federation_enabled` |
| peer row | string `peer_id`, `state`, `outbound_state`, `last_error`; Boolean `ready`/`outbound_ready`; non-negative integer `inbound_connections`/`channels_active`; integer `last_handshake_ms`; nullable `configuration` |
| peer `configuration` | string `host`; integer `port`; Boolean `tls_pin_present`, `psk_present`, `carrier_secret_present` |

`federation.topology` contains:

- `self`: reporting server identity, port, local endpoint count, and enablement;
- `nodes`: directly configured/observed peers with link state, redacted
  configuration, endpoint counts, `route`, and `hops`;
- `edges`: the reporting node's direct federation links;
- `channels`: active relay-channel metadata;
- `transit`: currently `{ "supported": false, "max_hops": 1 }`.

Topology repeats the exact `self` and peer link fields above. Each node also
requires non-negative integer `endpoints`, string-array `route`, and
integer `hops` (currently `1`). Each edge requires string `from`,
`to`, `kind`, and `state`; Boolean `ready` and
`outbound_ready`; and non-negative integer `inbound_connections`.
Each channel requires string `channel_id`, `channel_kind`,
`left_endpoint_id`, and `right_endpoint_id`; Boolean `federated`
and `pending`; and integer `route_hops`. Peer-derived node and edge
arrays are ordered by `peer_id`; consumers must still not depend on JSON
object key order.

No field implies multi-hop forwarding. The design that could change this is
explicitly unimplemented in
[`protocol/YUME_2_0_FEDERATION_TRANSIT.md`](protocol/YUME_2_0_FEDERATION_TRANSIT.md).

## Compatibility

### Compatibility migrations

The current pre-GUI/Android synchronization snapshot intentionally replaces
four earlier, unqualified development shapes:

- `invite.accept` and `invite.reject` take `invite_selector`, not the
  misleading `invite_id` name, because an unambiguous display name is also valid;
- deleting all history requires explicit `{"all":true}` rather than an empty
  object;
- `history.list` returns the bounded availability document above rather than
  a bare array;
- federation timestamps use `last_handshake_ms`, not
  `last_handshake_ts`.

GUI and Android consumers must migrate all four together and must not implement
fallback retries with the old mutation schemas.

Within ABI v1, the envelope, outer-status split, operation names documented as
public, required input meaning, and existing required result fields do not
change incompatibly. Implementations may add result fields. Callers must ignore
unknown fields and must not depend on object key order or diagnostic wording.

The product remains pre-1.0, so adding a new operation or optional field does
not require a transport or ABI version bump. Removing/renaming an operation,
changing an existing field's type/meaning, or turning a handled operation
failure into an outer ABI failure requires an explicit compatibility decision
and synchronized consumer migration.
