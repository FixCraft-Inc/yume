# YTP/1 foundation operations

This document covers the experimental schema-1 operator surface. The default
build still provides the runnable transport-v2 client and daemon, documented in
the [0.2 operations guide](https://github.com/FixCraft-Inc/yume/tree/f0cc9e7/docs/OPERATIONS.md). A production YTP/1
daemon and client are not available yet; the authoritative boundary is
[IMPLEMENTATION_STATUS.md](../../IMPLEMENTATION_STATUS.md).

## Provision without exposing secrets

Generate a new server kit and first client bundle with:

```bash
yume-setup-ytp1 init \
  --host tunnel.example.com \
  --output /secure/staging/yume-kit \
  --client-name laptop
```

The output path must not already exist. Setup creates the complete tree in a
private staging directory, syncs it, and publishes it atomically. Private keys,
PSKs, and admission material use owner-only permissions and are never printed.
Keep the server and client subtrees separated after generation; transfer a
client bundle through an authenticated channel and remove offline CA material
from the server host.

Generate one kit per deployment and one client bundle per client. Never reuse
one access PSK across authorized keys, copy credentials into JSON, or commit a kit,
capture, profile, or diagnostic artifact.

## Validate before start

Run doctor as the identity that will run YUME:

```bash
yume-doctor-ytp1 --config /etc/yume/yumed.json
yume-doctor-ytp1 --config "$XDG_CONFIG_HOME/yume/yume.json"
```

The experimental doctor rejects unknown schema keys, provider mismatch, unsafe limits, missing
cover content, unsupported or mismatched key algorithms, symlink and file-race
conditions, permissive secret modes, and incompatible manifest values. Fix the
reported JSON pointer or path; do not bypass the check with a CLI override.

## Configuration authority

Schema 1 is role tagged and contains these sections only:

- `endpoint`: one client target or bounded server listeners;
- `suite`: the exact mandatory provider composition;
- `credentials`: references to files, never inline private material;
- `cover`: the qualified profile and server cover root;
- `services` and `adapters`: explicit named-service exposure. Services are
  unique by `(name, kind)`, not name alone. Multiple adapters of one kind are
  valid when their concrete resources differ: SOCKS bind address and port,
  packet interface, or direct service and kind. Exact resource collisions are
  rejected;
- `limits`: bounded frames, streams, queues, opens, rekeys, controls, and
  packets.

Runtime CLIs will accept config selection, validation, version, and diagnostic
controls only. Network or security policy does not have a CLI override.

## Service management target

Once the runtime gate closes, a service manager should invoke only:

```ini
ExecStart=/usr/bin/yumed --config /etc/yume/yumed.json
```

Run it as a dedicated unprivileged identity. Prefer a high port or grant only
`CAP_NET_BIND_SERVICE` when port 443 is required. Restrict filesystem access to
the generated server tree and the configured cover root. Do not grant shell,
firewall, package-management, or arbitrary filesystem privileges to the
key-holding process.

This is the target YTP/1 operational model, not evidence that the current
transport-v2 `yumed` accepts schema-1 configuration. The unqualified
`yume-setup`, `yume`, and `yumed` commands remain the runnable 0.2 lane.

## Failure handling

- Treat provider, suite, exporter, identity, capability, and credential
  mismatches as terminal. YTP/1 has no downgrade or fallback.
- Invalid or absent public admission must remain ordinary cover traffic. Do not
  expose a YUME-specific error to an unauthenticated peer.
- Treat queue, stream, packet, control, and rekey exhaustion as bounded
  failures; increasing limits requires a measured resource review.
- Rotate a compromised key by issuing a new per-identity bundle and removing
  the old public identity and PSK mapping. Reusing unaffected devices is a
  deployment-policy choice, not a protocol downgrade.
- Retain only redacted logs and reproducible evidence. Never collect private
  keys, PSKs, plaintext, full AUTH messages, or exported keying material.

## Release qualification

Before production use, require all freeze gates listed in
[IMPLEMENTATION_STATUS.md](../../IMPLEMENTATION_STATUS.md): installed C/C++
consumers, setup-to-first-stream and cover-browser smokes, protocol vectors,
sanitizers and fuzzing, cross-platform builds, documentation drift checks,
profile evidence, and external security review. A successful setup or doctor
run alone is not runtime qualification.
